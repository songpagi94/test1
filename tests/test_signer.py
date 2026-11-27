"""서명 엔진 전달과 요청별 Sid 정책을 실제 전송 없이 검증합니다."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from unittest.mock import Mock

import pytest

from pykorail.auth.signer import RequestSigner
from pykorail.client import Korail
from pykorail.constants import API_ENDPOINTS, DYNAPATH_LOGIN_OP
from pykorail.crypto import encrypt_sid
from tests.declaration_decoder import decode_declaration
from tests.payloads import CIPHER_PAYLOAD, LOGIN_OK
from tests.signing_support import LegacyEngineAdapter

INIT_MS = 1_700_000_000_000
SYNTHETIC_SID_KEY = b"0123456789abcdef"
IDENTITY = "0123456789abcdef"


def test_parallel_signatures_have_independent_nonces_and_matching_sid(monkeypatch) -> None:
    # given
    monkeypatch.setattr("pykorail.auth.declaration.time.time", lambda: INIT_MS / 1000)
    nonces = iter([0, 5])
    monkeypatch.setattr("pykorail.auth.declaration.secrets.randbits", lambda bits: next(nonces))
    signer = RequestSigner(device_id=IDENTITY, sid_key=SYNTHETIC_SID_KEY)
    # when
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(signer.sign, [API_ENDPOINTS["login"]] * 2))
    # then
    tokens = [headers["x-dynapath-m-token"] for headers, _ in results]
    assert tokens[0] != tokens[1]
    assert [decode_declaration(token)["ts"] for token in tokens] == [str(INIT_MS)] * 2
    assert [sid for _, sid in results] == [encrypt_sid("AD", INIT_MS, SYNTHETIC_SID_KEY)] * 2


def test_unsigned_path_does_not_call_engine() -> None:
    # given
    engine = Mock()
    signer = RequestSigner(device_id=IDENTITY, engine=engine)
    # when
    result = signer.sign(API_ENDPOINTS["stationdata"])
    # then
    assert result == ({}, None)
    engine.generate_token_with_timestamp.assert_not_called()


@pytest.mark.parametrize(("endpoint", "bound"), [("login", True), ("search_schedule", False), ("reserve", False)])
def test_engine_receives_identity_and_operation(endpoint, bound) -> None:
    # given
    engine = Mock()
    engine.generate_token_with_timestamp.return_value = ("201fixture", INIT_MS)
    signer = RequestSigner(device_id=IDENTITY, engine=engine, sid_key=SYNTHETIC_SID_KEY)
    # when
    result = signer.sign(API_ENDPOINTS[endpoint], include_sid=False)
    # then
    assert result == ({"x-dynapath-m-token": "201fixture"}, None)
    engine.generate_token_with_timestamp.assert_called_once_with(
        request_bound=bound, op_id=DYNAPATH_LOGIN_OP, device_id=IDENTITY
    )


def test_logged_in_factory_uses_injected_engine_for_search_and_reservation(korail, monkeypatch) -> None:
    # given
    _, session = korail
    session.routes.update({"code": CIPHER_PAYLOAD, "login": LOGIN_OK})
    monkeypatch.setattr("pykorail.client.create_session", lambda headers: session)
    engine = Mock()
    engine.generate_token_with_timestamp.return_value = ("201fixture", INIT_MS)
    # when
    client = Korail.logged_in("fixture@example.test", "fixture-only", android_id=IDENTITY, dynapath_engine=engine)
    train = client.trains.search("서울", "부산", depart_after=datetime(2099, 10, 3, 9))[0]
    client.reservations.create(train)
    # then
    assert engine.generate_token_with_timestamp.call_count == 3
    assert [call.kwargs for call in engine.generate_token_with_timestamp.call_args_list] == [
        {"request_bound": bound, "op_id": DYNAPATH_LOGIN_OP, "device_id": IDENTITY} for bound in [True, False, False]
    ]
    assert [session.kwargs_for(endpoint)["headers"] for endpoint in ["login", "search_schedule", "reserve"]] == [
        {"x-dynapath-m-token": "201fixture"}
    ] * 3


def test_v2_engine_preserves_complete_search_and_reservation_forms(korail, make_korail, monkeypatch) -> None:
    # given
    monkeypatch.setattr("pykorail.auth.declaration.time.time", lambda: INIT_MS / 1000)
    current, current_session = korail
    previous, previous_session = make_korail(dict(current_session.routes), dynapath_engine=LegacyEngineAdapter())
    departure = datetime(2099, 10, 3, 9)
    # when
    current.reservations.create(current.trains.search("서울", "부산", depart_after=departure)[0])
    previous.reservations.create(previous.trains.search("서울", "부산", depart_after=departure)[0])
    # then
    assert [
        (method, url, {k: v for k, v in kwargs.items() if k != "headers"})
        for method, url, kwargs in current_session.calls
    ] == [
        (method, url, {k: v for k, v in kwargs.items() if k != "headers"})
        for method, url, kwargs in previous_session.calls
    ]
    assert current_session.kwargs_for("search_schedule")["params"]["Sid"] == ""
    assert "Key" not in current_session.kwargs_for("search_schedule")["params"]
    assert [
        decode_declaration(current_session.kwargs_for(endpoint)["headers"]["x-dynapath-m-token"])["sv"]
        for endpoint in ["search_schedule", "reserve"]
    ] == ["2.0.2"] * 2
