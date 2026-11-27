"""네이티브 기준 벡터와 v2 선언 필드를 오프라인에서 검증합니다."""

from __future__ import annotations

import pytest

from pykorail.auth import DeclarationDynaPathEngine
from pykorail.auth.declaration import _sdk_for
from pykorail.device import DeviceProfile
from tests.declaration_decoder import decode_declaration, decoded_field
from tests.declaration_vectors import NATIVE_RECORDED


@pytest.mark.parametrize(("nonce", "plaintext", "expected"), NATIVE_RECORDED)
def test_matches_upstream_native_recording(monkeypatch, nonce, plaintext, expected) -> None:
    # given
    monkeypatch.setattr("pykorail.auth.declaration.time.time", lambda: 1_700_000_000)
    engine = DeclarationDynaPathEngine(
        release=b"REL",
        model=b"MODELAAAA",
        manufacturer=b"MFR",
        board=b"BD",
        sdk_int=34,
        strongbox=1,
        android_id=bytes(16),
        nonce=nonce,
        sdk_version="2.0.1",
    )
    # when
    token = engine.generate_token(op_id=533034890897565508)
    # then
    assert token == expected
    assert plaintext.startswith("!v=2&es=533034890897565508&")


@pytest.mark.parametrize("nonce", [-1, 2**32])
def test_rejects_nonce_outside_wire_range(nonce) -> None:
    # when & then
    with pytest.raises(ValueError, match="nonce"):
        DeclarationDynaPathEngine(nonce=nonce)


@pytest.mark.parametrize(
    ("release", "expected"), [("10", 29), ("13", 33), ("16", 36), ("17", 37), ("9", 33), ("custom", 33)]
)
def test_android_release_maps_to_sdk_int(release, expected) -> None:
    # when
    actual = _sdk_for(release)
    # then
    assert actual == expected


def test_profile_sets_encoded_device_facts() -> None:
    # given
    profile = DeviceProfile(id="test", marketing="test", model="SM-TEST", android="14", build_id="TEST")
    engine = DeclarationDynaPathEngine.from_profile(profile)
    # when
    fields = decode_declaration(engine.generate_token(device_id="0123456789abcdef"))
    # then
    assert decoded_field(fields, "dm") == "SM-TEST"
    assert decoded_field(fields, "os") == "14"
    assert decoded_field(fields, "iid") == "0123456789abcdef"
    assert (fields["sv"], fields["sl"], fields["ai"]) == ("2.0.2", "34", "korailplus")


@pytest.mark.parametrize(("identity", "expected"), [("", ""), ("0123456789abcdef", "0123456789abcdef")])
def test_explicit_identity_takes_priority_over_fallback(identity, expected) -> None:
    # given
    engine = DeclarationDynaPathEngine(android_id=b"", nonce=2**32 - 1)
    # when
    fields = decode_declaration(engine.generate_token(device_id=identity))
    # then
    assert decoded_field(fields, "iid") == expected


@pytest.mark.parametrize("model", [b"M", b"MM", b"MMM", b"MMMM"])
def test_variable_frame_tail_decodes_without_padding(model) -> None:
    # given
    engine = DeclarationDynaPathEngine(model=model, nonce=5)
    # when
    fields = decode_declaration(engine.generate_token(device_id="0123456789abcdef"))
    # then
    assert decoded_field(fields, "dm") == model.decode("ascii")
