"""요청 서명 — 어떤 경로에 어떤 인증 재료를 붙일지 결정합니다."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pykorail.auth.declaration import DeclarationDynaPathEngine, _sdk_for
from pykorail.constants import DEVICE, DYNAPATH_LOGIN_OP, DYNAPATH_PATHS, SID_KEY
from pykorail.crypto import encrypt_sid
from pykorail.device.android_id import generate_android_id, validate_android_id
from pykorail.device.request_settings import RequestSettings

if TYPE_CHECKING:
    from pykorail.auth.declaration import DynaPathEngine
    from pykorail.device import DeviceProfileLike


class RequestSigner:
    """DynaPath 서명이 필요한 요청에 헤더와 ``Sid`` 를 만들어 줍니다.

    기본은 v2 선언 토큰입니다. 하드웨어 KeyStore 서명을 재현하지는 않습니다.
    """

    def __init__(
        self,
        profile: DeviceProfileLike | None = None,
        device: str = DEVICE,
        device_id: str | None = None,
        sid_key: bytes = SID_KEY,
        *,
        request_settings: RequestSettings | None = None,
        engine: DynaPathEngine | None = None,
    ) -> None:
        settings = request_settings or RequestSettings()
        model = settings.device_model or (
            profile.model if profile is not None else DeclarationDynaPathEngine.DEVICE_MODEL
        )
        release = settings.os_version or (
            profile.android if profile is not None else DeclarationDynaPathEngine.OS_VERSION
        )
        self._engine: DynaPathEngine = (
            engine
            if engine is not None
            else DeclarationDynaPathEngine(
                model=model.encode("utf-8"),
                release=release.encode("ascii"),
                sdk_int=_sdk_for(release),
                os_type=settings.os_type or DeclarationDynaPathEngine.OS_TYPE,
                sdk_version=settings.sdk_version or DeclarationDynaPathEngine.SDK_VERSION,
            )
        )
        self._device = device
        self._device_id = generate_android_id() if device_id is None else validate_android_id(device_id)
        self._sid_key = settings.sid_key if settings.sid_key is not None else sid_key

    def sign(self, url: str, *, include_sid: bool = True) -> tuple[dict[str, str], str | None]:
        """``url`` 에 필요한 ``(헤더, Sid)`` 를 만듭니다.

        서명 대상이 아닌 경로면 ``({}, None)`` 을 돌려줍니다. 토큰과 ``Sid`` 는
        같은 타임스탬프로 만들어야 서버가 짝을 맞춰 검증할 수 있습니다.
        """
        if not any(path in url for path in DYNAPATH_PATHS):
            return {}, None

        token, ts = self._engine.generate_token_with_timestamp(
            request_bound="/classes/com.korail.mobile.login.Login" in url,
            op_id=DYNAPATH_LOGIN_OP,
            device_id=self._device_id,
        )
        sid = encrypt_sid(self._device, ts, self._sid_key) if include_sid else None
        return {"x-dynapath-m-token": token}, sid
