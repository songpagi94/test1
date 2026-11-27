"""pykorail v0.6.0 (030576a)에서 이식한 DynaPath v2 선언 토큰 코덱.

출처와 라이선스는 LICENSE 및 THIRD_PARTY_NOTICES.md를 참조하세요.
Flow-1 선언 토큰을 구현하며 하드웨어 증명이나 Flow-2 서명은 구현하지 않습니다.
네이티브 정합성은 upstream의 기록된 테스트 벡터로 검증합니다.
이 오프라인 테스트는 실제 서버의 인증 수용을 보장하지 않습니다.
"""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
import struct
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Final, Protocol

from pykorail.constants import DYNAPATH_APP_ID, DYNAPATH_SDK_VERSION, TOKEN_PREFIX

if TYPE_CHECKING:
    from pykorail.device import DeviceProfileLike

#: 빌드 내장 상수(64 ASCII-hex). .so init 에서 추출.
_V2_SECRET_HEX: Final = b"9a330fd663b62c5f888a7ce76ac7202d93f646b4e0bd605cd4183278ca4ca888"
#: base62 커스텀 알파벳. div 루프(.so 0x35dd8)에서 캡처한 치환열이며 표준 base62 가 아닙니다.
_V2_ALPHABET: Final = "TeFOuQBxj1qRUHwKkymSY8l3psvCzAL5tofNcihg9WDG072EZ4bVad6rJnPXIM"
#: ``kl``/``ec`` 는 keystore/attestation 경로에서 나오는 값으로, 에뮬레이터(게이트 강제)
#: 에서는 요청 입력과 무관하게 고정입니다. 실제 기기의 attestation 값과 다를 수 있으나
#: upstream이 2026-10-28 로그인 수용을 보고한 기본값입니다. 로컬에서 실서버 검증은 하지 않았습니다.
_V2_KL_DEFAULT: Final = "990094375841594426"
_V2_EC_DEFAULT: Final = "978212327729758430"

# UA와 기존 사용자 설정의 기본 기기 값은 유지합니다. board/strongbox는 단말 증명이 아닌 선언 값입니다.
_DEFAULT_RELEASE: Final = b"13"
_DEFAULT_MODEL: Final = b"SM-S928N"
_DEFAULT_BOARD: Final = b"kalama"
_DEFAULT_MANUFACTURER: Final = b"samsung"
_DEFAULT_SDK_INT: Final = 33
_DEFAULT_STRONGBOX: Final = 1
#: 안드로이드 메이저 버전 → ``Build.VERSION.SDK_INT``.
#: 12는 폰 기준 31입니다. RELEASE만으로는 12L(API 32)을 구분할 수 없습니다.
_SDK_BY_ANDROID: Final[dict[str, int]] = {"10": 29, "11": 30, "12": 31, "13": 33, "14": 34, "15": 35, "16": 36}


class DynaPathEngine(Protocol):
    """``x-dynapath-m-token`` 생성기 계약.

    기본 구현은 :class:`DeclarationDynaPathEngine`(순수 파이썬 선언 토큰 코덱)이고,
    이 계약을 만족하는 다른 엔진을 ``Korail(dynapath_engine=...)`` 로 주입해 교체할
    수 있습니다 — 예컨대 실기기 ``board``·attestation 값을 담은 엔진. 엔진은 ``op_id``
    와 ``device_id`` 로 선언 봉투를 채웁니다.
    """

    def generate_token_with_timestamp(self, *, request_bound: bool, op_id: int, device_id: str) -> tuple[str, int]:
        """토큰과 ``Sid`` 에 쓸 생성 시각(ms)을 함께 돌려줍니다."""
        ...


def _v2_b64(raw: bytes) -> str:
    """Android ``Base64.URL_SAFE | NO_PADDING | NO_WRAP`` — 봉투의 os/dm/iid/mf/bd 인코딩."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _v2_keystream(nbytes: int, nonce: int) -> bytes:
    """``SHA256(SECRET_HEX || LE_u32(nonce) || BE_u32(블록인덱스))`` 를 32바이트 블록으로 이어 붙인 키스트림.

    블록 카운터는 **빅엔디언 u32** 입니다(네이티브 ``sub_35f84`` 의 ``rev w8, w20`` → 4바이트 append).
    upstream의 네이티브 기록(nonce 0·5)을 테스트 벡터로 사용합니다.
    """
    blocks = math.ceil(nbytes / 32)
    nonce_le = struct.pack("<I", nonce)
    chunks = [hashlib.sha256(_V2_SECRET_HEX + nonce_le + struct.pack(">I", block)).digest() for block in range(blocks)]
    return b"".join(chunks)[:nbytes]


def _v2_width(nbytes: int) -> int:
    """``nbytes`` 바이트 워드를 담는 고정 base62 자릿수(4B→6, 1B→2)."""
    return math.ceil(nbytes * 8 / math.log2(62))


def _v2_b62_word(value: int, width: int) -> str:
    """정수 하나를 고정폭 base62 로 인코딩(MSB 우선, 앞자리는 알파벳[0] 로 채움)."""
    out = [_V2_ALPHABET[0]] * width
    for i in range(width - 1, -1, -1):
        out[i] = _V2_ALPHABET[value % 62]
        value //= 62
    return "".join(out)


def _sdk_for(android: str) -> int:
    """안드로이드 메이저 버전 문자열 → SDK_INT.

    표에 없는 버전은 안드로이드 13+ 의 규칙(API = 버전 + 20)으로 외삽하고, 숫자가
    아니거나 표에 없는 13 미만 버전이면(규칙이 성립하지 않음) 현행 기본값을 씁니다.
    """
    if android in _SDK_BY_ANDROID:
        return _SDK_BY_ANDROID[android]
    return int(android) + 20 if android.isdigit() and int(android) >= 13 else _DEFAULT_SDK_INT


@dataclass(frozen=True)
class DeclarationDynaPathEngine:
    """DynaPath v2 선언 토큰을 생성합니다.

    요청마다 nonce를 생성하고 저장된 device_id를 유지합니다.
    이 선언 값들은 실제 하드웨어 인증서나 서명을 대신하지 않습니다.
    """

    DEVICE_MODEL: ClassVar[str] = "SM-S928N"
    OS_VERSION: ClassVar[str] = "13"
    OS_TYPE: ClassVar[str] = "Android"
    SDK_VERSION: ClassVar[str] = DYNAPATH_SDK_VERSION

    release: bytes = _DEFAULT_RELEASE
    model: bytes = _DEFAULT_MODEL
    manufacturer: bytes = _DEFAULT_MANUFACTURER
    board: bytes = _DEFAULT_BOARD
    sdk_int: int = _DEFAULT_SDK_INT
    strongbox: int = _DEFAULT_STRONGBOX
    android_id: bytes | None = None
    nonce: int | None = None
    kl: str = _V2_KL_DEFAULT
    ec: str = _V2_EC_DEFAULT
    os_type: str = "Android"
    sdk_version: str = DYNAPATH_SDK_VERSION

    def __post_init__(self) -> None:
        # nonce 는 봉투와 버퍼에 LE_u32 로 실리므로 32비트를 벗어나면 생성 시점에 막습니다
        # (아니면 요청 때 struct.pack 에서 늦게 터집니다).
        if self.nonce is not None and not 0 <= self.nonce < 2**32:
            raise ValueError("nonce는 0 이상 2**32 미만이어야 합니다")

    @classmethod
    def from_profile(cls, profile: DeviceProfileLike) -> DeclarationDynaPathEngine:
        """기기 프로파일에서 ``model``·``release``·``sdk_int`` 를 끌어와 엔진을 만듭니다.

        ``manufacturer``·``board``·``strongbox`` 는 프로파일에 없어 upstream의
        기본 선언 값을 씁니다. 실기기와의 일치는 보장하지 않습니다.
        ``android_id`` 는 서명기가 ``device_id`` 로 매 호출에 넘깁니다.
        """
        return cls(
            release=profile.android.encode("ascii"),
            model=profile.model.encode("utf-8"),
            sdk_int=_sdk_for(profile.android),
        )

    def _plaintext(self, op_id: int, ts_ms: int, android_id: bytes) -> bytes:
        """암호화 직전의 선언 봉투를 조립합니다(앞의 ``!`` 포함)."""
        envelope = (
            f"!v=2&es={op_id}&ts={ts_ms}&st={self.os_type}&sv={self.sdk_version}&ai={DYNAPATH_APP_ID}"
            f"&os={_v2_b64(self.release)}&dm={_v2_b64(self.model)}&iid={_v2_b64(android_id)}"
            f"&mf={_v2_b64(self.manufacturer)}&bd={_v2_b64(self.board)}"
            f"&sl={self.sdk_int}&sb={self.strongbox}&kl={self.kl}&ec={self.ec}"
        )
        return envelope.encode("latin1")

    def _build(self, op_id: int, device_id: str, ts_ms: int, nonce: int) -> str:
        """봉투 → SHA256-CTR XOR → MAC[0:3] → 워드별 base62 로 토큰을 만듭니다."""
        # iid 는 android_id **문자열의 UTF-8 바이트**입니다(16자리 16진수 → 16바이트). 앱의
        # C3907n.b() 가 Settings.Secure "android_id" 문자열을 getBytes(UTF_8) 하는 것을 그대로
        # 옮긴 것이라 16진수로 디코드(8바이트)하면 안 됩니다 — APK 7.0.10 에서 확인.
        android_id = device_id.encode("ascii") if device_id else (self.android_id or b"")
        plaintext = self._plaintext(op_id, ts_ms, android_id)
        keystream = _v2_keystream(len(plaintext), nonce)
        eor = bytes(p ^ k for p, k in zip(plaintext, keystream, strict=True))
        # 태그 = SHA256(SECRET || LE_u32(nonce) || eor) 의 앞 3바이트(네이티브는 ldurh+ldurb 로 3바이트만 읽음).
        mac3 = hashlib.sha256(_V2_SECRET_HEX + struct.pack("<I", nonce) + eor).digest()[:3]
        buffer = struct.pack("<I", nonce) + mac3 + eor
        body = [
            _v2_b62_word(int.from_bytes(buffer[i : i + 4], "big"), _v2_width(len(buffer[i : i + 4])))
            for i in range(0, len(buffer), 4)
        ]
        return TOKEN_PREFIX + "".join(body)

    def generate_token(self, *, request_bound: bool = False, op_id: int = 0, device_id: str = "") -> str:
        """``x-dynapath-m-token`` 값을 만듭니다(현재 시각 기준).

        Args:
            request_bound: 계약상 인자. 이 엔진은 Flow-1 선언 토큰만 내므로 영향이 없습니다
                (Flow-2 로그인 토큰은 하드웨어 서명이라 재현 불가 — 클래스 설명 참조).
            op_id: 엔드포인트의 DynaPath op id. 봉투 ``es`` 로 들어갑니다.
            device_id: 기기 android_id(16진수). ``iid`` 로 들어갑니다.
        """
        return self.generate_token_with_timestamp(request_bound=request_bound, op_id=op_id, device_id=device_id)[0]

    def generate_token_with_timestamp(
        self, *, request_bound: bool = False, op_id: int = 0, device_id: str = ""
    ) -> tuple[str, int]:
        """토큰과 ``Sid`` 에 쓸 생성 시각(ms)을 같은 시각으로 함께 돌려줍니다."""
        ts_ms = int(time.time() * 1000)
        return self._build(op_id, device_id, ts_ms, self._resolve_nonce()), ts_ms

    def _resolve_nonce(self) -> int:
        """고정 nonce 가 없으면 요청마다 32비트 난수를 뽑습니다(실제 앱처럼 매번 달라지도록)."""
        return self.nonce if self.nonce is not None else secrets.randbits(32)
