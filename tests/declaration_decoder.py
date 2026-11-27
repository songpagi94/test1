"""프로덕션 인코더와 독립적으로 v2 토큰을 검사하는 테스트 도구."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qsl

ALPHABET = "TeFOuQBxj1qRUHwKkymSY8l3psvCzAL5tofNcihg9WDG072EZ4bVad6rJnPXIM"
SECRET = b"9a330fd663b62c5f888a7ce76ac7202d93f646b4e0bd605cd4183278ca4ca888"


def decode_declaration(token: str) -> dict[str, str]:
    """태그를 검증하고 선언 필드를 돌려줍니다."""
    assert token.startswith("201")
    body = token[3:]
    chunks = []
    for offset in range(0, len(body), 6):
        word = body[offset : offset + 6]
        value = 0
        for digit in word:
            value = value * 62 + ALPHABET.index(digit)
        chunks.append(value.to_bytes({2: 1, 3: 2, 5: 3, 6: 4}[len(word)], "big"))
    frame = b"".join(chunks)
    nonce, tag, ciphertext = frame[:4], frame[4:7], frame[7:]
    assert tag == hashlib.sha256(SECRET + nonce + ciphertext).digest()[:3]
    plaintext = bytes(
        byte ^ hashlib.sha256(SECRET + nonce + (index // 32).to_bytes(4, "big")).digest()[index % 32]
        for index, byte in enumerate(ciphertext)
    )
    assert plaintext.startswith(b"!v=2&")
    return dict(parse_qsl(plaintext[1:].decode("latin1"), keep_blank_values=True))


def decoded_field(fields: dict[str, str], name: str) -> str:
    """URL-safe base64인 기기 필드를 문자열로 돌려줍니다."""
    value = fields[name]
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
