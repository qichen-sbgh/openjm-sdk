"""`.jm` v1 密钥派生（RFC 5869 HKDF-SHA256，三端逐字节对齐）。

三种语言的内置能力即可完成，不引入第三方密码学库：

* Python  —— :func:`hashlib.pbkdf2_hmac` / :mod:`hmac`
* Android —— javax.crypto ``SecretKeyFactory(PBKDF2WithHmacSHA256)`` / ``Mac("HmacSHA256")``
* iOS     —— CommonCrypto ``CCKeyDerivationPBKDF`` / ``CCHmac``

派生流程::

    IKM  = ROOT_KEYS[key_id]                      # 无感模式
         | PBKDF2-HMAC-SHA256(pwd, nonce, 100k, 32)  # 口令模式
    PRK  = HMAC-SHA256(key=nonce, msg=IKM)
    T1   = HMAC-SHA256(key=PRK, msg="JM01-KEYS" + 0x01)
    T2   = HMAC-SHA256(key=PRK, msg=T1 + "JM01-KEYS" + 0x02)
    enc_key = T1[0:16]   iv = T1[16:32]   mac_key = T2[0:32]
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Mapping, Optional, Tuple

from .errors import JMFormatError, JMPasswordRequiredError
from .header import FLAG_PASSWORD

HKDF_INFO = b"JM01-KEYS"
PBKDF2_ITERATIONS = 100_000


def derive_keys(
    nonce: bytes,
    flags: int,
    key_id: int,
    root_keys: Mapping[int, bytes],
    password: Optional[str],
) -> Tuple[bytes, bytes, bytes]:
    """返回 ``(enc_key[16], iv[16], mac_key[32])``。"""
    if len(nonce) != 16:
        raise JMFormatError(f"nonce 必须为 16 字节，实际 {len(nonce)}")

    if flags & FLAG_PASSWORD:
        if not password:
            raise JMPasswordRequiredError("此 .jm 文件需要口令，请提供后再试")
        ikm = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            nonce,
            PBKDF2_ITERATIONS,
            dklen=32,
        )
    else:
        ikm = root_keys.get(key_id)
        if ikm is None:
            raise JMFormatError(f"未知的 key_id: {key_id}（本地没有对应根密钥）")
        if len(ikm) != 32:
            raise ValueError(f"key_id={key_id} 的根密钥必须为 32 字节")

    prk = hmac.new(nonce, ikm, hashlib.sha256).digest()
    t1 = hmac.new(prk, HKDF_INFO + b"\x01", hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + HKDF_INFO + b"\x02", hashlib.sha256).digest()

    return t1[:16], t1[16:32], t2[:32]


def normalize_root_keys(root_keys: Mapping[int, bytes]) -> Dict[int, bytes]:
    """校验 key_id 范围与密钥长度，返回拷贝。"""
    if not root_keys:
        raise ValueError("root_keys 不能为空")
    normalized: Dict[int, bytes] = {}
    for key_id, key in root_keys.items():
        if not isinstance(key_id, int) or not 1 <= key_id <= 255:
            raise ValueError(f"key_id 必须为 1..255 的整数，收到 {key_id!r}")
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError(f"key_id={key_id} 的根密钥必须为 32 字节")
        normalized[key_id] = bytes(key)
    return normalized
