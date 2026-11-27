"""openjm —— `.jm` v1 加密文档容器的发送端 SDK。

用法::

    from openjm import JMCrypto, load_root_keys

    crypto = JMCrypto(load_root_keys("keys.json"))
    result = crypto.encrypt_file("深入理解计算机系统.pdf")
    print(result.output_path)          # doc_20261127_a1b2c3d4.jm
    print(crypto.verify_file(result.output_path)["name"])   # 原始文件名

协议见 openjm 仓库 `docs/protocol-v1.md`；跨端测试向量见 `testvectors/`。
"""

from __future__ import annotations

from .container import DecryptResult, EncryptResult, JMCrypto
from .errors import JMAuthError, JMError, JMFormatError, JMPasswordRequiredError
from .header import (
    ALG_AES128_CTR_HMAC_SHA256,
    FLAG_PASSWORD,
    HEADER_SIZE,
    MAC_SIZE,
    MAX_META_LEN,
    MAX_PAD_LEN,
    MIN_FILE_SIZE,
    HeaderInfo,
)
from .kdf import derive_keys
from .keys import ENV_KEY_FILE, load_root_keys, load_root_keys_from_env

__version__ = "0.1.0"

__all__ = [
    "JMCrypto",
    "EncryptResult",
    "DecryptResult",
    "HeaderInfo",
    "JMError",
    "JMFormatError",
    "JMPasswordRequiredError",
    "JMAuthError",
    "load_root_keys",
    "load_root_keys_from_env",
    "derive_keys",
    "ENV_KEY_FILE",
    "HEADER_SIZE",
    "MAC_SIZE",
    "MIN_FILE_SIZE",
    "MAX_META_LEN",
    "MAX_PAD_LEN",
    "FLAG_PASSWORD",
    "ALG_AES128_CTR_HMAC_SHA256",
]
