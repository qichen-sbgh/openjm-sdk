"""`.jm` v1 固定文件头：解析与常量。

头部 28 字节明文布局（大端序）::

    [0..3]   magic    4B  ASCII "JM01"
    [4]      version  1B  0x01
    [5]      alg      1B  0x01 = AES-128-CTR + HMAC-SHA256
    [6]      flags    1B  bit0 = 口令模式
    [7]      key_id   1B  内置根密钥版本 1..255；口令模式为 0x00
    [8..23]  nonce    16B CSPRNG
    [24..27] meta_len 4B  EncryptedMeta 长度
"""

from __future__ import annotations

import dataclasses
import struct
from pathlib import Path
from typing import Union

from .errors import JMFormatError

MAGIC = b"JM01"
VERSION = 0x01
ALG_AES128_CTR_HMAC_SHA256 = 0x01
FLAG_PASSWORD = 0x01

HEADER_STRUCT = struct.Struct(">4sBBBB16sI")
HEADER_SIZE = HEADER_STRUCT.size  # 28
MAC_SIZE = 32
MIN_FILE_SIZE = HEADER_SIZE + MAC_SIZE  # 60

MAX_META_LEN = 64 * 1024
MAX_PAD_LEN = 4096


@dataclasses.dataclass(frozen=True)
class HeaderInfo:
    version: int
    alg: int
    flags: int
    key_id: int
    nonce: bytes
    meta_len: int

    @property
    def is_password_protected(self) -> bool:
        return bool(self.flags & FLAG_PASSWORD)


def parse_header(raw: bytes) -> HeaderInfo:
    """校验并解析 28 字节明文头。任何不认识的值直接拒绝，不做宽容解析。"""
    if len(raw) < HEADER_SIZE:
        raise JMFormatError(f"文件长度不足 {HEADER_SIZE} 字节")

    magic, version, alg, flags, key_id, nonce, meta_len = HEADER_STRUCT.unpack(raw[:HEADER_SIZE])
    if magic != MAGIC:
        raise JMFormatError(f"无效的文件头魔数: {magic!r}（期望 {MAGIC!r}）")
    if version != VERSION:
        raise JMFormatError(f"不支持的协议版本: {version}")
    if alg != ALG_AES128_CTR_HMAC_SHA256:
        raise JMFormatError(f"不支持的算法标识: {alg}")
    if meta_len == 0 or meta_len > MAX_META_LEN:
        raise JMFormatError(f"非法的元数据长度: {meta_len}")

    return HeaderInfo(version, alg, flags, key_id, nonce, meta_len)


def read_header(path: Union[str, Path]) -> HeaderInfo:
    """只读取前 28 字节，不触碰密文主体，也不解密。"""
    with open(path, "rb") as fh:
        raw = fh.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise JMFormatError(f"文件长度不足 {HEADER_SIZE} 字节，不是完整的 .jm 文件")
    return parse_header(raw)
