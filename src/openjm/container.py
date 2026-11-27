"""`.jm` v1 容器：加密、校验、解密。

设计取舍（与协议文档一致）：

* 全量 AES-128-CTR 流式加密，64KB 分块，内存占用与文件大小无关；
* Encrypt-then-MAC：尾部 32B HMAC-SHA256 覆盖 ``Header || EncryptedStream``，
  一次比对同时挡掉截断、损坏、篡改与口令错误；
* 每次封装都换新 nonce、新填充长度，同一份 PDF 的两次输出没有任何字节关联；
* 落盘一律先写隐藏 ``.tmp`` 再 ``os.replace``，中途失败不留下半个可用文件。
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, Mapping, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import JMAuthError, JMFormatError
from .header import (
    ALG_AES128_CTR_HMAC_SHA256,
    FLAG_PASSWORD,
    HEADER_SIZE,
    HEADER_STRUCT,
    MAGIC,
    MAC_SIZE,
    MAX_META_LEN,
    MAX_PAD_LEN,
    MIN_FILE_SIZE,
    VERSION,
    HeaderInfo,
    read_header,
)
from .kdf import derive_keys, normalize_root_keys

DEFAULT_CHUNK_SIZE = 64 * 1024


@dataclasses.dataclass(frozen=True)
class EncryptResult:
    output_path: Path
    doc_id: str
    original_name: str
    original_size: int
    encrypted_size: int
    pad_len: int
    password_protected: bool


@dataclasses.dataclass(frozen=True)
class DecryptResult:
    output_path: Path
    meta: Dict[str, Any]


def _masked_name(prefix: str) -> str:
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    return f"{prefix}_{date_str}_{secrets.token_hex(4)}.jm"


def _hash_source(stream: BinaryIO, chunk_size: int) -> Tuple[str, int]:
    """流式算 SHA-256 前 16 字节（doc_id）与原始长度，只读一遍。"""
    sha = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        sha.update(chunk)
        total += len(chunk)
    return sha.digest()[:16].hex(), total


def _tmp_beside(path: Path) -> Path:
    return path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")


class JMCrypto:
    """JM v1 加解密客户端。实例无状态，可在线程间复用。"""

    def __init__(self, root_keys: Mapping[int, bytes], default_key_id: int = 1) -> None:
        self._root_keys = normalize_root_keys(root_keys)
        if default_key_id not in self._root_keys:
            raise ValueError(f"default_key_id={default_key_id} 不在 root_keys 中")
        self._default_key_id = default_key_id

    # ---------------------------------------------------------------- 头部
    @staticmethod
    def inspect_header(jm_path: Union[str, Path]) -> HeaderInfo:
        """只读 28 字节头，用来判断“是不是 .jm / 要不要口令”。"""
        return read_header(jm_path)

    # ---------------------------------------------------------------- 加密
    def encrypt_file(
        self,
        src_path: Union[str, Path],
        dst_path: Optional[Union[str, Path]] = None,
        *,
        mask_name: bool = True,
        alias_prefix: str = "doc",
        password: Optional[str] = None,
        key_id: Optional[int] = None,
        pad_range: Tuple[int, int] = (0, MAX_PAD_LEN),
        extra_meta: Optional[Dict[str, Any]] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> EncryptResult:
        """把本地文件封装成 .jm。"""
        src = Path(src_path)
        if not src.is_file():
            raise FileNotFoundError(f"源文件不存在: {src}")

        pad_min, pad_max = pad_range
        if not (0 <= pad_min <= pad_max <= MAX_PAD_LEN):
            raise ValueError(f"pad_range 必须满足 0 <= min <= max <= {MAX_PAD_LEN}")

        if dst_path is None:
            dst = src.parent / (_masked_name(alias_prefix) if mask_name else f"{src.stem}.jm")
        else:
            dst = Path(dst_path)
            if dst.is_dir():
                dst = dst / (_masked_name(alias_prefix) if mask_name else f"{src.stem}.jm")

        if password:
            flags = FLAG_PASSWORD
            eff_key_id = 0
        else:
            flags = 0
            eff_key_id = self._default_key_id if key_id is None else key_id
            if eff_key_id not in self._root_keys:
                raise ValueError(f"key_id={eff_key_id} 不在已装载的根密钥中")

        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp_dst = _tmp_beside(dst)

        try:
            with open(src, "rb") as fin:
                doc_id, file_size = _hash_source(fin, chunk_size)
                fin.seek(0)

                pad_len = secrets.randbelow(pad_max - pad_min + 1) + pad_min
                meta: Dict[str, Any] = {
                    "doc_id": doc_id,
                    "name": src.name,
                    "ext": src.suffix.lstrip(".").lower(),
                    "size": file_size,
                    "pad": pad_len,
                    "ts": int(time.time()),
                }
                if extra_meta:
                    meta.update(extra_meta)

                meta_bytes = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(meta_bytes) > MAX_META_LEN:
                    raise ValueError(f"Meta JSON 超过上限 {MAX_META_LEN} 字节")

                nonce = os.urandom(16)
                enc_key, iv, mac_key = derive_keys(nonce, flags, eff_key_id, self._root_keys, password)
                header = HEADER_STRUCT.pack(
                    MAGIC, VERSION, ALG_AES128_CTR_HMAC_SHA256, flags, eff_key_id, nonce, len(meta_bytes)
                )

                encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).encryptor()
                mac = hmac.new(mac_key, digestmod=hashlib.sha256)

                with open(tmp_dst, "wb") as fout:
                    fout.write(header)
                    mac.update(header)

                    enc_meta = encryptor.update(meta_bytes)
                    fout.write(enc_meta)
                    mac.update(enc_meta)

                    while True:
                        chunk = fin.read(chunk_size)
                        if not chunk:
                            break
                        enc_chunk = encryptor.update(chunk)
                        fout.write(enc_chunk)
                        mac.update(enc_chunk)

                    if pad_len:
                        enc_pad = encryptor.update(os.urandom(pad_len))
                        fout.write(enc_pad)
                        mac.update(enc_pad)

                    tail = encryptor.finalize()
                    if tail:
                        fout.write(tail)
                        mac.update(tail)

                    fout.write(mac.digest())

            os.replace(tmp_dst, dst)
        except BaseException:
            tmp_dst.unlink(missing_ok=True)
            raise

        return EncryptResult(
            output_path=dst,
            doc_id=doc_id,
            original_name=src.name,
            original_size=file_size,
            encrypted_size=dst.stat().st_size,
            pad_len=pad_len,
            password_protected=bool(password),
        )

    # ---------------------------------------------------------------- 校验
    def verify_file(
        self,
        jm_path: Union[str, Path],
        *,
        password: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> Dict[str, Any]:
        """校验完整性并返回解密后的 Meta。不产生任何明文文件。"""
        jm = Path(jm_path)
        total_size = jm.stat().st_size
        if total_size < MIN_FILE_SIZE:
            raise JMFormatError("文件不完整（小于最小合法长度 60 字节）")

        info = read_header(jm)
        enc_key, iv, mac_key = derive_keys(info.nonce, info.flags, info.key_id, self._root_keys, password)

        claimed_end = total_size - MAC_SIZE
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        with open(jm, "rb") as fin:
            remaining = claimed_end
            while remaining > 0:
                chunk = fin.read(min(chunk_size, remaining))
                if not chunk:
                    raise JMAuthError("读取文件意外提前结束")
                mac.update(chunk)
                remaining -= len(chunk)
            expected_mac = fin.read(MAC_SIZE)

            if len(expected_mac) != MAC_SIZE or not hmac.compare_digest(mac.digest(), expected_mac):
                raise JMAuthError("HMAC 校验失败：文件下载不完整、已损坏，或口令错误")

            fin.seek(HEADER_SIZE)
            enc_meta = fin.read(info.meta_len)

        decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).decryptor()
        meta = json.loads((decryptor.update(enc_meta) + decryptor.finalize()).decode("utf-8"))

        claimed_total = HEADER_SIZE + info.meta_len + int(meta["size"]) + int(meta["pad"]) + MAC_SIZE
        if claimed_total != total_size:
            raise JMFormatError(f"元数据声明长度({claimed_total})与实际文件大小({total_size})不符")
        return meta

    # ---------------------------------------------------------------- 解密
    def decrypt_file(
        self,
        jm_path: Union[str, Path],
        dst_path: Union[str, Path],
        *,
        password: Optional[str] = None,
        use_original_name: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> DecryptResult:
        """先校验再解密，按 Meta 声明的 size 截断，剥离随机填充。"""
        jm = Path(jm_path)
        meta = self.verify_file(jm, password=password, chunk_size=chunk_size)
        info = read_header(jm)
        enc_key, iv, _ = derive_keys(info.nonce, info.flags, info.key_id, self._root_keys, password)

        dst = Path(dst_path)
        if dst.is_dir() or use_original_name:
            target_dir = dst if dst.is_dir() else dst.parent
            dst = target_dir / Path(str(meta["name"])).name

        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp_dst = _tmp_beside(dst)

        try:
            decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).decryptor()
            with open(jm, "rb") as fin, open(tmp_dst, "wb") as fout:
                fin.seek(HEADER_SIZE)
                decryptor.update(fin.read(info.meta_len))

                remaining = int(meta["size"])
                while remaining > 0:
                    chunk = fin.read(min(chunk_size, remaining))
                    if not chunk:
                        raise JMFormatError("主体数据读取中断")
                    fout.write(decryptor.update(chunk))
                    remaining -= len(chunk)

                tail = decryptor.finalize()
                if tail:
                    fout.write(tail)

            os.replace(tmp_dst, dst)
        except BaseException:
            tmp_dst.unlink(missing_ok=True)
            raise

        return DecryptResult(output_path=dst, meta=meta)
