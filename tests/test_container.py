import hashlib
import re
from pathlib import Path

import pytest

from openjm import (
    FLAG_PASSWORD,
    HEADER_SIZE,
    JMAuthError,
    JMFormatError,
    JMPasswordRequiredError,
    MAC_SIZE,
)

MASKED_NAME_RE = re.compile(r"^doc_\d{8}_[0-9a-f]{8}\.jm$")


def test_roundtrip_preserves_bytes_and_meta(crypto, sample_pdf: Path, tmp_path: Path):
    result = crypto.encrypt_file(sample_pdf)
    assert MASKED_NAME_RE.match(result.output_path.name)
    assert result.output_path.suffix == ".jm"

    meta = crypto.verify_file(result.output_path)
    assert meta["name"] == "深入理解计算机系统.pdf"
    assert meta["ext"] == "pdf"
    assert meta["size"] == sample_pdf.stat().st_size
    assert meta["doc_id"] == hashlib.sha256(sample_pdf.read_bytes()).digest()[:16].hex()

    out = crypto.decrypt_file(result.output_path, tmp_path / "out.pdf")
    assert out.output_path.read_bytes() == sample_pdf.read_bytes()
    assert out.meta == meta


def test_same_source_never_repeats_ciphertext(crypto, sample_pdf: Path):
    first = crypto.encrypt_file(sample_pdf)
    second = crypto.encrypt_file(sample_pdf)

    assert first.doc_id == second.doc_id
    assert first.output_path.read_bytes() != second.output_path.read_bytes()
    assert crypto.inspect_header(first.output_path).nonce != crypto.inspect_header(second.output_path).nonce


def test_size_equation_holds(crypto, sample_pdf: Path):
    result = crypto.encrypt_file(sample_pdf, pad_range=(100, 100))
    info = crypto.inspect_header(result.output_path)
    total = result.output_path.stat().st_size
    assert result.pad_len == 100
    assert total == HEADER_SIZE + info.meta_len + result.original_size + 100 + MAC_SIZE


def test_password_mode(crypto, sample_pdf: Path):
    result = crypto.encrypt_file(sample_pdf, password="correct horse battery staple")
    info = crypto.inspect_header(result.output_path)
    assert info.flags & FLAG_PASSWORD
    assert info.key_id == 0

    meta = crypto.verify_file(result.output_path, password="correct horse battery staple")
    assert meta["doc_id"] == result.doc_id

    with pytest.raises(JMPasswordRequiredError):
        crypto.verify_file(result.output_path)
    with pytest.raises(JMAuthError):
        crypto.verify_file(result.output_path, password="wrong password")


def test_unknown_key_id_rejected(crypto, sample_pdf: Path):
    from openjm import JMCrypto

    other = JMCrypto({9: hashlib.sha256(b"another-root-key").digest()}, default_key_id=9)
    result = other.encrypt_file(sample_pdf)

    with pytest.raises(JMFormatError):
        crypto.verify_file(result.output_path)


def test_truncated_file_raises_auth_error(crypto, sample_pdf: Path):
    result = crypto.encrypt_file(sample_pdf)
    data = result.output_path.read_bytes()
    result.output_path.write_bytes(data[:-1])

    with pytest.raises(JMAuthError):
        crypto.verify_file(result.output_path)


def test_tampered_payload_raises_auth_error(crypto, sample_pdf: Path):
    result = crypto.encrypt_file(sample_pdf)
    data = bytearray(result.output_path.read_bytes())
    data[HEADER_SIZE + 40] ^= 0x01
    result.output_path.write_bytes(bytes(data))

    with pytest.raises(JMAuthError):
        crypto.verify_file(result.output_path)


def test_bad_magic_rejected(crypto, sample_pdf: Path):
    result = crypto.encrypt_file(sample_pdf)
    data = bytearray(result.output_path.read_bytes())
    data[0:4] = b"JK01"
    result.output_path.write_bytes(bytes(data))

    with pytest.raises(JMFormatError):
        crypto.inspect_header(result.output_path)


def test_too_short_file_rejected(crypto, tmp_path: Path):
    short = tmp_path / "short.jm"
    short.write_bytes(b"JM01" + b"\x00" * 20)

    with pytest.raises(JMFormatError):
        crypto.verify_file(short)


def test_streaming_across_chunk_boundaries(crypto, tmp_path: Path):
    src = tmp_path / "large.pdf"
    src.write_bytes(b"%PDF-1.7\n" + bytes(range(256)) * 1024)  # 256KB

    result = crypto.encrypt_file(src, chunk_size=1024)
    out = crypto.decrypt_file(result.output_path, tmp_path / "large.out", chunk_size=4096)
    assert out.output_path.read_bytes() == src.read_bytes()


def test_extra_meta_and_keep_name(crypto, sample_pdf: Path, tmp_path: Path):
    result = crypto.encrypt_file(
        sample_pdf,
        tmp_path / "keep.jm",
        mask_name=False,
        extra_meta={"source": "qq-group-123"},
    )
    meta = crypto.verify_file(result.output_path)
    assert meta["source"] == "qq-group-123"
    assert result.output_path.name == "keep.jm"


def test_key_id_upgrade_path(crypto, sample_pdf: Path):
    """key_id=2 的文件用同一实例可解，且头部记录的版本号正确。"""
    result = crypto.encrypt_file(sample_pdf, key_id=2)
    assert crypto.inspect_header(result.output_path).key_id == 2
    assert crypto.verify_file(result.output_path)["doc_id"] == result.doc_id


def test_pad_range_validation(crypto, sample_pdf: Path):
    with pytest.raises(ValueError):
        crypto.encrypt_file(sample_pdf, pad_range=(500, 100))
    with pytest.raises(ValueError):
        crypto.encrypt_file(sample_pdf, pad_range=(0, 5000))


def test_decrypt_cleans_up_on_bad_password(crypto, sample_pdf: Path, tmp_path: Path):
    result = crypto.encrypt_file(sample_pdf, password="pw")
    with pytest.raises(JMAuthError):
        crypto.decrypt_file(result.output_path, tmp_path / "x.pdf", password="bad")
    assert not (tmp_path / "x.pdf").exists()
    assert not list(tmp_path.glob(".*.tmp"))
