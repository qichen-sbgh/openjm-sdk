import hashlib
import os
from pathlib import Path

import pytest

# key_id=1 只是单测里用的假根密钥，跟任何线上密钥无关。
TEST_KEY_ID = 1
TEST_KEY = hashlib.sha256(b"openjm-sdk-unit-test-key").digest()
OTHER_KEY_ID = 2
OTHER_KEY = hashlib.sha256(b"openjm-sdk-unit-test-key-2").digest()


@pytest.fixture()
def root_keys():
    return {TEST_KEY_ID: TEST_KEY, OTHER_KEY_ID: OTHER_KEY}


@pytest.fixture()
def crypto(root_keys):
    from openjm import JMCrypto

    return JMCrypto(root_keys, default_key_id=TEST_KEY_ID)


@pytest.fixture()
def sample_pdf(tmp_path: Path) -> Path:
    """一段带 PDF 头的字节，单测只关心字节流是否原样回来。"""
    path = tmp_path / "深入理解计算机系统.pdf"
    body = b"%PDF-1.4\n" + os.urandom(3000) + b"\n%%EOF\n"
    path.write_bytes(body)
    return path
