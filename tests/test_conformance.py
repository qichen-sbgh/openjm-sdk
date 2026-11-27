"""跨端一致性测试：回放 openjm 仓库里已冻结的测试向量。

向量位于相邻检出目录 ``../openjm/testvectors``，或用 ``OPENJM_TESTVECTORS``
指向任意检出位置；找不到时整体 skip，不阻塞本地单测。
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from openjm import JMAuthError, JMFormatError, JMCrypto, load_root_keys

ERRORS = {"JMFormatError": JMFormatError, "JMAuthError": JMAuthError}


def _vectors_root() -> Optional[Path]:
    env = os.environ.get("OPENJM_TESTVECTORS")
    candidate = Path(env) if env else Path(__file__).resolve().parents[2] / "openjm" / "testvectors"
    return candidate if (candidate / "manifest.json").is_file() else None


VECTORS = _vectors_root()
MANIFEST: Dict = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8")) if VECTORS else {"vectors": []}
VALID: List[Dict] = [c for c in MANIFEST["vectors"] if c["kind"] == "valid"]
INVALID: List[Dict] = [c for c in MANIFEST["vectors"] if c["kind"] == "invalid"]
PASSWORD_CASES: List[Dict] = [c for c in VALID if c.get("wrong_password")]


@pytest.fixture(scope="module")
def crypto() -> JMCrypto:
    if VECTORS is None:
        pytest.skip("未找到测试向量目录，设置 OPENJM_TESTVECTORS 后重跑")
    return JMCrypto(load_root_keys(VECTORS / MANIFEST["keys_file"]), default_key_id=MANIFEST["test_key_id"])


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["id"])
def test_valid_vectors_decrypt_to_expected_plaintext(case: Dict, crypto: JMCrypto, tmp_path: Path):
    if VECTORS is None:
        pytest.skip("未找到测试向量目录")

    jm = VECTORS / case["file"]
    meta = crypto.verify_file(jm, password=case.get("password"))

    expect = case["expect"]
    assert meta["doc_id"] == expect["doc_id"]
    assert meta["name"] == expect["name"]
    assert meta["size"] == expect["size"]
    assert meta["pad"] == expect["pad"]

    out = crypto.decrypt_file(jm, tmp_path / "out.bin", password=case.get("password"))
    assert hashlib.sha256(out.output_path.read_bytes()).hexdigest() == expect["sha256"]


@pytest.mark.parametrize("case", INVALID, ids=lambda c: c["id"])
def test_invalid_vectors_raise_expected_error(case: Dict, crypto: JMCrypto):
    if VECTORS is None:
        pytest.skip("未找到测试向量目录")

    with pytest.raises(ERRORS[case["error"]]):
        crypto.verify_file(VECTORS / case["file"], password=case.get("password"))


@pytest.mark.parametrize("case", PASSWORD_CASES, ids=lambda c: c["id"])
def test_wrong_password_vectors_raise_auth_error(case: Dict, crypto: JMCrypto):
    if VECTORS is None:
        pytest.skip("未找到测试向量目录")

    with pytest.raises(JMAuthError):
        crypto.verify_file(VECTORS / case["file"], password=case["wrong_password"])
