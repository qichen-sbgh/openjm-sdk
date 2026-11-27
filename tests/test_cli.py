import hashlib
import json
from pathlib import Path

import pytest

from openjm.__main__ import main

KEY_ID = 254
KEY = hashlib.sha256(b"openjm-cli-test-key").digest()


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({str(KEY_ID): KEY.hex()}), encoding="utf-8")
    return path


def test_cli_accepts_global_options_after_subcommand(tmp_path: Path, key_file: Path, sample_pdf: Path, capsys):
    out = tmp_path / "out.jm"
    rc = main([
        "encrypt", str(sample_pdf),
        "-o", str(out),
        "--key-file", str(key_file),
        "--key-id", str(KEY_ID),
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["output"] == str(out)
    assert out.is_file()


def test_cli_accepts_global_options_before_subcommand(tmp_path: Path, key_file: Path, sample_pdf: Path):
    out = tmp_path / "out.jm"
    rc = main([
        "--key-file", str(key_file),
        "--key-id", str(KEY_ID),
        "encrypt", str(sample_pdf),
        "-o", str(out),
    ])
    assert rc == 0 and out.is_file()


def test_cli_roundtrip_and_error_exit_code(tmp_path: Path, key_file: Path, sample_pdf: Path, capsys):
    out = tmp_path / "out.jm"
    base = ["--key-file", str(key_file), "--key-id", str(KEY_ID)]
    assert main(["encrypt", str(sample_pdf), "-o", str(out)] + base) == 0

    restored = tmp_path / "restored.pdf"
    assert main(["decrypt", str(out), "-o", str(restored)] + base) == 0
    assert restored.read_bytes() == sample_pdf.read_bytes()

    broken = bytearray(out.read_bytes())
    broken[40] ^= 0xFF
    out.write_bytes(bytes(broken))
    assert main(["verify", str(out)] + base) == 1
    assert "HMAC" in capsys.readouterr().err
