"""命令行入口：``python -m openjm {encrypt,verify,decrypt,inspect}``。

给 QQ 机器人流水线和 shell 批处理用；参数刻意少，复杂场景请直接用库 API。
根密钥默认读 ``$OPENJM_KEY_FILE``，也可用 ``--key-file`` 覆盖。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from .container import JMCrypto
from .errors import JMError
from .header import read_header
from .keys import ENV_KEY_FILE, load_root_keys


def _build_crypto(args: argparse.Namespace) -> JMCrypto:
    if not args.key_file:
        raise JMError(f"缺少根密钥文件：请设置 ${ENV_KEY_FILE} 或传 --key-file")
    return JMCrypto(load_root_keys(args.key_file), default_key_id=args.key_id)


def _cmd_inspect(args: argparse.Namespace) -> int:
    info = read_header(args.file)
    print(
        json.dumps(
            {
                "version": info.version,
                "alg": info.alg,
                "flags": info.flags,
                "key_id": info.key_id,
                "nonce": info.nonce.hex(),
                "meta_len": info.meta_len,
                "password_required": info.is_password_protected,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    crypto = _build_crypto(args)
    result = crypto.encrypt_file(
        args.file,
        args.output,
        mask_name=not args.keep_name,
        password=args.password,
        pad_range=(args.pad_min, args.pad_max),
    )
    print(json.dumps(
        {
            "output": str(result.output_path),
            "doc_id": result.doc_id,
            "name": result.original_name,
            "size": result.original_size,
            "encrypted_size": result.encrypted_size,
            "pad": result.pad_len,
            "password": result.password_protected,
        },
        ensure_ascii=False,
    ))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    crypto = _build_crypto(args)
    meta = crypto.verify_file(args.file, password=args.password)
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    crypto = _build_crypto(args)
    result = crypto.decrypt_file(
        args.file,
        args.output,
        password=args.password,
        use_original_name=args.original_name,
    )
    print(json.dumps({"output": str(result.output_path), **result.meta}, ensure_ascii=False))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="openjm", description="JM v1 加密文档容器")
    parser.add_argument("--key-file", help=f"根密钥 JSON 路径（默认读 ${ENV_KEY_FILE}）")
    parser.add_argument("--key-id", type=int, default=1, help="无感模式使用的 key_id，默认 1")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect", help="只看头部，不解密")
    p.add_argument("file")
    p.set_defaults(func=_cmd_inspect)

    p = sub.add_parser("encrypt", help="封装为 .jm")
    p.add_argument("file")
    p.add_argument("-o", "--output", help="输出路径或目录；默认与源文件同目录、脱敏命名")
    p.add_argument("--keep-name", action="store_true", help="保留原文件名（默认脱敏为 doc_日期_随机.jm）")
    p.add_argument("--password", help="启用口令模式")
    p.add_argument("--pad-min", type=int, default=0, help="随机填充下限，默认 0")
    p.add_argument("--pad-max", type=int, default=4096, help="随机填充上限，默认 4096")
    p.set_defaults(func=_cmd_encrypt)

    p = sub.add_parser("verify", help="只校验完整性并打印 Meta")
    p.add_argument("file")
    p.add_argument("--password")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("decrypt", help="校验通过后解密为明文")
    p.add_argument("file")
    p.add_argument("-o", "--output", required=True, help="输出目录，或 --original-name 时导出的父目录")
    p.add_argument("--original-name", action="store_true", help="用 Meta 里的原始文件名落盘")
    p.add_argument("--password")
    p.set_defaults(func=_cmd_decrypt)

    args = parser.parse_args(argv)
    if not args.key_file:
        args.key_file = os.environ.get(ENV_KEY_FILE)
    try:
        return args.func(args)
    except (JMError, OSError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
