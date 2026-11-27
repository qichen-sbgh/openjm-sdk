"""根密钥装载。

生产密钥不随仓库分发：仓库里只出现测试向量用的公开测试密钥（key_id=254）。
真实根密钥通过环境变量指向的文件或部署系统注入，格式为::

    {"1": "<64 位 hex，32 字节>", "2": "..."}

口令模式的 key_id 恒为 0x00，不需要也不允许出现在这里。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Mapping, Optional, Union

from .kdf import normalize_root_keys

ENV_KEY_FILE = "OPENJM_KEY_FILE"


def load_root_keys(source: Union[str, Path, Mapping]) -> Dict[int, bytes]:
    """从 JSON 文件路径、dict 或 ``{ "1": "hex" }`` 形式的映射装载根密钥。"""
    if isinstance(source, Mapping):
        raw = dict(source)
    else:
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"根密钥文件不存在: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("根密钥文件必须是一个 JSON 对象")

    parsed: Dict[int, bytes] = {}
    for key_id_str, hex_key in raw.items():
        if not isinstance(hex_key, str):
            raise ValueError(f"key_id={key_id_str} 的根密钥必须是 hex 字符串")
        try:
            key_id = int(str(key_id_str))
        except ValueError:
            raise ValueError(f"无法解析 key_id: {key_id_str!r}") from None
        try:
            key = bytes.fromhex(hex_key.strip())
        except ValueError:
            raise ValueError(f"key_id={key_id} 的根密钥不是合法 hex") from None
        parsed[key_id] = key

    return normalize_root_keys(parsed)


def load_root_keys_from_env(env_var: str = ENV_KEY_FILE) -> Optional[Dict[int, bytes]]:
    """读 ``OPENJM_KEY_FILE`` 指向的文件；未设置时返回 None，便于脚本自己兜底。"""
    path = os.environ.get(env_var)
    if not path:
        return None
    return load_root_keys(path)
