"""openjm 异常体系。

与 `.jm` v1 协议的三类失败场景一一对应，调用方据此决定提示文案：

* :class:`JMFormatError`            —— 根本不是 .jm，或头部/长度自相矛盾
* :class:`JMPasswordRequiredError`  —— 是口令文件，但没给口令
* :class:`JMAuthError`              —— HMAC 不过：下载不完整、损坏、篡改或口令错
"""

from __future__ import annotations


class JMError(Exception):
    """openjm 基础异常。"""


class JMFormatError(JMError):
    """文件魔数、版本、结构或长度不合法。"""


class JMPasswordRequiredError(JMError):
    """文件为口令加密模式，但未提供口令。"""


class JMAuthError(JMError):
    """HMAC 校验失败（文件下载不完整、已损坏、密钥版本错误或口令错误）。"""
