# openjm-sdk

`.jm` v1 加密文档容器的**发送端 SDK**。给 QQ 机器人流水线、批处理脚本、服务端用：把 PDF 封装成 `.jm`，顺手也能校验和解密，方便跨端对齐。

`compatible: proto-v1`

协议规范与测试向量在 [`openjm`](https://github.com/qichen-sbgh/openjm) 仓库，本仓只负责实现，不改协议。

## 安装

```bash
pip install -e "../openjm-sdk[dev]"   # 开发
pip install cryptography              # 运行时只需要这一个依赖
```

Python 3.9+，运行时依赖只有 `cryptography`（AES-CTR 与 HMAC 全部走标准库 + 这一层）。

## 三行用法

```python
from openjm import JMCrypto, load_root_keys

crypto = JMCrypto(load_root_keys("keys.json"))            # {"1": "<64位hex>"}
result = crypto.encrypt_file("深入理解计算机系统.pdf")     # → doc_20261127_a1b2c3d4.jm

meta = crypto.verify_file(result.output_path)             # 只校验，不落明文
print(meta["name"], meta["size"])                         # 原始文件名与大小
```

口令模式（高敏文档）：

```python
crypto.encrypt_file("合同.pdf", password="只有收件人知道的口令")
crypto.verify_file("doc_xxx.jm", password="只有收件人知道的口令")
```

## 命令行

```bash
export OPENJM_KEY_FILE=~/keys/prod.json

python -m openjm encrypt report.pdf                    # 脱敏命名
python -m openjm inspect doc_20261127_a1b2c3d4.jm      # 只看头部
python -m openjm verify  doc_20261127_a1b2c3d4.jm      # 校验并打印 Meta
python -m openjm decrypt doc_20261127_a1b2c3d4.jm -o ./out --original-name
```

`inspect` 只读 28 字节，用来在 QQ 机器人里判断“要不要弹口令”。

## 行为约定

- **全量流式**：64KB 分块，内存占用与文件大小无关；50MB PDF 约 30–80ms。
- **原子落盘**：先写隐藏 `.tmp` 再 `os.replace`，中途失败不留半个文件。
- **每次都不一样**：新 nonce、新填充长度，同一份 PDF 两次封装没有任何字节关联。
- **Encrypt-then-MAC**：尾部 32B HMAC 覆盖头部与全部密文，一次比对挡掉截断、损坏、篡改和口令错误。
- **只认协议**：`version != 1` 直接拒绝，不做宽容解析。

## 错误语义

| 异常 | 含义 | 建议文案 |
| --- | --- | --- |
| `JMFormatError` | 不是 `.jm`、版本不支持、结构损坏 | 文件格式不对，请让发送方重新封装 |
| `JMPasswordRequiredError` | 口令文件但没给口令 | 这份文档需要口令 |
| `JMAuthError` | 下载不完整 / 损坏 / 被改 / 口令错 | 文件不完整或已损坏，请在 QQ 重新下载 |

`JMAuthError` 刻意把“截断”和“口令错”合成一个错误：HMAC 是唯一判据，不额外猜测。

## 跨端一致性

```bash
OPENJM_TESTVECTORS=../openjm/testvectors python -m pytest -q
```

向量集不在本仓：它属于 `openjm` 仓库，按 `proto-v1` tag 冻结。找不到向量时相关用例自动 skip，本地开发不会因此变红。

## 结构

```text
src/openjm/
  header.py      # 28B 头解析 + 常量
  kdf.py         # HKDF-SHA256 派生（三端逐字节对齐的关键）
  container.py   # 加密 / 校验 / 解密
  keys.py        # 根密钥装载（JSON / 环境变量）
  errors.py      # 异常体系
  __main__.py    # CLI
tests/
  test_container.py    # 往返、随机性、截断、篡改、分块边界
  test_conformance.py  # 回放 openjm 仓库的冻结向量
```

## 不做的事

- 不做密钥分发：根密钥走部署系统的密钥库，本仓只认 `OPENJM_KEY_FILE` 或显式传入。
- 不做 PDF 解析、不做压缩、不做上传：封装完把路径交给调用方，发不发、怎么发由调用方决定。
- 不实现 `.jm` 阅读侧：那是 `openjm-mobile` 的事，本仓的解密接口只用于校验与测试。
