# auto-crypto-vectors

SM2 / SM3 / SM4 国密算法的 pytest 测试向量与行为测试集：标准 KAT 向量逐字节比对、负向/边界用例、以及 gmssl × pysm4 双实现 SM4 互通对拍。零硬件，纯 Python。

> 定位声明：本项目用于**教学与仿真环境**中的密码模块测试方法练习，不针对、也不适用于任何真实车辆、真实 ECU 或任何产品。

## 解决什么问题

如何证明一个密码模块「对不对」，而不是「会不会调用」：

- **KAT**：SM3（GM/T 0004 示例）、SM4 单块与 1e6 次迭代（GB/T 32907 附录 A）、SM2 标准签名路径（GM/T 0003 示例密钥对）逐字节比对
- **负向/边界**：篡改消息/签名/密文必须失败；空输入、非块整数倍、非法公钥等畸形输入的拒绝行为
- **互通性**：gmssl 与 pysm4 交叉加解密（ECB/CBC 双向），同输入密文逐字节一致；接口契约回归（pysm4 传 int 静默返回 None 等）
- **缺陷钉死**：把实测到的库缺陷行为固化成用例——SM2 解密不校验 C3、SM4-CBC 无 MAC 篡改静默通过、gmssl 非标准签名路径（无 ZA）与标准验证互不可验等（均为**教学演示**，用于展示「把加密当认证用」的风险）

## 快速开始

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

注意：`test_sm4.py` 中的 1e6 次迭代 KAT 占总时长的大头（约 45~50 s），属于正常现象。

## 目录结构

```text
auto-crypto-vectors/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── tests/
│   ├── test_sm2.py       # 标准签验 / 篡改负向 / 非法公钥 / 非标准路径互斥 / C3 不校验（缺陷演示）
│   ├── test_sm3.py       # KAT 'abc'、'abcd'×16、空串 / MD 填充边界 11 长度 / HMAC-SM3
│   ├── test_sm4.py       # 单块与 1e6 迭代 KAT（one_round 路径）/ CBC 往返 / 篡改静默 / 畸形输入
│   └── test_interop.py   # gmssl × pysm4 ECB/CBC 双向互通 + 类型契约回归
└── evidence/
    └── RUN-20261110-030330/    # 一次真实运行的 JUnit 证据包（见下）
```

## 证据

**evidence/RUN-20261110-030330**（运行日期 2026-11-10）：

- `pytest.xml`：**24 tests / 0 failures / 0 errors / 0 skipped**，总时长 59.087 s
- `sha256.txt`：pytest.xml 的 SHA-256 清单
- 说明：`pytest.xml` 中的 `hostname` 属性已脱敏为 `localhost`，`sha256.txt` 为脱敏后副本重算的清单

**本机复跑记录**（2026-11-12，gmssl 3.2.2 / pysm4 0.7.2 / pytest 9.2.0 / Python 3.12.0）：`python -m pytest -q` → **24 passed in 55.78s**，退出码 0。

## Status

- **已完成**：SM2/SM3/SM4 共 24 条用例（KAT + 负向 + 边界 + 互通）全部通过；SM4 双实现互通矩阵 6 格全通（ECB/CBC × 双向 + 密文一致 + 契约回归）。
- **未完成**：互通矩阵仅覆盖 SM4——gmssl 与 pysm4 均无 SM2/SM3 第二实现，SM2/SM3 互通未测；「自定义 ID 互通」用例因 gmssl 不支持自定义 ID 而无法构造；未引入国密 OpenSSL 等第三实现。

## License

MIT（见 LICENSE）。

---

**English TL;DR:** Pytest vector and behavior tests for the Chinese national cryptography algorithms SM2/SM3/SM4: byte-exact KAT vectors (GM/T 0002/0003/0004, GB/T 32907), negative/boundary cases, and an SM4 interop matrix between gmssl and pysm4. Known library quirks are pinned as teaching cases. Packaged run RUN-20261110-030330 (2026-11-10): 24 passed / 0 failed in 59.1 s; re-run locally on 2026-11-12: 24 passed. Interop covers SM4 only (no second SM2/SM3 implementation available). Study/simulation use only — not applicable to real vehicles.
