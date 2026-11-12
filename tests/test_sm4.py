"""SM4 KAT 与解密侧行为（负向）。

向量来源：GB/T 32907 附录 A 示例（标准 16 字节单块、1e6 次迭代）——公开常识级；
解密侧行为为本机实测（gmssl，2026-11-09）。
"""
from __future__ import annotations

import pytest

from gmssl import sm4

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
PT = bytes.fromhex("0123456789abcdeffedcba9876543210")
STANDARD_1E6 = "595298c7c6fd271f0402f804c33d3f66"


# ---------------------------------------------------------------- KAT
def test_kat_single_block_via_one_round():
    """标准单块：681edf34…。⚠️ 必须走 one_round——crypt_ecb 强制 PKCS7（见 05/06 §2.4）。"""
    c = sm4.CryptSM4()
    c.set_key(KEY, sm4.SM4_ENCRYPT)
    out = sm4.list_to_bytes(c.one_round(c.sk, list(PT))).hex()
    assert out == "681edf34d206965e86b3e94f536e4246"


def test_kat_million_iterations():
    """GB/T 32907 附录 A 示例 2：1e6 次迭代 → 595298c7…。"""
    c = sm4.CryptSM4()
    c.set_key(KEY, sm4.SM4_ENCRYPT)
    blk = list(PT)
    for _ in range(1_000_000):
        blk = c.one_round(c.sk, blk)
    assert sm4.list_to_bytes(blk).hex() == STANDARD_1E6


def test_cbc_roundtrip():
    """CBC 往返：crypt_cbc 自带 PKCS7，解密应还原原文主体。"""
    c = sm4.CryptSM4()
    c.set_key(KEY, sm4.SM4_ENCRYPT)
    ct = c.crypt_cbc(bytes(16), b"vehicle-secret-data" + bytes(12))
    d = sm4.CryptSM4()
    d.set_key(KEY, sm4.SM4_DECRYPT)
    assert d.crypt_cbc(bytes(16), ct).startswith(b"vehicle-secret-data")


# ------------------------------------------------ 解密侧行为（本机实测）
def test_cbc_tampering_is_silently_accepted():
    """⚠️ 已知行为（缺陷演示）：CBC 无 MAC——篡改密文最后一字节**不报错**，静默解出错误明文。

    这就是「CBC 必须配合 MAC」的原因（对照知识库 05/01 §4.4 与 SecOC 的存在理由）。
    在带认证的真实被测件上，本用例的正确预期是【抛异常 / 认证失败】。
    """
    c = sm4.CryptSM4()
    c.set_key(KEY, sm4.SM4_ENCRYPT)
    ct = c.crypt_cbc(bytes(16), b"payload-16-bytes-padd")
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    d = sm4.CryptSM4()
    d.set_key(KEY, sm4.SM4_DECRYPT)
    garbage = d.crypt_cbc(bytes(16), bytes(tampered))   # 不抛异常 = 无完整性保护
    assert garbage != b"payload-16-bytes-padd"          # 明文已变，但没有任何告警


@pytest.mark.parametrize("bad_input", [b"", b"\x00" * 33], ids=["空输入", "非块整数倍"])
def test_decrypt_rejects_malformed_input(bad_input):
    """畸形输入应报错（gmssl 抛 IndexError——虽非类型化错误码，但至少不是静默通过）。"""
    d = sm4.CryptSM4()
    d.set_key(KEY, sm4.SM4_DECRYPT)
    with pytest.raises(Exception):
        d.crypt_ecb(bad_input)
