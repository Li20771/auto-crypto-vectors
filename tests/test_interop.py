"""互通性矩阵：gmssl × pysm4 的 SM4 双实现对拍（ECB / CBC）。

实测的接口契约（2026-11-09，pysm4 0.7.2）：
    encrypt_ecb(bytes, bytes) → base64 str
    decrypt_ecb(b64_str, bytes) → bytes str
    传 int 参数 → 静默返回 None（互通用例必须加类型断言，见 05/06 §6.2）

判定：A 加密 → B 解密必须还原明文；同输入两库密文逐字节一致。
"""
from __future__ import annotations

import base64

import pytest

from gmssl import sm4

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
IV = bytes(16)
PLAIN = b"P11-interop-16"


def gmssl_ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_ENCRYPT)
    return bytes(c.crypt_ecb(plain))


def gmssl_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_DECRYPT)
    return bytes(c.crypt_ecb(cipher))


def gmssl_cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_ENCRYPT)
    return bytes(c.crypt_cbc(iv, plain))


def gmssl_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_DECRYPT)
    return bytes(c.crypt_cbc(iv, cipher))


import pysm4  # noqa: E402  （第二实现，接口契约见模块 docstring）


# ---------------------------------------------------------------- ECB 互通
def test_ecb_gmssl_encrypt_pysm4_decrypt():
    """A 加密 → B 解密 → 明文一致（⚠️ pysm4 解密返回 str，与 bytes 比较前需编码）。"""
    ct_g = gmssl_ecb_encrypt(PLAIN, KEY)
    pt = pysm4.decrypt_ecb(base64.b64encode(ct_g).decode(), KEY)
    assert isinstance(pt, str)                       # 契约：返回 str
    assert pt.encode() == PLAIN


def test_ecb_pysm4_encrypt_gmssl_decrypt():
    """B 加密 → A 解密 → 明文一致（pysm4 返回 base64 str，先解码）。"""
    ct_p = base64.b64decode(pysm4.encrypt_ecb(PLAIN, KEY))
    pt = gmssl_ecb_decrypt(ct_p, KEY)
    assert pt == PLAIN


def test_ecb_ciphertexts_identical():
    """同明文同密钥：两库密文逐字节一致（确定性密码算法的必然）。"""
    ct_g = gmssl_ecb_encrypt(PLAIN, KEY)
    ct_p = base64.b64decode(pysm4.encrypt_ecb(PLAIN, KEY))
    assert ct_g == ct_p


# ---------------------------------------------------------------- CBC 互通
def test_cbc_gmssl_encrypt_pysm4_decrypt():
    """CBC 同样互通（IV 显式传入两端）。"""
    ct_g = gmssl_cbc_encrypt(PLAIN, KEY, IV)
    pt = pysm4.decrypt_cbc(base64.b64encode(ct_g).decode(), KEY, IV)
    assert pt.encode() == PLAIN


def test_cbc_pysm4_encrypt_gmssl_decrypt():
    ct_p = base64.b64decode(pysm4.encrypt_cbc(PLAIN, KEY, IV))
    pt = gmssl_cbc_decrypt(ct_p, KEY, IV)
    assert pt == PLAIN


# ------------------------------------------------ 接口契约回归（防静默失败）
def test_pysm4_type_contract_regression():
    """接口契约回归：bytes → base64 str；int → 静默 None（缺陷演示，防回归）。"""
    assert isinstance(pysm4.encrypt_ecb(PLAIN, KEY), str)
    assert pysm4.encrypt_ecb(0x1234, 0x5678) is None        # 实测：int 静默 None
    with pytest.raises(ValueError):
        pysm4.encrypt_ecb(PLAIN, "0123456789abcdef" * 2)    # hex 串密钥被拒
