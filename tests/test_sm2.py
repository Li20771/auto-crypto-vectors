"""SM2 标准路径（sign_with_sm3，含 ZA）与负向用例。

密钥对来源：GM/T 0003 标准示例（公开常识级）；本机实测 2026-11-09。
注意：gmssl 无自定义 ID 入参（写死默认 ID）——「自定义 ID 互通失败」用例
在当前工具链不可构造，见知识库 05/06 §6.2 实测限制一。
"""
from __future__ import annotations

import pytest

from gmssl import sm2, func

PRIV = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
PUB = ("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
       "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
MSG = b"P11|ota-manifest|version=2.0.0|rollback=FALSE"


@pytest.fixture()
def sm2_client():
    return sm2.CryptSM2(private_key=PRIV.lower(), public_key=PUB.lower())


# ---------------------------------------------------------------- 正向
def test_sign_verify_standard_path(sm2_client):
    """标准路径（含 ZA）：sign_with_sm3 → verify_with_sm3 = True。"""
    sig = sm2_client.sign_with_sm3(MSG, func.random_hex(sm2_client.para_len))
    assert isinstance(sig, str) and len(sig) == 128      # 64 字节 RAW r∥s 的 hex
    assert sm2_client.verify_with_sm3(sig, MSG) is True


# ---------------------------------------------------------------- 负向
def test_tampered_message_must_fail(sm2_client):
    """篡改消息 → 验签必须 False。"""
    sig = sm2_client.sign_with_sm3(MSG, func.random_hex(sm2_client.para_len))
    assert sm2_client.verify_with_sm3(sig, MSG.replace(b"FALSE", b"TRUE ")) is False


def test_tampered_signature_must_fail(sm2_client):
    """篡改签名首字节 → 验签必须 False（⚠️ sig 是 hex 字符串，先 fromhex 再改）。"""
    sig = sm2_client.sign_with_sm3(MSG, func.random_hex(sm2_client.para_len))
    bad = bytearray(bytes.fromhex(sig))
    bad[0] ^= 0x01
    assert sm2_client.verify_with_sm3(bytes(bad).hex(), MSG) is False


def test_invalid_pubkey_raises_instead_of_clean_fail(sm2_client):
    """⚠️ 已知缺陷（教学植入）：非法公钥（全零=不在曲线上）→ gmssl 抛 TypeError 崩溃，
    而不是干净的验签 False。真实实现应「拒绝并返回错误」，不应异常外溢。

    实测（gmssl，捆绑 3.12 运行时）：verify_with_sm3 → TypeError（P2 解析为 None）。
    """
    other = sm2.CryptSM2(private_key=PRIV.lower(), public_key="0" * 128)
    sig = sm2_client.sign_with_sm3(MSG, func.random_hex(sm2_client.para_len))
    with pytest.raises(Exception):
        other.verify_with_sm3(sig, MSG)


# ------------------------------------------------ 非标准路径（同库两套 API 互斥）
def test_nonstandard_sign_path_is_not_interoperable(sm2_client):
    """sign(digest)（无 ZA）与标准验证互不可验——同库两套 API 的互通性缺陷演示。

    ⚠️ 这是「发现」不是「期望」：实测两者互不可验（见知识库 05/06 §6.2 矩阵）。
    """
    digest = bytes.fromhex(__import__("gmssl").sm3.sm3_hash(
        __import__("gmssl").func.bytes_to_list(MSG)))
    sig_nonstd = sm2_client.sign(digest, func.random_hex(sm2_client.para_len))
    assert sm2_client.verify(sig_nonstd, digest) is True           # 同链路自洽
    assert sm2_client.verify_with_sm3(sig_nonstd, MSG) is False    # 标准验证方拒绝 ← 缺陷


# ------------------------------------------------ 加密往返 + C3 不校验缺陷
def test_encrypt_decrypt_roundtrip(sm2_client):
    """加密往返成功（同时验证密文无 0x04 前缀、总长 112）。"""
    ct = sm2_client.encrypt(b"\x01" * 16)
    assert len(ct) == 112 and ct[0] != 0x04
    assert sm2_client.decrypt(ct) == b"\x01" * 16


def test_decrypt_does_not_verify_c3(sm2_client):
    """⚠️ 已知缺陷（教学植入）：gmssl decrypt 不校验 C3——篡改完整性字段仍返回明文。

    该用例断言的是「缺陷存在」，用于演示「把加密当认证用」的风险；
    在真实被测件上，这条的正确预期是【抛异常 / 返回错误】。
    """
    ct = sm2_client.encrypt(b"\x01" * 16)
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    assert sm2_client.decrypt(bytes(tampered)) == b"\x01" * 16     # 缺陷证据
