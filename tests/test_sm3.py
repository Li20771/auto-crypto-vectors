"""SM3 摘要 KAT（Known Answer Test）。

向量来源：GM/T 0004 标准示例（'abc' / 'abcd'*16 为公开常识级向量）；
空串值为本机实测记录（gmssl，2026-11-09，捆绑 3.12 运行时）。
"""
from __future__ import annotations

from gmssl import sm3, func


def sm3_hash(data: bytes) -> str:
    return sm3.sm3_hash(func.bytes_to_list(data))


def test_kat_abc():
    """标准向量：SM3('abc')（GM/T 0004 示例 1）。"""
    assert sm3_hash(b"abc") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_kat_abcd_x16():
    """标准向量：SM3('abcd'*16)（GM/T 0004 示例 2）。"""
    assert sm3_hash(b"abcd" * 16) == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"


def test_empty_input_is_valid():
    """空输入是合法输入（边界）：输出 64 位 hex 且有确定值（本机实测）。"""
    assert sm3_hash(b"") == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"


def test_output_always_256bit():
    """MD 填充边界附近的多长度输入，输出恒为 32 字节。"""
    for n in (0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113):
        assert len(bytes.fromhex(sm3_hash(b"x" * n))) == 32


def test_hmac_sm3_deterministic():
    """HMAC-SM3（RFC 2104 结构手写）：同 key 同消息可复现，tag 32 字节。"""
    key = b"secoc-demo-key"
    msg = b"PDU_PAYLOAD\x00\x00\x00\x01"

    def digest(k: bytes, m: bytes) -> str:
        block = k.ljust(64, b"\x00") if len(k) <= 64 else bytes.fromhex(sm3_hash(k))
        ipad = bytes(b ^ 0x36 for b in block)
        opad = bytes(b ^ 0x5C for b in block)
        inner = bytes.fromhex(sm3_hash(ipad + m))
        return sm3_hash(opad + inner)

    assert digest(key, msg) == digest(key, msg)
    assert len(digest(key, msg)) == 64
