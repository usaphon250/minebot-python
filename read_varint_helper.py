import varint
import socket
import struct


# ――― VarInt ヘルパー ―――
def to_varint(v: int) -> bytes:
    """varintライブラリを使って整数をVarIntバイト列にエンコードする"""
    return varint.encode(v)


def read_varint_from_buffer(buf: bytes) -> tuple[int, int]:
    num = 0
    for i in range(5):
        byte = buf[i]
        num |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return num, i + 1
    raise ValueError("VarInt too big")


def read_varint(sock: socket.socket) -> int:
    num = 0
    shift = 0
    for _ in range(5):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("Socket closed")
        byte = b[0]
        num |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return num
        shift += 7
    raise ValueError("VarInt too big")


# よくわからんやつ
def read_string_from_buffer(data: bytes, offset: int) -> tuple[str, int]:
    """バッファから文字列を読み取る"""
    length, varint_len = read_varint_from_buffer(data[offset:])
    offset += varint_len
    value = data[offset : offset + length].decode("utf-8")
    return value, offset + length


def read_long_from_buffer(data: bytes, offset: int) -> tuple[int, int]:
    """バッファからLong(8バイト)を読み取る"""
    value = struct.unpack(">q", data[offset : offset + 8])[0]
    return value, offset + 8


def read_boolean_from_buffer(data: bytes, offset: int) -> tuple[bool, int]:
    """バッファからBoolean(1バイト)を読み取る"""
    value = struct.unpack("?", data[offset : offset + 1])[0]
    return value, offset + 1


def read_bytes_from_buffer(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    """バッファから指定長のバイト列を読み取る"""
    value = data[offset : offset + length]
    return value, offset + length

