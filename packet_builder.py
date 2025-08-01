import read_varint_helper
import struct
import uuid


# ――― パケットビルダー ―――
def build_packet(pid: int, body: bytes = b"") -> bytes:
    return read_varint_helper.to_varint(pid) + body


def build_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return read_varint_helper.to_varint(len(b)) + b


def build_handshake(PROTOCOL_VERSION, HOST, PORT) -> bytes:
    return build_packet(
        0x00,
        read_varint_helper.to_varint(PROTOCOL_VERSION)
        + build_string(HOST)
        + struct.pack(">H", PORT)
        + read_varint_helper.to_varint(2),
    )


def build_login_start(BOT_USERNAME) -> bytes:
    return build_packet(
        0x00,
        build_string(BOT_USERNAME)
        + uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{BOT_USERNAME}").bytes,
    )


def build_login_ack() -> bytes:
    return build_packet(0x03)


def build_brand() -> bytes:
    return build_packet(0x02, build_string("minecraft:brand") + build_string("vanilla"))


def build_client_info() -> bytes:
    p = build_string("ja_jp")
    p += struct.pack("b", 8)
    p += read_varint_helper.to_varint(0)
    p += struct.pack("?", True)
    p += struct.pack("B", 0x7F)
    p += read_varint_helper.to_varint(1)
    p += struct.pack("?", False)
    p += struct.pack("?", True)
    p += read_varint_helper.to_varint(0)
    return build_packet(0x00, p)


def build_known_packs(data: bytes) -> bytes:
    return build_packet(0x07, data)


def build_config_keepalive(data: bytes) -> bytes:
    return build_packet(0x03, data)


def build_finish_config() -> bytes:
    return build_packet(0x03)


def build_confirm_teleport(tid: int) -> bytes:
    return build_packet(0x00, read_varint_helper.to_varint(tid))


def build_player_loaded() -> bytes:
    return build_packet(0x2A)


def build_keep_alive_response(data: bytes) -> bytes:
    if len(data) != 8:
        raise ValueError(f"Invalid KeepAlive payload length: {len(data)}")
    res = build_packet(0x1A, data)

    return res
