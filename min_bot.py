import socket, struct, uuid, zlib, time
import read_varint_helper, packet_builder
import logging

HOST = "127.0.0.1"
PORT = 25565
PROTOCOL_VERSION = 770
BOT_USERNAME = "MiniBOT"
STATE = "Handshake"
compression_threshold = -1

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(),
    ],
)

# デバッグ用パケット名マップ
PACKET_NAMES = {
    "Handshake": {"C->S": {0x00: "Handshake"}},
    "Login": {
        "C->S": {0x00: "Login Start"},
        "S->C": {0x02: "Login Success", 0x03: "Set Compression"},
    },
    "Config": {
        "C->S": {
            0x00: "Client Info",
            0x03: "Config Ack",
            0x07: "Serverbound Known Packs",
            0x02: "Login Plugin Response",
        },
        "S->C": {
            0x01: "Clientbound Plugin Message",
            0x0E: "Clientbound Known Packs",
            0x03: "Finish Config",
            0x04: "Keep Alive",
            0x07: "Registry Data",
            0x0C: "Feature Flags",
            0x0D: "Update Tags",
            0x09: "Add Resource Pack",
        },
    },
    "Play": {
        "C->S": {
            0x00: "Confirm Teleport",
            0x2B: "Player Loaded",
            0x14: "Player Position",
            0x15: "Player Pos&Rot",
            0x16: "Keep Alive Resp",
            0x2C: "Pong",
            0x1C: "Lock Difficulty",
            0x03: "Change Difficulty",
            0x1A: "?Serverbound Keep Alive",
            0x1D: "Set Player Position and Rotation",
        },
        "S->C": {
            0x2B: "Join Game",
            0x18: "Clientbound Plugin Message",
            0x0A: "Change Difficulty",
            0x39: "Player Abilities",
            0x62: "Set Held Item",
            0x7E: "Update Recipes",
            0x1E: "Entity Event",
            0x45: "Recipe Book Settings",
            0x43: "Recipe Book Add",
            0x41: "Synchronize Player Position",
            0x4F: "Server Data",
            0x72: "System Chat Message",
            0x3F: "Player Info Update",
            0x58: "Set Render Distance",
            0x68: "Set Simulation Distance",
            0x25: "Initialize World Border",
            0x6A: "Update Time",
            0x5A: "Set Default Spawn Position",
            0x22: "Game Event",
            0x78: "Set Ticking State",
            0x79: "Step Tick",
            0x12: "Set Container Content",
            0x14: "Set Container Slot",
            0x10: "Commands",
            0x5C: "Set Entity Metadata",
            0x7C: "Update Attributes",
            0x7B: "Update Advancements",
            0x61: "Set Health",
            0x60: "Set Experience",
            0x1C: "Disconnect",
            0x24: "Keep Alive",
            0x3E: "Sync Player Pos",
            0x57: "Set Center Chunk",
            0x36: "Ping",
            0x27: "Chunk Data and Update Light",
            0x00: "Bundle Delimiter",
            0x1F: "Teleport Entity",
            0x01: "Spawn Entity",
            0x4C: "Set Head Rotation",
            0x2E: "Update Entity Position",
            0x5F: "Set Equipment",
            0x2F: "Rename item",
            0x6E: "Sound Effect",
            0x1B: "Delete Message",
            0x26: "Clientbound Keep Alive",
            0x5E: "Set Entity Velocity",
            0x3A: "Player Chat Message",
            0x31: "Update Entity Rotation",
            0x3C: "Enter Combat",
            0x19: "Damage Event",
            0x02: "Entity Animation",
            0x08: "Block Update",
        },
    },
}


def log_packet(direction: str, state: str, pid: int, payload: bytes):
    name = PACKET_NAMES.get(state, {}).get(direction, {}).get(pid, "Unknown")
    logging.debug(
        f"[{direction}] [{state:^7}] ID=0x{pid:02X} ({name}) len={len(payload)}"
    )


def send_packet(sock, data):
    global compression_threshold
    if compression_threshold >= 0:
        if len(data) >= compression_threshold:
            compressed = zlib.compress(data)
            uncompressed_len = read_varint_helper.to_varint(len(data))
            final_data = (
                read_varint_helper.to_varint(len(uncompressed_len + compressed))
                + uncompressed_len
                + compressed
            )
        else:
            final_data = read_varint_helper.to_varint(len(data) + 1) + b"\x00" + data
    else:
        final_data = read_varint_helper.to_varint(len(data)) + data
    sock.sendall(final_data)


def read_packet_and_log(sock: socket.socket) -> tuple[int, bytes]:
    global STATE

    packet_length = read_varint_helper.read_varint(sock)
    packet_data = b""
    while len(packet_data) < packet_length:
        chunk = sock.recv(packet_length - len(packet_data))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        packet_data += chunk

    if compression_threshold >= 0:
        data_length, data_length_len = read_varint_helper.read_varint_from_buffer(
            packet_data
        )
        content_after_length = packet_data[data_length_len:]

        if data_length > 0:  # データ長が0より大きい場合、データは圧縮されている
            decompressed_data = zlib.decompress(content_after_length)
            if len(decompressed_data) != data_length:
                raise ValueError(
                    f"Decompressed data length mismatch: expected {data_length}, got {len(decompressed_data)}"
                )
            final_data = decompressed_data
        else:  # データ長が0の場合、データは圧縮されていない
            final_data = content_after_length
    else:
        final_data = packet_data

    pid, header_len = read_varint_helper.read_varint_from_buffer(final_data)
    payload = final_data[header_len:]
    log_packet("S->C", STATE, pid, payload)
    return pid, payload


def main():
    global STATE, compression_threshold
    sock = socket.socket()
    sock.connect((HOST, PORT))

    # Handshake
    send_packet(sock, packet_builder.build_handshake(PROTOCOL_VERSION, HOST, PORT))
    STATE = "Login"

    # Login Start
    send_packet(sock, packet_builder.build_login_start(BOT_USERNAME))

    # Wait for Set Compression or Login Success
    while True:
        pid, data = read_packet_and_log(sock)
        if pid == 0x03:
            compression_threshold, _ = read_varint_helper.read_varint_from_buffer(data)
        elif pid == 0x02:
            break

    # Config phase
    STATE = "Config"
    send_packet(sock, packet_builder.build_login_ack())
    send_packet(sock, packet_builder.build_brand())
    send_packet(sock, packet_builder.build_client_info())

    # Wait for Finish Config
    while True:
        pid, data = read_packet_and_log(sock)
        if pid == 0x0E:
            send_packet(sock, packet_builder.build_known_packs(data))
        elif pid == 0x03:
            send_packet(sock, packet_builder.build_finish_config())
            break

    # Play phase
    STATE = "Play"
    while True:
        pid, data = read_packet_and_log(sock)
        if pid == 0x26:  # Keep Alive
            send_packet(sock, packet_builder.build_keep_alive_response(data))
        elif pid == 0x1C:  # Disconnect
            print("Disconnected")
            break


if __name__ == "__main__":
    main()
