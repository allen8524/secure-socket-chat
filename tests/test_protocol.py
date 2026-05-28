import struct

import pytest

from secure_chat.config import MAX_PAYLOAD_SIZE
from secure_chat.protocol import ProtocolError, pack_logical_packet, unpack_logical_packet


def test_pack_and_unpack_logical_packet_round_trip():
    header = {"type": "chat", "text": "hello"}
    payload = b""

    packed = pack_logical_packet(header, payload)
    packet = unpack_logical_packet(packed)

    assert packet.header["type"] == "chat"
    assert packet.header["text"] == "hello"
    assert packet.header["payload_size"] == 0
    assert packet.payload == payload


def test_pack_and_unpack_binary_payload_round_trip():
    header = {"type": "image", "filename": "sample.png"}
    payload = b"\x89PNG\r\n\x1a\n" + b"sample"

    packed = pack_logical_packet(header, payload)
    packet = unpack_logical_packet(packed)

    assert packet.header["type"] == "image"
    assert packet.header["filename"] == "sample.png"
    assert packet.header["payload_size"] == len(payload)
    assert packet.payload == payload


def test_payload_size_limit_is_enforced():
    payload = b"0" * (MAX_PAYLOAD_SIZE + 1)

    with pytest.raises(ProtocolError):
        pack_logical_packet({"type": "image"}, payload)


def test_unpack_rejects_short_packet():
    with pytest.raises(ProtocolError):
        unpack_logical_packet(b"abc")


def test_unpack_rejects_invalid_header_size():
    invalid_header_size = struct.pack("!I", 0)

    with pytest.raises(ProtocolError):
        unpack_logical_packet(invalid_header_size)
