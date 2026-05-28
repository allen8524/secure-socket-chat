import json
import struct

import pytest

from secure_chat.config import MAX_HEADER_SIZE, MAX_PAYLOAD_SIZE
from secure_chat.protocol import ProtocolError, raw_recv_packet, unpack_logical_packet
from secure_chat.utils import safe_filename


class FakeSocket:
    def __init__(self, data: bytes):
        self._data = bytearray(data)

    def recv(self, size: int) -> bytes:
        if not self._data:
            return b""
        chunk = self._data[:size]
        del self._data[:size]
        return bytes(chunk)


def test_raw_recv_rejects_oversized_header():
    data = struct.pack("!I", MAX_HEADER_SIZE + 1)

    with pytest.raises(ProtocolError, match="invalid header size"):
        raw_recv_packet(FakeSocket(data))


def test_raw_recv_rejects_oversized_payload_size():
    header = json.dumps({"type": "secure", "payload_size": MAX_PAYLOAD_SIZE + 2_000_000}).encode("utf-8")
    data = struct.pack("!I", len(header)) + header

    with pytest.raises(ProtocolError, match="payload size is out of bounds"):
        raw_recv_packet(FakeSocket(data), max_payload_size=MAX_PAYLOAD_SIZE)


def test_raw_recv_rejects_broken_json_header():
    header = b"{not-json"
    data = struct.pack("!I", len(header)) + header

    with pytest.raises(ProtocolError, match="header is not valid"):
        raw_recv_packet(FakeSocket(data))


def test_unpack_rejects_payload_size_mismatch():
    header = json.dumps({"type": "chat", "payload_size": 99}).encode("utf-8")
    data = struct.pack("!I", len(header)) + header + b"short"

    with pytest.raises(ProtocolError, match="does not match"):
        unpack_logical_packet(data)


def test_safe_filename_blocks_path_traversal_components():
    assert safe_filename("../../secret.txt", fallback="file.bin") == "secret.txt"
    assert safe_filename("nested\\secret.txt", fallback="file.bin") == "nested_secret.txt"
