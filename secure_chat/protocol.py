"""Length-prefixed packet protocol utilities.

Raw packet format:
    4 bytes unsigned big-endian header length
    UTF-8 JSON header
    binary payload

Logical packets use the same structure before encryption. The encrypted logical packet is
sent as the payload of an outer raw packet whose header has type="secure".
"""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import Any

from secure_chat.config import MAX_ENCRYPTED_PACKET_SIZE, MAX_HEADER_SIZE, MAX_PAYLOAD_SIZE


class ProtocolError(ValueError):
    """Raised when a packet violates the protocol contract."""


@dataclass(frozen=True)
class Packet:
    """Decrypted logical packet."""

    header: dict[str, Any]
    payload: bytes = b""


def recv_exact(sock_obj: socket.socket, size: int) -> bytes | None:
    """Receive exactly size bytes, or None when the peer closed the connection."""
    if size < 0:
        raise ProtocolError("receive size must not be negative")

    chunks: list[bytes] = []
    received = 0

    while received < size:
        chunk = sock_obj.recv(size - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def _encode_header(header: dict[str, Any], payload_size: int) -> bytes:
    normalized_header = dict(header)
    normalized_header["payload_size"] = payload_size
    header_data = json.dumps(normalized_header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    if len(header_data) <= 0 or len(header_data) > MAX_HEADER_SIZE:
        raise ProtocolError("header size is out of bounds")

    return header_data


def raw_send_packet(sock_obj: socket.socket, header: dict[str, Any], payload: bytes = b"") -> None:
    """Send an unencrypted raw packet."""
    header_data = _encode_header(header, len(payload))
    packet = struct.pack("!I", len(header_data)) + header_data + payload
    sock_obj.sendall(packet)


def raw_recv_packet(
    sock_obj: socket.socket,
    *,
    max_payload_size: int = MAX_ENCRYPTED_PACKET_SIZE,
) -> tuple[dict[str, Any], bytes] | tuple[None, None]:
    """Receive an unencrypted raw packet.

    Returns (None, None) when the peer cleanly closes the connection.
    """
    header_size_data = recv_exact(sock_obj, 4)
    if header_size_data is None:
        return None, None

    header_size = struct.unpack("!I", header_size_data)[0]
    if header_size <= 0 or header_size > MAX_HEADER_SIZE:
        raise ProtocolError("invalid header size")

    header_data = recv_exact(sock_obj, header_size)
    if header_data is None:
        return None, None

    try:
        header = json.loads(header_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("header is not valid UTF-8 JSON") from exc

    if not isinstance(header, dict):
        raise ProtocolError("header must be a JSON object")

    try:
        payload_size = int(header.get("payload_size", 0))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("payload_size must be an integer") from exc

    if payload_size < 0 or payload_size > max_payload_size:
        raise ProtocolError("payload size is out of bounds")

    payload = b""
    if payload_size > 0:
        payload = recv_exact(sock_obj, payload_size)
        if payload is None:
            return None, None

    return header, payload


def pack_logical_packet(header: dict[str, Any], payload: bytes = b"") -> bytes:
    """Pack a logical packet before encryption."""
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ProtocolError("logical payload exceeds max payload size")

    header_data = _encode_header(header, len(payload))
    return struct.pack("!I", len(header_data)) + header_data + payload


def unpack_logical_packet(data: bytes) -> Packet:
    """Unpack a decrypted logical packet."""
    if len(data) < 4:
        raise ProtocolError("decrypted packet is too short")

    header_size = struct.unpack("!I", data[:4])[0]
    if header_size <= 0 or header_size > MAX_HEADER_SIZE:
        raise ProtocolError("invalid decrypted header size")

    header_start = 4
    header_end = header_start + header_size
    if len(data) < header_end:
        raise ProtocolError("decrypted packet is missing header bytes")

    try:
        header = json.loads(data[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("decrypted header is not valid UTF-8 JSON") from exc

    if not isinstance(header, dict):
        raise ProtocolError("decrypted header must be a JSON object")

    try:
        payload_size = int(header.get("payload_size", 0))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("decrypted payload_size must be an integer") from exc

    payload = data[header_end:]
    if payload_size < 0 or payload_size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("decrypted payload size is out of bounds")
    if len(payload) != payload_size:
        raise ProtocolError("decrypted payload size does not match header")

    return Packet(header=header, payload=payload)


def packet_summary(header: dict[str, Any], payload: bytes = b"") -> str:
    """Return a log-safe one-line summary of a packet."""
    msg_type = str(header.get("type", ""))

    if msg_type in {"chat", "whisper"}:
        text = str(header.get("text", ""))
        if len(text) > 80:
            text = text[:80] + "..."
        return f"type={msg_type}, text={text}"

    if msg_type == "image":
        filename = str(header.get("filename", "image.bin"))
        return f"type=image, filename={filename}, bytes={len(payload)}"

    if msg_type == "file":
        filename = str(header.get("filename", "file.bin"))
        digest = str(header.get("sha256", ""))
        hash_preview = digest[:16] if digest else "-"
        return f"type=file, filename={filename}, bytes={len(payload)}, sha256={hash_preview}"

    if msg_type == "users":
        return f"type=users, users={header.get('users', [])}"

    return f"type={msg_type}"
