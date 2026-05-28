"""Safe packet inspection summaries for GUI demonstrations."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

Direction = Literal["OUTBOUND", "INBOUND"]


@dataclass(frozen=True)
class PacketInspectionEvent:
    direction: Direction
    logical_type: str
    logical_header_summary: str
    payload_size: int
    encrypted_packet_size: int
    ciphertext_preview: str
    timestamp: datetime
    integrity_hash_present: bool
    decrypt_success: bool | None
    error_message: str


def truncate_value(value: Any, limit: int = 32) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def ciphertext_preview(data: bytes, limit: int = 72) -> str:
    if not data:
        return "-"

    encoded = base64.b64encode(data).decode("ascii")
    if len(encoded) <= limit:
        return encoded
    return encoded[:limit] + "..."


def has_integrity_hash(header: dict[str, Any]) -> bool:
    return bool(str(header.get("sha256", "")).strip())


def summarize_logical_header(header: dict[str, Any], payload_size: int = 0) -> str:
    msg_type = str(header.get("type", "unknown") or "unknown")

    if msg_type == "chat":
        return f"type=chat, text_preview={truncate_value(header.get('text', ''))!r}"

    if msg_type == "whisper":
        return (
            "type=whisper, "
            f"from={truncate_value(header.get('from', '-'), 18)!r}, "
            f"to={truncate_value(header.get('to', '-'), 18)!r}, "
            f"text_preview={truncate_value(header.get('text', ''))!r}"
        )

    if msg_type == "image":
        file_size = header.get("file_size", payload_size)
        return (
            "type=image, "
            f"from={truncate_value(header.get('from', '-'), 18)!r}, "
            f"to={truncate_value(header.get('to', '-'), 18)!r}, "
            f"filename={truncate_value(header.get('filename', 'image.bin'), 28)!r}, "
            f"file_size={file_size}, "
            f"sha256={'yes' if has_integrity_hash(header) else 'no'}"
        )

    if msg_type == "users":
        users = header.get("users", [])
        user_count = len(users) if isinstance(users, list) else 0
        return f"type=users, count={user_count}"

    if msg_type in {"system", "error"}:
        return f"type={msg_type}, text_preview={truncate_value(header.get('text', ''))!r}"

    if msg_type == "join":
        return f"type=join, username={truncate_value(header.get('username', ''), 18)!r}"

    if msg_type == "stats":
        keys = ["online_count", "total_messages", "total_images", "total_image_bytes"]
        details = [f"{key}={header[key]}" for key in keys if key in header]
        return "type=stats" + (", " + ", ".join(details) if details else "")

    if msg_type == "leave":
        return f"type=leave, text_preview={truncate_value(header.get('text', ''))!r}"

    return f"type={truncate_value(msg_type, 24)}, payload_size={payload_size}"


def build_packet_inspection_event(
    *,
    direction: Direction,
    header: dict[str, Any] | None,
    payload: bytes = b"",
    encrypted_packet: bytes = b"",
    decrypt_success: bool | None = None,
    error_message: str = "-",
) -> PacketInspectionEvent:
    safe_header = header or {}
    payload_size = len(payload)
    return PacketInspectionEvent(
        direction=direction,
        logical_type=str(safe_header.get("type", "unknown") or "unknown"),
        logical_header_summary=summarize_logical_header(safe_header, payload_size),
        payload_size=payload_size,
        encrypted_packet_size=len(encrypted_packet),
        ciphertext_preview=ciphertext_preview(encrypted_packet),
        timestamp=datetime.now(),
        integrity_hash_present=has_integrity_hash(safe_header),
        decrypt_success=decrypt_success,
        error_message=truncate_value(error_message or "-", 80),
    )


def format_packet_inspection_event(event: PacketInspectionEvent) -> str:
    decrypt_text = "N/A" if event.decrypt_success is None else ("OK" if event.decrypt_success else "FAIL")
    hash_text = "yes" if event.integrity_hash_present else "no"
    return "\n".join(
        [
            f"[{event.timestamp.strftime('%H:%M:%S')}] {event.direction} {event.logical_type}",
            f"  logical header: {event.logical_header_summary}",
            f"  payload size: {event.payload_size} bytes",
            f"  encrypted packet size: {event.encrypted_packet_size} bytes",
            f"  ciphertext preview: {event.ciphertext_preview}",
            f"  integrity hash: {hash_text} | decrypt: {decrypt_text}",
            f"  last error: {event.error_message}",
        ]
    )
