"""Helpers for SHA-256 verified file transfer."""

from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path
from typing import Any

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
RISKY_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".jar",
    ".js",
    ".msi",
    ".ps1",
    ".scr",
    ".sh",
    ".vbs",
}


def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_file_size(size: int) -> str:
    if size < 0:
        raise ValueError("file size must not be negative")

    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024

    if unit == "B":
        return f"{int(value)} B"
    if value >= 10:
        return f"{value:.0f} {unit}"
    return f"{value:.1f} {unit}"


def file_extension(filename: str) -> str:
    return Path(filename).suffix.lower()


def guess_mime_type(filename: str) -> str:
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def is_image_file(filename: str) -> bool:
    return file_extension(filename) in IMAGE_EXTENSIONS


def is_potentially_risky_file(filename: str) -> bool:
    return file_extension(filename) in RISKY_EXTENSIONS


def build_file_header(
    *,
    target: str,
    filename: str,
    file_size: int,
    sha256: str,
    packet_type: str = "file",
) -> dict[str, Any]:
    return {
        "type": packet_type,
        "to": target,
        "filename": filename,
        "file_size": file_size,
        "sha256": sha256,
        "mime_type": guess_mime_type(filename),
        "extension": file_extension(filename),
    }


def verify_file_hash(payload: bytes, expected_hash: str) -> bool:
    return bool(expected_hash) and calculate_sha256(payload) == expected_hash
