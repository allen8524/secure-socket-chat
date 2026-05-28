"""Persistent server transport private-key storage."""

from __future__ import annotations

import binascii
import os
from pathlib import Path

from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey


class ServerKeyStoreError(RuntimeError):
    """Raised when a server private key cannot be loaded or saved safely."""


def private_key_to_base64(private_key: PrivateKey) -> str:
    """Encode a server private key as base64 text."""
    return private_key.encode(encoder=Base64Encoder).decode("ascii")


def private_key_from_base64(value: str) -> PrivateKey:
    """Decode a base64 server private key."""
    normalized_value = value.strip()
    if not normalized_value:
        raise ServerKeyStoreError("server private key file is empty")

    try:
        return PrivateKey(normalized_value.encode("ascii"), encoder=Base64Encoder)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ServerKeyStoreError("server private key file is invalid") from exc


def load_server_private_key(path: str | Path) -> PrivateKey:
    """Load a server private key from a base64 key file."""
    key_path = Path(path)
    try:
        encoded_key = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ServerKeyStoreError(f"failed to read server private key file: {key_path}") from exc

    try:
        return private_key_from_base64(encoded_key)
    except ServerKeyStoreError as exc:
        raise ServerKeyStoreError(f"failed to load server private key file: {key_path}") from exc


def save_server_private_key(path: str | Path, private_key: PrivateKey) -> None:
    """Save a server private key as base64 text."""
    key_path = Path(path)
    encoded_key = private_key_to_base64(private_key) + "\n"

    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with key_path.open("x", encoding="utf-8") as file_obj:
            file_obj.write(encoded_key)
        _apply_private_file_mode(key_path)
    except FileExistsError as exc:
        raise ServerKeyStoreError(f"server private key file already exists: {key_path}") from exc
    except OSError as exc:
        raise ServerKeyStoreError(f"failed to save server private key file: {key_path}") from exc


def load_or_create_server_private_key(path: str | Path) -> PrivateKey:
    """Load an existing server private key or create a new key file."""
    key_path = Path(path)
    if key_path.exists():
        return load_server_private_key(key_path)

    private_key = PrivateKey.generate()
    save_server_private_key(key_path, private_key)
    return private_key


def _apply_private_file_mode(path: Path) -> None:
    if os.name != "posix":
        return

    try:
        path.chmod(0o600)
    except OSError:
        pass
