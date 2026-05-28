"""Experimental E2E whisper helpers."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

from secure_chat.security import public_key_fingerprint

E2E_ALGORITHM = "PyNaCl Box"
E2E_VERSION = 1


class E2EEncryptionError(ValueError):
    """Raised when an E2E payload cannot be encrypted or decrypted."""


@dataclass(frozen=True)
class E2EIdentity:
    private_key: PrivateKey
    public_key: str
    fingerprint: str


def generate_e2e_identity() -> E2EIdentity:
    private_key = PrivateKey.generate()
    public_key = encode_public_key(private_key.public_key)
    return E2EIdentity(
        private_key=private_key,
        public_key=public_key,
        fingerprint=public_key_fingerprint(public_key),
    )


def encode_public_key(public_key: PublicKey) -> str:
    return public_key.encode(encoder=Base64Encoder).decode("utf-8")


def decode_public_key(public_key_b64: str) -> PublicKey:
    try:
        return PublicKey(public_key_b64.encode("utf-8"), encoder=Base64Encoder)
    except Exception as exc:
        raise E2EEncryptionError("invalid E2E public key") from exc


def ciphertext_preview(ciphertext_b64: str, limit: int = 48) -> str:
    if len(ciphertext_b64) <= limit:
        return ciphertext_b64
    return ciphertext_b64[:limit] + "..."


def build_inner_payload(sender: str, recipient: str, text: str) -> dict[str, Any]:
    return {
        "type": "e2e_message",
        "from": sender,
        "to": recipient,
        "text": text,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def encrypt_inner_payload(
    sender_private_key: PrivateKey,
    recipient_public_key_b64: str,
    inner_payload: dict[str, Any],
) -> str:
    recipient_public_key = decode_public_key(recipient_public_key_b64)
    box = Box(sender_private_key, recipient_public_key)
    plain = json.dumps(inner_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = bytes(box.encrypt(plain))
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_inner_payload(
    receiver_private_key: PrivateKey,
    sender_public_key_b64: str,
    ciphertext_b64: str,
) -> dict[str, Any]:
    sender_public_key = decode_public_key(sender_public_key_b64)
    box = Box(receiver_private_key, sender_public_key)

    try:
        encrypted = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
        plain = box.decrypt(encrypted)
        payload = json.loads(plain.decode("utf-8"))
    except (CryptoError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise E2EEncryptionError("failed to decrypt E2E payload") from exc

    if not isinstance(payload, dict):
        raise E2EEncryptionError("E2E payload must be a JSON object")
    return payload
