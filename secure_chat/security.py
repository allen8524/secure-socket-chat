"""Security metadata helpers used by SecureSocketChat."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ChannelMetadata:
    """Human-readable metadata for an encrypted client-server channel."""

    cipher: str
    local_public_key: str
    peer_public_key: str
    local_fingerprint: str
    peer_fingerprint: str
    session_id: str


def public_key_fingerprint(public_key_b64: str) -> str:
    """Return a short SHA-256 fingerprint for a base64 encoded public key."""
    digest = hashlib.sha256(public_key_b64.encode("utf-8")).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, 16, 2))


def session_id_from_fingerprints(left: str, right: str) -> str:
    """Build a stable short session id from both public-key fingerprints."""
    joined = "|".join(sorted([left, right]))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12].upper()


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of bytes as lowercase hexadecimal text."""
    return hashlib.sha256(data).hexdigest()
