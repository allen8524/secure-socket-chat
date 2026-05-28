"""Encrypted channel abstraction based on PyNaCl public-key boxes."""

from __future__ import annotations

import base64
import logging
import socket
import threading
from typing import Any

from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

from secure_chat.protocol import (
    ProtocolError,
    packet_summary,
    pack_logical_packet,
    raw_recv_packet,
    raw_send_packet,
    unpack_logical_packet,
)
from secure_chat.security import ChannelMetadata, public_key_fingerprint, session_id_from_fingerprints

logger = logging.getLogger(__name__)


class KeyExchangeError(RuntimeError):
    """Raised when the public-key exchange handshake fails."""


class SecureChannel:
    """Thread-safe encrypted wrapper around a socket."""

    def __init__(self, sock_obj: socket.socket, box: Box, peer_label: str, metadata: ChannelMetadata) -> None:
        self._sock = sock_obj
        self._box = box
        self._peer_label = peer_label
        self.metadata = metadata
        self._send_lock = threading.Lock()

    def send(self, header: dict[str, Any], payload: bytes = b"") -> None:
        plain_packet = pack_logical_packet(header, payload)
        encrypted_packet = bytes(self._box.encrypt(plain_packet))

        with self._send_lock:
            raw_send_packet(self._sock, {"type": "secure"}, encrypted_packet)

        logger.debug("encrypted packet sent to %s: %s", self._peer_label, packet_summary(header, payload))
        logger.debug("ciphertext preview: %s", preview_bytes(encrypted_packet))

    def recv(self) -> tuple[dict[str, Any], bytes] | tuple[None, None]:
        outer_header, encrypted_packet = raw_recv_packet(self._sock)
        if outer_header is None:
            return None, None

        if outer_header.get("type") != "secure":
            raise ProtocolError("outer packet is not encrypted")

        try:
            plain_packet = self._box.decrypt(encrypted_packet)
        except CryptoError as exc:
            raise ProtocolError("failed to decrypt packet") from exc

        packet = unpack_logical_packet(plain_packet)
        logger.debug("encrypted packet received from %s: %s", self._peer_label, packet_summary(packet.header, packet.payload))
        return packet.header, packet.payload

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def preview_bytes(data: bytes, limit: int = 120) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    if len(encoded) > limit:
        return encoded[:limit] + "..."
    return encoded


def create_client_channel(sock_obj: socket.socket) -> SecureChannel:
    """Create a SecureChannel from the client side."""
    client_private_key = PrivateKey.generate()
    client_public_key = client_private_key.public_key.encode(encoder=Base64Encoder).decode("utf-8")

    header, _ = raw_recv_packet(sock_obj, max_payload_size=0)
    if header is None or header.get("type") != "server_public_key":
        raise KeyExchangeError("server public key packet is required")

    try:
        server_public_key = PublicKey(str(header.get("public_key", "")).encode("utf-8"), encoder=Base64Encoder)
    except Exception as exc:
        raise KeyExchangeError("server public key is invalid") from exc

    raw_send_packet(sock_obj, {"type": "client_public_key", "public_key": client_public_key})

    local_fingerprint = public_key_fingerprint(client_public_key)
    peer_fingerprint = public_key_fingerprint(str(header.get("public_key", "")))
    metadata = ChannelMetadata(
        cipher="PyNaCl Box (Curve25519 XSalsa20-Poly1305)",
        local_public_key=client_public_key,
        peer_public_key=str(header.get("public_key", "")),
        local_fingerprint=local_fingerprint,
        peer_fingerprint=peer_fingerprint,
        session_id=session_id_from_fingerprints(local_fingerprint, peer_fingerprint),
    )

    logger.info("key exchange complete: client private key + server public key / session=%s", metadata.session_id)
    return SecureChannel(sock_obj, Box(client_private_key, server_public_key), "server", metadata)


def create_server_channel(client_sock: socket.socket) -> SecureChannel:
    """Create a SecureChannel from the server side."""
    server_private_key = PrivateKey.generate()
    server_public_key = server_private_key.public_key.encode(encoder=Base64Encoder).decode("utf-8")

    raw_send_packet(client_sock, {"type": "server_public_key", "public_key": server_public_key})

    header, _ = raw_recv_packet(client_sock, max_payload_size=0)
    if header is None or header.get("type") != "client_public_key":
        raise KeyExchangeError("client public key packet is required")

    try:
        client_public_key = PublicKey(str(header.get("public_key", "")).encode("utf-8"), encoder=Base64Encoder)
    except Exception as exc:
        raise KeyExchangeError("client public key is invalid") from exc

    local_fingerprint = public_key_fingerprint(server_public_key)
    peer_fingerprint = public_key_fingerprint(str(header.get("public_key", "")))
    metadata = ChannelMetadata(
        cipher="PyNaCl Box (Curve25519 XSalsa20-Poly1305)",
        local_public_key=server_public_key,
        peer_public_key=str(header.get("public_key", "")),
        local_fingerprint=local_fingerprint,
        peer_fingerprint=peer_fingerprint,
        session_id=session_id_from_fingerprints(local_fingerprint, peer_fingerprint),
    )

    logger.info("key exchange complete: server private key + client public key / session=%s", metadata.session_id)
    return SecureChannel(client_sock, Box(server_private_key, client_public_key), "client", metadata)
