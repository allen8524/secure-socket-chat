"""Network client used by the GUI."""

from __future__ import annotations

import logging
import queue
import socket
import threading
from pathlib import Path
from typing import Any

from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT, MAX_PAYLOAD_SIZE
from secure_chat.crypto_channel import SecureChannel, create_client_channel
from secure_chat.security import ChannelMetadata, sha256_hex

logger = logging.getLogger(__name__)


class ChatClient:
    """Encrypted chat client connection."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, username: str = "") -> None:
        self.host = host
        self.port = port
        self.username = username.strip()
        self.inbox: queue.Queue[tuple[dict[str, Any], bytes]] = queue.Queue()
        self._sock: socket.socket | None = None
        self._channel: SecureChannel | None = None
        self._running = threading.Event()
        self._receiver_thread: threading.Thread | None = None

    @property
    def connected(self) -> bool:
        return self._channel is not None and self._running.is_set()

    @property
    def security_metadata(self) -> ChannelMetadata | None:
        if self._channel is None:
            return None
        return self._channel.metadata

    def security_report(self) -> str:
        metadata = self.security_metadata
        if metadata is None:
            return "보안 세션 정보가 없습니다."
        return (
            f"cipher={metadata.cipher} | "
            f"session={metadata.session_id} | "
            f"client_fp={metadata.local_fingerprint} | "
            f"server_fp={metadata.peer_fingerprint}"
        )

    def connect(self) -> None:
        if not self.username:
            raise ValueError("username is required")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.host, self.port))
        self._channel = create_client_channel(self._sock)
        self._channel.send({"type": "join", "username": self.username})

        self._running.set()
        self._receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver_thread.start()
        logger.info("connected to %s:%s as %s", self.host, self.port, self.username)

    def send_chat(self, text: str) -> None:
        self._send({"type": "chat", "text": text})

    def send_whisper(self, target: str, text: str) -> None:
        self._send({"type": "whisper", "to": target, "text": text})

    def send_image(self, target: str, file_path: str | Path) -> str:
        path = Path(file_path)
        if path.stat().st_size > MAX_PAYLOAD_SIZE:
            raise ValueError("이미지는 10MB 이하만 전송할 수 있습니다.")

        payload = path.read_bytes()
        digest = sha256_hex(payload)
        self._send(
            {
                "type": "image",
                "to": target,
                "filename": path.name,
                "file_size": len(payload),
                "sha256": digest,
            },
            payload,
        )
        return digest

    def request_stats(self) -> None:
        self._send({"type": "stats"})

    def leave(self) -> None:
        if self.connected:
            try:
                self._send({"type": "leave", "text": "end"})
            except OSError:
                pass
        self.close()

    def close(self) -> None:
        self._running.clear()
        if self._channel is not None:
            self._channel.close()
        self._channel = None
        self._sock = None

    def _send(self, header: dict[str, Any], payload: bytes = b"") -> None:
        if self._channel is None:
            raise OSError("not connected")
        self._channel.send(header, payload)

    def _receive_loop(self) -> None:
        while self._running.is_set() and self._channel is not None:
            try:
                header, payload = self._channel.recv()
                if header is None:
                    self.inbox.put(({"type": "system", "text": "서버와 연결이 종료되었습니다."}, b""))
                    break
                self.inbox.put((header, payload))
            except OSError:
                break
            except Exception as exc:
                self.inbox.put(({"type": "error", "text": str(exc)}, b""))
                break

        self._running.clear()
