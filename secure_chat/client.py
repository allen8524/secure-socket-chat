"""Network client used by the GUI."""

from __future__ import annotations

import logging
import queue
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT, MAX_PAYLOAD_SIZE
from secure_chat.crypto_channel import PacketSequenceError, ReplayAttackError, SecureChannel, create_client_channel
from secure_chat.packet_inspector import PacketInspectionEvent
from secure_chat.security import ChannelMetadata, sha256_hex
from secure_chat.trust_store import TrustCheckResult, check_server_fingerprint, trust_server_fingerprint

logger = logging.getLogger(__name__)


class ServerTrustError(RuntimeError):
    """Raised when TOFU server fingerprint verification blocks a connection."""


class ChatClient:
    """Encrypted chat client connection."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        username: str = "",
        trust_store_path: str | Path | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username.strip()
        self.trust_store_path = trust_store_path
        self.inbox: queue.Queue[tuple[dict[str, Any], bytes]] = queue.Queue()
        self.packet_events: queue.Queue[PacketInspectionEvent] = queue.Queue()
        self._sock: socket.socket | None = None
        self._channel: SecureChannel | None = None
        self._trust_check_result: TrustCheckResult | None = None
        self._running = threading.Event()
        self._receiver_thread: threading.Thread | None = None
        self.connected_at: datetime | None = None
        self._sent_packet_count = 0
        self._received_packet_count = 0
        self._last_received_message_type = "-"

    @property
    def connected(self) -> bool:
        return self._channel is not None and self._running.is_set()

    @property
    def security_metadata(self) -> ChannelMetadata | None:
        if self._channel is None:
            return None
        return self._channel.metadata

    @property
    def trust_check_result(self) -> TrustCheckResult | None:
        return self._trust_check_result

    @property
    def server_trust_status(self) -> str:
        if self._trust_check_result is None:
            return "Unknown"
        return self._trust_check_result.status

    @property
    def tofu_verification(self) -> str:
        if self._trust_check_result is None:
            return "Unknown"
        return self._trust_check_result.verification

    @property
    def sent_packet_count(self) -> int:
        return self._sent_packet_count

    @property
    def received_packet_count(self) -> int:
        return self._received_packet_count

    @property
    def last_received_message_type(self) -> str:
        return self._last_received_message_type

    @property
    def send_sequence(self) -> int:
        if self._channel is None:
            return 0
        return self._channel.send_sequence

    @property
    def receive_sequence(self) -> int:
        if self._channel is None:
            return 0
        return self._channel.receive_sequence

    @property
    def last_replay_status(self) -> str:
        if self._channel is None:
            return "Not checked"
        return self._channel.last_replay_status

    def security_report(self) -> str:
        metadata = self.security_metadata
        if metadata is None:
            return "보안 세션 정보가 없습니다."
        connection_state = "Connected" if self.connected else "Disconnected"
        encryption_state = "Active" if self.connected else "Inactive"
        return (
            f"connection={connection_state} | "
            f"encryption={encryption_state} | "
            f"cipher={metadata.cipher} | "
            f"session={metadata.session_id} | "
            f"client_fp={metadata.local_fingerprint} | "
            f"server_fp={metadata.peer_fingerprint} | "
            f"sent_packets={self._sent_packet_count} | "
            f"received_packets={self._received_packet_count} | "
            f"send_sequence={self.send_sequence} | "
            f"receive_sequence={self.receive_sequence} | "
            f"replay={self.last_replay_status} | "
            f"server_trust={self.server_trust_status} | "
            f"tofu={self.tofu_verification} | "
            f"last_received={self._last_received_message_type}"
        )

    def connect(self, trust_decider: Callable[[TrustCheckResult], bool] | None = None) -> None:
        if not self.username:
            raise ValueError("username is required")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.host, self.port))
        self._sent_packet_count = 0
        self._received_packet_count = 0
        self._last_received_message_type = "-"
        self._channel = create_client_channel(self._sock, inspection_callback=self.packet_events.put)
        self._verify_server_trust(trust_decider)
        self.connected_at = datetime.now()
        self._send({"type": "join", "username": self.username})

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
        self._sent_packet_count += 1

    def _verify_server_trust(self, trust_decider: Callable[[TrustCheckResult], bool] | None) -> None:
        metadata = self.security_metadata
        if metadata is None:
            raise ServerTrustError("서버 fingerprint를 확인할 수 없습니다.")

        result = check_server_fingerprint(
            self.host,
            self.port,
            metadata.peer_fingerprint,
            path=self.trust_store_path,
        )

        if result.status == "Changed":
            accepted = bool(trust_decider(result)) if trust_decider is not None else False
            if not accepted:
                self._trust_check_result = result
                self.close()
                raise ServerTrustError("서버 fingerprint 변경이 감지되어 연결을 중단했습니다.")

            stored = trust_server_fingerprint(
                self.host,
                self.port,
                metadata.peer_fingerprint,
                path=self.trust_store_path,
            )
            self._trust_check_result = TrustCheckResult(
                host=result.host,
                port=result.port,
                server_id=result.server_id,
                fingerprint=result.fingerprint,
                status="Changed",
                verification="Warning",
                stored_fingerprint=stored.stored_fingerprint,
                first_seen=stored.first_seen,
                last_seen=stored.last_seen,
                trust_mode=stored.trust_mode,
                accepted=True,
                message="server fingerprint changed and was accepted",
            )
            return

        if result.status == "New":
            stored = trust_server_fingerprint(
                self.host,
                self.port,
                metadata.peer_fingerprint,
                path=self.trust_store_path,
            )
            self._trust_check_result = TrustCheckResult(
                host=result.host,
                port=result.port,
                server_id=result.server_id,
                fingerprint=result.fingerprint,
                status="New",
                verification="Not registered",
                stored_fingerprint=stored.stored_fingerprint,
                first_seen=stored.first_seen,
                last_seen=stored.last_seen,
                trust_mode=stored.trust_mode,
                accepted=True,
                message="new server fingerprint stored",
            )
            return

        if result.status == "Trusted":
            self._trust_check_result = trust_server_fingerprint(
                self.host,
                self.port,
                metadata.peer_fingerprint,
                path=self.trust_store_path,
            )
            return

        self._trust_check_result = result

    def _receive_loop(self) -> None:
        while self._running.is_set() and self._channel is not None:
            try:
                header, payload = self._channel.recv()
                if header is None:
                    self.inbox.put(({"type": "system", "text": "서버와 연결이 종료되었습니다."}, b""))
                    break
                self._received_packet_count += 1
                self._last_received_message_type = str(header.get("type", "unknown"))
                self.inbox.put((header, payload))
            except ReplayAttackError:
                self.inbox.put(({"type": "security_warning", "text": "replay 의심 패킷 차단"}, b""))
                continue
            except PacketSequenceError:
                self.inbox.put(({"type": "security_warning", "text": "비정상 sequence 패킷 차단"}, b""))
                continue
            except OSError:
                break
            except Exception as exc:
                self.inbox.put(({"type": "error", "text": str(exc)}, b""))
                break

        self._running.clear()
