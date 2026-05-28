"""Threaded chat server."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Iterable

from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT, SOCKET_TIMEOUT_SECONDS
from secure_chat.crypto_channel import PacketSequenceError, ReplayAttackError, SecureChannel, create_server_channel
from secure_chat.file_transfer import file_extension, guess_mime_type
from secure_chat.protocol import ProtocolError
from secure_chat.utils import safe_filename

logger = logging.getLogger(__name__)


class ChatServer:
    """Multi-client encrypted chat server."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self._clients: dict[str, SecureChannel] = {}
        self._clients_lock = threading.Lock()
        self._started_at = time.time()
        self._total_messages = 0
        self._total_images = 0
        self._total_image_bytes = 0
        self._total_files = 0
        self._total_file_bytes = 0
        self._stats_lock = threading.Lock()
        self._server_sock: socket.socket | None = None
        self._running = threading.Event()

    def start(self) -> None:
        self._running.set()
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen()
        self._server_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        self._started_at = time.time()
        logger.info("chat server started on %s:%s", self.host, self.port)
        logger.info("encryption: PyNaCl PrivateKey/PublicKey + Box")

        try:
            while self._running.is_set():
                try:
                    client_sock, addr = self._server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self._running.is_set():
                        break
                    raise

                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                client_thread.start()
        finally:
            self.stop()

    def stop(self) -> None:
        self._running.clear()

        for channel in self._get_channels_snapshot():
            channel.close()

        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        logger.info("chat server stopped")

    def _get_clients_snapshot(self) -> dict[str, SecureChannel]:
        with self._clients_lock:
            return dict(self._clients)

    def _get_channels_snapshot(self) -> Iterable[SecureChannel]:
        return self._get_clients_snapshot().values()

    def _send_to(self, username: str, header: dict, payload: bytes = b"") -> bool:
        with self._clients_lock:
            target_channel = self._clients.get(username)

        if target_channel is None:
            return False

        try:
            target_channel.send(header, payload)
            return True
        except OSError:
            self._remove_user(username)
            return False

    def _broadcast(self, header: dict, payload: bytes = b"") -> None:
        current_clients = self._get_clients_snapshot()
        for username, channel in current_clients.items():
            try:
                channel.send(header, payload)
            except OSError:
                self._remove_user(username)

    def _broadcast_user_list(self) -> None:
        with self._clients_lock:
            usernames = sorted(self._clients.keys())
        self._broadcast({"type": "users", "users": usernames})

    def _add_user(self, username: str, channel: SecureChannel) -> bool:
        normalized_username = username.strip()

        if not normalized_username:
            channel.send({"type": "error", "text": "이름을 입력해야 합니다."})
            return False

        with self._clients_lock:
            if normalized_username in self._clients:
                channel.send({"type": "error", "text": "이미 사용 중인 이름입니다."})
                return False
            self._clients[normalized_username] = channel

        channel.send({"type": "system", "text": f"{normalized_username}님 접속 완료"})
        self._broadcast({"type": "system", "text": f"{normalized_username}님이 입장했습니다."})
        self._broadcast_user_list()
        logger.info("user joined: %s / online=%s", normalized_username, len(self._get_clients_snapshot()))
        return True

    def _remove_user(self, username: str) -> None:
        removed_channel = None

        with self._clients_lock:
            removed_channel = self._clients.pop(username, None)

        if removed_channel is None:
            return

        removed_channel.close()
        self._broadcast({"type": "system", "text": f"{username}님이 퇴장했습니다."})
        self._broadcast_user_list()
        logger.info("user left: %s / online=%s", username, len(self._get_clients_snapshot()))

    def _handle_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        username: str | None = None
        channel: SecureChannel | None = None
        logger.info("connection requested from %s", addr)

        try:
            channel = create_server_channel(client_sock)

            header, payload = channel.recv()
            if header is None or header.get("type") != "join":
                channel.send({"type": "error", "text": "join 요청이 필요합니다."})
                return

            username = str(header.get("username", "")).strip()
            if not self._add_user(username, channel):
                return

            while self._running.is_set():
                header, payload = channel.recv()
                if header is None:
                    break

                msg_type = header.get("type")

                if msg_type == "leave" or header.get("text") == "end":
                    break
                if msg_type == "chat":
                    self._handle_chat(username, header)
                elif msg_type == "whisper":
                    self._handle_whisper(username, header)
                elif msg_type == "image":
                    self._handle_image(username, header, payload)
                elif msg_type == "file":
                    self._handle_file(username, header, payload)
                elif msg_type == "stats":
                    self._handle_stats(username)
                else:
                    self._send_to(username, {"type": "error", "text": "알 수 없는 요청입니다."})

        except (ConnectionResetError, ConnectionAbortedError, OSError):
            logger.info("connection closed by peer: %s", addr)
        except ReplayAttackError as exc:
            logger.warning("replay suspected from %s: %s", addr, exc)
            if channel is not None:
                self._safe_send(channel, {"type": "error", "text": "replay 의심 패킷이 차단되었습니다."})
        except PacketSequenceError as exc:
            logger.warning("invalid sequence from %s: %s", addr, exc)
            if channel is not None:
                self._safe_send(channel, {"type": "error", "text": "비정상 sequence 패킷이 차단되었습니다."})
        except ProtocolError as exc:
            logger.warning("protocol error from %s: %s", addr, exc)
            if channel is not None:
                self._safe_send(channel, {"type": "error", "text": str(exc)})
        except Exception as exc:
            logger.exception("unexpected client error from %s", addr)
            if channel is not None:
                self._safe_send(channel, {"type": "error", "text": str(exc)})
        finally:
            if username:
                self._remove_user(username)
            elif channel is not None:
                channel.close()
            else:
                try:
                    client_sock.close()
                except OSError:
                    pass

    def _safe_send(self, channel: SecureChannel, header: dict, payload: bytes = b"") -> None:
        try:
            channel.send(header, payload)
        except OSError:
            pass

    def _handle_chat(self, username: str, header: dict) -> None:
        text = str(header.get("text", ""))
        if not text.strip():
            return

        self._record_message()
        logger.info("chat: %s", username)
        self._broadcast({"type": "chat", "from": username, "text": text})

    def _handle_whisper(self, username: str, header: dict) -> None:
        target = str(header.get("to", "")).strip()
        text = str(header.get("text", ""))

        if not target or not text.strip():
            self._send_to(username, {"type": "error", "text": "귓속말 대상과 내용을 입력해야 합니다."})
            return

        if target not in self._get_clients_snapshot():
            self._send_to(username, {"type": "error", "text": f"{target} 사용자를 찾을 수 없습니다."})
            return

        self._record_message()
        packet = {"type": "whisper", "from": username, "to": target, "text": text}
        self._send_to(target, packet)
        if target != username:
            self._send_to(username, packet)
        logger.info("whisper: %s -> %s", username, target)

    def _handle_image(self, username: str, header: dict, payload: bytes) -> None:
        target = str(header.get("to", "전체")).strip() or "전체"
        filename = safe_filename(str(header.get("filename", "image.bin")))

        if not payload:
            self._send_to(username, {"type": "error", "text": "이미지 데이터가 비어 있습니다."})
            return

        self._record_image(len(payload))
        packet = {
            "type": "image",
            "from": username,
            "to": target,
            "filename": filename,
            "file_size": len(payload),
            "sha256": str(header.get("sha256", "")),
        }

        if target == "전체":
            self._broadcast(packet, payload)
            logger.info("image broadcast: %s / %s bytes", username, len(payload))
            return

        if target not in self._get_clients_snapshot():
            self._send_to(username, {"type": "error", "text": f"{target} 사용자를 찾을 수 없습니다."})
            return

        self._send_to(target, packet, payload)
        if target != username:
            self._send_to(username, packet, payload)
        logger.info("image whisper: %s -> %s / %s bytes", username, target, len(payload))

    def _handle_file(self, username: str, header: dict, payload: bytes) -> None:
        target = str(header.get("to", "전체")).strip() or "전체"
        filename = safe_filename(str(header.get("filename", "file.bin")), fallback="file.bin")

        if not payload:
            self._send_to(username, {"type": "error", "text": "파일 데이터가 비어 있습니다."})
            return

        self._record_file(len(payload))
        packet = {
            "type": "file",
            "from": username,
            "to": target,
            "filename": filename,
            "file_size": len(payload),
            "sha256": str(header.get("sha256", "")),
            "mime_type": str(header.get("mime_type", "")) or guess_mime_type(filename),
            "extension": str(header.get("extension", "")) or file_extension(filename),
        }
        hash_preview = packet["sha256"][:16] if packet["sha256"] else "-"

        if target == "전체":
            self._broadcast(packet, payload)
            logger.info("file broadcast: %s / %s / %s bytes / sha256=%s", username, filename, len(payload), hash_preview)
            return

        if target not in self._get_clients_snapshot():
            self._send_to(username, {"type": "error", "text": f"{target} 사용자를 찾을 수 없습니다."})
            return

        self._send_to(target, packet, payload)
        if target != username:
            self._send_to(username, packet, payload)
        logger.info(
            "file whisper: %s -> %s / %s / %s bytes / sha256=%s",
            username,
            target,
            filename,
            len(payload),
            hash_preview,
        )

    def _record_message(self) -> None:
        with self._stats_lock:
            self._total_messages += 1

    def _record_image(self, byte_count: int) -> None:
        with self._stats_lock:
            self._total_images += 1
            self._total_image_bytes += byte_count

    def _record_file(self, byte_count: int) -> None:
        with self._stats_lock:
            self._total_files += 1
            self._total_file_bytes += byte_count

    def _handle_stats(self, username: str) -> None:
        with self._clients_lock:
            online_users = sorted(self._clients.keys())
        with self._stats_lock:
            total_messages = self._total_messages
            total_images = self._total_images
            total_image_bytes = self._total_image_bytes
            total_files = self._total_files
            total_file_bytes = self._total_file_bytes

        uptime_seconds = int(time.time() - self._started_at)
        self._send_to(
            username,
            {
                "type": "stats",
                "uptime_seconds": uptime_seconds,
                "online_count": len(online_users),
                "online_users": online_users,
                "total_messages": total_messages,
                "total_images": total_images,
                "total_image_bytes": total_image_bytes,
                "total_files": total_files,
                "total_file_bytes": total_file_bytes,
            },
        )
