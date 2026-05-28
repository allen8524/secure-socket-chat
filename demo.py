from __future__ import annotations

import argparse
import logging
import queue
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from secure_chat.client import ChatClient
from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT
from secure_chat.file_transfer import calculate_sha256, format_file_size, verify_file_hash
from secure_chat.logging_config import configure_logging
from secure_chat.server import ChatServer
from secure_chat.trust_store import TrustCheckResult


def build_demo_steps() -> list[str]:
    return [
        "서버 시작",
        "alice 클라이언트 연결",
        "bob 클라이언트 연결",
        "전체 메시지 전송 및 수신 확인",
        "귓속말 전송 및 수신 확인",
        "샘플 파일 전송 및 SHA-256 검증",
        "서버 통계 요청",
        "연결 종료",
    ]


def create_demo_file(directory: Path) -> Path:
    path = directory / "secure_socket_chat_demo.txt"
    path.write_text(
        "SecureSocketChat demo file\n"
        "This file is used to verify SHA-256 protected file transfer.\n",
        encoding="utf-8",
    )
    return path


def is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def wait_until(predicate: Callable[[], bool], timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def wait_for_message(
    client: ChatClient,
    predicate: Callable[[dict, bytes], bool],
    timeout: float = 5.0,
) -> tuple[dict, bytes]:
    deadline = time.time() + timeout
    last_error: str | None = None

    while time.time() < deadline:
        try:
            header, payload = client.inbox.get(timeout=0.1)
        except queue.Empty:
            continue

        if header.get("type") == "error":
            last_error = str(header.get("text", ""))

        if predicate(header, payload):
            return header, payload

    suffix = f" last_error={last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for demo message.{suffix}")


def accept_changed_fingerprint(result: TrustCheckResult) -> bool:
    print(
        "   TOFU 경고: 저장된 서버 fingerprint와 현재 fingerprint가 다릅니다. "
        "데모에서는 변경된 fingerprint를 신뢰하고 계속합니다."
    )
    print(f"   stored={result.stored_fingerprint or '-'} current={result.fingerprint}")
    return True


def start_demo_server(host: str, port: int) -> tuple[ChatServer, threading.Thread]:
    if not is_port_available(host, port):
        raise OSError(f"{host}:{port} 포트를 사용할 수 없습니다. 이미 서버가 실행 중인지 확인하세요.")

    server = ChatServer(host, port)
    thread = threading.Thread(target=server.start, name="secure-chat-demo-server", daemon=True)
    thread.start()

    if not wait_until(lambda: server._server_sock is not None, timeout=3.0):
        server.stop()
        raise RuntimeError("서버 시작 대기 시간이 초과되었습니다.")

    return server, thread


def run_demo(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> int:
    print("Secure Socket Chat Demo")

    server: ChatServer | None = None
    server_thread: threading.Thread | None = None
    alice: ChatClient | None = None
    bob: ChatClient | None = None

    with tempfile.TemporaryDirectory(prefix="secure_socket_chat_demo_") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        trust_store_path = temp_dir / "trusted_servers.json"
        sample_file = create_demo_file(temp_dir)

        try:
            server, server_thread = start_demo_server(host, port)
            print(f"1. 서버 시작: {host}:{port}")

            alice = ChatClient(host, port, "alice", trust_store_path=trust_store_path)
            alice.connect()
            print(
                "2. alice 클라이언트 연결 완료 "
                f"(session={alice.security_metadata.session_id}, TOFU={alice.tofu_verification})"
            )

            bob = ChatClient(host, port, "bob", trust_store_path=trust_store_path)
            bob.connect(trust_decider=accept_changed_fingerprint)
            print(
                "3. bob 클라이언트 연결 완료 "
                f"(session={bob.security_metadata.session_id}, TOFU={bob.tofu_verification})"
            )

            alice.send_chat("hello from demo")
            wait_for_message(bob, lambda header, _: header.get("type") == "chat" and header.get("from") == "alice")
            print(f"4. alice -> 전체 메시지 전송 완료 (alice sequence={alice.send_sequence})")

            alice.send_whisper("bob", "secret hello from demo")
            wait_for_message(
                bob,
                lambda header, _: header.get("type") == "whisper"
                and header.get("from") == "alice"
                and header.get("to") == "bob",
            )
            print(f"5. alice -> bob 귓속말 전송 완료 (alice sequence={alice.send_sequence})")

            expected_digest = calculate_sha256(sample_file.read_bytes())
            alice.send_file("bob", sample_file)
            file_header, file_payload = wait_for_message(
                bob,
                lambda header, _: header.get("type") == "file" and header.get("from") == "alice",
            )
            integrity_ok = verify_file_hash(file_payload, str(file_header.get("sha256", "")))
            if not integrity_ok:
                raise RuntimeError("파일 SHA-256 무결성 검증 실패")

            print(
                "6. 샘플 파일 전송 완료 "
                f"({file_header.get('filename')}, {format_file_size(len(file_payload))})"
            )
            print(f"7. SHA-256 무결성 검증 OK ({expected_digest[:16]})")

            alice.request_stats()
            stats_header, _ = wait_for_message(alice, lambda header, _: header.get("type") == "stats")
            print(
                "8. 서버 통계 확인 완료 "
                f"(online={stats_header.get('online_count')}, "
                f"messages={stats_header.get('total_messages')}, "
                f"files={stats_header.get('total_files')})"
            )

            print(
                "   Security summary: "
                f"alice sent_seq={alice.send_sequence}, recv_seq={alice.receive_sequence}; "
                f"bob sent_seq={bob.send_sequence}, recv_seq={bob.receive_sequence}"
            )
            print("9. 데모 종료")
            return 0
        finally:
            if alice is not None:
                alice.leave()
            if bob is not None:
                bob.leave()
            if server is not None:
                server.stop()
            if server_thread is not None:
                server_thread.join(timeout=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SecureSocketChat CLI demo scenario.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="server port")
    parser.add_argument("--dry-run", action="store_true", help="print the demo scenario without opening sockets")
    parser.add_argument("--verbose", action="store_true", help="enable debug logs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(verbose=args.verbose)
    if not args.verbose:
        logging.getLogger().setLevel(logging.WARNING)

    if args.dry_run:
        print("Secure Socket Chat Demo")
        for index, step in enumerate(build_demo_steps(), start=1):
            print(f"{index}. {step}")
        return 0

    try:
        return run_demo(args.host, args.port)
    except Exception as exc:
        print(f"데모 실행 실패: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
