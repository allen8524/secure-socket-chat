import queue
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from secure_chat.client import ChatClient
from secure_chat.server import ChatServer


def unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until(predicate: Callable[[], bool], timeout: float = 3.0, interval: float = 0.02) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def wait_for_message(
    client: ChatClient,
    predicate: Callable[[dict, bytes], bool],
    timeout: float = 3.0,
) -> tuple[dict, bytes]:
    deadline = time.time() + timeout
    seen: list[str] = []

    while time.time() < deadline:
        try:
            header, payload = client.inbox.get(timeout=0.1)
        except queue.Empty:
            continue

        seen.append(str(header.get("type", "unknown")))
        if predicate(header, payload):
            return header, payload

    raise AssertionError(f"timed out waiting for message; seen types={seen}")


@dataclass
class RunningServer:
    host: str
    port: int
    server: ChatServer
    thread: threading.Thread

    def stop(self) -> None:
        self.server.stop()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), "server thread did not stop cleanly"


@pytest.fixture
def running_server():
    host = "127.0.0.1"
    port = unused_tcp_port()
    server = ChatServer(host, port)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()

    assert wait_until(lambda: server._server_sock is not None), "server did not start"
    running = RunningServer(host=host, port=port, server=server, thread=thread)
    try:
        yield running
    finally:
        running.stop()


@pytest.fixture
def client_factory(running_server, tmp_path):
    clients: list[ChatClient] = []
    trust_store_path = Path(tmp_path) / "trusted_servers.json"

    def connect(username: str) -> ChatClient:
        client = ChatClient(
            running_server.host,
            running_server.port,
            username,
            trust_store_path=trust_store_path,
        )
        client.connect(trust_decider=lambda _result: True)
        clients.append(client)
        return client

    try:
        yield connect
    finally:
        for client in clients:
            client.leave()
