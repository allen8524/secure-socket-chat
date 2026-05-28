import queue
import socket

import pytest

from demo import build_demo_steps, create_demo_file, is_port_available, wait_for_message


class FakeClient:
    def __init__(self):
        self.inbox = queue.Queue()


def test_build_demo_steps_contains_core_flow():
    steps = build_demo_steps()

    assert "서버 시작" in steps
    assert "전체 메시지 전송 및 수신 확인" in steps
    assert "샘플 파일 전송 및 SHA-256 검증" in steps


def test_create_demo_file_writes_sample_payload(tmp_path):
    path = create_demo_file(tmp_path)

    assert path.exists()
    assert "SecureSocketChat demo file" in path.read_text(encoding="utf-8")


def test_is_port_available_detects_bound_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        assert not is_port_available("127.0.0.1", port)


def test_wait_for_message_returns_matching_message():
    client = FakeClient()
    client.inbox.put(({"type": "system"}, b""))
    client.inbox.put(({"type": "chat", "from": "alice"}, b""))

    header, payload = wait_for_message(client, lambda item, _: item.get("type") == "chat", timeout=0.5)

    assert header["from"] == "alice"
    assert payload == b""


def test_wait_for_message_times_out_with_clear_error():
    client = FakeClient()
    client.inbox.put(({"type": "error", "text": "sample failure"}, b""))

    with pytest.raises(TimeoutError, match="sample failure"):
        wait_for_message(client, lambda item, _: item.get("type") == "chat", timeout=0.1)
