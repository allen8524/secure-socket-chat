import socket
import threading

import pytest

pytest.importorskip("nacl")

from secure_chat.crypto_channel import (
    PacketSequenceError,
    ReplayAttackError,
    create_client_channel,
    create_server_channel,
)
from secure_chat.protocol import pack_logical_packet, raw_recv_packet, raw_send_packet


def _create_channels(client_events=None, server_events=None):
    client_sock, server_sock = socket.socketpair()
    created = {}

    def create_server():
        created["server"] = create_server_channel(server_sock, inspection_callback=server_events.append if server_events is not None else None)

    server_thread = threading.Thread(target=create_server)
    server_thread.start()
    client_channel = create_client_channel(client_sock, inspection_callback=client_events.append if client_events is not None else None)
    server_thread.join(timeout=2)

    return client_channel, created["server"], client_sock, server_sock


def _close_channels(client_channel, server_channel):
    client_channel.close()
    server_channel.close()


def test_secure_channel_adds_increasing_sequence_numbers():
    client_channel, server_channel, _, _ = _create_channels()

    try:
        client_channel.send({"type": "chat", "text": "one"})
        header, _ = server_channel.recv()
        assert header["sequence"] == 1

        client_channel.send({"type": "chat", "text": "two"})
        header, _ = server_channel.recv()
        assert header["sequence"] == 2

        assert client_channel.send_sequence == 2
        assert server_channel.receive_sequence == 2
        assert server_channel.last_replay_status == "OK sequence=2"
    finally:
        _close_channels(client_channel, server_channel)


def test_secure_channel_rejects_duplicate_sequence_replay():
    server_events = []
    client_channel, server_channel, client_sock, server_sock = _create_channels(server_events=server_events)

    try:
        client_channel.send({"type": "chat", "text": "hello"})
        _, encrypted_packet = raw_recv_packet(server_sock)

        raw_send_packet(client_sock, {"type": "secure"}, encrypted_packet)
        header, _ = server_channel.recv()
        assert header["sequence"] == 1

        raw_send_packet(client_sock, {"type": "secure"}, encrypted_packet)
        with pytest.raises(ReplayAttackError):
            server_channel.recv()

        assert server_channel.receive_sequence == 1
        assert server_channel.last_replay_status == "Replay blocked sequence=1 last=1"
        assert server_events[-1].blocked is True
        assert server_events[-1].replay_status == "Replay blocked sequence=1 last=1"
    finally:
        _close_channels(client_channel, server_channel)


def test_secure_channel_rejects_decreasing_sequence():
    client_channel, server_channel, client_sock, server_sock = _create_channels()

    try:
        client_channel.send({"type": "chat", "text": "first"})
        _, encrypted_first = raw_recv_packet(server_sock)
        client_channel.send({"type": "chat", "text": "second"})
        _, encrypted_second = raw_recv_packet(server_sock)

        raw_send_packet(client_sock, {"type": "secure"}, encrypted_second)
        header, _ = server_channel.recv()
        assert header["sequence"] == 2

        raw_send_packet(client_sock, {"type": "secure"}, encrypted_first)
        with pytest.raises(ReplayAttackError):
            server_channel.recv()

        assert server_channel.receive_sequence == 2
        assert server_channel.last_replay_status == "Replay blocked sequence=1 last=2"
    finally:
        _close_channels(client_channel, server_channel)


def test_secure_channel_rejects_missing_sequence():
    client_channel, server_channel, client_sock, _ = _create_channels()

    try:
        encrypted_packet = bytes(server_channel._box.encrypt(pack_logical_packet({"type": "chat", "text": "hello"})))
        raw_send_packet(client_sock, {"type": "secure"}, encrypted_packet)

        with pytest.raises(PacketSequenceError):
            server_channel.recv()

        assert server_channel.receive_sequence == 0
        assert server_channel.last_replay_status == "Invalid sequence"
    finally:
        _close_channels(client_channel, server_channel)


def test_secure_channel_rejects_non_integer_sequence():
    client_channel, server_channel, client_sock, _ = _create_channels()

    try:
        encrypted_packet = bytes(
            server_channel._box.encrypt(pack_logical_packet({"type": "chat", "text": "hello", "sequence": "1"}))
        )
        raw_send_packet(client_sock, {"type": "secure"}, encrypted_packet)

        with pytest.raises(PacketSequenceError):
            server_channel.recv()

        assert server_channel.receive_sequence == 0
        assert server_channel.last_replay_status == "Invalid sequence"
    finally:
        _close_channels(client_channel, server_channel)
