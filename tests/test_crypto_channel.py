import socket
import threading

import pytest

pytest.importorskip("nacl")

from secure_chat.crypto_channel import create_client_channel, create_server_channel


def test_secure_channel_encrypts_and_decrypts_between_socket_pair():
    client_sock, server_sock = socket.socketpair()
    created = {}

    def create_server():
        created["server"] = create_server_channel(server_sock)

    inspection_events = []
    server_thread = threading.Thread(target=create_server)
    server_thread.start()
    client_channel = create_client_channel(client_sock, inspection_callback=inspection_events.append)
    server_thread.join(timeout=2)

    server_channel = created["server"]
    client_channel.send({"type": "chat", "text": "hello"})
    header, payload = server_channel.recv()

    assert header["type"] == "chat"
    assert header["text"] == "hello"
    assert payload == b""

    server_channel.send({"type": "system", "text": "ok"})
    header, payload = client_channel.recv()

    assert header["type"] == "system"
    assert header["text"] == "ok"
    assert payload == b""

    assert inspection_events[0].direction == "OUTBOUND"
    assert inspection_events[0].logical_type == "chat"
    assert inspection_events[0].encrypted_packet_size > 0
    assert inspection_events[0].ciphertext_preview != "-"
    assert inspection_events[1].direction == "INBOUND"
    assert inspection_events[1].logical_type == "system"
    assert inspection_events[1].decrypt_success is True

    client_channel.close()
    server_channel.close()
