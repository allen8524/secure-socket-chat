from secure_chat.e2e import generate_e2e_identity
from secure_chat.server import ChatServer, ClientE2EMetadata


class FakeChannel:
    def __init__(self):
        self.sent = []

    def send(self, header, payload=b""):
        self.sent.append((header, payload))


def test_server_e2e_whisper_target_without_e2e_key_returns_error():
    server = ChatServer()
    alice_channel = FakeChannel()
    bob_channel = FakeChannel()
    alice_identity = generate_e2e_identity()

    server._clients["alice"] = alice_channel
    server._clients["bob"] = bob_channel
    server._client_e2e_keys["alice"] = ClientE2EMetadata(
        public_key=alice_identity.public_key,
        fingerprint=alice_identity.fingerprint,
    )

    server._handle_e2e_whisper(
        "alice",
        {
            "type": "e2e_whisper",
            "to": "bob",
            "ciphertext": "ciphertext",
        },
    )

    assert alice_channel.sent
    header, _ = alice_channel.sent[-1]
    assert header["type"] == "error"
    assert "E2E 공개키" in header["text"]
    assert bob_channel.sent == []
