import pytest

from secure_chat.client import ChatClient
from secure_chat.e2e import (
    E2EEncryptionError,
    build_inner_payload,
    decode_public_key,
    decrypt_inner_payload,
    encode_public_key,
    encrypt_inner_payload,
    generate_e2e_identity,
)
from secure_chat.packet_inspector import summarize_logical_header
from secure_chat.security import public_key_fingerprint


def test_e2e_keypair_generates_public_key_and_fingerprint():
    identity = generate_e2e_identity()

    assert identity.public_key
    assert identity.fingerprint == public_key_fingerprint(identity.public_key)


def test_e2e_public_key_encode_decode_roundtrip():
    identity = generate_e2e_identity()

    decoded = decode_public_key(identity.public_key)
    encoded = encode_public_key(decoded)

    assert encoded == identity.public_key


def test_e2e_encrypt_decrypt_between_alice_and_bob():
    alice = generate_e2e_identity()
    bob = generate_e2e_identity()
    inner = build_inner_payload("alice", "bob", "hello e2e")

    ciphertext = encrypt_inner_payload(alice.private_key, bob.public_key, inner)
    decrypted = decrypt_inner_payload(bob.private_key, alice.public_key, ciphertext)

    assert decrypted["type"] == "e2e_message"
    assert decrypted["from"] == "alice"
    assert decrypted["to"] == "bob"
    assert decrypted["text"] == "hello e2e"


def test_e2e_decrypt_with_wrong_key_fails():
    alice = generate_e2e_identity()
    bob = generate_e2e_identity()
    mallory = generate_e2e_identity()
    inner = build_inner_payload("alice", "bob", "hello e2e")

    ciphertext = encrypt_inner_payload(alice.private_key, bob.public_key, inner)

    with pytest.raises(E2EEncryptionError):
        decrypt_inner_payload(mallory.private_key, alice.public_key, ciphertext)


def test_e2e_outer_packet_summary_does_not_include_plaintext():
    plaintext = "this message must not appear in the outer packet"
    alice = generate_e2e_identity()
    bob = generate_e2e_identity()
    ciphertext = encrypt_inner_payload(
        alice.private_key,
        bob.public_key,
        build_inner_payload("alice", "bob", plaintext),
    )
    outer = {
        "type": "e2e_whisper",
        "from": "alice",
        "to": "bob",
        "sender_e2e_fingerprint": alice.fingerprint,
        "recipient_e2e_fingerprint": bob.fingerprint,
        "ciphertext": ciphertext,
    }

    summary = summarize_logical_header(outer)

    assert "type=e2e_whisper" in summary
    assert "ciphertext_size=" in summary
    assert plaintext not in summary
    assert "text=" not in summary


def test_chat_client_e2e_outer_packet_does_not_include_plaintext(monkeypatch):
    plaintext = "outer header must not contain this"
    client = ChatClient(username="alice")
    bob = generate_e2e_identity()
    client.e2e_key_cache["bob"] = {"public_key": bob.public_key, "fingerprint": bob.fingerprint}
    sent_headers = []

    monkeypatch.setattr(client, "_send", lambda header, payload=b"": sent_headers.append(header))

    client.send_e2e_whisper("bob", plaintext)

    outer = sent_headers[0]
    assert outer["type"] == "e2e_whisper"
    assert outer["to"] == "bob"
    assert "text" not in outer
    assert plaintext not in str(outer)
