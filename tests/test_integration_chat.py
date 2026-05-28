from tests.conftest import wait_for_message


def test_integration_chat_broadcast_and_user_list(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")

    users_header, _ = wait_for_message(
        bob,
        lambda header, _payload: header.get("type") == "users" and {"alice", "bob"}.issubset(set(header.get("users", []))),
    )
    assert "alice" in users_header["users"]
    assert "bob" in users_header["users"]

    alice.send_chat("hello integration")
    header, payload = wait_for_message(
        bob,
        lambda item, _payload: item.get("type") == "chat"
        and item.get("from") == "alice"
        and item.get("text") == "hello integration",
    )

    assert header["type"] == "chat"
    assert payload == b""
    assert alice.send_sequence >= 2
    assert bob.receive_sequence >= 1


def test_integration_whisper_routes_to_target_and_echoes_sender(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")

    alice.send_whisper("bob", "quiet hello")
    bob_header, _ = wait_for_message(
        bob,
        lambda header, _payload: header.get("type") == "whisper"
        and header.get("from") == "alice"
        and header.get("to") == "bob"
        and header.get("text") == "quiet hello",
    )
    alice_header, _ = wait_for_message(
        alice,
        lambda header, _payload: header.get("type") == "whisper"
        and header.get("from") == "alice"
        and header.get("to") == "bob"
        and header.get("text") == "quiet hello",
    )

    assert bob_header["type"] == "whisper"
    assert alice_header["type"] == "whisper"


def test_integration_whisper_to_missing_user_returns_error(client_factory):
    alice = client_factory("alice")

    alice.send_whisper("missing", "hello?")
    header, _ = wait_for_message(
        alice,
        lambda item, _payload: item.get("type") == "error" and "missing" in str(item.get("text", "")),
    )

    assert header["type"] == "error"


def test_integration_e2e_whisper_routes_ciphertext_and_decrypts_for_target(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")

    wait_for_message(
        alice,
        lambda header, _payload: header.get("type") == "users" and "bob" in header.get("e2e_keys", {}),
    )
    wait_for_message(
        bob,
        lambda header, _payload: header.get("type") == "users" and "alice" in header.get("e2e_keys", {}),
    )

    alice.send_e2e_whisper("bob", "private hello")
    header, _ = wait_for_message(
        bob,
        lambda item, _payload: item.get("type") == "e2e_whisper"
        and item.get("from") == "alice"
        and item.get("to") == "bob"
        and item.get("text") == "private hello",
    )

    assert header["type"] == "e2e_whisper"
    assert header["text"] == "private hello"
    assert bob.last_e2e_decrypt_result == "OK"


def test_integration_e2e_whisper_requires_target_key(client_factory):
    alice = client_factory("alice")

    alice.e2e_key_cache["missing"] = {"public_key": alice.e2e_identity.public_key, "fingerprint": alice.e2e_fingerprint}
    alice.send_e2e_whisper("missing", "hello?")
    header, _ = wait_for_message(
        alice,
        lambda item, _payload: item.get("type") == "error" and "missing" in str(item.get("text", "")),
    )

    assert header["type"] == "error"
