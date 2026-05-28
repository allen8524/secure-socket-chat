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
