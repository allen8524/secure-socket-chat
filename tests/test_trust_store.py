import json

from secure_chat.trust_store import (
    check_server_fingerprint,
    load_trusted_servers,
    server_id,
    trust_server_fingerprint,
)


def test_load_trusted_servers_returns_empty_when_file_is_missing(tmp_path):
    store_path = tmp_path / "trusted_servers.json"

    assert load_trusted_servers(store_path) == {}


def test_trust_server_fingerprint_creates_store_file(tmp_path):
    store_path = tmp_path / ".secure_socket_chat" / "trusted_servers.json"

    result = trust_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)

    assert result.status == "Trusted"
    assert result.verification == "OK"
    assert store_path.exists()

    data = json.loads(store_path.read_text(encoding="utf-8"))
    assert data["127.0.0.1:9999"]["fingerprint"] == "AA:BB"
    assert data["127.0.0.1:9999"]["trust_mode"] == "tofu"
    assert "first_seen" in data["127.0.0.1:9999"]
    assert "last_seen" in data["127.0.0.1:9999"]


def test_check_server_fingerprint_reports_new_when_not_registered(tmp_path):
    result = check_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=tmp_path / "store.json")

    assert result.status == "New"
    assert result.verification == "Not registered"
    assert result.server_id == "127.0.0.1:9999"


def test_check_server_fingerprint_reports_trusted_for_same_fingerprint(tmp_path):
    store_path = tmp_path / "store.json"
    trust_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)

    result = check_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)

    assert result.status == "Trusted"
    assert result.verification == "OK"
    assert result.stored_fingerprint == "AA:BB"


def test_check_server_fingerprint_reports_changed_for_different_fingerprint(tmp_path):
    store_path = tmp_path / "store.json"
    trust_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)

    result = check_server_fingerprint("127.0.0.1", 9999, "CC:DD", path=store_path)

    assert result.status == "Changed"
    assert result.verification == "Warning"
    assert result.stored_fingerprint == "AA:BB"
    assert result.fingerprint == "CC:DD"


def test_load_trusted_servers_handles_broken_json(tmp_path):
    store_path = tmp_path / "store.json"
    store_path.write_text("{not-json", encoding="utf-8")

    assert load_trusted_servers(store_path) == {}
    result = check_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)

    assert result.status == "New"


def test_trust_store_keeps_host_port_entries_separate(tmp_path):
    store_path = tmp_path / "store.json"
    trust_server_fingerprint("127.0.0.1", 9999, "AA:BB", path=store_path)
    trust_server_fingerprint("127.0.0.1", 10000, "CC:DD", path=store_path)

    data = load_trusted_servers(store_path)

    assert data[server_id("127.0.0.1", 9999)]["fingerprint"] == "AA:BB"
    assert data[server_id("127.0.0.1", 10000)]["fingerprint"] == "CC:DD"
