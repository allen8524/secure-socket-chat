from datetime import datetime
from types import SimpleNamespace

from secure_chat.gui import build_security_dashboard_state, compact_fingerprint
from secure_chat.security import ChannelMetadata


def test_compact_fingerprint_keeps_front_and_back_groups():
    fingerprint = "AA:BB:CC:DD:EE:FF:00:11"

    assert compact_fingerprint(fingerprint) == "AA:BB:CC:...:00:11"


def test_security_dashboard_state_defaults_without_client():
    state = build_security_dashboard_state(None)

    assert state.connection_state == "Disconnected"
    assert state.encryption_state == "Inactive"
    assert state.session_id == "-"
    assert state.sent_packet_count == 0
    assert state.received_packet_count == 0
    assert state.send_sequence == 0
    assert state.receive_sequence == 0
    assert state.last_replay_status == "Not checked"
    assert state.server_trust_status == "Unknown"
    assert state.tofu_verification == "Unknown"
    assert state.e2e_mode == "Unavailable"
    assert state.e2e_fingerprint == "-"
    assert state.selected_e2e_fingerprint == "-"
    assert state.last_e2e_decrypt_result == "Not checked"


def test_security_dashboard_state_uses_client_metadata_and_counters():
    metadata = ChannelMetadata(
        cipher="PyNaCl Box (Curve25519 XSalsa20-Poly1305)",
        local_public_key="client-key",
        peer_public_key="server-key",
        local_fingerprint="AA:BB:CC:DD:EE:FF:00:11",
        peer_fingerprint="11:22:33:44:55:66:77:88",
        session_id="ABCDEF123456",
    )
    client = SimpleNamespace(
        connected=True,
        security_metadata=metadata,
        connected_at=datetime(2026, 5, 28, 10, 30, 0),
        sent_packet_count=3,
        received_packet_count=5,
        send_sequence=4,
        receive_sequence=6,
        last_replay_status="OK sequence=6",
        server_trust_status="Trusted",
        tofu_verification="OK",
        e2e_available="Available",
        e2e_fingerprint="AA:AA:AA:BB:BB:BB:CC:CC",
        last_e2e_decrypt_result="OK",
        last_received_message_type="image",
    )

    state = build_security_dashboard_state(
        client,
        last_file_integrity="OK",
        selected_e2e_fingerprint="DD:DD:DD:EE:EE:EE:FF:FF",
    )

    assert state.connection_state == "Connected"
    assert state.encryption_state == "Active"
    assert state.cipher == "PyNaCl Box"
    assert state.key_exchange == "PublicKey 기반"
    assert state.session_id == "ABCDEF123456"
    assert state.local_fingerprint == "AA:BB:CC:...:00:11"
    assert state.peer_fingerprint == "11:22:33:...:77:88"
    assert state.session_started_at == "2026-05-28 10:30:00"
    assert state.sent_packet_count == 3
    assert state.received_packet_count == 5
    assert state.send_sequence == 4
    assert state.receive_sequence == 6
    assert state.last_replay_status == "OK sequence=6"
    assert state.server_trust_status == "Trusted"
    assert state.tofu_verification == "OK"
    assert state.e2e_mode == "Available"
    assert state.e2e_fingerprint == "AA:AA:AA:...:CC:CC"
    assert state.selected_e2e_fingerprint == "DD:DD:DD:...:FF:FF"
    assert state.last_e2e_decrypt_result == "OK"
    assert state.last_file_integrity == "OK"
    assert state.last_received_message_type == "image"
