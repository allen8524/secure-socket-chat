from secure_chat.security import public_key_fingerprint, session_id_from_fingerprints, sha256_hex


def test_public_key_fingerprint_format_is_short_colon_separated_hex():
    fingerprint = public_key_fingerprint("sample-public-key")
    parts = fingerprint.split(":")

    assert len(parts) == 8
    assert all(len(part) == 2 for part in parts)


def test_session_id_is_order_independent():
    left = "AA:BB:CC:DD:EE:FF:00:11"
    right = "11:22:33:44:55:66:77:88"

    assert session_id_from_fingerprints(left, right) == session_id_from_fingerprints(right, left)


def test_sha256_hex_returns_known_digest():
    assert sha256_hex(b"hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
