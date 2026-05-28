from secure_chat.file_transfer import calculate_sha256, verify_file_hash
from secure_chat.packet_inspector import summarize_logical_header
from tests.conftest import wait_for_message


def test_integration_file_transfer_routes_payload_and_hash(client_factory, tmp_path):
    alice = client_factory("alice")
    bob = client_factory("bob")
    file_path = tmp_path / "report.txt"
    file_payload = b"integration file payload"
    file_path.write_bytes(file_payload)

    expected_digest = calculate_sha256(file_payload)
    returned_digest = alice.send_file("bob", file_path)
    header, payload = wait_for_message(
        bob,
        lambda item, body: item.get("type") == "file" and item.get("from") == "alice" and body == file_payload,
    )

    assert returned_digest == expected_digest
    assert header["filename"] == "report.txt"
    assert header["file_size"] == len(file_payload)
    assert header["sha256"] == expected_digest
    assert verify_file_hash(payload, header["sha256"])

    summary = summarize_logical_header(header, len(payload))
    assert "type=file" in summary
    assert "filename='report.txt'" in summary
    assert file_payload.decode("utf-8") not in summary


def test_integration_image_transfer_still_routes_existing_type(client_factory, tmp_path):
    alice = client_factory("alice")
    bob = client_factory("bob")
    image_path = tmp_path / "sample.png"
    payload = b"\x89PNG\r\n\x1a\nsample"
    image_path.write_bytes(payload)

    expected_digest = calculate_sha256(payload)
    returned_digest = alice.send_image("bob", image_path)
    header, received_payload = wait_for_message(
        bob,
        lambda item, body: item.get("type") == "image" and item.get("filename") == "sample.png" and body == payload,
    )

    assert returned_digest == expected_digest
    assert header["sha256"] == expected_digest
    assert verify_file_hash(received_payload, header["sha256"])
