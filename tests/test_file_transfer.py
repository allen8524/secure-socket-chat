from secure_chat.file_transfer import (
    build_file_header,
    calculate_sha256,
    format_file_size,
    is_image_file,
    is_potentially_risky_file,
    verify_file_hash,
)
from secure_chat.client import ChatClient
from secure_chat.utils import safe_filename


def test_calculate_sha256_returns_expected_digest():
    assert calculate_sha256(b"hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_format_file_size_uses_readable_units():
    assert format_file_size(512) == "512 B"
    assert format_file_size(245 * 1024) == "245 KB"
    assert format_file_size(1536) == "1.5 KB"


def test_file_type_helpers_detect_image_and_risky_extensions():
    assert is_image_file("photo.PNG")
    assert not is_image_file("report.pdf")
    assert is_potentially_risky_file("install.exe")
    assert is_potentially_risky_file("script.ps1")
    assert not is_potentially_risky_file("notes.txt")


def test_safe_filename_neutralizes_path_components_for_files():
    assert safe_filename("../../report.pdf", fallback="file.bin") == "report.pdf"
    assert safe_filename("folder\\report.pdf", fallback="file.bin") == "folder_report.pdf"


def test_verify_file_hash_success_and_failure():
    digest = calculate_sha256(b"payload")

    assert verify_file_hash(b"payload", digest)
    assert not verify_file_hash(b"changed", digest)


def test_build_file_header_includes_file_metadata():
    digest = calculate_sha256(b"payload")

    header = build_file_header(
        target="bob",
        filename="report.pdf",
        file_size=7,
        sha256=digest,
    )

    assert header["type"] == "file"
    assert header["to"] == "bob"
    assert header["filename"] == "report.pdf"
    assert header["file_size"] == 7
    assert header["sha256"] == digest
    assert header["extension"] == ".pdf"
    assert header["mime_type"] == "application/pdf"


def test_chat_client_send_file_sends_file_packet(tmp_path):
    class DummyChannel:
        def __init__(self):
            self.sent = None

        def send(self, header, payload=b""):
            self.sent = (header, payload)

    path = tmp_path / "report.pdf"
    path.write_bytes(b"payload")
    client = ChatClient(username="alice")
    channel = DummyChannel()
    client._channel = channel

    digest = client.send_file("bob", path)

    header, payload = channel.sent
    assert header["type"] == "file"
    assert header["to"] == "bob"
    assert header["filename"] == "report.pdf"
    assert header["file_size"] == len(b"payload")
    assert header["sha256"] == digest
    assert header["mime_type"] == "application/pdf"
    assert payload == b"payload"
