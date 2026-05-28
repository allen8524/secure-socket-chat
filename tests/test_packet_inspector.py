from secure_chat.packet_inspector import (
    build_packet_inspection_event,
    ciphertext_preview,
    format_packet_inspection_event,
    summarize_logical_header,
)


def test_chat_header_summary_uses_limited_text_preview():
    long_text = "hello-" * 20

    summary = summarize_logical_header({"type": "chat", "text": long_text})

    assert "type=chat" in summary
    assert "text_preview=" in summary
    assert long_text not in summary


def test_image_header_summary_hides_binary_payload_and_marks_hash():
    header = {
        "type": "image",
        "from": "alice",
        "to": "bob",
        "filename": "sample.png",
        "sha256": "abc123",
    }

    summary = summarize_logical_header(header, payload_size=1024)

    assert "type=image" in summary
    assert "filename='sample.png'" in summary
    assert "file_size=1024" in summary
    assert "sha256=yes" in summary
    assert "binary" not in summary.lower()


def test_ciphertext_preview_is_base64_and_truncated():
    preview = ciphertext_preview(b"a" * 200, limit=24)

    assert preview.endswith("...")
    assert len(preview) == 27


def test_packet_inspection_event_formats_safe_fields():
    event = build_packet_inspection_event(
        direction="OUTBOUND",
        header={"type": "whisper", "to": "bob", "text": "secret message body that should be shortened"},
        payload=b"",
        encrypted_packet=b"ciphertext" * 20,
        decrypt_success=None,
    )

    rendered = format_packet_inspection_event(event)

    assert "OUTBOUND whisper" in rendered
    assert "payload size: 0 bytes" in rendered
    assert "encrypted packet size:" in rendered
    assert "decrypt: N/A" in rendered
    assert "secret message body that should be shortened" not in rendered
