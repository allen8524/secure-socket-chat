from secure_chat.utils import safe_filename, save_received_file


def test_safe_filename_strips_path_components():
    assert safe_filename("../../secret.png") == "secret.png"
    assert safe_filename("folder\\image.png") == "folder_image.png"


def test_safe_filename_uses_fallback_for_blank_name():
    assert safe_filename("   ") == "image.bin"


def test_save_received_file_writes_payload(tmp_path):
    path = save_received_file(tmp_path, "alice", "sample.png", b"data")

    assert path.exists()
    assert path.read_bytes() == b"data"
    assert "alice" in path.name
    assert "sample.png" in path.name
