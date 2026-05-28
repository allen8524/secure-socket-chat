"""Small utility functions shared by client and server."""

from __future__ import annotations

import os
import time
from pathlib import Path


def safe_filename(name: str, fallback: str = "image.bin") -> str:
    """Return a filesystem-safe basename.

    This intentionally strips directory components to reduce path traversal risk when
    saving files received over the network.
    """
    base = os.path.basename(name).strip()
    if not base:
        base = fallback
    return base.replace("/", "_").replace("\\", "_")


def save_received_file(directory: str | Path, sender: str, filename: str, payload: bytes) -> Path:
    receive_dir = Path(directory)
    receive_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_sender = safe_filename(sender, fallback="unknown")
    safe_name = safe_filename(filename)
    save_path = receive_dir / f"{timestamp}_{safe_sender}_{safe_name}"

    counter = 1
    original_path = save_path
    while save_path.exists():
        save_path = original_path.with_name(f"{original_path.stem}_{counter}{original_path.suffix}")
        counter += 1

    save_path.write_bytes(payload)
    return save_path
