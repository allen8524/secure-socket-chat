"""TOFU trust store for server public-key fingerprints."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

TrustStatus = Literal["New", "Trusted", "Changed", "Unknown"]
TofuVerification = Literal["OK", "Warning", "Not registered", "Unknown"]

DEFAULT_TRUST_STORE_PATH = Path.home() / ".secure_socket_chat" / "trusted_servers.json"


@dataclass(frozen=True)
class TrustCheckResult:
    host: str
    port: int
    server_id: str
    fingerprint: str
    status: TrustStatus
    verification: TofuVerification
    stored_fingerprint: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    trust_mode: str = "tofu"
    accepted: bool = False
    message: str = ""


def server_id(host: str, port: int) -> str:
    return f"{host}:{port}"


def _utc_now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def load_trusted_servers(path: str | Path | None = None) -> dict[str, Any]:
    store_path = Path(path) if path is not None else DEFAULT_TRUST_STORE_PATH
    if not store_path.exists():
        return {}

    try:
        data = json.loads(store_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}
    return data


def save_trusted_servers(data: dict[str, Any], path: str | Path | None = None) -> None:
    store_path = Path(path) if path is not None else DEFAULT_TRUST_STORE_PATH
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def check_server_fingerprint(
    host: str,
    port: int,
    fingerprint: str,
    *,
    path: str | Path | None = None,
    trusted_servers: dict[str, Any] | None = None,
) -> TrustCheckResult:
    normalized_fingerprint = str(fingerprint).strip()
    key = server_id(host, port)
    data = trusted_servers if trusted_servers is not None else load_trusted_servers(path)
    record = data.get(key)

    if not normalized_fingerprint:
        return TrustCheckResult(
            host=host,
            port=port,
            server_id=key,
            fingerprint=normalized_fingerprint,
            status="Unknown",
            verification="Unknown",
            message="server fingerprint is empty",
        )

    if not isinstance(record, dict):
        return TrustCheckResult(
            host=host,
            port=port,
            server_id=key,
            fingerprint=normalized_fingerprint,
            status="New",
            verification="Not registered",
            message="server fingerprint is not registered",
        )

    stored_fingerprint = str(record.get("fingerprint", "")).strip()
    if stored_fingerprint == normalized_fingerprint:
        return TrustCheckResult(
            host=host,
            port=port,
            server_id=key,
            fingerprint=normalized_fingerprint,
            status="Trusted",
            verification="OK",
            stored_fingerprint=stored_fingerprint,
            first_seen=str(record.get("first_seen", "")) or None,
            last_seen=str(record.get("last_seen", "")) or None,
            trust_mode=str(record.get("trust_mode", "tofu")),
            message="server fingerprint matches trusted store",
        )

    return TrustCheckResult(
        host=host,
        port=port,
        server_id=key,
        fingerprint=normalized_fingerprint,
        status="Changed",
        verification="Warning",
        stored_fingerprint=stored_fingerprint or None,
        first_seen=str(record.get("first_seen", "")) or None,
        last_seen=str(record.get("last_seen", "")) or None,
        trust_mode=str(record.get("trust_mode", "tofu")),
        message="server fingerprint changed",
    )


def trust_server_fingerprint(
    host: str,
    port: int,
    fingerprint: str,
    *,
    path: str | Path | None = None,
) -> TrustCheckResult:
    normalized_fingerprint = str(fingerprint).strip()
    key = server_id(host, port)
    data = load_trusted_servers(path)
    existing = data.get(key) if isinstance(data.get(key), dict) else {}
    now = _utc_now_iso()
    first_seen = str(existing.get("first_seen", "")) or now

    data[key] = {
        "fingerprint": normalized_fingerprint,
        "first_seen": first_seen,
        "last_seen": now,
        "trust_mode": "tofu",
    }
    save_trusted_servers(data, path)

    return TrustCheckResult(
        host=host,
        port=port,
        server_id=key,
        fingerprint=normalized_fingerprint,
        status="Trusted",
        verification="OK",
        stored_fingerprint=normalized_fingerprint,
        first_seen=first_seen,
        last_seen=now,
        trust_mode="tofu",
        accepted=True,
        message="server fingerprint stored",
    )
