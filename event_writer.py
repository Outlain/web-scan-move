#!/usr/bin/env python3
"""Durable schema-v1 event writer for the central ClamAV notifier."""

from __future__ import annotations

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

SERVICE = "web-scan-move"
EVENT_DIR = Path(os.environ.get("EVENT_DIR", "/events"))


def emit_event(
    event_type: str,
    severity: str,
    message: str,
    *,
    source_path: str | None = None,
    destination_path: str | None = None,
    threat_name: str | None = None,
    action_success: bool | None = None,
    failure_kind: str | None = None,
) -> str:
    """Atomically spool one event and return its globally unique identifier."""
    event_id = str(uuid.uuid4())
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": event_type,
        "service": SERVICE,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "message": message[:2000],
    }
    optional = {
        "source_path": source_path,
        "destination_path": destination_path,
        "threat_name": threat_name,
        "action_success": action_success,
        "failure_kind": failure_kind,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})

    EVENT_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    directory_info = EVENT_DIR.lstat()
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode):
        raise RuntimeError(f"event path is not a real directory: {EVENT_DIR}")

    final_path = EVENT_DIR / f"{event_id}.json"
    temporary_path = EVENT_DIR / f".{event_id}.tmp"
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, final_path)
        directory_descriptor = os.open(EVENT_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return event_id
