#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import stat
import sys
import time
from pathlib import Path

DEFINITIONS_DIR = Path(os.environ.get("DEFINITIONS_DIR", "/var/lib/clamav"))
MAX_AGE = max(int(os.environ.get("DEFINITIONS_MAX_AGE_SECONDS", "172800")), 300)
SOCKET_PATH = os.environ.get("CLAMD_SOCKET", "/run/clamav/clamd.sock")


def candidate(stem: str) -> Path:
    choices: list[tuple[int, Path]] = []
    for suffix in ("cld", "cvd"):
        path = DEFINITIONS_DIR / f"{stem}.{suffix}"
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_size > 0 and os.access(path, os.R_OK):
            choices.append((info.st_mtime_ns, path))
    if not choices:
        raise RuntimeError(f"missing readable {stem} database")
    return max(choices, key=lambda value: value[0])[1]


def definitions_ready() -> tuple[Path, int]:
    candidate("main")
    daily = candidate("daily")
    age = max(0, int(time.time() - daily.stat().st_mtime))
    if age > MAX_AGE:
        raise RuntimeError(f"daily definitions are stale: age={age}s max={MAX_AGE}s")
    return daily, age


def command(value: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(SOCKET_PATH)
        client.sendall(b"z" + value + b"\0")
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                raise RuntimeError("clamd closed the health connection")
            marker = chunk.find(b"\0")
            chunks.append(chunk if marker < 0 else chunk[:marker])
            if marker >= 0:
                return b"".join(chunks).decode("utf-8", "replace")


def main() -> int:
    try:
        daily, age = definitions_ready()
        if command(b"PING") != "PONG":
            raise RuntimeError("clamd did not answer PONG")
        version = command(b"VERSION")
        if not version.startswith("ClamAV "):
            raise RuntimeError("clamd returned an invalid version")
        print(f"healthy: {version}; daily={daily.name} age={age}s")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
