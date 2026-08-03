#!/usr/bin/env python3
"""Minimal, descriptor-safe ClamD INSTREAM client."""

from __future__ import annotations

import os
import socket
import stat
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path


class ClamdError(RuntimeError):
    pass


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass(frozen=True)
class ScanResult:
    infected: bool
    threat_name: str | None
    response: str


@dataclass(frozen=True)
class ClamdIdentity:
    engine_version: str
    database_version: str
    database_updated_at: datetime
    raw_version: str


class ClamdClient:
    def __init__(
        self,
        socket_path: str,
        *,
        connect_timeout: float,
        scan_timeout: float,
        max_stream_bytes: int,
        max_definition_age_seconds: int,
    ) -> None:
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout
        self.scan_timeout = scan_timeout
        self.max_stream_bytes = max_stream_bytes
        self.max_definition_age_seconds = max_definition_age_seconds

    def _connect(self, timeout: float) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            client.connect(self.socket_path)
        except Exception:
            client.close()
            raise
        return client

    @staticmethod
    def _receive_nul(client: socket.socket, *, maximum: int = 1024 * 1024) -> str:
        response = bytearray()
        while len(response) <= maximum:
            chunk = client.recv(min(65536, maximum + 1 - len(response)))
            if not chunk:
                raise ClamdError("clamd closed the connection without a complete reply")
            marker = chunk.find(b"\0")
            response.extend(chunk if marker < 0 else chunk[:marker])
            if marker >= 0:
                return response.decode("utf-8", "replace")
        raise ClamdError("clamd reply exceeded the safety limit")

    def command(self, command: bytes) -> str:
        try:
            with self._connect(self.connect_timeout) as client:
                client.sendall(b"z" + command + b"\0")
                return self._receive_nul(client)
        except (OSError, TimeoutError) as exc:
            raise ClamdError(f"clamd {command.decode('ascii', 'replace')} failed: {exc}") from exc

    def health(self) -> ClamdIdentity:
        if self.command(b"PING") != "PONG":
            raise ClamdError("clamd did not answer PONG")
        raw = self.command(b"VERSION")
        identity = parse_version(raw)
        now = datetime.now(timezone.utc)
        age = max(0, int((now - identity.database_updated_at).total_seconds()))
        if age > self.max_definition_age_seconds:
            raise ClamdError(
                f"clamd definitions are stale: age={age}s max={self.max_definition_age_seconds}s"
            )
        return identity

    def scan_file(self, path: Path) -> ScanResult:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ClamdError(f"cannot safely open {path}: {exc}") from exc

        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ClamdError(f"refusing to scan a non-regular file: {path}")
            original = FileIdentity.from_stat(opened)
            if original.size > self.max_stream_bytes:
                raise ClamdError(
                    f"file exceeds configured stream limit: {original.size} > {self.max_stream_bytes}: {path}"
                )
            self._verify_path_identity(path, original)
            response = self._stream_descriptor(descriptor)
            if FileIdentity.from_stat(os.fstat(descriptor)) != original:
                raise ClamdError(f"file changed while clamd scanned it: {path}")
            self._verify_path_identity(path, original)
        finally:
            os.close(descriptor)
        return parse_scan_response(response)

    def _stream_descriptor(self, descriptor: int) -> str:
        try:
            with self._connect(self.connect_timeout) as client:
                client.settimeout(self.scan_timeout)
                client.sendall(b"zINSTREAM\0")
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    client.sendall(struct.pack("!I", len(chunk)))
                    client.sendall(chunk)
                client.sendall(struct.pack("!I", 0))
                return self._receive_nul(client)
        except (OSError, TimeoutError) as exc:
            raise ClamdError(f"clamd stream failed: {exc}") from exc

    @staticmethod
    def _verify_path_identity(path: Path, expected: FileIdentity) -> None:
        try:
            current = path.lstat()
        except OSError as exc:
            raise ClamdError(f"scanned path disappeared: {path}: {exc}") from exc
        if FileIdentity.from_stat(current) != expected or not stat.S_ISREG(current.st_mode):
            raise ClamdError(f"scanned path was replaced: {path}")


def parse_version(raw: str) -> ClamdIdentity:
    if not raw.startswith("ClamAV "):
        raise ClamdError(f"invalid clamd version response: {raw[:200]}")
    fields = raw.removeprefix("ClamAV ").split("/", 2)
    if len(fields) != 3 or not fields[0] or not fields[1]:
        raise ClamdError(f"incomplete clamd version response: {raw[:200]}")
    try:
        updated = parsedate_to_datetime(fields[2])
    except (TypeError, ValueError) as exc:
        raise ClamdError(f"invalid clamd definition timestamp: {fields[2][:100]}") from exc
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return ClamdIdentity(fields[0], fields[1], updated.astimezone(timezone.utc), raw)


def parse_scan_response(response: str) -> ScanResult:
    normalized = response.strip()
    lower = normalized.casefold()
    limit_markers = (
        "heuristics.limits.exceeded",
        "size limit exceeded",
        "scan limit exceeded",
        "limits exceeded",
        "stream size limit exceeded",
    )
    if any(marker in lower for marker in limit_markers):
        raise ClamdError(f"clamd scan limit was exceeded: {normalized[:500]}")
    if normalized.endswith(": OK"):
        return ScanResult(False, None, normalized)
    if normalized.endswith(" FOUND") and ": " in normalized:
        threat = normalized.rsplit(": ", 1)[1].removesuffix(" FOUND").strip()
        if not threat:
            raise ClamdError(f"clamd returned an empty threat name: {normalized[:500]}")
        return ScanResult(True, threat, normalized)
    if normalized.endswith(" ERROR") or " error" in lower:
        raise ClamdError(f"clamd scan failed: {normalized[:500]}")
    raise ClamdError(f"unrecognized clamd response: {normalized[:500]}")
