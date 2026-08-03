#!/usr/bin/env python3
"""Poll stable web-download items, scan through ClamD, and move safely."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from clamd_client import ClamdClient, ClamdError
from event_writer import EVENT_DIR, emit_event
from safe_move import (
    Fingerprint,
    IncompleteItemError,
    UnsafePathError,
    fingerprint,
    has_incomplete_suffix,
    move_safely,
    recover_moves,
    regular_files,
    unique_destination,
)

WATCH_DIR = Path(os.environ.get("WATCH_DIR", "/watch"))
DEST_DIR = Path(os.environ.get("DEST_DIR", "/dest"))
QUARANTINE_DIR = Path(os.environ.get("QUARANTINE_DIR", "/quarantine"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
CLAMD_SOCKET = os.environ.get("CLAMD_SOCKET", "/run/clamav/clamd.sock")
POLL_SECONDS = max(float(os.environ.get("POLL_SECONDS", "5")), 1.0)
SETTLE_SECONDS = max(float(os.environ.get("SETTLE_SECONDS", "30")), 5.0)
MAX_WORKERS = min(max(int(os.environ.get("MAX_SCAN_WORKERS", "1")), 1), 8)
DISCOVERY_WORKERS = min(max(int(os.environ.get("DISCOVERY_WORKERS", "4")), 2), 16)
DISCOVERY_QUEUE = min(
    max(int(os.environ.get("DISCOVERY_QUEUE", "64")), DISCOVERY_WORKERS),
    4096,
)
CLAMD_CONNECT_TIMEOUT_SECONDS = max(float(os.environ.get("CLAMD_CONNECT_TIMEOUT_SECONDS", "5")), 1.0)
SCAN_TIMEOUT_SECONDS = max(int(os.environ.get("SCAN_TIMEOUT_SECONDS", "7200")), 60)
MAX_STREAM_BYTES = min(max(int(os.environ.get("MAX_STREAM_MIB", "2000")), 1), 2000) * 1024 * 1024
MAX_DEFINITION_AGE_SECONDS = max(int(os.environ.get("MAX_DEFINITION_AGE_SECONDS", "172800")), 300)
WATCH_MOUNT_MARKER = os.environ.get("WATCH_MOUNT_MARKER", "").strip()
DEST_MOUNT_MARKER = os.environ.get("DEST_MOUNT_MARKER", "").strip()
QUARANTINE_MOUNT_MARKER = os.environ.get("QUARANTINE_MOUNT_MARKER", "").strip()

TEMP_SUFFIXES = tuple(
    suffix.strip().casefold()
    for suffix in os.environ.get(
        "INCOMPLETE_SUFFIXES",
        ".part,.tmp,.crdownload,.aria2,.partial,.download,.!qb",
    ).split(",")
    if suffix.strip()
)


@dataclass(frozen=True)
class PathIdentity:
    device: int
    inode: int
    mode_type: int

    @classmethod
    def capture(cls, path: Path) -> "PathIdentity":
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"required path is a symbolic link: {path}")
        return cls(info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


@dataclass(frozen=True)
class MountSnapshot:
    roots: tuple[tuple[str, PathIdentity], ...]
    markers: tuple[tuple[str, PathIdentity], ...]


@dataclass
class Stability:
    fingerprint: Fingerprint
    unchanged_since: float


class RecoveryTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failed = False

    def failed(self) -> None:
        with self._lock:
            self._failed = True

    def recovered(self, message: str) -> None:
        with self._lock:
            if not self._failed:
                return
            emit_event("service_recovered", "info", message, action_success=True)
            self._failed = False


def log(event: str, **fields: object) -> None:
    payload: dict[str, object] = {"timestamp": int(time.time()), "event": event}
    for key, value in fields.items():
        payload[key] = str(value) if isinstance(value, Path) else value
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


def _emit_failure(
    tracker: RecoveryTracker,
    event_type: str,
    severity: str,
    message: str,
    **fields: object,
) -> None:
    tracker.failed()
    try:
        emit_event(event_type, severity, message, **fields)
    except Exception as exc:
        log("event_spool_failed", event_type=event_type, error=str(exc))


def _marker_path(root: Path, configured: str) -> Path | None:
    if not configured:
        return None
    relative = Path(configured)
    if relative.is_absolute() or relative == Path(".") or ".." in relative.parts:
        raise RuntimeError(f"mount marker must be a relative path inside its root: {configured}")
    root_resolved = root.resolve(strict=True)
    candidate = root / relative
    try:
        candidate.resolve(strict=True).relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"mount marker escapes its root: {configured}") from exc
    return candidate


def capture_mounts() -> MountSnapshot:
    roots: list[tuple[str, PathIdentity]] = []
    markers: list[tuple[str, PathIdentity]] = []
    configured = (
        (WATCH_DIR, WATCH_MOUNT_MARKER),
        (DEST_DIR, DEST_MOUNT_MARKER),
        (QUARANTINE_DIR, QUARANTINE_MOUNT_MARKER),
    )
    for root, marker_name in configured:
        identity = PathIdentity.capture(root)
        if identity.mode_type != stat.S_IFDIR:
            raise RuntimeError(f"required mount is not a directory: {root}")
        roots.append((str(root), identity))
        marker = _marker_path(root, marker_name)
        if marker is not None:
            markers.append((str(marker), PathIdentity.capture(marker)))
    return MountSnapshot(tuple(roots), tuple(markers))


def verify_mounts(expected: MountSnapshot) -> None:
    if capture_mounts() != expected:
        raise RuntimeError("a required mount or configured marker changed during processing")


def _write_probe(directory: Path) -> None:
    name = directory / f".write-probe-{os.getpid()}-{threading.get_ident()}"
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.close(descriptor)
    name.unlink()


class ItemProcessor:
    def __init__(self, tracker: RecoveryTracker) -> None:
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._tracker = tracker
        self._clamd = ClamdClient(
            CLAMD_SOCKET,
            connect_timeout=CLAMD_CONNECT_TIMEOUT_SECONDS,
            scan_timeout=SCAN_TIMEOUT_SECONDS,
            max_stream_bytes=MAX_STREAM_BYTES,
            max_definition_age_seconds=MAX_DEFINITION_AGE_SECONDS,
        )

    @staticmethod
    def key(path: Path) -> str:
        return os.fsdecode(os.fsencode(path))

    def reserve(self, path: Path) -> bool:
        key = self.key(path)
        with self._lock:
            if key in self._active:
                return False
            self._active.add(key)
            return True

    def is_active(self, path: Path) -> bool:
        with self._lock:
            return self.key(path) in self._active

    def release(self, path: Path) -> None:
        with self._lock:
            self._active.discard(self.key(path))

    def process(self, path: Path) -> None:
        try:
            self._process_reserved(path)
        finally:
            self.release(path)

    def _process_reserved(self, path: Path) -> None:
        try:
            mounts = capture_mounts()
            before = fingerprint(path, incomplete_suffixes=TEMP_SUFFIXES)
            clamd_identity = self._clamd.health()
        except (OSError, RuntimeError, UnsafePathError, ClamdError) as exc:
            log("scan_precondition_failed", path=path, error=str(exc))
            _emit_failure(
                self._tracker,
                "scan_failed",
                "warning",
                f"Scan precondition failed: {exc}",
                source_path=str(path),
                action_success=False,
            )
            return

        log(
            "scan_started",
            path=path,
            files=before.files,
            bytes=before.bytes,
            clamd=clamd_identity.raw_version,
        )
        infected_path: Path | None = None
        threat_name: str | None = None
        try:
            for file_path in regular_files(path, incomplete_suffixes=TEMP_SUFFIXES):
                result = self._clamd.scan_file(file_path)
                if result.infected:
                    infected_path = file_path
                    threat_name = result.threat_name
                    break
            after = fingerprint(path, incomplete_suffixes=TEMP_SUFFIXES)
            verify_mounts(mounts)
            if before != after:
                raise RuntimeError("item changed while it was being scanned")
        except (OSError, RuntimeError, UnsafePathError, ClamdError) as exc:
            log("scan_failed", path=path, error=str(exc))
            _emit_failure(
                self._tracker,
                "scan_failed",
                "warning",
                f"ClamAV scan failed: {exc}",
                source_path=str(path),
                action_success=False,
            )
            return

        infected = infected_path is not None
        if infected:
            try:
                emit_event(
                    "threat_detected",
                    "critical",
                    "Malware detected in web-download content",
                    source_path=str(infected_path),
                    threat_name=threat_name,
                    action_success=False,
                )
            except Exception as exc:
                log("threat_event_failed", path=path, error=str(exc))
                _emit_failure(
                    self._tracker,
                    "scan_failed",
                    "critical",
                    f"Threat was found but its durable event could not be written: {exc}",
                    source_path=str(path),
                    threat_name=threat_name,
                    action_success=False,
                )
                return

        target_root = QUARANTINE_DIR if infected else DEST_DIR
        try:
            verify_mounts(mounts)
            destination = move_safely(
                path,
                target_root,
                expected=after,
                state_dir=STATE_DIR,
                incomplete_suffixes=TEMP_SUFFIXES,
            )
        except Exception as exc:
            event_type = "quarantine_failed" if infected else "promotion_failed"
            severity = "critical" if infected else "warning"
            log(event_type, path=path, target_root=target_root, error=str(exc))
            _emit_failure(
                self._tracker,
                event_type,
                severity,
                f"Could not move scanned content: {exc}",
                source_path=str(path),
                destination_path=str(target_root),
                threat_name=threat_name,
                action_success=False,
            )
            return

        if infected:
            try:
                emit_event(
                    "infected_content_quarantined",
                    "critical",
                    "Infected web-download content was quarantined",
                    source_path=str(path),
                    destination_path=str(destination),
                    threat_name=threat_name,
                    action_success=True,
                )
            except Exception as exc:
                # The earlier threat_detected event is already durable, so do not
                # undo a completed quarantine merely because this follow-up fails.
                log("quarantine_event_failed", destination=destination, error=str(exc))
        log(
            "moved",
            path=path,
            destination=destination,
            verdict="infected" if infected else "clean",
        )
        try:
            self._tracker.recovered("Web-download scanning and movement recovered")
        except Exception as exc:
            log("recovery_event_failed", error=str(exc))


def list_top_level_items() -> list[Path]:
    identity = PathIdentity.capture(WATCH_DIR)
    if identity.mode_type != stat.S_IFDIR:
        raise RuntimeError(f"watch mount is not a directory: {WATCH_DIR}")
    with os.scandir(WATCH_DIR) as entries:
        paths = [Path(entry.path) for entry in entries]
    return sorted(paths, key=lambda item: os.fsencode(item.name))


def healthcheck() -> int:
    try:
        capture_mounts()
        PathIdentity.capture(STATE_DIR)
        PathIdentity.capture(EVENT_DIR)
        if not os.access(WATCH_DIR, os.R_OK | os.W_OK | os.X_OK):
            raise RuntimeError(f"watch directory is not readable and writable: {WATCH_DIR}")
        for directory in (DEST_DIR, QUARANTINE_DIR, STATE_DIR, EVENT_DIR):
            _write_probe(directory)
        client = ClamdClient(
            CLAMD_SOCKET,
            connect_timeout=CLAMD_CONNECT_TIMEOUT_SECONDS,
            scan_timeout=SCAN_TIMEOUT_SECONDS,
            max_stream_bytes=MAX_STREAM_BYTES,
            max_definition_age_seconds=MAX_DEFINITION_AGE_SECONDS,
        )
        identity = client.health()
        print(f"healthy: {identity.raw_version}")
        return 0
    except (OSError, RuntimeError, ClamdError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    if "--healthcheck" in sys.argv:
        return healthcheck()

    stop = threading.Event()
    for signal_number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signal_number, lambda _signum, _frame: stop.set())

    tracker = RecoveryTracker()
    processor = ItemProcessor(tracker)
    stability: dict[str, Stability] = {}
    discovery_futures: dict[Future[Fingerprint], Path] = {}
    processing_futures: dict[Future[None], Path] = {}
    discovery_cursor = 0
    recovery_complete = False

    log(
        "service_started",
        watch=WATCH_DIR,
        destination=DEST_DIR,
        quarantine=QUARANTINE_DIR,
        settle_seconds=SETTLE_SECONDS,
        max_scan_workers=MAX_WORKERS,
        discovery_workers=DISCOVERY_WORKERS,
        clamd_socket=CLAMD_SOCKET,
    )

    with (
        ThreadPoolExecutor(max_workers=DISCOVERY_WORKERS, thread_name_prefix="web-discovery") as discovery,
        ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="web-scan") as workers,
    ):
        while not stop.is_set():
            try:
                mounts = capture_mounts()
                if not recovery_complete:
                    recovered = recover_moves(
                        STATE_DIR,
                        watch_root=WATCH_DIR,
                        destination_roots=(DEST_DIR, QUARANTINE_DIR),
                    )
                    if recovered:
                        log("cross_filesystem_moves_recovered", destinations=recovered)
                        emit_event(
                            "service_recovered",
                            "info",
                            f"Recovered {len(recovered)} interrupted web-download move(s)",
                            action_success=True,
                        )
                    recovery_complete = True
                verify_mounts(mounts)
                current_paths = list_top_level_items()
            except (OSError, RuntimeError, UnsafePathError) as exc:
                log("mount_unavailable", error=str(exc))
                _emit_failure(
                    tracker,
                    "mount_unavailable",
                    "critical",
                    f"Web-download mount or move state is unavailable: {exc}",
                    action_success=False,
                )
                stop.wait(POLL_SECONDS)
                continue

            for future, path in list(processing_futures.items()):
                if not future.done():
                    continue
                processing_futures.pop(future, None)
                try:
                    future.result()
                except Exception as exc:
                    log("worker_crashed", path=path, error=str(exc))
                    _emit_failure(
                        tracker,
                        "scan_failed",
                        "critical",
                        f"Web scan worker crashed: {exc}",
                        source_path=str(path),
                        action_success=False,
                    )

            now = time.monotonic()
            for future, path in list(discovery_futures.items()):
                if not future.done():
                    continue
                discovery_futures.pop(future, None)
                key = processor.key(path)
                try:
                    current = future.result()
                except IncompleteItemError as exc:
                    log("not_ready", path=path, reason=str(exc))
                    stability.pop(key, None)
                    continue
                except UnsafePathError as exc:
                    log("unsafe_item", path=path, error=str(exc))
                    stability.pop(key, None)
                    _emit_failure(
                        tracker,
                        "scan_failed",
                        "warning",
                        f"Unsafe web-download item was rejected: {exc}",
                        source_path=str(path),
                        action_success=False,
                    )
                    continue
                except OSError as exc:
                    log("stat_failed", path=path, error=str(exc))
                    stability.pop(key, None)
                    continue

                previous = stability.get(key)
                if previous is None or previous.fingerprint != current:
                    stability[key] = Stability(current, now)
                    continue
                if now - previous.unchanged_since < SETTLE_SECONDS or not processor.reserve(path):
                    continue
                stability.pop(key, None)
                processing_futures[workers.submit(processor.process, path)] = path

            current_keys = {processor.key(path) for path in current_paths}
            for stale_key in list(stability):
                if stale_key not in current_keys:
                    stability.pop(stale_key, None)

            pending_keys = {processor.key(path) for path in discovery_futures.values()}
            available = DISCOVERY_QUEUE - len(discovery_futures)
            if current_paths and available > 0:
                start = discovery_cursor % len(current_paths)
                ordered = current_paths[start:] + current_paths[:start]
                submitted = 0
                for path in ordered:
                    key = processor.key(path)
                    if key in pending_keys or processor.is_active(path):
                        continue
                    discovery_futures[
                        discovery.submit(fingerprint, path, incomplete_suffixes=TEMP_SUFFIXES)
                    ] = path
                    pending_keys.add(key)
                    submitted += 1
                    if submitted >= available:
                        break
                discovery_cursor = (start + max(submitted, 1)) % len(current_paths)

            stop.wait(POLL_SECONDS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
