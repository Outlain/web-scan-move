#!/usr/bin/env python3
"""Reliable scan-and-promote service for completed web downloads.

Design goals:
- Processes items already present when the container starts.
- Does not depend on a single inotify event being delivered.
- Does not block discovery while one item is settling or scanning.
- Treats files and directories consistently.
- Sends infected files *and directories* to quarantine.
- Never overwrites an existing destination.
- Re-checks the item after scanning so changed data is not promoted as clean.
- Uses temporary destination names for cross-filesystem copies.

This service intentionally uses polling. For an intake directory, correctness and
restart recovery are more important than reacting within a fraction of a second.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

WATCH_DIR = Path(os.environ.get("WATCH_DIR", "/watch"))
DEST_DIR = Path(os.environ.get("DEST_DIR", "/dest"))
QUARANTINE_DIR = Path(os.environ.get("QUARANTINE_DIR", "/quarantine"))
POLL_SECONDS = max(float(os.environ.get("POLL_SECONDS", "5")), 1.0)
SETTLE_SECONDS = max(float(os.environ.get("SETTLE_SECONDS", "30")), 5.0)
MAX_WORKERS = max(int(os.environ.get("MAX_SCAN_WORKERS", "1")), 1)
CLAMSCAN_BINARY = os.environ.get("CLAMSCAN_BINARY", "clamscan")
CLAMSCAN_EXTRA_ARGS = shlex.split(os.environ.get("CLAMSCAN_EXTRA_ARGS", ""))
DEFINITIONS_DIR = Path(os.environ.get("DEFINITIONS_DIR", "/var/lib/clamav"))
MAX_DEFINITION_AGE_SECONDS = max(int(os.environ.get("MAX_DEFINITION_AGE_SECONDS", "172800")), 300)
SCAN_TIMEOUT_SECONDS = max(int(os.environ.get("SCAN_TIMEOUT_SECONDS", "7200")), 60)

TEMP_SUFFIXES = tuple(
    suffix.strip().casefold()
    for suffix in os.environ.get(
        "INCOMPLETE_SUFFIXES",
        ".part,.tmp,.crdownload,.aria2,.partial,.download,.!qb",
    ).split(",")
    if suffix.strip()
)


class UnsafePathError(RuntimeError):
    pass


class DefinitionsUnavailable(RuntimeError):
    pass


def _definition_candidate(stem: str) -> Path:
    available: list[tuple[int, Path]] = []
    for suffix in ("cld", "cvd"):
        path = DEFINITIONS_DIR / f"{stem}.{suffix}"
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_size > 0 and os.access(path, os.R_OK):
            available.append((info.st_mtime_ns, path))
    if not available:
        raise DefinitionsUnavailable(
            f"missing readable {stem}.cld/{stem}.cvd in {DEFINITIONS_DIR}"
        )
    return max(available, key=lambda item: item[0])[1]


def check_definitions() -> None:
    _definition_candidate("main")
    daily = _definition_candidate("daily")
    age = max(0, int(time.time() - daily.stat().st_mtime))
    if age > MAX_DEFINITION_AGE_SECONDS:
        raise DefinitionsUnavailable(
            f"daily definitions are stale: age={age}s max={MAX_DEFINITION_AGE_SECONDS}s"
        )


@dataclass(frozen=True)
class Fingerprint:
    digest: str
    files: int
    bytes: int


@dataclass
class Stability:
    fingerprint: Fingerprint
    unchanged_since: float


class ItemProcessor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._clamscan_args = self._build_clamscan_args()

    def _build_clamscan_args(self) -> list[str]:
        args = ["--infected", "--no-summary", "--recursive"]
        try:
            help_result = subprocess.run(
                [CLAMSCAN_BINARY, "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
                check=False,
            )
            help_text = help_result.stdout or ""
        except Exception:
            help_text = ""

        # Fail closed when the installed ClamAV supports this option. Without it,
        # files that exceed engine limits may otherwise be skipped as clean.
        if "--alert-exceeds-max" in help_text:
            args.append("--alert-exceeds-max=yes")

        args.extend(CLAMSCAN_EXTRA_ARGS)
        return args

    def reserve(self, path: Path) -> bool:
        key = os.fsdecode(os.fsencode(path))
        with self._lock:
            if key in self._active:
                return False
            self._active.add(key)
            return True

    def release(self, path: Path) -> None:
        key = os.fsdecode(os.fsencode(path))
        with self._lock:
            self._active.discard(key)

    def process(self, path: Path) -> None:
        try:
            self._process_reserved(path)
        finally:
            self.release(path)

    def _process_reserved(self, path: Path) -> None:
        if not path.exists():
            return

        try:
            before = fingerprint(path)
        except (OSError, UnsafePathError) as exc:
            log("unsafe_or_unavailable", path=path, error=str(exc))
            return

        try:
            check_definitions()
        except DefinitionsUnavailable as exc:
            log("definitions_unavailable", path=path, error=str(exc))
            return

        log("scan_started", path=path, files=before.files, bytes=before.bytes)
        try:
            result = subprocess.run(
                [CLAMSCAN_BINARY, *self._clamscan_args, "--", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            log("scan_timeout", path=path, timeout_seconds=SCAN_TIMEOUT_SECONDS, output=exc.stdout or "")
            return
        except OSError as exc:
            log("scan_start_failed", path=path, error=str(exc))
            return
        output = result.stdout or ""

        try:
            after = fingerprint(path)
        except (OSError, UnsafePathError) as exc:
            log("changed_or_unavailable_after_scan", path=path, error=str(exc), output=output)
            return

        if before != after:
            log(
                "changed_during_scan",
                path=path,
                before=before.digest,
                after=after.digest,
                output=output,
            )
            return

        if "Heuristics.Limits.Exceeded" in output:
            log(
                "scan_policy_error",
                path=path,
                returncode=result.returncode,
                output=output,
            )
            return

        if result.returncode == 0:
            target_root = DEST_DIR
            verdict = "clean"
        elif result.returncode == 1:
            target_root = QUARANTINE_DIR
            verdict = "infected"
        else:
            log(
                "scan_error",
                path=path,
                returncode=result.returncode,
                output=output,
            )
            return

        try:
            destination = move_safely(path, target_root, expected=after)
        except Exception as exc:
            log(
                "move_failed",
                path=path,
                verdict=verdict,
                target_root=target_root,
                error=str(exc),
                output=output,
            )
            return

        log(
            "moved",
            path=path,
            destination=destination,
            verdict=verdict,
            output=output,
        )


def log(event: str, **fields: object) -> None:
    payload = {"time": int(time.time()), "event": event}
    for key, value in fields.items():
        if isinstance(value, Path):
            payload[key] = str(value)
        else:
            payload[key] = value
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


def has_incomplete_suffix(path: Path) -> bool:
    name = path.name.casefold()
    return any(name.endswith(suffix) for suffix in TEMP_SUFFIXES)


def _safe_lstat(path: Path) -> os.stat_result:
    info = path.lstat()
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        raise UnsafePathError(f"symbolic links are not accepted: {path}")
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise UnsafePathError(f"non-regular item is not accepted: {path}")
    return info


def iter_tree(root: Path) -> Iterable[tuple[str, os.stat_result]]:
    root_info = _safe_lstat(root)
    if stat.S_ISREG(root_info.st_mode):
        if has_incomplete_suffix(root):
            raise UnsafePathError(f"incomplete-file suffix is still present: {root}")
        yield ".", root_info
        return

    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names.sort()
        file_names.sort()

        for directory_name in list(directory_names):
            child = current / directory_name
            child_info = _safe_lstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                raise UnsafePathError(f"unexpected directory entry type: {child}")
            relative = child.relative_to(root).as_posix() + "/"
            yield relative, child_info

        for file_name in file_names:
            child = current / file_name
            if has_incomplete_suffix(child):
                raise UnsafePathError(f"incomplete file is still present: {child}")
            child_info = _safe_lstat(child)
            if not stat.S_ISREG(child_info.st_mode):
                raise UnsafePathError(f"non-regular file is not accepted: {child}")
            relative = child.relative_to(root).as_posix()
            yield relative, child_info


def fingerprint(root: Path) -> Fingerprint:
    digest = hashlib.sha256()
    files = 0
    byte_count = 0
    for relative, info in iter_tree(root):
        encoded = os.fsencode(relative)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(info.st_dev.to_bytes(8, "big", signed=False))
        digest.update(info.st_ino.to_bytes(8, "big", signed=False))
        digest.update(info.st_size.to_bytes(16, "big", signed=False))
        digest.update(info.st_mtime_ns.to_bytes(16, "big", signed=True))
        digest.update(info.st_ctime_ns.to_bytes(16, "big", signed=True))
        if not relative.endswith("/"):
            files += 1
            byte_count += info.st_size
    return Fingerprint(digest.hexdigest(), files, byte_count)


def unique_destination(root: Path, source_name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    candidate = root / source_name
    if not candidate.exists() and not candidate.is_symlink():
        return candidate

    source = Path(source_name)
    stem = source.stem
    suffix = source.suffix
    for index in range(1, 100_000):
        candidate = root / f"{stem}_{index}{suffix}"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise RuntimeError(f"unable to allocate a destination name for {source_name}")


def _copy_file_verified(source: Path, destination: Path, expected: Fingerprint) -> None:
    temp = destination.parent / f".{destination.name}.partial-{uuid.uuid4().hex}"
    try:
        with source.open("rb") as src, temp.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        shutil.copystat(source, temp, follow_symlinks=False)

        if fingerprint(source) != expected:
            raise RuntimeError("source changed while it was being copied")
        if fingerprint(temp).bytes != expected.bytes:
            raise RuntimeError("copied file size does not match source")

        os.rename(temp, destination)
        source.unlink()
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def _copy_directory_verified(source: Path, destination: Path, expected: Fingerprint) -> None:
    temp = destination.parent / f".{destination.name}.partial-{uuid.uuid4().hex}"
    try:
        shutil.copytree(source, temp, symlinks=False, copy_function=shutil.copy2)
        copied = fingerprint(temp)
        current_source = fingerprint(source)
        if current_source != expected:
            raise RuntimeError("source directory changed while it was being copied")
        if copied.files != expected.files or copied.bytes != expected.bytes:
            raise RuntimeError("copied directory contents do not match source")

        os.rename(temp, destination)
        shutil.rmtree(source)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def move_safely(source: Path, target_root: Path, *, expected: Fingerprint) -> Path:
    if fingerprint(source) != expected:
        raise RuntimeError("source changed after scanning and before move")
    destination = unique_destination(target_root, source.name)
    try:
        os.rename(source, destination)
        return destination
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise

    # Cross-filesystem move: copy to a hidden temporary name, verify, atomically
    # reveal it on the destination filesystem, and only then remove the source.
    if source.is_dir():
        _copy_directory_verified(source, destination, expected)
    else:
        _copy_file_verified(source, destination, expected)
    return destination


def list_top_level_items() -> list[Path]:
    try:
        with os.scandir(WATCH_DIR) as entries:
            return sorted((Path(entry.path) for entry in entries), key=lambda item: os.fsencode(item.name))
    except FileNotFoundError:
        WATCH_DIR.mkdir(parents=True, exist_ok=True)
        return []


def healthcheck() -> int:
    try:
        check_definitions()
        for directory in (WATCH_DIR, DEST_DIR, QUARANTINE_DIR):
            if not directory.is_dir():
                raise RuntimeError(f"required directory is unavailable: {directory}")
        print("healthy")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    if "--healthcheck" in sys.argv:
        return healthcheck()
    for directory in (WATCH_DIR, DEST_DIR, QUARANTINE_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    processor = ItemProcessor()
    stability: dict[str, Stability] = {}
    futures: dict[Future[None], Path] = {}

    log(
        "service_started",
        watch=WATCH_DIR,
        destination=DEST_DIR,
        quarantine=QUARANTINE_DIR,
        settle_seconds=SETTLE_SECONDS,
        max_workers=MAX_WORKERS,
        clamscan_args=processor._clamscan_args,
        definitions=DEFINITIONS_DIR,
        max_definition_age_seconds=MAX_DEFINITION_AGE_SECONDS,
        scan_timeout_seconds=SCAN_TIMEOUT_SECONDS,
    )

    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="clamav-intake") as executor:
        while True:
            for future, path in list(futures.items()):
                if not future.done():
                    continue
                futures.pop(future, None)
                try:
                    future.result()
                except Exception as exc:
                    log("worker_crashed", path=path, error=str(exc))

            current_paths = list_top_level_items()
            current_keys = {os.fsdecode(os.fsencode(path)) for path in current_paths}
            for stale_key in list(stability):
                if stale_key not in current_keys:
                    stability.pop(stale_key, None)

            now = time.monotonic()
            for path in current_paths:
                key = os.fsdecode(os.fsencode(path))
                try:
                    current = fingerprint(path)
                except UnsafePathError as exc:
                    # Incomplete suffixes are expected while a download is active.
                    log("not_ready", path=path, reason=str(exc))
                    stability.pop(key, None)
                    continue
                except OSError as exc:
                    log("stat_failed", path=path, error=str(exc))
                    stability.pop(key, None)
                    continue

                previous = stability.get(key)
                if previous is None or previous.fingerprint != current:
                    stability[key] = Stability(current, now)
                    continue

                if now - previous.unchanged_since < SETTLE_SECONDS:
                    continue
                if not processor.reserve(path):
                    continue

                stability.pop(key, None)
                future = executor.submit(processor.process, path)
                futures[future] = path

            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
