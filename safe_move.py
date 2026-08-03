#!/usr/bin/env python3
"""Tree validation and crash-recoverable, no-overwrite movement helpers."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

PARTIAL_PREFIX = ".web-scan-move-partial-"
JOURNAL_SUFFIX = ".json"


class UnsafePathError(RuntimeError):
    pass


class IncompleteItemError(UnsafePathError):
    pass


@dataclass(frozen=True)
class Fingerprint:
    digest: str
    portable_digest: str
    files: int
    bytes: int


@dataclass(frozen=True)
class RootIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "RootIdentity":
        return cls(value.st_dev, value.st_ino)


def _safe_lstat(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise UnsafePathError(f"symbolic links are not accepted: {path}")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise UnsafePathError(f"special files are not accepted: {path}")
    return info


def has_incomplete_suffix(path: Path, suffixes: tuple[str, ...]) -> bool:
    name = path.name.casefold()
    return any(name.endswith(suffix) for suffix in suffixes)


def iter_tree(
    root: Path,
    *,
    incomplete_suffixes: tuple[str, ...] = (),
) -> Iterable[tuple[str, os.stat_result]]:
    root_info = _safe_lstat(root)
    if stat.S_ISREG(root_info.st_mode):
        if has_incomplete_suffix(root, incomplete_suffixes):
            raise IncompleteItemError(f"incomplete-file suffix is still present: {root}")
        yield ".", root_info
        return

    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names.sort(key=os.fsencode)
        file_names.sort(key=os.fsencode)
        for directory_name in list(directory_names):
            child = current / directory_name
            child_info = _safe_lstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                raise UnsafePathError(f"unexpected directory entry type: {child}")
            yield child.relative_to(root).as_posix() + "/", child_info
        for file_name in file_names:
            child = current / file_name
            if has_incomplete_suffix(child, incomplete_suffixes):
                raise IncompleteItemError(f"incomplete file is still present: {child}")
            child_info = _safe_lstat(child)
            if not stat.S_ISREG(child_info.st_mode):
                raise UnsafePathError(f"non-regular file is not accepted: {child}")
            yield child.relative_to(root).as_posix(), child_info


def regular_files(root: Path, *, incomplete_suffixes: tuple[str, ...] = ()) -> Iterable[Path]:
    for relative, info in iter_tree(root, incomplete_suffixes=incomplete_suffixes):
        if stat.S_ISREG(info.st_mode):
            yield root if relative == "." else root / relative


def fingerprint(root: Path, *, incomplete_suffixes: tuple[str, ...] = ()) -> Fingerprint:
    identity_digest = hashlib.sha256()
    portable_digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for relative, info in iter_tree(root, incomplete_suffixes=incomplete_suffixes):
        encoded = os.fsencode(relative)
        common = (
            len(encoded).to_bytes(8, "big")
            + encoded
            + stat.S_IFMT(info.st_mode).to_bytes(8, "big")
            + stat.S_IMODE(info.st_mode).to_bytes(8, "big")
            + info.st_mtime_ns.to_bytes(16, "big", signed=True)
        )
        portable_digest.update(common)
        identity_digest.update(common)
        identity_digest.update(info.st_dev.to_bytes(8, "big", signed=False))
        identity_digest.update(info.st_ino.to_bytes(8, "big", signed=False))
        identity_digest.update(info.st_ctime_ns.to_bytes(16, "big", signed=True))
        if stat.S_ISREG(info.st_mode):
            size = info.st_size
            file_count += 1
            byte_count += size
            portable_digest.update(size.to_bytes(16, "big", signed=False))
            identity_digest.update(size.to_bytes(16, "big", signed=False))
    return Fingerprint(
        identity_digest.hexdigest(),
        portable_digest.hexdigest(),
        file_count,
        byte_count,
    )


def _real_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UnsafePathError(f"target root is not a real directory: {path}")


def destination_candidates(root: Path, source_name: str) -> Iterable[Path]:
    source = Path(source_name)
    yield root / source_name
    for index in range(1, 100_000):
        yield root / f"{source.stem}_{index}{source.suffix}"


def unique_destination(root: Path, source_name: str) -> Path:
    _real_directory(root)
    for candidate in destination_candidates(root, source_name):
        try:
            candidate.lstat()
        except FileNotFoundError:
            return candidate
    raise RuntimeError(f"unable to allocate a destination name for {source_name}")


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename without replacing an existing entry (Linux renameat2)."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
        if result == 0:
            return
        error = ctypes.get_errno()
        if error not in {errno.ENOSYS, errno.EINVAL}:
            raise OSError(error, os.strerror(error), str(destination))

    source_info = _safe_lstat(source)
    if not stat.S_ISREG(source_info.st_mode):
        raise OSError(errno.ENOTSUP, "atomic no-replace directory rename is unavailable")
    os.link(source, destination, follow_symlinks=False)
    source.unlink()


def _same_entry(path: Path, identity: RootIdentity) -> bool:
    try:
        return RootIdentity.from_stat(path.lstat()) == identity
    except FileNotFoundError:
        return False


def _copy_regular(source: Path, destination: Path) -> None:
    source_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    try:
        opened = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafePathError(f"copy source is not a regular file: {source}")
        opened_identity = RootIdentity.from_stat(opened)
        if not _same_entry(source, opened_identity):
            raise UnsafePathError(f"copy source was replaced while opening: {source}")

        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            stat.S_IMODE(opened.st_mode),
        )
        try:
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            os.fchmod(destination_descriptor, stat.S_IMODE(opened.st_mode))
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        os.utime(destination, ns=(opened.st_atime_ns, opened.st_mtime_ns), follow_symlinks=False)
        if RootIdentity.from_stat(os.fstat(source_descriptor)) != opened_identity:
            raise UnsafePathError(f"copy source identity changed: {source}")
        if not _same_entry(source, opened_identity):
            raise UnsafePathError(f"copy source path was replaced: {source}")
    finally:
        os.close(source_descriptor)


def _copy_directory(source: Path, temporary: Path) -> None:
    source_root = _safe_lstat(source)
    temporary.mkdir(mode=stat.S_IMODE(source_root.st_mode))
    copied_directories: list[tuple[Path, Path]] = [(source, temporary)]
    for current_root, directory_names, file_names in os.walk(source, followlinks=False):
        current = Path(current_root)
        relative = current.relative_to(source)
        target_current = temporary / relative
        directory_names.sort(key=os.fsencode)
        file_names.sort(key=os.fsencode)
        for directory_name in directory_names:
            child = current / directory_name
            child_info = _safe_lstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                raise UnsafePathError(f"unexpected directory entry during copy: {child}")
            target_child = target_current / directory_name
            target_child.mkdir(mode=stat.S_IMODE(child_info.st_mode))
            copied_directories.append((child, target_child))
        for file_name in file_names:
            child = current / file_name
            _safe_lstat(child)
            _copy_regular(child, target_current / file_name)
    for original, copied in reversed(copied_directories):
        _safe_lstat(original)
        shutil.copystat(original, copied, follow_symlinks=False)


def _copy_to_temporary(source: Path, temporary: Path) -> None:
    source_info = _safe_lstat(source)
    if stat.S_ISDIR(source_info.st_mode):
        _copy_directory(source, temporary)
    else:
        _copy_regular(source, temporary)


def _remove_owned_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


class MoveJournal:
    def __init__(self, state_dir: Path, identifier: str, data: dict[str, object]) -> None:
        self.state_dir = state_dir
        self.identifier = identifier
        self.data = data
        self.path = state_dir / f"{identifier}{JOURNAL_SUFFIX}"

    @classmethod
    def create(
        cls,
        state_dir: Path,
        source: Path,
        destination: Path,
        temporary: Path,
        expected: Fingerprint,
        source_identity: RootIdentity,
    ) -> "MoveJournal":
        identifier = str(uuid.uuid4())
        journal = cls(
            state_dir,
            identifier,
            {
                "schema_version": 1,
                "phase": "copying",
                "source": str(source),
                "destination": str(destination),
                "temporary": str(temporary),
                "expected": asdict(expected),
                "source_identity": asdict(source_identity),
            },
        )
        journal.write()
        return journal

    def write(self) -> None:
        self.state_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        _real_directory(self.state_dir)
        temporary = self.state_dir / f".{self.identifier}.tmp"
        encoded = (json.dumps(self.data, sort_keys=True) + "\n").encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_descriptor = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except Exception:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def update(self, phase: str, **values: object) -> None:
        self.data.update(values)
        self.data["phase"] = phase
        self.write()

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


def _publish_temporary(
    temporary: Path,
    target_root: Path,
    source_name: str,
    journal: MoveJournal,
) -> Path:
    for destination in destination_candidates(target_root, source_name):
        journal.update("ready", destination=str(destination))
        try:
            _rename_noreplace(temporary, destination)
            return destination
        except FileExistsError:
            continue
    raise RuntimeError(f"unable to allocate a destination name for {source_name}")


def _remove_original(source: Path, source_identity: RootIdentity) -> None:
    try:
        current = source.lstat()
    except FileNotFoundError:
        return
    if RootIdentity.from_stat(current) != source_identity:
        # A new item took the old name; it is unrelated and must remain queued.
        return
    _remove_owned_path(source)


def _fingerprint_from_mapping(value: object) -> Fingerprint:
    if not isinstance(value, dict):
        raise RuntimeError("journal fingerprint is invalid")
    return Fingerprint(
        digest=str(value["digest"]),
        portable_digest=str(value["portable_digest"]),
        files=int(value["files"]),
        bytes=int(value["bytes"]),
    )


def move_safely(
    source: Path,
    target_root: Path,
    *,
    expected: Fingerprint,
    state_dir: Path,
    incomplete_suffixes: tuple[str, ...] = (),
) -> Path:
    _real_directory(target_root)
    _real_directory(state_dir)
    if fingerprint(source, incomplete_suffixes=incomplete_suffixes) != expected:
        raise RuntimeError("source changed after scanning and before move")
    source_identity = RootIdentity.from_stat(_safe_lstat(source))

    for destination in destination_candidates(target_root, source.name):
        try:
            _rename_noreplace(source, destination)
            return destination
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            break
    else:
        raise RuntimeError(f"unable to allocate a destination name for {source.name}")

    temporary = target_root / f"{PARTIAL_PREFIX}{uuid.uuid4().hex}"
    initial_destination = unique_destination(target_root, source.name)
    journal = MoveJournal.create(
        state_dir,
        source,
        initial_destination,
        temporary,
        expected,
        source_identity,
    )
    published = False
    try:
        _copy_to_temporary(source, temporary)
        if fingerprint(source, incomplete_suffixes=incomplete_suffixes) != expected:
            raise RuntimeError("source changed while it was being copied")
        copied = fingerprint(temporary)
        if copied.portable_digest != expected.portable_digest:
            raise RuntimeError("copied content does not match the scanned source")
        temporary_identity = RootIdentity.from_stat(_safe_lstat(temporary))
        journal.update("ready", temporary_identity=asdict(temporary_identity))
        destination = _publish_temporary(temporary, target_root, source.name, journal)
        published = True
        destination_identity = RootIdentity.from_stat(_safe_lstat(destination))
        journal.update(
            "published",
            destination=str(destination),
            destination_identity=asdict(destination_identity),
        )
        if _same_entry(source, source_identity):
            if fingerprint(source, incomplete_suffixes=incomplete_suffixes) != expected:
                # Content added after publication is a new intake concern. Leave it
                # visible for another scan instead of deleting unscanned changes.
                journal.clear()
                return destination
            journal.update("deleting")
            _remove_original(source, source_identity)
        journal.clear()
        return destination
    except Exception:
        if not published:
            _remove_owned_path(temporary)
            journal.clear()
        raise


def recover_moves(
    state_dir: Path,
    *,
    watch_root: Path,
    destination_roots: tuple[Path, ...],
) -> list[str]:
    """Finish committed cross-filesystem moves; discard only unpublished partials."""
    recovered: list[str] = []
    _real_directory(state_dir)
    allowed_watch = watch_root.resolve(strict=True)
    allowed_destinations = tuple(root.resolve(strict=True) for root in destination_roots)
    for journal_path in sorted(state_dir.glob(f"*{JOURNAL_SUFFIX}")):
        try:
            data = json.loads(journal_path.read_text(encoding="utf-8"))
            source = Path(str(data["source"]))
            destination = Path(str(data["destination"]))
            temporary = Path(str(data["temporary"]))
            source_parent = source.parent.resolve(strict=True)
            destination_parent = destination.parent.resolve(strict=True)
            temporary_parent = temporary.parent.resolve(strict=True)
            if source_parent != allowed_watch:
                raise UnsafePathError(f"journal source is outside the watch root: {source}")
            if destination_parent not in allowed_destinations or temporary_parent not in allowed_destinations:
                raise UnsafePathError("journal destination is outside configured roots")
            source_identity = RootIdentity(**data["source_identity"])
            expected = _fingerprint_from_mapping(data["expected"])
            phase = str(data["phase"])
            temporary_identity_data = data.get("temporary_identity")
            destination_identity_data = data.get("destination_identity")

            committed = False
            destination_identity: RootIdentity | None = None
            if destination_identity_data:
                destination_identity = RootIdentity(**destination_identity_data)
            elif temporary_identity_data:
                destination_identity = RootIdentity(**temporary_identity_data)
            if phase in {"published", "deleting"} and destination_identity and _same_entry(destination, destination_identity):
                committed = True
            elif phase == "ready" and destination_identity and _same_entry(destination, destination_identity):
                # The process can die after renameat2 and before recording "published".
                committed = True

            if committed:
                if phase == "deleting":
                    _remove_original(source, source_identity)
                elif _same_entry(source, source_identity):
                    try:
                        unchanged = fingerprint(source) == expected
                    except (OSError, UnsafePathError):
                        unchanged = False
                    if unchanged:
                        _remove_original(source, source_identity)
                recovered.append(str(destination))
            else:
                _remove_owned_path(temporary)
            journal_path.unlink()
        except Exception as exc:
            raise RuntimeError(f"cannot safely recover {journal_path}: {exc}") from exc
    return recovered
