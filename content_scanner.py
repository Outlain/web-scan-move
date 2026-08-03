#!/usr/bin/env python3
"""Bounded routing for native, oversized-media, and ZIP scans."""

from __future__ import annotations

import json
import os
import stat
import struct
import subprocess
import time
import zipfile
from pathlib import Path

from clamd_client import ClamdClient, ClamdError, ClamdPolicyError, FileIdentity, ScanResult

MAX_FFPROBE_OUTPUT_BYTES = 1024 * 1024
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
ZIP_EOCD_MIN_BYTES = 22
ZIP_EOCD_MAX_BYTES = ZIP_EOCD_MIN_BYTES + 65535
MEDIA_FORMATS = frozenset(
    {"avi", "matroska", "mov", "mp4", "mpeg", "mpegts", "ogg", "webm"}
)
MEDIA_STREAM_TYPES = frozenset({"audio", "attachment", "subtitle", "video"})
SAFE_ATTACHMENT_SUFFIXES = frozenset(
    {
        ".ass",
        ".gif",
        ".jpeg",
        ".jpg",
        ".nfo",
        ".otf",
        ".png",
        ".srt",
        ".ssa",
        ".ttf",
        ".txt",
        ".webp",
        ".woff",
        ".woff2",
    }
)
NESTED_ARCHIVE_SUFFIXES = frozenset(
    {
        ".7z",
        ".bz2",
        ".dmg",
        ".gz",
        ".img",
        ".iso",
        ".rar",
        ".tar",
        ".tbz",
        ".tgz",
        ".txz",
        ".vhd",
        ".vhdx",
        ".xz",
        ".zip",
    }
)
NESTED_ARCHIVE_MAGIC = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
)


def window_ranges(total_bytes: int, window_bytes: int, overlap_bytes: int) -> list[tuple[int, int]]:
    if total_bytes < 0 or window_bytes <= 0:
        raise ValueError("invalid large-media size or window")
    if overlap_bytes < 0 or overlap_bytes >= window_bytes:
        raise ValueError("large-media overlap must be smaller than its window")
    if total_bytes == 0:
        return [(0, 0)]
    result: list[tuple[int, int]] = []
    offset = 0
    step = window_bytes - overlap_bytes
    while offset < total_bytes:
        length = min(window_bytes, total_bytes - offset)
        result.append((offset, length))
        if offset + length >= total_bytes:
            break
        offset += step
    return result


def parse_media_probe(raw_output: str, path: Path) -> str:
    try:
        payload = json.loads(raw_output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ClamdPolicyError(f"oversized file is not a valid video container: {path}") from exc
    if not isinstance(payload, dict):
        raise ClamdPolicyError(f"ffprobe returned an invalid media description: {path}")
    format_payload = payload.get("format")
    format_name = format_payload.get("format_name") if isinstance(format_payload, dict) else None
    detected = {
        part.strip().casefold()
        for part in str(format_name or "").split(",")
        if part.strip()
    }
    approved = detected & MEDIA_FORMATS
    if not approved:
        label = ",".join(sorted(detected)) or "unknown"
        raise ClamdPolicyError(
            f"oversized content is not an approved video container ({label}): {path}"
        )

    streams = payload.get("streams")
    if not isinstance(streams, list) or len(streams) > 1024:
        raise ClamdPolicyError(f"oversized media has an invalid or excessive stream table: {path}")
    videos = 0
    attachments = 0
    for stream in streams:
        if not isinstance(stream, dict):
            raise ClamdPolicyError(f"oversized media has a malformed stream entry: {path}")
        stream_type = str(stream.get("codec_type") or "").casefold()
        if stream_type not in MEDIA_STREAM_TYPES:
            raise ClamdPolicyError(
                f"oversized media has unsupported stream type {stream_type or 'unknown'}: {path}"
            )
        if stream_type == "video":
            videos += 1
        elif stream_type == "attachment":
            attachments += 1
            if attachments > 64:
                raise ClamdPolicyError(f"oversized media contains too many attachments: {path}")
            tags = stream.get("tags")
            filename = tags.get("filename") if isinstance(tags, dict) else None
            suffix = Path(str(filename or "")).suffix.casefold()
            if suffix not in SAFE_ATTACHMENT_SUFFIXES:
                raise ClamdPolicyError(
                    "oversized media contains an attachment that is not a recognized font, "
                    f"image, subtitle, or text file ({filename or 'unnamed'}): {path}"
                )
    if videos == 0:
        raise ClamdPolicyError(f"oversized container has no video stream: {path}")
    return ",".join(sorted(approved))


def _is_zip_descriptor(descriptor: int) -> bool:
    return os.pread(descriptor, 4, 0) in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}


def _is_nested_archive(name: str, header: bytes) -> bool:
    lowered = name.casefold()
    if any(lowered.endswith(suffix) for suffix in NESTED_ARCHIVE_SUFFIXES):
        return True
    return any(header.startswith(magic) for magic in NESTED_ARCHIVE_MAGIC)


def _validate_zip_directory(
    descriptor: int,
    path: Path,
    source_size: int,
    maximum_entries: int,
) -> None:
    tail_size = min(source_size, ZIP_EOCD_MAX_BYTES)
    tail = os.pread(descriptor, tail_size, source_size - tail_size)
    position = tail.rfind(b"PK\x05\x06")
    while position >= 0:
        if position + ZIP_EOCD_MIN_BYTES <= len(tail):
            (
                _signature,
                disk_number,
                central_disk,
                entries_on_disk,
                total_entries,
                central_size,
                _central_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", tail, position)
            if position + ZIP_EOCD_MIN_BYTES + comment_size == len(tail):
                if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
                    raise ClamdPolicyError(f"multi-disk ZIP archives are not supported: {path}")
                if total_entries > maximum_entries:
                    raise ClamdPolicyError(
                        f"ZIP contains {total_entries} entries; limit is {maximum_entries}: {path}"
                    )
                if central_size == 0xFFFFFFFF:
                    raise ClamdPolicyError(
                        f"ZIP64 central directory is too large to preflight safely: {path}"
                    )
                if central_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
                    raise ClamdPolicyError(
                        "ZIP central-directory metadata exceeds the fixed 64 MiB memory-safety "
                        f"limit: {path}"
                    )
                if central_size > source_size:
                    raise ClamdPolicyError(f"ZIP central-directory size is invalid: {path}")
                return
        position = tail.rfind(b"PK\x05\x06", 0, position)
    raise ClamdPolicyError(f"ZIP end-of-central-directory record is missing or malformed: {path}")


class ContentScanner:
    def __init__(
        self,
        clamd: ClamdClient,
        *,
        large_media_enabled: bool,
        large_media_max_bytes: int,
        large_media_window_bytes: int,
        large_media_overlap_bytes: int,
        large_media_probe_timeout_seconds: int,
        large_media_scan_timeout_seconds: int,
        ffprobe_binary: str,
        archive_scan_enabled: bool,
        archive_max_source_bytes: int,
        archive_max_total_bytes: int,
        archive_max_entries: int,
        archive_max_compression_ratio: int,
        archive_scan_timeout_seconds: int,
    ) -> None:
        self.clamd = clamd
        self.large_media_enabled = large_media_enabled
        self.large_media_max_bytes = large_media_max_bytes
        self.large_media_window_bytes = large_media_window_bytes
        self.large_media_overlap_bytes = large_media_overlap_bytes
        self.large_media_probe_timeout_seconds = large_media_probe_timeout_seconds
        self.large_media_scan_timeout_seconds = large_media_scan_timeout_seconds
        self.ffprobe_binary = ffprobe_binary
        self.archive_scan_enabled = archive_scan_enabled
        self.archive_max_source_bytes = archive_max_source_bytes
        self.archive_max_total_bytes = archive_max_total_bytes
        self.archive_max_entries = archive_max_entries
        self.archive_max_compression_ratio = archive_max_compression_ratio
        self.archive_scan_timeout_seconds = archive_scan_timeout_seconds

    def scan_file(self, path: Path) -> ScanResult:
        descriptor, original = self._open(path)
        try:
            if self.archive_scan_enabled and _is_zip_descriptor(descriptor):
                # ZIPs are intentionally handled by the bounded entry reader in
                # this service. This makes the bomb, nesting, entry-count, and
                # decompressed-byte policy deterministic instead of depending on
                # which native ClamAV parser limit happens to be reached first.
                return self._scan_zip(descriptor, path, original)
            if original.size <= self.clamd.max_stream_bytes:
                return self.clamd.scan_file(path)
            return self._scan_large_media(descriptor, path, original)
        finally:
            os.close(descriptor)

    @staticmethod
    def _open(path: Path) -> tuple[int, FileIdentity]:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ClamdError(f"cannot safely open {path}: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ClamdError(f"refusing to scan a non-regular file: {path}")
            identity = FileIdentity.from_stat(info)
            ContentScanner._verify_identity(descriptor, path, identity)
            return descriptor, identity
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _verify_identity(descriptor: int, path: Path, expected: FileIdentity) -> None:
        try:
            descriptor_identity = FileIdentity.from_stat(os.fstat(descriptor))
            path_info = path.lstat()
        except OSError as exc:
            raise ClamdError(f"source disappeared while it was scanned: {path}: {exc}") from exc
        if (
            descriptor_identity != expected
            or FileIdentity.from_stat(path_info) != expected
            or not stat.S_ISREG(path_info.st_mode)
        ):
            raise ClamdError(f"source changed or was replaced while it was scanned: {path}")

    def _scan_large_media(
        self,
        descriptor: int,
        path: Path,
        original: FileIdentity,
    ) -> ScanResult:
        if not self.large_media_enabled:
            raise ClamdPolicyError(
                f"file exceeds native ClamD size and large-media scanning is disabled: {path}"
            )
        if original.size > self.large_media_max_bytes:
            raise ClamdPolicyError(
                f"file exceeds bounded large-media ceiling: {original.size} > "
                f"{self.large_media_max_bytes}: {path}"
            )
        if self.large_media_window_bytes > self.clamd.max_stream_bytes:
            raise ClamdPolicyError("large-media window exceeds native ClamD stream limit")
        try:
            ranges = window_ranges(
                original.size,
                self.large_media_window_bytes,
                self.large_media_overlap_bytes,
            )
        except ValueError as exc:
            raise ClamdPolicyError(f"invalid large-media window policy: {exc}") from exc

        deadline = time.monotonic() + max(self.large_media_scan_timeout_seconds, 60)
        media_format = self._probe(descriptor, path, deadline=deadline)
        self._verify_identity(descriptor, path, original)
        for index, (offset, length) in enumerate(ranges, start=1):
            if time.monotonic() >= deadline:
                raise ClamdPolicyError("large-media scan exceeded its total time limit")
            result = self.clamd.scan_descriptor_range(
                descriptor,
                offset,
                length,
                deadline=deadline,
            )
            self._verify_identity(descriptor, path, original)
            if result.infected:
                return ScanResult(
                    True,
                    result.threat_name,
                    f"large-media window={index}/{len(ranges)} offset={offset}: {result.response}",
                    "large_media_full_byte_windows",
                )
        return ScanResult(
            False,
            None,
            f"large-media format={media_format} windows={len(ranges)} coverage=all-bytes",
            "large_media_full_byte_windows",
        )

    def _probe(
        self,
        descriptor: int,
        path: Path,
        *,
        deadline: float | None = None,
    ) -> str:
        command = [
            self.ffprobe_binary,
            "-v",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-show_entries",
            "format=format_name:stream=index,codec_type,codec_name:stream_tags=filename,mimetype",
            "-of",
            "json",
            f"/proc/self/fd/{descriptor}",
        ]
        probe_timeout = max(float(self.large_media_probe_timeout_seconds), 1.0)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClamdPolicyError(f"oversized media validation timed out: {path}")
            probe_timeout = min(probe_timeout, remaining)
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=probe_timeout,
                check=False,
                pass_fds=(descriptor,),
            )
        except FileNotFoundError as exc:
            raise ClamdError(f"ffprobe is unavailable: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ClamdPolicyError(f"oversized media validation timed out: {path}") from exc
        if len(completed.stdout.encode("utf-8", "replace")) > MAX_FFPROBE_OUTPUT_BYTES:
            raise ClamdPolicyError(f"oversized media has an excessive stream description: {path}")
        if completed.returncode != 0:
            detail = " ".join(completed.stderr.strip().split())[:500]
            raise ClamdPolicyError(
                f"oversized file failed video-container validation{': ' + detail if detail else ''}: {path}"
            )
        return parse_media_probe(completed.stdout, path)

    def _scan_zip(
        self,
        descriptor: int,
        path: Path,
        original: FileIdentity,
    ) -> ScanResult:
        if original.size > self.archive_max_source_bytes:
            raise ClamdPolicyError(
                f"ZIP source exceeds bounded archive size: {original.size} > "
                f"{self.archive_max_source_bytes}: {path}"
            )
        _validate_zip_directory(descriptor, path, original.size, self.archive_max_entries)
        deadline = time.monotonic() + max(self.archive_scan_timeout_seconds, 60)
        try:
            with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source, zipfile.ZipFile(source) as archive:
                entries = archive.infolist()
                if len(entries) > self.archive_max_entries:
                    raise ClamdPolicyError(
                        f"ZIP contains {len(entries)} entries; limit is {self.archive_max_entries}: {path}"
                    )
                regular_entries: list[zipfile.ZipInfo] = []
                declared_total = 0
                for entry in entries:
                    if entry.is_dir():
                        continue
                    if entry.flag_bits & 0x1:
                        raise ClamdPolicyError(f"encrypted ZIP entry cannot be inspected: {entry.filename}")
                    mode_type = stat.S_IFMT(entry.external_attr >> 16)
                    if mode_type not in {0, stat.S_IFREG}:
                        raise ClamdPolicyError(
                            f"ZIP symlink or special entry is not allowed: {entry.filename}"
                        )
                    if entry.file_size > self.clamd.max_stream_bytes:
                        raise ClamdPolicyError(
                            f"ZIP entry exceeds native ClamD stream limit: {entry.filename}"
                        )
                    ratio = (
                        entry.file_size / entry.compress_size
                        if entry.compress_size > 0
                        else (float("inf") if entry.file_size else 1.0)
                    )
                    if ratio > self.archive_max_compression_ratio:
                        raise ClamdPolicyError(
                            f"ZIP entry compression ratio exceeds {self.archive_max_compression_ratio}: "
                            f"{entry.filename}"
                        )
                    declared_total += entry.file_size
                    if declared_total > self.archive_max_total_bytes:
                        raise ClamdPolicyError(
                            f"ZIP expands beyond {self.archive_max_total_bytes} bytes: {path}"
                        )
                    regular_entries.append(entry)
                if not regular_entries:
                    raise ClamdPolicyError(f"ZIP contains no regular files to inspect: {path}")

                actual_total = 0
                for entry in regular_entries:
                    if time.monotonic() >= deadline:
                        raise ClamdPolicyError("bounded ZIP scan exceeded its total time limit")
                    with archive.open(entry, "r") as header_reader:
                        header = header_reader.read(1024)
                    if _is_nested_archive(entry.filename, header):
                        raise ClamdPolicyError(
                            f"nested archive is held instead of recursively expanding it: {entry.filename}"
                        )
                    with archive.open(entry, "r") as reader:
                        result, actual_bytes = self.clamd.scan_reader(
                            reader,
                            maximum_bytes=entry.file_size,
                            deadline=deadline,
                        )
                    if actual_bytes != entry.file_size:
                        raise ClamdPolicyError(
                            f"ZIP entry size changed while it was decompressed: {entry.filename}"
                        )
                    actual_total += actual_bytes
                    if actual_total > self.archive_max_total_bytes:
                        raise ClamdPolicyError("ZIP actual expanded bytes exceeded the total limit")
                    self._verify_identity(descriptor, path, original)
                    if result.infected:
                        return ScanResult(
                            True,
                            result.threat_name,
                            f"ZIP entry {entry.filename}: {result.response}",
                            "bounded_zip_entries",
                        )
        except ClamdPolicyError:
            raise
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            NotImplementedError,
            RuntimeError,
            OSError,
            ValueError,
        ) as exc:
            raise ClamdPolicyError(f"ZIP could not be completely and safely inspected: {path}: {exc}") from exc
        self._verify_identity(descriptor, path, original)
        return ScanResult(
            False,
            None,
            f"ZIP entries={len(regular_entries)} expanded_bytes={actual_total} coverage=all-entries",
            "bounded_zip_entries",
        )
