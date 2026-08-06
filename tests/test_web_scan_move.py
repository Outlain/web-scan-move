from __future__ import annotations

import errno
import json
import os
import socket
import stat
import struct
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import clamd_client
import content_scanner
import event_writer
import safe_move
import web_scan_move as service


class FakeClamd:
    def __init__(self, infected_name: str | None = None) -> None:
        self.infected_name = infected_name
        self.max_stream_bytes = 1024 * 1024

    def health(self) -> SimpleNamespace:
        return SimpleNamespace(raw_version="ClamAV test/1/current")

    def scan_file(self, path: Path) -> clamd_client.ScanResult:
        if path.name == self.infected_name:
            return clamd_client.ScanResult(True, "Test.Eicar", "stream: Test.Eicar FOUND")
        return clamd_client.ScanResult(False, None, "stream: OK")


class PolicyLimitClamd(FakeClamd):
    def scan_file(self, path: Path) -> clamd_client.ScanResult:
        raise clamd_client.ClamdPolicyError(f"scan limit exceeded: {path}")


class StreamingFakeClamd(FakeClamd):
    def __init__(self, max_stream_bytes: int = 32) -> None:
        super().__init__()
        self.max_stream_bytes = max_stream_bytes
        self.ranges: list[bytes] = []
        self.entries: list[bytes] = []

    def scan_descriptor_range(
        self,
        descriptor: int,
        offset: int,
        length: int,
        *,
        deadline: float | None = None,
    ) -> clamd_client.ScanResult:
        content = os.pread(descriptor, length, offset)
        self.ranges.append(content)
        infected = b"EICAR" in content
        return clamd_client.ScanResult(
            infected,
            "Test.Eicar" if infected else None,
            "stream: Test.Eicar FOUND" if infected else "stream: OK",
            "large_media_full_byte_windows",
        )

    def scan_reader(self, reader, *, maximum_bytes: int, deadline: float):
        content = reader.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise clamd_client.ClamdPolicyError("entry exceeded maximum")
        self.entries.append(content)
        infected = b"EICAR" in content
        return (
            clamd_client.ScanResult(
                infected,
                "Test.Eicar" if infected else None,
                "stream: Test.Eicar FOUND" if infected else "stream: OK",
                "bounded_zip_entries",
            ),
            len(content),
        )


def make_content_scanner(fake: FakeClamd) -> content_scanner.ContentScanner:
    return content_scanner.ContentScanner(
        fake,
        large_media_enabled=True,
        large_media_max_bytes=1024 * 1024,
        large_media_window_bytes=min(fake.max_stream_bytes, 16),
        large_media_overlap_bytes=min(fake.max_stream_bytes, 16) // 4,
        large_media_probe_timeout_seconds=5,
        large_media_scan_timeout_seconds=60,
        ffprobe_binary="/unused/ffprobe",
        archive_scan_enabled=True,
        archive_max_source_bytes=1024 * 1024,
        archive_max_total_bytes=1024 * 1024,
        archive_max_entries=100,
        archive_max_compression_ratio=20,
        archive_scan_timeout_seconds=60,
    )


class SafeTreeTests(unittest.TestCase):
    def test_incomplete_suffix_is_case_insensitive(self) -> None:
        self.assertTrue(safe_move.has_incomplete_suffix(Path("file.PART"), (".part",)))
        self.assertFalse(safe_move.has_incomplete_suffix(Path("file.iso"), (".part",)))

    def test_symlink_and_special_file_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("target", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(safe_move.UnsafePathError):
                safe_move.fingerprint(link)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(safe_move.UnsafePathError):
                safe_move.fingerprint(fifo)

    def test_same_filesystem_move_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch = base / "watch"
            destination_root = base / "destination"
            state = base / "state"
            for directory in (watch, destination_root, state):
                directory.mkdir()
            source = watch / "sample.txt"
            source.write_text("new", encoding="utf-8")
            (destination_root / source.name).write_text("existing", encoding="utf-8")
            destination = safe_move.move_safely(
                source,
                destination_root,
                expected=safe_move.fingerprint(source),
                state_dir=state,
            )
            self.assertEqual((destination_root / "sample.txt").read_text(encoding="utf-8"), "existing")
            self.assertEqual(destination.name, "sample_1.txt")
            self.assertEqual(destination.read_text(encoding="utf-8"), "new")

    def test_collision_created_during_move_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch = base / "watch"
            destination_root = base / "destination"
            state = base / "state"
            for directory in (watch, destination_root, state):
                directory.mkdir()
            source = watch / "sample.bin"
            source.write_bytes(b"new")
            original = safe_move._rename_noreplace
            collided = False

            def collide_once(current: Path, destination: Path) -> None:
                nonlocal collided
                if current == source and not collided:
                    collided = True
                    destination.write_bytes(b"racer")
                    raise FileExistsError(errno.EEXIST, "exists", str(destination))
                original(current, destination)

            with patch.object(safe_move, "_rename_noreplace", side_effect=collide_once):
                destination = safe_move.move_safely(
                    source,
                    destination_root,
                    expected=safe_move.fingerprint(source),
                    state_dir=state,
                )
            self.assertEqual((destination_root / "sample.bin").read_bytes(), b"racer")
            self.assertEqual(destination.name, "sample_1.bin")

    def test_nfs_directory_fallback_moves_with_standard_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            destination = base / "destination"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")

            with patch.object(
                safe_move,
                "_renameat2_noreplace",
                side_effect=OSError(errno.EOPNOTSUPP, "operation not supported"),
            ):
                safe_move._rename_noreplace(source, destination)

            self.assertFalse(source.exists())
            self.assertEqual((destination / "payload.bin").read_bytes(), b"payload")

    def test_nfs_directory_fallback_preserves_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch = base / "watch"
            destination_root = base / "destination"
            state = base / "state"
            for directory in (watch, destination_root, state):
                directory.mkdir()
            source = watch / "folder"
            source.mkdir()
            (source / "new.bin").write_bytes(b"new")
            existing = destination_root / "folder"
            existing.mkdir()
            (existing / "keep.bin").write_bytes(b"keep")

            with patch.object(
                safe_move,
                "_renameat2_noreplace",
                side_effect=OSError(errno.EOPNOTSUPP, "operation not supported"),
            ):
                destination = safe_move.move_safely(
                    source,
                    destination_root,
                    expected=safe_move.fingerprint(source),
                    state_dir=state,
                )

            self.assertEqual((existing / "keep.bin").read_bytes(), b"keep")
            self.assertEqual(destination.name, "folder_1")
            self.assertEqual((destination / "new.bin").read_bytes(), b"new")

    def test_cross_filesystem_move_is_recovered_after_publish_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch = base / "watch"
            destination_root = base / "destination"
            state = base / "state"
            for directory in (watch, destination_root, state):
                directory.mkdir()
            source = watch / "folder"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            expected = safe_move.fingerprint(source)
            original_rename = safe_move._rename_noreplace
            original_update = safe_move.MoveJournal.update
            first_move = True

            def simulate_cross_filesystem(current: Path, destination: Path) -> None:
                nonlocal first_move
                if current == source and first_move:
                    first_move = False
                    raise OSError(errno.EXDEV, "cross-device link")
                original_rename(current, destination)

            def crash_after_publish(journal: safe_move.MoveJournal, phase: str, **values: object) -> None:
                if phase == "published":
                    raise RuntimeError("simulated process crash")
                original_update(journal, phase, **values)

            with (
                patch.object(safe_move, "_rename_noreplace", side_effect=simulate_cross_filesystem),
                patch.object(safe_move.MoveJournal, "update", new=crash_after_publish),
                self.assertRaisesRegex(RuntimeError, "simulated process crash"),
            ):
                safe_move.move_safely(source, destination_root, expected=expected, state_dir=state)

            self.assertTrue(source.exists())
            self.assertEqual(len(list(state.glob("*.json"))), 1)
            recovered = safe_move.recover_moves(
                state,
                watch_root=watch,
                destination_roots=(destination_root,),
            )
            self.assertEqual(len(recovered), 1)
            self.assertFalse(source.exists())
            self.assertEqual((destination_root / "folder" / "payload.bin").read_bytes(), b"payload")
            self.assertEqual(list(state.glob("*.json")), [])

    def test_cross_filesystem_nfs_fallback_is_recovered_after_publish_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch = base / "watch"
            destination_root = base / "destination"
            state = base / "state"
            for directory in (watch, destination_root, state):
                directory.mkdir()
            source = watch / "folder"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            expected = safe_move.fingerprint(source)
            original_update = safe_move.MoveJournal.update

            def emulate_mount(current: Path, destination: Path) -> None:
                if current == source:
                    raise OSError(errno.EXDEV, "cross-device link")
                raise OSError(errno.EOPNOTSUPP, "operation not supported")

            def crash_after_publish(journal: safe_move.MoveJournal, phase: str, **values: object) -> None:
                if phase == "published":
                    raise RuntimeError("simulated process crash")
                original_update(journal, phase, **values)

            with (
                patch.object(safe_move, "_renameat2_noreplace", side_effect=emulate_mount),
                patch.object(safe_move.MoveJournal, "update", new=crash_after_publish),
                self.assertRaisesRegex(RuntimeError, "simulated process crash"),
            ):
                safe_move.move_safely(source, destination_root, expected=expected, state_dir=state)

            self.assertTrue(source.exists())
            self.assertEqual(len(list(state.glob("*.json"))), 1)
            recovered = safe_move.recover_moves(
                state,
                watch_root=watch,
                destination_roots=(destination_root,),
            )
            self.assertEqual(recovered, [str(destination_root / "folder")])
            self.assertFalse(source.exists())
            self.assertEqual((destination_root / "folder" / "payload.bin").read_bytes(), b"payload")
            self.assertEqual(list(state.glob("*.json")), [])


class HealthTests(unittest.TestCase):
    def test_mount_marker_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "watch"
            root.mkdir()
            with self.assertRaisesRegex(RuntimeError, "relative path"):
                service._marker_path(root, "../outside")

    def test_read_only_watch_mount_is_unhealthy(self) -> None:
        identity = service.PathIdentity(1, 1, stat.S_IFDIR)
        with (
            patch.object(service, "capture_mounts"),
            patch.object(service.PathIdentity, "capture", return_value=identity),
            patch.object(service, "LARGE_MEDIA_ENABLED", False),
            patch.object(service.os, "access", return_value=False),
        ):
            self.assertEqual(service.healthcheck(), 1)


class ClamdProtocolTests(unittest.TestCase):
    @staticmethod
    def _recv_exact(connection: socket.socket, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                raise RuntimeError("client disconnected")
            result.extend(chunk)
        return bytes(result)

    def _server(
        self,
        socket_path: Path,
        received: list[bytes],
        response: bytes,
        scanned: threading.Event | None = None,
        resume: threading.Event | None = None,
    ) -> threading.Thread:
        ready = threading.Event()

        def serve() -> None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(socket_path))
                listener.listen(1)
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    command = self._recv_exact(connection, len(b"zINSTREAM\0"))
                    self.assertEqual(command, b"zINSTREAM\0")
                    content = bytearray()
                    while True:
                        length = struct.unpack("!I", self._recv_exact(connection, 4))[0]
                        if not length:
                            break
                        content.extend(self._recv_exact(connection, length))
                    received.append(bytes(content))
                    if scanned:
                        scanned.set()
                    if resume:
                        resume.wait(5)
                    connection.sendall(response + b"\0")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(2))
        return thread

    @staticmethod
    def _client(socket_path: Path) -> clamd_client.ClamdClient:
        return clamd_client.ClamdClient(
            str(socket_path),
            connect_timeout=2,
            scan_timeout=2,
            max_stream_bytes=1024 * 1024,
            max_definition_age_seconds=172800,
        )

    def test_descriptor_stream_handles_newline_names_and_eicar_threat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "line\nbreak.bin"
            path.write_bytes(b"EICAR test bytes")
            socket_path = root / "clamd.sock"
            received: list[bytes] = []
            thread = self._server(socket_path, received, b"stream: Eicar-Signature FOUND")
            result = self._client(socket_path).scan_file(path)
            thread.join(2)
            self.assertTrue(result.infected)
            self.assertEqual(result.threat_name, "Eicar-Signature")
            self.assertEqual(received, [b"EICAR test bytes"])

    def test_file_replacement_during_scan_is_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "payload.bin"
            path.write_bytes(b"first")
            socket_path = root / "clamd.sock"
            scanned = threading.Event()
            resume = threading.Event()
            thread = self._server(socket_path, [], b"stream: OK", scanned, resume)

            def replace() -> None:
                self.assertTrue(scanned.wait(2))
                replacement = root / "replacement"
                replacement.write_bytes(b"second")
                os.replace(replacement, path)
                resume.set()

            replacer = threading.Thread(target=replace)
            replacer.start()
            with self.assertRaisesRegex(clamd_client.ClamdError, "changed|replaced"):
                self._client(socket_path).scan_file(path)
            replacer.join(2)
            thread.join(2)

    def test_limit_and_malformed_responses_are_failures(self) -> None:
        with self.assertRaises(clamd_client.ClamdPolicyError):
            clamd_client.parse_scan_response("stream: Heuristics.Limits.Exceeded FOUND")
        with self.assertRaises(clamd_client.ClamdError):
            clamd_client.parse_scan_response("nonsense")

    def test_definition_freshness_is_enforced(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(days=4)).strftime("%a, %d %b %Y %H:%M:%S %z")
        client = self._client(Path("/unused"))
        with patch.object(client, "command", side_effect=["PONG", f"ClamAV 1.4.5/123/{old}"]):
            with self.assertRaisesRegex(clamd_client.ClamdError, "stale"):
                client.health()


class LargeContentPolicyTests(unittest.TestCase):
    def test_large_media_windows_cover_all_bytes_and_overlap(self) -> None:
        ranges = content_scanner.window_ranges(25, 10, 2)
        self.assertEqual(ranges, [(0, 10), (8, 10), (16, 9)])
        covered = [False] * 25
        for offset, length in ranges:
            for index in range(offset, offset + length):
                covered[index] = True
        self.assertTrue(all(covered))

    def test_oversized_video_uses_full_byte_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "movie.mkv"
            path.write_bytes(b"0123456789abcdefghijklmnop")
            fake = StreamingFakeClamd(max_stream_bytes=10)
            scanner = make_content_scanner(fake)
            scanner.large_media_window_bytes = 10
            scanner.large_media_overlap_bytes = 2
            with patch.object(scanner, "_probe", return_value="matroska,webm"):
                result = scanner.scan_file(path)

            self.assertFalse(result.infected)
            self.assertEqual(result.scan_method, "large_media_full_byte_windows")
            self.assertEqual(fake.ranges, [b"0123456789", b"89abcdefgh", b"ghijklmnop"])
            covered = bytearray(len(path.read_bytes()))
            for offset, length in content_scanner.window_ranges(len(covered), 10, 2):
                covered[offset : offset + length] = b"\x01" * length
            self.assertTrue(all(covered))

    def test_bounded_zip_is_streamed_entry_by_entry_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "bundle.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("first.txt", b"safe")
                archive.writestr("second.bin", b"also safe")
            fake = StreamingFakeClamd(max_stream_bytes=32)
            scanner = make_content_scanner(fake)
            result = scanner.scan_file(path)

            self.assertFalse(result.infected)
            self.assertEqual(result.scan_method, "bounded_zip_entries")
            self.assertEqual(fake.entries, [b"safe", b"also safe"])
            self.assertEqual({item.name for item in root.iterdir()}, {"bundle.zip"})

    def test_small_zip_always_uses_bounded_entry_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "small.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("payload.txt", b"safe")
            fake = StreamingFakeClamd(max_stream_bytes=1024 * 1024)

            result = make_content_scanner(fake).scan_file(path)

            self.assertEqual(result.scan_method, "bounded_zip_entries")
            self.assertEqual(fake.entries, [b"safe"])

    def test_infected_zip_entry_is_reported_infected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bundle.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("malware.bin", b"EICAR test bytes")
            fake = StreamingFakeClamd(max_stream_bytes=32)
            result = make_content_scanner(fake).scan_file(path)

            self.assertTrue(result.infected)
            self.assertEqual(result.threat_name, "Test.Eicar")
            self.assertIn("malware.bin", result.response)

    def test_zip_bomb_ratio_and_nested_archive_are_held(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bomb = root / "bomb.zip"
            with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("zeros.txt", b"0" * 10000)
                archive.comment = b"padding" * 3000
            scanner = make_content_scanner(StreamingFakeClamd(max_stream_bytes=20000))
            with self.assertRaisesRegex(clamd_client.ClamdPolicyError, "compression ratio"):
                scanner.scan_file(bomb)

            nested = root / "nested.zip"
            with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("inside.zip", b"PK\x03\x04nested")
            scanner = make_content_scanner(StreamingFakeClamd(max_stream_bytes=32))
            with self.assertRaisesRegex(clamd_client.ClamdPolicyError, "nested archive"):
                scanner.scan_file(nested)

    def test_zip_entry_count_is_rejected_before_zipfile_allocates_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "too-many.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("one.txt", b"safe")
            payload = bytearray(path.read_bytes())
            eocd = payload.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            struct.pack_into("<HH", payload, eocd + 8, 101, 101)
            path.write_bytes(payload)
            scanner = make_content_scanner(StreamingFakeClamd(max_stream_bytes=1024))
            scanner.archive_max_entries = 100

            with self.assertRaisesRegex(clamd_client.ClamdPolicyError, "101 entries"):
                scanner.scan_file(path)

    def test_media_probe_rejects_renamed_archive(self) -> None:
        with self.assertRaisesRegex(clamd_client.ClamdPolicyError, "not an approved video"):
            content_scanner.parse_media_probe(
                json.dumps(
                    {
                        "format": {"format_name": "zip"},
                        "streams": [{"codec_type": "video"}],
                    }
                ),
                Path("renamed.mkv"),
            )


class ProcessorTests(unittest.TestCase):
    def _configure(self, base: Path):
        watch = base / "watch"
        destination = base / "dest"
        quarantine = base / "quarantine"
        events = base / "events"
        state = base / "state"
        for directory in (watch, destination, quarantine, events, state):
            directory.mkdir()
        return (
            watch,
            destination,
            quarantine,
            events,
            state,
            patch.multiple(
                service,
                WATCH_DIR=watch,
                DEST_DIR=destination,
                QUARANTINE_DIR=quarantine,
                EVENT_DIR=events,
                STATE_DIR=state,
            ),
            patch.object(event_writer, "EVENT_DIR", events),
        )

    def test_clean_file_is_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch, destination, _, _, _, service_patch, event_patch = self._configure(base)
            source = watch / "clean.txt"
            source.write_text("clean", encoding="utf-8")
            with service_patch, event_patch:
                processor = service.ItemProcessor(service.RecoveryTracker())
                processor._clamd = FakeClamd()
                self.assertTrue(processor.reserve(source))
                processor.process(source)
            self.assertFalse(source.exists())
            self.assertEqual((destination / "clean.txt").read_text(encoding="utf-8"), "clean")

    def test_move_failure_defers_the_next_scan_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch, _, _, _, _, service_patch, event_patch = self._configure(base)
            source = watch / "clean.txt"
            source.write_text("clean", encoding="utf-8")
            with (
                service_patch,
                event_patch,
                patch.object(service, "MOVE_FAILURE_RETRY_SECONDS", 300),
                patch.object(service, "move_safely", side_effect=OSError("NFS unavailable")),
            ):
                processor = service.ItemProcessor(service.RecoveryTracker())
                processor._clamd = FakeClamd()
                self.assertTrue(processor.reserve(source))
                processor.process(source)
                self.assertFalse(processor.reserve(source))

            self.assertTrue(source.exists())

    def test_infected_folder_goes_to_non_overwriting_quarantine_and_emits_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch, destination, quarantine, events, _, service_patch, event_patch = self._configure(base)
            source = watch / "bundle"
            source.mkdir()
            (source / "malware.exe").write_bytes(b"infected")
            existing = quarantine / "bundle"
            existing.mkdir()
            (existing / "keep.txt").write_text("keep", encoding="utf-8")
            with service_patch, event_patch:
                processor = service.ItemProcessor(service.RecoveryTracker())
                processor._clamd = FakeClamd("malware.exe")
                self.assertTrue(processor.reserve(source))
                processor.process(source)
            self.assertFalse(source.exists())
            self.assertFalse((destination / "bundle").exists())
            self.assertEqual((existing / "keep.txt").read_text(encoding="utf-8"), "keep")
            self.assertEqual((quarantine / "bundle_1" / "malware.exe").read_bytes(), b"infected")
            event_types = {
                json.loads(path.read_text(encoding="utf-8"))["event_type"]
                for path in events.glob("*.json")
            }
            self.assertEqual(event_types, {"threat_detected", "infected_content_quarantined"})

    def test_policy_limited_item_is_held_and_reported_as_scan_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            watch, destination, quarantine, events, _, service_patch, event_patch = self._configure(base)
            source = watch / "movie.mkv"
            source.write_bytes(b"oversized-media-placeholder")
            with service_patch, event_patch:
                processor = service.ItemProcessor(service.RecoveryTracker())
                processor._clamd = PolicyLimitClamd()
                self.assertTrue(processor.reserve(source))
                processor.process(source)

            self.assertTrue(source.exists())
            self.assertFalse((destination / source.name).exists())
            self.assertFalse((quarantine / source.name).exists())
            event_payloads = [json.loads(path.read_text(encoding="utf-8")) for path in events.glob("*.json")]
            self.assertEqual(len(event_payloads), 1)
            self.assertEqual(event_payloads[0]["event_type"], "scan_failed")
            self.assertEqual(event_payloads[0]["failure_kind"], "scan_policy_limit")


if __name__ == "__main__":
    unittest.main()
