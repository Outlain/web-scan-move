from __future__ import annotations

import importlib.util
import tempfile
import unittest
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "web_scan_move.py"
spec = importlib.util.spec_from_file_location("web_scan_move", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)


class WebScanMoveTests(unittest.TestCase):
    def test_incomplete_suffix_is_case_insensitive(self) -> None:
        self.assertTrue(module.has_incomplete_suffix(Path("file.PART")))
        self.assertFalse(module.has_incomplete_suffix(Path("file.iso")))

    def test_unique_destination_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sample.bin").write_bytes(b"existing")
            selected = module.unique_destination(root, "sample.bin")
            self.assertEqual(selected.name, "sample_1.bin")

    def test_safe_same_filesystem_move(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_root = base / "source"
            destination_root = base / "destination"
            source_root.mkdir()
            source = source_root / "sample.txt"
            source.write_text("hello", encoding="utf-8")
            expected = module.fingerprint(source)
            destination = module.move_safely(source, destination_root, expected=expected)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), "hello")


if __name__ == "__main__":
    unittest.main()
