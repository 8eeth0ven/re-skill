import gzip
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LegacyHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="re-legacy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_failed_catalog_is_not_completed_and_retry_is_finite(self):
        hunter = module("hardening_hunter", "cve-hunter/hunter.py")
        with (
            patch.object(hunter, "PROGRESS", self.root / "progress.json"),
            patch.object(hunter, "FINDINGS", self.root / "findings.jsonl"),
            patch.object(hunter, "build_combos", return_value=[("fixture", "arch", "base")]),
            patch.object(hunter, "fetch", return_value=None) as fetch,
            patch.object(hunter, "log"),
            patch.object(hunter, "write_ledger"),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            for _ in range(5):
                hunter.run_once()
        value = json.loads((self.root / "progress.json").read_text())
        self.assertEqual(value["done"], [])
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual(value["phase"], "incomplete-with-errors")

    def test_failed_firmware_download_is_error_not_done(self):
        fw = module("hardening_fw", "fw-discover/fw.py")
        items = [{"url": "https://downloads.openwrt.org/fixture.bin", "src": "openwrt", "name": "fixture", "status": "pending"}]
        with (
            patch.object(fw, "queue_load", return_value=items),
            patch.object(fw, "queue_save"),
            patch.object(fw, "load_progress", return_value={}),
            patch.object(fw, "save_progress"),
            patch.object(fw, "read_findings", return_value=[]),
            patch.object(fw, "process_one", return_value="error-download-failed TimeoutError") as process,
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            for _ in range(5):
                fw.run_once()
        self.assertEqual(items[0]["status"], "error")
        self.assertEqual(process.call_count, 3)

    def test_bounded_legacy_gzip(self):
        safety = module("hardening_legacy_safety", "fw-discover/_legacy_safety.py")
        with self.assertRaises(ValueError):
            safety.bounded_gzip(gzip.compress(b"x" * 100000), limit=1024)

    def test_legacy_scan_marks_cooccurrence_as_low_priority_candidate(self):
        analyzer = module("hardening_analyzers", "fw-discover/analyzers.py")
        path = self.root / "binary.bin"
        path.write_bytes(b"\x7fELFsystem\x00QUERY_STRING\x00")
        rows = analyzer.scan_file(path)
        hit = next(row for row in rows if row[0] == "cmdi-candidate")
        self.assertEqual(hit[1]["evidence_class"], "string-cooccurrence")
        self.assertEqual(hit[1]["reachability"], "unknown")
        self.assertEqual(hit[2], 1)

    def test_mixed_failed_and_zero_hit_lookup_is_unknown(self):
        novelty = module("hardening_novelty", "fw-discover/novelty.py")
        self.assertTrue(novelty.aggregate([None, {"totalResults": 0}]).startswith("UNKNOWN"))
        self.assertTrue(novelty.aggregate([{"totalResults": 0}]).startswith("NO-KEYWORD-HITS"))
        self.assertNotEqual(novelty.aggregate([{"totalResults": 0}]), "NEW")

    def test_nvd_cache_uses_hash_names_for_pathlike_keywords(self):
        novelty = module("hardening_novelty_cache", "fw-discover/novelty.py")
        data = b'{"totalResults":0,"vulnerabilities":[]}'

        class Response(io.BytesIO):
            headers = {}

        with (
            patch.object(novelty, "CACHE", self.root / "cache"),
            patch.object(novelty.OPENER, "open", return_value=Response(data)),
        ):
            value = novelty.nvd("../../outside")
        self.assertEqual(value["totalResults"], 0)
        self.assertFalse((self.root / "outside.json").exists())
        filenames = [p.name for p in (self.root / "cache").glob("*.json")]
        self.assertEqual(len(filenames), 1)
        self.assertRegex(filenames[0], r"^[a-f0-9]{64}\.json$")


if __name__ == "__main__":
    unittest.main()

