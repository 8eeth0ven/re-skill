"""Offline regressions for firmware intake, status, and CVE banner rechecks."""

import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_ipk(banner):
    """Build an ar package with a gzip tar member containing a test binary."""
    body = io.BytesIO()
    content = b"\x7fELF\x00" + banner
    with tarfile.open(fileobj=body, mode="w:gz") as archive:
        member = tarfile.TarInfo("usr/bin/test-component")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    payload = body.getvalue()
    header = (
        f"{'data.tar.gz/':<16}{0:<12}{0:<6}{0:<6}"
        f"{'100644':<8}{len(payload):<10}`\n"
    ).encode("ascii")
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) % 2 else b"")


class FirmwareRegressionTests(unittest.TestCase):
    def setUp(self):
        self.fw = load_module("re_fw_regression", "fw-discover/fw.py")
        self.temp = tempfile.TemporaryDirectory(prefix="re-firmware-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_failed_gzip_extraction_preserves_original_sample(self):
        original = gzip.compress(b"firmware-test-input-without-a-filesystem")
        sample = self.root / "sample.gz"
        sample.write_bytes(original)

        filesystem, _, _ = self.fw.extract_firmware(
            sample, self.root / "outputs" / "rootfs"
        )

        self.assertIsNone(filesystem)
        self.assertEqual(sample.read_bytes(), original)

    def test_successful_gzip_extraction_preserves_original_sample(self):
        filesystem_bytes = b"hsqs" + b"fixture-filesystem" * 4
        original = gzip.compress(filesystem_bytes)
        sample = self.root / "sample.gz"
        sample.write_bytes(original)

        def extract(slice_path, output_path):
            self.assertEqual(slice_path.read_bytes(), filesystem_bytes)
            output_path.mkdir(parents=True)
            (output_path / "fixture.txt").write_text("extracted", encoding="utf-8")
            return "fixture-extractor"

        with patch.object(self.fw, "extract_squashfs", side_effect=extract):
            filesystem, extractor, _ = self.fw.extract_firmware(
                sample, self.root / "outputs" / "rootfs"
            )

        self.assertTrue((filesystem / "fixture.txt").is_file())
        self.assertEqual(extractor, "fixture-extractor")
        self.assertEqual(sample.read_bytes(), original)

    def test_explicit_status_matches_default_without_analysis(self):
        module_dir = self.root / "fw-discover"
        module_dir.mkdir()
        for filename in ("fw.py", "analyzers.py", "_legacy_safety.py"):
            shutil.copyfile(REPO_ROOT / "fw-discover" / filename, module_dir / filename)
        command = [sys.executable, str(module_dir / "fw.py")]
        env = {**os.environ, "PYTHONUTF8": "1"}
        default = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True,
            encoding="utf-8", env=env, timeout=10,
        )
        explicit = subprocess.run(
            command + ["--status"], cwd=self.root, capture_output=True, text=True,
            encoding="utf-8", env=env, timeout=10,
        )

        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(explicit.returncode, 0, explicit.stderr)
        self.assertTrue(default.stdout.strip())
        self.assertEqual(explicit.stdout, default.stdout)
        self.assertFalse((self.root / "data/fw-discover/findings.jsonl").exists())
        self.assertFalse((self.root / "data/fw-discover/queue.jsonl").exists())


class CveBannerRecheckTests(unittest.TestCase):
    def setUp(self):
        self.hunter = load_module("re_cve_regression", "cve-hunter/hunter.py")
        self.temp = tempfile.TemporaryDirectory(prefix="re-cve-regression-")
        self.addCleanup(self.temp.cleanup)
        self.findings = Path(self.temp.name) / "findings.jsonl"
        record = {
            "key": "fixture", "cls": "sbom-candidate", "release": "23.05.0",
            "arch": "x86_64", "feed": "base", "pkg": "busybox",
            "ver": "1.30.0", "fname": "busybox_fixture_x86_64.ipk",
        }
        self.findings.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def verify(self, package):
        with (
            patch.object(self.hunter, "FINDINGS", self.findings),
            patch.object(self.hunter, "fetch", return_value=package) as fetch,
            patch.object(self.hunter, "write_ledger"),
            patch.object(self.hunter, "log"),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            promoted = self.hunter.run_verify()
        records = [json.loads(line) for line in self.findings.read_text("utf-8").splitlines()]
        return promoted, records[0], fetch.call_args.args[0]

    def test_matching_banner_uses_feed_url_and_promotes_version_evidence(self):
        promoted, record, url = self.verify(make_ipk(b"BusyBox v1.30.0\x00"))

        self.assertEqual(
            url,
            "https://downloads.openwrt.org/releases/23.05.0/packages/"
            "x86_64/base/busybox_fixture_x86_64.ipk",
        )
        self.assertEqual(promoted, 1)
        self.assertEqual(record["cls"], "binary-confirmed")
        self.assertIn("busybox 1.30.0", record["evidence"])

    def test_different_version_does_not_promote(self):
        promoted, record, _ = self.verify(make_ipk(b"BusyBox v1.31.0\x00"))

        self.assertEqual(promoted, 0)
        self.assertEqual(record["cls"], "sbom-candidate")
        self.assertNotIn("evidence", record)

    def test_different_component_does_not_promote(self):
        promoted, record, _ = self.verify(make_ipk(b"OpenSSL 1.30.0\x00"))

        self.assertEqual(promoted, 0)
        self.assertEqual(record["cls"], "sbom-candidate")

    def test_download_failure_preserves_candidate(self):
        promoted, record, _ = self.verify(None)

        self.assertEqual(promoted, 0)
        self.assertEqual(record["cls"], "sbom-candidate")
        self.assertNotIn("evidence", record)


if __name__ == "__main__":
    unittest.main()
