"""Real 7-Zip acceptance for the firmware S1 unpack stage.

Everything here is offline and runs the actual installed tools when present:
7-Zip 25.01 full (tools-env/7zip-full, squashfs/cpio capable) plus the
redistributable squashfs oracle sample in tools-env/samples (see
SQUASHFS-SAMPLE-PROVENANCE.txt for source/hash/license). Without RE_RUN_7Z or
the binaries the positive tests are skipped and the negative controls still
run. The stage only ever lists/unpacks; nothing extracted is executed.
"""
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import InvalidInput
from re_runner.extractors import configured_executable, sevenzip_extract
from re_runner.models import Asset
from re_runner.profiles.source_firmware import analyze as firmware_analyze
from re_runner.safety import Budget, load_json
from re_runner.scope import ScopePolicy

REPO = Path(__file__).resolve().parents[1]
# Cross-platform resolution (round 3): explicit env, repo-local distribution,
# then PATH. The hardcoded Windows layout made macOS/Linux skip real runs.


def _resolve_7z() -> Path | None:
    for candidate in (os.environ.get("RE_RUN_7Z"), REPO / "tools-env" / "7zip-full" / "7z.exe", shutil.which("7z"), shutil.which("7zz")):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


SEVENZIP = _resolve_7z()
SQUASHFS_SAMPLE = REPO / "tools-env" / "samples" / "gzip.sqfs"
ENV_VAR = "RE_RUN_7Z"


def budget() -> Budget:
    return Budget(dict(BUDGET_DEFAULTS))


def firmware_asset(path: Path) -> Asset:
    return Asset(id="firmware", locator=str(path), kind="firmware", format="firmware-image")


def cpio_bytes(files: dict[str, bytes]) -> bytes:
    """Minimal but spec-correct newc cpio archive (7z reads the 'New ASCII' format)."""

    def header(name: str, size: int) -> bytes:
        values = [0, 0o100644, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name) + 1, 0]
        return b"070701" + "".join("%08X" % value for value in values).encode()

    out = bytearray()
    for name, data in files.items():
        raw = name.encode()
        out += header(name, len(data)) + raw + b"\x00"
        out += b"\x00" * ((4 - ((110 + len(raw) + 1) % 4)) % 4)
        out += data
        out += b"\x00" * ((4 - (len(data) % 4)) % 4)
    out += header("TRAILER!!!", 0) + b"TRAILER!!!\x00"
    out += b"\x00" * ((4 - ((110 + 11) % 4)) % 4)
    return bytes(out)


class EnvironmentGuard:
    """Pin RE_RUN_7Z for the duration of a test."""

    def __init__(self, value: str | None):
        self.value, self.saved = value, None

    def __enter__(self):
        self.saved = os.environ.get(ENV_VAR)
        if self.value is None:
            os.environ.pop(ENV_VAR, None)
        else:
            os.environ[ENV_VAR] = self.value
        return self

    def __exit__(self, *exc):
        if self.saved is None:
            os.environ.pop(ENV_VAR, None)
        else:
            os.environ[ENV_VAR] = self.saved
        return False


class ExtractorUnitTests(unittest.TestCase):
    """Tool-level contract of extractors.sevenzip_extract."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-7z-extract-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def test_unconfigured_returns_none_and_writes_nothing(self):
        # The direct call must also be isolated from an inherited RE_RUN_7Z:
        # "unconfigured" means neither argument nor environment.
        with EnvironmentGuard(None):
            self.assertIsNone(configured_executable(None))
        with EnvironmentGuard(None):
            self.assertIsNone(configured_executable())
            self.assertIsNone(sevenzip_extract(self.work / "sample.bin", self.work / "out", budget()))
        self.assertEqual(list(self.work.iterdir()), [], "skipped stage must not touch the output directory")

    def test_nonexistent_configuration_is_skipped_not_fatal(self):
        with EnvironmentGuard(str(self.work / "missing-7z.exe")):
            self.assertIsNone(configured_executable())

    @unittest.skipUnless(bool(SEVENZIP), f"7-Zip missing: {SEVENZIP}")
    def test_cpio_container_extracts_completely(self):
        payload = cpio_bytes({"etc/config": b"http_passwd=fixture-secret\n", "bin/busybox": b"\x7fELF\x00BusyBox v1.30.0\n"})
        sample = self.work / "rootfs.cpio"
        sample.write_bytes(payload)
        out = self.work / "rootfs-7z"
        with EnvironmentGuard(str(SEVENZIP)):
            result = sevenzip_extract(sample, out, budget(), executable=str(SEVENZIP))
        self.assertEqual(result["tool"], "7z")
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["format"], "Cpio")
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["member_count"], 2)
        match = re.search(r"(\d+)\.\d+", result["version"] or "")
        self.assertIsNotNone(match, f"7z version recorded: {result['version']!r}")
        self.assertGreaterEqual(int(match.group(1)), 15, "7z major version recorded")
        self.assertTrue((out / "etc" / "config").is_file())
        self.assertEqual((out / "etc" / "config").read_bytes(), b"http_passwd=fixture-secret\n")
        self.assertIn("BusyBox v1.30.0", (out / "bin" / "busybox").read_text("ascii", errors="replace"))
        evidence = load_json(self.work / "sevenzip-extract-run.json")
        for key in ("argv", "status", "exit_code", "stdout", "stderr"):
            self.assertIn(key, evidence)
        self.assertEqual(evidence["status"], "succeeded")
        self.assertIn("x", evidence["argv"])
        # Round 3: per-member streaming replaced the bulk `-o` extraction; the
        # evidence file records the aggregate shape instead.
        self.assertEqual(evidence["mode"], "per-member-streaming")
        self.assertTrue((self.work / "sevenzip-inspect-run.json").is_file())
        self.assertTrue((self.work / "sevenzip-list-run.json").is_file())
        self.assertTrue((self.work / "sevenzip-version-run.json").is_file())

    @unittest.skipUnless(bool(SEVENZIP), f"7-Zip missing: {SEVENZIP}")
    def test_corrupt_container_fails_with_signature(self):
        sample = self.work / "broken.squashfs"
        sample.write_bytes(b"hsqs" + b"\x00" * 8192)
        out = self.work / "rootfs-7z"
        with EnvironmentGuard(str(SEVENZIP)):
            result = sevenzip_extract(sample, out, budget(), executable=str(SEVENZIP))
        self.assertEqual(result["status"], "failed")
        self.assertIn("Listing failed", result["error"])
        self.assertEqual(result["files"], 0)


@unittest.skipUnless(bool(SEVENZIP), f"7-Zip missing: {SEVENZIP}")
@unittest.skipUnless(SQUASHFS_SAMPLE.is_file(), f"squashfs oracle sample missing: {SQUASHFS_SAMPLE}")
class FirmwareProfileSquashfsTests(unittest.TestCase):
    """Profile-level wiring: the unpacked tree becomes the scan tree."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-fw-squashfs-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "out"

    def analyze(self) -> object:
        return firmware_analyze(firmware_asset(SQUASHFS_SAMPLE), SQUASHFS_SAMPLE, self.output, ScopePolicy(), budget())

    def test_unpacked_tree_is_scanned_and_check_is_recorded(self):
        with EnvironmentGuard(str(SEVENZIP)):
            result = self.analyze()
        checks = {check["name"]: check for check in result.checks}
        self.assertIn("firmware-filesystem-extract-7z", checks)
        extract = checks["firmware-filesystem-extract-7z"]
        # A Windows host without symlink privilege cannot extract the sample's
        # three symlink entries; that partial result is honestly degraded, and
        # on privileged hosts the same run reports succeeded.
        self.assertIn(extract["status"], ("succeeded", "degraded"), extract["detail"])
        self.assertEqual(result.analysis["container"], "squashfs")
        extractor = result.analysis["extractor"]
        self.assertEqual(extractor["format"], "SquashFS")
        self.assertGreaterEqual(extractor["files"], 100)
        # The analysis tree is the unpacked content, not the raw image: the
        # sparse large-file and directory members are inventoried as files.
        scanned = {row["path"] for row in result.analysis["files"]}
        self.assertIn("small-file", scanned)
        self.assertIn("dir/file_1", scanned)
        self.assertIn("large-file", scanned)
        self.assertGreater(result.analysis["file_count"], 1)
        self.assertEqual(extract["status"] == "degraded", bool(result.limitations and "with errors" in result.limitations[0]))
        evidence = load_json(self.output / "sevenzip-extract-run.json")
        self.assertIn("x", evidence["argv"])

    def test_unconfigured_keeps_raw_scan_with_skipped_check(self):
        with EnvironmentGuard(None):
            result = self.analyze()
        checks = {check["name"]: check for check in result.checks}
        self.assertEqual(checks["firmware-filesystem-extract-7z"]["status"], "skipped")
        self.assertIn("RE_RUN_7Z", checks["firmware-filesystem-extract-7z"]["detail"])
        # No extraction happened: the single scanned file is the image itself.
        self.assertEqual(result.analysis["file_count"], 1)
        self.assertEqual(result.analysis["files"][0]["path"], SQUASHFS_SAMPLE.name)
        self.assertEqual({c["name"]: c for c in result.checks}["firmware-container-inspection"]["status"], "degraded")

    def test_ubi_container_reports_honest_limitation(self):
        sample = Path(self.temporary.name) / "fw.ubi"
        sample.write_bytes(b"UBI#" + b"\xff" * 4096)
        with EnvironmentGuard(str(SEVENZIP)):
            result = firmware_analyze(firmware_asset(sample), sample, self.output, ScopePolicy(), budget())
        check = {c["name"]: c for c in result.checks}["firmware-filesystem-extract-7z"]
        self.assertEqual(check["status"], "degraded")
        self.assertIn("UBI/TRX", check["detail"])
        self.assertEqual(result.analysis["file_count"], 1, "UBI stays on the raw scan")

    def test_extraction_failure_degrades_and_retains_raw_scan(self):
        sample = Path(self.temporary.name) / "broken.squashfs"
        sample.write_bytes(b"hsqs" + b"\x00" * 8192)
        with EnvironmentGuard(str(SEVENZIP)):
            result = firmware_analyze(firmware_asset(sample), sample, self.output, ScopePolicy(), budget())
        check = {c["name"]: c for c in result.checks}["firmware-filesystem-extract-7z"]
        self.assertEqual(check["status"], "degraded", "an extraction failure never fails the profile")
        self.assertIn("Listing failed", check["detail"])
        self.assertTrue(any("raw signature scan is retained" in limit for limit in result.limitations))
        self.assertEqual(result.analysis["file_count"], 1)

    def test_base_layer_still_rejects_broken_container_headers(self):
        # The built-in container inspection keeps its own strictness: a file
        # whose gzip/pcap-style structure is invalid is an intake error, which
        # is unchanged behavior of the unchanged first layer.
        sample = Path(self.temporary.name) / "trunc.bin"
        sample.write_bytes(b"\x1f\x8b" + b"\x00" * 10)
        with EnvironmentGuard(str(SEVENZIP)):
            with self.assertRaises(InvalidInput):
                firmware_analyze(firmware_asset(sample), sample, self.output, ScopePolicy(), budget())


if __name__ == "__main__":
    unittest.main()
