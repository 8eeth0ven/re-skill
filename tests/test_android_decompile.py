"""Real jadx/apktool acceptance for the android S1 unpack stage.

Everything here is offline and runs the actual installed tools when present:
jadx 1.5.1 (java classpath mode) and apktool 2.11.1 (java -jar mode). Without
the tools the positive tests are skipped and the negative control still runs.
"""
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from fixture_factory import android_manifest, dex
from re_runner import decompile
from re_runner.contracts import BUDGET_DEFAULTS, WORKER_RESULT_SCHEMA, validate
from re_runner.models import Asset
from re_runner.safety import Budget, load_json, sha256_file
from re_runner.scope import ScopePolicy
from re_runner.profiles import analyze

REPO = Path(__file__).resolve().parents[1]
# Cross-platform tool resolution (round 3): prefer an explicit RE_RUN_* value,
# then the repo-local distribution, then PATH. The old hardcoded Windows
# layout made macOS/Linux skip tests that could actually run.


def _resolve_jadx() -> Path | None:
    for candidate in (os.environ.get("RE_RUN_JADX"), REPO / "tools-env" / "jadx-1.5.1", shutil.which("jadx")):
        if candidate and Path(candidate).exists():
            return Path(candidate)
    return None


def _resolve_apktool() -> Path | None:
    for candidate in (os.environ.get("RE_RUN_APKTOOL"), REPO / "tools-env" / "dl" / "apktool_2.11.1.jar"):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


JADX_DIR = _resolve_jadx()


def _jadx_ready() -> bool:
    # A directory distribution or a direct launcher both count; decompile.py
    # handles either shape.
    return bool(JADX_DIR) and (JADX_DIR.is_dir() or JADX_DIR.is_file())
APKTOOL_JAR = _resolve_apktool()
FIXTURE_APK = REPO / "re-runs" / "fixtures" / "fixture.apk"
ENV_VARS = ("RE_RUN_JADX", "RE_RUN_APKTOOL")


def budget() -> Budget:
    # jadx/apktool JVM starts dominate; 90s tool timeout stays well under the
    # 120s suite budget because the fixture apk is a few hundred bytes.
    return Budget(dict(BUDGET_DEFAULTS))


def apk_asset(locator: Path) -> Asset:
    return Asset(id="android", locator=str(locator), kind="android", format="apk")


def build_apk(path: Path, blob: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", android_manifest())
        archive.writestr("classes.dex", blob)
    return path


def empty_dex() -> bytes:
    """The historical header-only fixture dex: valid indexes, zero classes."""
    import hashlib
    import struct
    import zlib

    result = bytearray(112)
    result[:8] = b"dex\n035\x00"
    struct.pack_into("<20I", result, 32, 112, 112, 0x12345678, *([0] * 17))
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xFFFFFFFF)
    return bytes(result)


class EnvironmentGuard:
    """Pin the tool configuration for the duration of a test."""

    def __enter__(self):
        self.saved = {name: os.environ.get(name) for name in ENV_VARS}
        return self

    def __exit__(self, *exc):
        for name, value in self.saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return False


@unittest.skipUnless((APKTOOL_JAR is not None and APKTOOL_JAR.is_file()), "apktool jar missing (set RE_RUN_APKTOOL)")
@unittest.skipUnless(FIXTURE_APK.is_file(), f"fixture apk missing: {FIXTURE_APK}")
class ApktoolDecodeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-apktool-")
        self.output = Path(self.temporary.name) / "out"

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_decode_produces_manifest_smali_and_evidence(self):
        with EnvironmentGuard():
            os.environ["RE_RUN_APKTOOL"] = str(APKTOOL_JAR)
            result = decompile.apktool(FIXTURE_APK, self.output, budget())
        self.assertEqual(result["tool"], "apktool")
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertEqual(result["version"], "2.11.1")
        self.assertIsNone(result["error"])
        decoded = self.output / "apktool" / "AndroidManifest.xml"
        self.assertTrue(decoded.is_file())
        text = decoded.read_text("utf-8", errors="replace")
        self.assertTrue(text.lstrip().startswith("<"), "manifest must be decoded text XML, not binary AXML")
        self.assertIn("org.example.fixture", text)
        smali = list((self.output / "apktool" / "smali").rglob("*.smali"))
        self.assertTrue(smali)
        evidence = load_json(self.output / "apktool-run.json")
        for key in ("argv", "status", "exit_code", "stdout", "stderr"):
            self.assertIn(key, evidence)
        self.assertEqual(evidence["status"], "succeeded")
        self.assertIn("-jar", evidence["argv"])
        self.assertTrue(any(argument.endswith(".jar") for argument in evidence["argv"]))
        # Evidence and artifacts are hashable files on disk.
        self.assertRegex(sha256_file(self.output / "apktool-run.json"), r"^[0-9a-f]{64}$")
        self.assertRegex(sha256_file(decoded), r"^[0-9a-f]{64}$")
        self.assertIn("apktool/AndroidManifest.xml", result["sources"])


@unittest.skipUnless(_jadx_ready(), "jadx distribution missing (set RE_RUN_JADX or put jadx on PATH)")
@unittest.skipUnless(FIXTURE_APK.is_file(), f"fixture apk missing: {FIXTURE_APK}")
class JadxDecompileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-jadx-")
        self.output = Path(self.temporary.name) / "out"

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_decompile_recovers_fixture_source(self):
        with EnvironmentGuard():
            os.environ["RE_RUN_JADX"] = str(JADX_DIR)
            result = decompile.jadx(FIXTURE_APK, self.output, budget())
        self.assertEqual(result["tool"], "jadx")
        # The fixture dex carries one real class, so jadx must recover java
        # source; an empty dex would only ever justify degraded.
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertTrue(str(result["version"]).startswith("1."), result["version"])  # version floats across installs
        self.assertIsNone(result["error"])
        sources = result["sources"]
        self.assertTrue(sources)
        java = self.output / sources[0]
        text = java.read_text("utf-8", errors="replace")
        self.assertIn("class Fixture", text)
        self.assertIn("fixture-ok", text)
        evidence = load_json(self.output / "jadx-run.json")
        self.assertEqual(evidence["status"], "succeeded")
        self.assertIn("--no-res", evidence["argv"])
        self.assertIn("-j", evidence["argv"])
        self.assertRegex(sha256_file(java), r"^[0-9a-f]{64}$")

    def test_unconfigured_and_broken_configuration_skip_honestly(self):
        with EnvironmentGuard():
            os.environ.pop("RE_RUN_JADX", None)
            self.assertIsNone(decompile.jadx(FIXTURE_APK, self.output, budget()))
            os.environ["RE_RUN_JADX"] = str(self.output / "does-not-exist")
            result = decompile.jadx(FIXTURE_APK, self.output, budget())
        self.assertEqual(result["status"], "skipped", result)
        self.assertTrue(result["error"])


class ProfileNegativeControlTests(unittest.TestCase):
    """Without RE_RUN_* the profile must keep its historical behavior."""

    def test_android_profile_without_tools_is_all_skipped(self):
        with tempfile.TemporaryDirectory(prefix="re-android-neg-") as temporary:
            root = Path(temporary)
            apk = build_apk(root / "fixture.apk", dex())
            with EnvironmentGuard():
                os.environ.pop("RE_RUN_JADX", None)
                os.environ.pop("RE_RUN_APKTOOL", None)
                result = analyze(apk_asset(apk), apk, root / "out", ScopePolicy(), budget())
            names = {entry["name"]: entry["status"] for entry in result.checks}
            self.assertEqual(names["android-bytecode-decompile-apktool"], "skipped")
            self.assertEqual(names["android-bytecode-decompile-jadx"], "skipped")
            self.assertEqual(names["package-safe-extraction-and-manifest"], "succeeded")
            self.assertEqual(names["dex-indexing"], "succeeded")
            self.assertNotIn("s1_extraction", result.analysis)
            self.assertFalse(any(rule.startswith("android-smali-") for rule in [c["rule_id"] for c in result.candidates]))
            self.assertEqual([p.name for p in (root / "out").iterdir()], ["package"])


@unittest.skipUnless(_jadx_ready(), "jadx distribution missing (set RE_RUN_JADX or put jadx on PATH)")
class EmptyDexDegradedTests(unittest.TestCase):
    """A dex with zero classes makes jadx exit non-zero; the honest result is
    degraded with a failure signature, never a crash and never success."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-emptydex-")
        self.output = Path(self.temporary.name) / "out"
        apk = self.output / "empty.apk"
        apk.parent.mkdir(parents=True, exist_ok=True)
        build_apk(apk, empty_dex())
        self.apk = apk

    def tearDown(self):
        self.temporary.cleanup()

    def test_jadx_reports_degraded_with_signature_on_classless_dex(self):
        with EnvironmentGuard():
            os.environ["RE_RUN_JADX"] = str(JADX_DIR)
            result = decompile.jadx(self.apk, self.output, budget())
        self.assertEqual(result["tool"], "jadx")
        self.assertEqual(result["status"], "degraded", result)
        self.assertEqual(result["sources"], [])
        self.assertIn("Exit code", result["error"])
        evidence = load_json(self.output / "jadx-run.json")
        self.assertEqual(evidence["status"], "failed")
        self.assertNotEqual(evidence["exit_code"], 0)


@unittest.skipUnless((APKTOOL_JAR is not None and APKTOOL_JAR.is_file()) and _jadx_ready(), "jadx/apktool tools missing (set RE_RUN_JADX / RE_RUN_APKTOOL)")
class CorruptInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-corrupt-")
        self.output = Path(self.temporary.name) / "out"
        self.output.mkdir(parents=True, exist_ok=True)
        self.corrupt = self.output / "corrupt.apk"
        # A structurally valid zip whose members are all garbage: the tools
        # must fail honestly instead of taking the pipeline down.
        with zipfile.ZipFile(self.corrupt, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x00\x01\x02garbage-not-axml")
            archive.writestr("classes.dex", b"garbage-not-a-dex")

    def tearDown(self):
        self.temporary.cleanup()

    def assert_honest_failure(self, result):
        # Non-zero exits and stopped runs are never reported as success, and
        # always carry a stderr-derived failure signature. Partial artifacts
        # (apktool copies raw files even on failure) may exist alongside.
        self.assertIn(result["status"], ("degraded", "failed"), result)
        self.assertNotEqual(result["status"], "succeeded")
        self.assertTrue(result["error"], "a failure must carry a signature")

    def test_jadx_on_garbage_fails_with_signature(self):
        with EnvironmentGuard():
            os.environ["RE_RUN_JADX"] = str(JADX_DIR)
            result = decompile.jadx(self.corrupt, self.output, budget())
        self.assert_honest_failure(result)
        self.assertEqual(result["sources"], [])
        evidence = load_json(self.output / "jadx-run.json")
        self.assertIn(evidence["status"], ("failed", "degraded", "timed-out", "output-exceeded"))
        self.assertIsInstance(evidence["stderr"], str)

    def test_apktool_on_garbage_fails_with_signature(self):
        with EnvironmentGuard():
            os.environ["RE_RUN_APKTOOL"] = str(APKTOOL_JAR)
            result = decompile.apktool(self.corrupt, self.output, budget())
        self.assert_honest_failure(result)
        self.assertFalse(any(source.endswith(".smali") for source in result["sources"]))
        evidence = load_json(self.output / "apktool-run.json")
        self.assertIn(evidence["status"], ("failed", "degraded", "timed-out", "output-exceeded"))
        self.assertIsInstance(evidence["stderr"], str)


@unittest.skipUnless((APKTOOL_JAR is not None and APKTOOL_JAR.is_file()) and _jadx_ready(), "jadx/apktool tools missing (set RE_RUN_JADX / RE_RUN_APKTOOL)")
class AndroidProfileIntegrationTests(unittest.TestCase):
    def test_profile_runs_s1_stage_and_schema_holds(self):
        with tempfile.TemporaryDirectory(prefix="re-android-s1-") as temporary:
            root = Path(temporary)
            apk = build_apk(root / "fixture.apk", dex())
            with EnvironmentGuard():
                os.environ["RE_RUN_JADX"] = str(JADX_DIR)
                os.environ["RE_RUN_APKTOOL"] = str(APKTOOL_JAR)
                result = analyze(apk_asset(apk), apk, root / "out", ScopePolicy(), budget())
            payload = result.to_dict()
            validate(payload, WORKER_RESULT_SCHEMA)
            names = {entry["name"]: entry["status"] for entry in result.checks}
            self.assertEqual(names["android-bytecode-decompile-apktool"], "succeeded")
            self.assertEqual(names["android-bytecode-decompile-jadx"], "succeeded")
            s1 = result.analysis["s1_extraction"]
            self.assertEqual(s1["apktool"]["status"], "succeeded")
            self.assertEqual(s1["jadx"]["status"], "succeeded")
            self.assertTrue(str(s1["jadx"]["version"]).startswith("1."), s1["jadx"]["version"])  # real jadx on PATH; version floats
            java = root / "out" / s1["jadx"]["sources"][0]
            self.assertIn("fixture-ok", java.read_text("utf-8", errors="replace"))
            # Lexical smali rule fired from the fixture's TelephonyManager reference.
            rules = [c["rule_id"] for c in result.candidates]
            self.assertIn("android-smali-telephony-identifier", rules)
            self.assertTrue((root / "out" / "apktool-run.json").is_file())
            self.assertTrue((root / "out" / "jadx-run.json").is_file())
            self.assertTrue((root / "out" / "apktool" / "AndroidManifest.xml").is_file())
            # The legacy manifest/analysis path is untouched.
            self.assertEqual(result.analysis["package"], "org.example.fixture")
            self.assertTrue(result.analysis["dex"][0]["checksum_valid"])


if __name__ == "__main__":
    unittest.main()
