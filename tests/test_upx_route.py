"""UPX static unpack route against the real tool: positive control and honest failures.

Platform-agnostic lanes (fixture work happens in setUp/setUpClass; the code
under test only ever runs `upx -d` on a real file):

- ELF lane (any host with a real `upx`): a minimal static ELF64 x86-64 is
  hand-crafted by tools/upx-sample (no cross compiler needed), packed by the
  local upx binary — UPX supports ELF everywhere, so the full
  pack -> detect -> `upx -d` positive path runs on macOS without Windows.
- Mach-O lane (macOS with cc): `cc` builds a Mach-O and `upx --force-macos`
  packs it (macho/arm64). Recorded honestly: brew upx 5.2.1 cannot `upx -d`
  its own Mach-O output (NotPackedException, while --file-info reports
  AlreadyPackedException), so this lane asserts DETECTION positive and the
  failed unpack attempt with its captured signature.
- Windows PE lane: the original tests, kept intact; they run only when the
  win64 upx.exe and a PE sample actually exist on disk ("run if present").
"""
import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from re_runner.models import Asset
from re_runner.profiles.binary import analyze as analyze_binary
from re_runner.protections import annotate
from re_runner.safety import Budget, load_json, sha256_file
from re_runner.scope import ScopePolicy
from re_runner.unpackers import upx_unpack

ROOT = Path(__file__).resolve().parents[1]
WIN_UPX = ROOT / "tools-env" / "upx-5.0.2" / "upx-5.0.2-win64" / "upx.exe"
WIN_PE = ROOT / ".venv" / "Scripts" / "python.exe"

_UPX_SAMPLE_PATH = ROOT / "tools" / "upx-sample"


def _resolve_upx() -> Path | None:
    """RE_RUN_UPX wins, then PATH, then the legacy bundled win64 binary."""
    configured = os.environ.get("RE_RUN_UPX")
    if configured and Path(configured).is_file():
        return Path(configured)
    on_path = shutil.which("upx")
    if on_path:
        return Path(on_path)
    return WIN_UPX if WIN_UPX.is_file() else None


def _load_sample_helpers():
    if not _UPX_SAMPLE_PATH.is_file():
        raise unittest.SkipTest("tools/upx-sample generator is missing")
    # The file has no .py suffix, so pick the source loader explicitly.
    loader = importlib.machinery.SourceFileLoader("re_upx_sample", str(_UPX_SAMPLE_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


UPX = _resolve_upx()
CC = shutil.which("cc")
IS_MAC = sys.platform == "darwin"


class _UpxEnvBase(unittest.TestCase):
    """Shared env handling: point RE_RUN_UPX at the resolved real binary."""

    upx: Path | None = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="re-upx-route-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self._saved_env = os.environ.get("RE_RUN_UPX")
        os.environ["RE_RUN_UPX"] = str(self.upx)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._saved_env is None:
            os.environ.pop("RE_RUN_UPX", None)
        else:
            os.environ["RE_RUN_UPX"] = self._saved_env

    def analyze(self, path, name):
        output = self.root / (Path(name).stem + "-out")
        output.mkdir()
        asset = Asset(id=Path(name).stem, locator=str(path), kind="binary", format="pe")
        return analyze_binary(asset, path, output, ScopePolicy(), Budget(ScopePolicy().budgets)), output

    def check_statuses(self, result):
        return {check["name"]: check["status"] for check in result.checks}


@unittest.skipUnless(UPX is not None, "a real upx executable (RE_RUN_UPX or PATH) is required")
class UpxElfRouteTests(_UpxEnvBase):
    """Full positive/negative controls via a hand-crafted ELF64 — no Windows toolchain."""

    upx = UPX

    @classmethod
    def setUpClass(cls):
        helpers = _load_sample_helpers()
        cls.fixtures = tempfile.TemporaryDirectory(prefix="re-upx-elf-")
        base = Path(cls.fixtures.name)
        cls.plain = helpers.build_plain_elf(base / "plain.elf")
        helpers.pack(UPX, cls.plain, base / "packed.elf")
        cls.packed = base / "packed.elf"
        cls.corrupted = helpers.corrupt_truncated(cls.packed, base / "corrupted.elf")

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def test_packed_elf_unpacks_with_behavioral_delta_and_evidence(self):
        route = upx_unpack(self.packed, self.root / "unpack-upx", Budget(ScopePolicy().budgets))
        self.assertEqual(route["tool"], "upx")
        self.assertEqual(route["status"], "succeeded")
        self.assertIn("upx", route["version"].lower())
        # Behavioral comparison: the unpacked image is the original crafted ELF.
        self.assertTrue(route["delta"]["size_grew"])
        self.assertTrue(route["delta"]["sha256_changed"])
        self.assertEqual(route["unpacked"]["sha256"], sha256_file(self.plain))
        self.assertGreater(route["unpacked"]["bytes"], route["baseline"]["bytes"])
        # A packed ELF drops its section header table, so no upx-named sections exist.
        self.assertEqual(route["delta"]["packed_section_names_baseline"], [])
        evidence_dir = self.root / "unpack-upx"
        evidence = evidence_dir / "upx-unpack-run.json"
        self.assertTrue(evidence.is_file())
        self.assertEqual(sha256_file(evidence), hashlib.sha256(evidence.read_bytes()).hexdigest())
        payload = load_json(evidence)
        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["argv"][1:3], ["-d", "-o"])
        self.assertEqual(payload["argv"][-1], str(self.packed.absolute()))
        self.assertTrue((evidence_dir / "upx-version-run.json").is_file())

    def test_plain_elf_is_a_negative_control(self):
        route = upx_unpack(self.plain, self.root / "direct-out", Budget(ScopePolicy().budgets))
        self.assertEqual(route["status"], "failed")
        self.assertIn("NotPackedException", route["error"])
        self.assertIn("not packed by UPX", route["error"])
        self.assertIsNone(route["unpacked"])
        self.assertIsNone(route["delta"])
        self.assertEqual(load_json(self.root / "direct-out" / "upx-unpack-run.json")["status"], "failed")
        # And the profile never triggers the route without a packing indication.
        result, output = self.analyze(self.plain, "plain.elf")
        self.assertNotIn("unpack_route", result.analysis)
        statuses = self.check_statuses(result)
        self.assertNotIn("protected-binary-unpack-upx", statuses)
        self.assertEqual(statuses["native-header-sections-imports"], "succeeded")
        self.assertFalse((output / "unpack-upx").exists())

    def test_corrupted_packed_elf_is_a_negative_control(self):
        # Truncation of the packed stream: upx -d must fail, never fabricate output.
        route = upx_unpack(self.corrupted, self.root / "corrupt-out", Budget(ScopePolicy().budgets))
        self.assertEqual(route["status"], "failed")
        self.assertTrue(route["error"])
        self.assertIsNone(route["unpacked"])
        self.assertIsNone(route["delta"])
        self.assertFalse((self.root / "corrupt-out" / "unpacked.bin").exists())

    def test_unconfigured_env_returns_none(self):
        plain, packed = self.plain, self.packed
        del os.environ["RE_RUN_UPX"]
        self.assertIsNone(upx_unpack(packed, self.root / "no-env", Budget(ScopePolicy().budgets)))
        self.assertIsNone(upx_unpack(plain, self.root / "no-env", Budget(ScopePolicy().budgets)))


@unittest.skipUnless(UPX is not None, "a real upx executable (RE_RUN_UPX or PATH) is required")
@unittest.skipUnless(IS_MAC and CC, "Mach-O lane needs macOS and a cc toolchain")
class UpxMachoDetectionTests(_UpxEnvBase):
    """macOS detection lane: `upx --force-macos` packs a Mach-O; `upx -d` on it is a
    recorded upstream limitation (brew upx 5.2.1 NotPackedException), so the positive
    control here is detection + attempted route, never a fabricated success."""

    upx = UPX

    @classmethod
    def setUpClass(cls):
        helpers = _load_sample_helpers()
        cls.fixtures = tempfile.TemporaryDirectory(prefix="re-upx-macho-")
        base = Path(cls.fixtures.name)
        cls.plain = helpers.build_macho(CC, base, base / "plain.macho")
        helpers.pack(UPX, cls.plain, base / "packed.macho", extra=("--force-macos",))
        cls.packed = base / "packed.macho"

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def macho_sections(self, result):
        return {item["name"].lower() for item in result.analysis["sections"]}

    def test_packed_macho_detected_and_route_attempted_with_honest_failure(self):
        result, output = self.analyze(self.packed, "packed.macho")
        # Detection positive: upx-named section found, indication fired, route ran.
        self.assertTrue(any(name.startswith("upx") for name in self.macho_sections(result)))
        route = result.analysis["unpack_route"]
        self.assertEqual(route["tool"], "upx")
        # Honest record: this upx build cannot -d its own Mach-O output.
        self.assertEqual(route["status"], "failed")
        self.assertIn("NotPackedException", route["error"])
        statuses = self.check_statuses(result)
        self.assertEqual(statuses["protected-binary-unpack-upx"], "degraded")
        self.assertTrue((output / "unpack-upx" / "upx-unpack-run.json").is_file())
        protection = annotate("binary", result.analysis)
        names = {item["name"] for item in protection["indicators"]}
        self.assertIn("upx-section-name", names)
        self.assertFalse(any(route.get("route") == "upx-static-unpack" for route in protection["next_routes"]))
        self.assertFalse(protection["bypass_executed"])

    def test_packed_macho_env_skipped_and_profile_unchanged(self):
        del os.environ["RE_RUN_UPX"]
        result, output = self.analyze(self.packed, "packed.macho")
        self.assertNotIn("unpack_route", result.analysis)
        statuses = self.check_statuses(result)
        self.assertEqual(statuses["protected-binary-unpack-upx"], "skipped")
        self.assertEqual(statuses["native-header-sections-imports"], "succeeded")
        self.assertEqual(result.analysis["sha256"], hashlib.sha256(self.packed.read_bytes()).hexdigest())
        self.assertFalse((output / "unpack-upx").exists())
        protection = annotate("binary", result.analysis)
        self.assertTrue(any(route["operation"] == "isolate-and-unpack" for route in protection["next_routes"]))
        self.assertFalse(any(route.get("route") == "upx-static-unpack" for route in protection["next_routes"]))
        self.assertFalse(protection["bypass_executed"])

    def test_plain_macho_is_a_negative_control(self):
        result, output = self.analyze(self.plain, "plain.macho")
        self.assertNotIn("unpack_route", result.analysis)
        statuses = self.check_statuses(result)
        self.assertNotIn("protected-binary-unpack-upx", statuses)
        self.assertEqual(statuses["native-header-sections-imports"], "succeeded")
        self.assertFalse((output / "unpack-upx").exists())
        route = upx_unpack(self.plain, self.root / "direct-out", Budget(ScopePolicy().budgets))
        self.assertEqual(route["status"], "failed")
        # upx -d diagnoses an unpacked Mach-O with CantUnpackException (ELF says
        # NotPackedException); any tool exception proves the negative control.
        self.assertIn("Exception", route["error"])


@unittest.skipUnless(WIN_UPX.is_file() and WIN_PE.is_file(), "run-if-present: needs the win64 upx.exe and a small PE sample")
class UpxWindowsPeRouteTests(_UpxEnvBase):
    """Original Windows PE lane, unchanged assertions; runs only when the assets exist."""

    upx = WIN_UPX

    def pack(self):
        # Fixture compression: a real packed PE built from a local python.exe copy.
        plain = self.root / "plain.exe"
        plain.write_bytes(WIN_PE.read_bytes())
        packed = self.root / "packed.exe"
        subprocess.run([str(WIN_UPX), "-o", str(packed), str(plain)], check=True, capture_output=True, timeout=60)
        return plain, packed

    def test_packed_pe_unpacks_with_behavioral_delta_and_evidence(self):
        plain, packed = self.pack()
        result, output = self.analyze(packed, "packed.exe")
        section_names = {item["name"].lower() for item in result.analysis["sections"]}
        self.assertTrue(any(name.startswith(("upx", ".upx")) for name in section_names))
        route = result.analysis["unpack_route"]
        self.assertEqual(route["tool"], "upx")
        self.assertEqual(route["status"], "succeeded")
        self.assertIn("5.0.2", route["version"])
        self.assertEqual(route["delta"]["packed_section_names_baseline"], ["upx0", "upx1"])
        self.assertTrue(route["delta"]["packed_sections_absent"])
        self.assertTrue(route["delta"]["entropy_dropped"])
        self.assertLess(route["unpacked"]["max_section_entropy"], route["baseline"]["max_section_entropy"])
        self.assertTrue(route["delta"]["size_grew"])
        self.assertGreater(route["unpacked"]["bytes"], route["baseline"]["bytes"])
        self.assertTrue(route["unpacked"]["import_libraries"])
        statuses = self.check_statuses(result)
        self.assertEqual(statuses["protected-binary-unpack-upx"], "succeeded")
        self.assertEqual(statuses["unpacked-binary-structure"], "succeeded")
        evidence = output / "unpack-upx" / "upx-unpack-run.json"
        self.assertTrue(evidence.is_file())
        self.assertEqual(sha256_file(evidence), hashlib.sha256(evidence.read_bytes()).hexdigest())
        payload = load_json(evidence)
        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["argv"][1:3], ["-d", "-o"])
        self.assertEqual(payload["argv"][-1].lower(), str(packed.absolute()).lower())
        self.assertTrue((output / "unpack-upx" / "upx-version-run.json").is_file())
        protection = annotate("binary", result.analysis)
        executed = [route for route in protection["next_routes"] if route.get("route") == "upx-static-unpack"]
        self.assertEqual(executed, [{"route": "upx-static-unpack", "executed": True, "evidence": "unpack-upx/upx-unpack-run.json"}])
        self.assertFalse(protection["bypass_executed"])

    def test_unpacked_sample_fails_with_upx_signature(self):
        plain, _ = self.pack()
        direct_out = self.root / "direct-out"
        direct_out.mkdir()
        route = upx_unpack(plain, direct_out, Budget(ScopePolicy().budgets))
        self.assertEqual(route["tool"], "upx")
        self.assertEqual(route["status"], "failed")
        self.assertIn("NotPackedException", route["error"])
        self.assertIn("not packed by UPX", route["error"])
        self.assertIsNone(route["unpacked"])
        self.assertIsNone(route["delta"])
        payload = load_json(direct_out / "upx-unpack-run.json")
        self.assertEqual(payload["status"], "failed")
        result, output = self.analyze(plain, "plain.exe")
        self.assertNotIn("unpack_route", result.analysis)
        statuses = self.check_statuses(result)
        self.assertNotIn("protected-binary-unpack-upx", statuses)
        self.assertEqual(statuses["native-header-sections-imports"], "succeeded")
        self.assertFalse((output / "unpack-upx").exists())

    def test_unconfigured_env_is_skipped_and_profile_unchanged(self):
        plain, packed = self.pack()
        del os.environ["RE_RUN_UPX"]
        result, output = self.analyze(packed, "packed.exe")
        self.assertNotIn("unpack_route", result.analysis)
        statuses = self.check_statuses(result)
        self.assertEqual(statuses["protected-binary-unpack-upx"], "skipped")
        self.assertEqual(statuses["native-header-sections-imports"], "succeeded")
        self.assertEqual(statuses["entry-disassembly"], "succeeded")
        self.assertEqual(result.analysis["sha256"], hashlib.sha256(packed.read_bytes()).hexdigest())
        self.assertFalse((output / "unpack-upx").exists())
        protection = annotate("binary", result.analysis)
        self.assertTrue(any(route["operation"] == "isolate-and-unpack" for route in protection["next_routes"]))
        self.assertFalse(any(route.get("route") == "upx-static-unpack" for route in protection["next_routes"]))
        self.assertFalse(protection["bypass_executed"])


if __name__ == "__main__":
    unittest.main()
