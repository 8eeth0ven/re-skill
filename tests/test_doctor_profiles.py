"""Doctor per-profile readiness: requirement matrix, statuses and backward-compatible global probe."""
import os
import tempfile
import unittest
from pathlib import Path

from re_runner.capabilities import PACKAGES, TOOLS, probe
from re_runner.models import KINDS

REPO = Path(__file__).resolve().parents[1]
R2 = REPO / "tools-env" / "radare2-6.2.4" / "radare2-6.2.4-w64" / "bin" / "radare2.exe"
TOP_LEVEL_KEYS = {"os", "python", "profile", "builtin_profiles", "capabilities", "isolation", "note"}
PROFILE_ENTRY_KEYS = {"name", "kind", "required", "available", "status", "purpose", "operations", "version"}
STATUSES = {"missing", "present", "runnable"}


class GlobalProbeTests(unittest.TestCase):
    def test_global_shape_is_backward_compatible(self):
        value = probe(None)
        self.assertTrue(TOP_LEVEL_KEYS <= set(value))
        self.assertIsNone(value["profile"])
        self.assertEqual(list(value["builtin_profiles"]), list(KINDS))
        self.assertEqual(len(value["capabilities"]), len(PACKAGES) + len(TOOLS))
        for item in value["capabilities"]:
            self.assertEqual(set(item), {"name", "available", "version", "operations", "reason"})


class ProfileProbeTests(unittest.TestCase):
    def test_binary_profile_required_packages_and_r2_provider(self):
        if not R2.exists():
            self.skipTest("radare2 fixture is not present under tools-env")
        self.addCleanup(os.environ.pop, "RE_RUN_R2", None)
        os.environ["RE_RUN_R2"] = str(R2)
        value = probe("binary")
        self.assertTrue(TOP_LEVEL_KEYS <= set(value))
        self.assertEqual(value["profile"], "binary")
        entries = {item["name"]: item for item in value["capabilities"]}
        for name in ("lief", "capstone"):
            item = entries[name]
            self.assertTrue(item["required"], name)
            self.assertEqual(item["kind"], "package", name)
            self.assertTrue(item["available"], name)
            self.assertEqual(item["status"], "runnable", name)
            self.assertTrue(item["version"], name)
        r2 = entries["r2"]
        self.assertFalse(r2["required"])
        self.assertEqual(r2["kind"], "tool")
        self.assertTrue(r2["available"])
        self.assertIn(r2["status"], ("present", "runnable"))
        requirements = value["profile_requirements"]
        self.assertEqual(requirements["required"], ["lief", "capstone"])
        self.assertEqual(requirements["required_missing"], [])
        self.assertTrue(requirements["summary"]["required_ready"])
        self.assertIn("r2", requirements["optional"])

    def test_binary_r2_wrapper_scripts_are_rejected(self):
        if not R2.exists():
            self.skipTest("radare2 fixture is not present under tools-env")
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "radare2.bat"
            wrapper.write_bytes(b"@echo off\r\n")
            self.addCleanup(os.environ.pop, "RE_RUN_R2", None)
            os.environ["RE_RUN_R2"] = str(wrapper)
            entries = {item["name"]: item for item in probe("binary")["capabilities"]}
        self.assertFalse(entries["r2"]["available"])
        self.assertEqual(entries["r2"]["status"], "missing")
        self.assertIn("wrapper", entries["r2"]["reason"])

    def test_android_optional_tools_missing_do_not_break_readiness(self):
        value = probe("android")
        entries = {item["name"]: item for item in value["capabilities"]}
        for name, variable in (("jadx", "RE_RUN_JADX"), ("apktool", "RE_RUN_APKTOOL")):
            item = entries[name]
            self.assertFalse(item["required"], name)
            self.assertEqual(item["kind"], "tool", name)
            # Both routes are wired; the purpose documents the resolving variable.
            self.assertIn(variable, item["purpose"], name)
            if not item["available"]:
                self.assertEqual(item["status"], "missing", name)
        requirements = value["profile_requirements"]
        self.assertTrue(requirements["summary"]["required_ready"])
        self.assertEqual(requirements["required_missing"], [])

    def test_traffic_profile_reports_requirements_structure(self):
        value = probe("traffic")
        self.assertEqual(value["profile"], "traffic")
        requirements = value["profile_requirements"]
        for key in ("required", "optional", "required_missing", "summary"):
            self.assertIn(key, requirements)
        self.assertIsInstance(requirements["summary"]["required_ready"], bool)
        entries = {item["name"]: item for item in value["capabilities"]}
        self.assertFalse(entries["tshark"]["required"])
        self.assertEqual(entries["tshark"]["kind"], "tool")
        for item in value["capabilities"]:
            self.assertTrue(PROFILE_ENTRY_KEYS <= set(item), item["name"])
            self.assertIn(item["status"], STATUSES, item["name"])

    def test_device_entries_declare_environment_requirement(self):
        value = probe("device")
        entries = {item["name"]: item for item in value["capabilities"]}
        self.assertEqual(set(entries), {"adb", "ideviceinfo", "pyserial"})
        for name, item in entries.items():
            self.assertTrue(item.get("requires-environment"), name)
            self.assertIn(item["status"], STATUSES, name)

    def test_every_kind_reports_a_complete_matrix(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                value = probe(kind)
                self.assertTrue(TOP_LEVEL_KEYS <= set(value))
                requirements = value["profile_requirements"]
                self.assertEqual(
                    sorted(requirements["required"] + requirements["optional"]),
                    sorted(item["name"] for item in value["capabilities"]),
                )
                self.assertEqual(
                    requirements["required"],
                    [item["name"] for item in value["capabilities"] if item["required"]],
                )
                self.assertEqual(
                    requirements["required_missing"],
                    [item["name"] for item in value["capabilities"] if item["required"] and not item["available"]],
                )
                self.assertEqual(
                    requirements["summary"]["required_ready"],
                    not requirements["required_missing"],
                )
                for item in value["capabilities"]:
                    self.assertIn(item["status"], STATUSES, item["name"])


if __name__ == "__main__":
    unittest.main()
