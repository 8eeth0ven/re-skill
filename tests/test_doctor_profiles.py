"""Doctor per-profile readiness: requirement matrix, statuses and backward-compatible global probe."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from re_runner.capabilities import PACKAGES, TOOLS, probe
from re_runner.models import KINDS

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
        # Readiness is a capability-input contract, not a real-radare2 acceptance run.
        # Use the current interpreter as a native-path fixture; the version call is mocked.
        version = SimpleNamespace(
            status="succeeded", exit_code=0, stdout="radare2 fixture-version\n",
            stderr="", timed_out=False,
        )
        with (
            patch.dict(os.environ, {"RE_RUN_R2": sys.executable, "RE_RUN_UPX": ""}),
            patch("re_runner.capabilities.shutil.which", return_value=None),
            patch("re_runner.capabilities.importlib.metadata.version", return_value="fixture-installed"),
            patch("re_runner.capabilities.run_command", return_value=version) as version_probe,
        ):
            value = probe("binary")
        version_probe.assert_called_once()
        self.assertEqual(version_probe.call_args.args[0], [sys.executable, "-qv"])
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
        # Rejecting a wrapper never requires an installed native radare2 binary.
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "radare2.bat"
            wrapper.write_bytes(b"@echo off\r\n")
            with (
                patch.dict(os.environ, {"RE_RUN_R2": str(wrapper), "RE_RUN_UPX": ""}),
                patch("re_runner.capabilities.shutil.which", return_value=None),
                patch("re_runner.capabilities.importlib.metadata.version", return_value="fixture-installed"),
                patch("re_runner.capabilities.run_command") as version_probe,
            ):
                entries = {item["name"]: item for item in probe("binary")["capabilities"]}
            version_probe.assert_not_called()
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
