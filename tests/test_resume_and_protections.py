import os
import tempfile
import unittest
from pathlib import Path

from re_runner.models import AssetRequest
from re_runner.protections import annotate
from re_runner.runner import Runner
from re_runner.safety import atomic_json
from re_runner.scope import ScopePolicy


class ResumeAndProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="re-resume-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup)
        self.asset = self.root / "source.py"
        self.asset.write_text("q=input()\nprint(q)\n", encoding="utf-8")

    def cleanup(self):
        for root, _, files in os.walk(self.root):
            for file in files:
                try:
                    (Path(root) / file).chmod(0o600)
                except OSError:
                    pass
        self.temp.cleanup()

    def test_interrupted_profile_resumes_without_repeating_snapshot(self):
        runner = Runner.new(self.root / "runs", [AssetRequest(str(self.asset))], ScopePolicy(), "triage", "en")
        item = runner.request["assets"][0]
        entry = runner.state["assets"].setdefault(item["id"], {"status": "pending", "attempts": 0})
        runner._intake(item, entry)
        interrupted = runner.root / "work" / item["id"] / "attempt-1"
        interrupted.mkdir(parents=True)
        atomic_json(interrupted / "usage.json", {"input_bytes": 0, "download_bytes": 0, "unpack_bytes": 0, "files": 0, "requests": 0})
        entry.update({"status": "running", "attempts": 1, "active_output": interrupted.relative_to(runner.root).as_posix(), "active_attempt_accounted": False})
        runner.persist()
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "succeeded", resumed["errors"])
        self.assertEqual(len([item for item in resumed["tool_runs"] if item["tool"] == "intake"]), 1)
        self.assertEqual(resumed["assets"]["asset-001"]["attempts"], 2)

    def test_cancelled_run_can_resume_after_explicit_request(self):
        runner = Runner.new(self.root / "runs", [AssetRequest(str(self.asset))], ScopePolicy(), "triage", "en")
        (runner.root / "cancel.request").write_text("cancel")
        state = runner.execute()
        self.assertEqual(state["status"], "cancelled")
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "succeeded", resumed["errors"])
        self.assertFalse((runner.root / "cancel.request").exists())

    def test_unknown_interrupted_usage_is_not_treated_as_zero(self):
        runner = Runner.new(self.root / "runs", [AssetRequest(str(self.asset))], ScopePolicy(), "triage", "en")
        item = runner.request["assets"][0]
        entry = runner.state["assets"].setdefault(item["id"], {"status": "pending", "attempts": 0})
        runner._intake(item, entry)
        interrupted = runner.root / "work" / item["id"] / "attempt-1"
        interrupted.mkdir(parents=True)
        entry.update({"status": "running", "attempts": 1, "active_output": interrupted.relative_to(runner.root).as_posix(), "active_attempt_accounted": False})
        runner.persist()
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "failed")
        self.assertTrue(resumed["assets"]["asset-001"]["budget_uncertain"])

    def test_protection_markers_do_not_claim_successful_bypass(self):
        result = annotate("binary", {"sections": [{"name": "UPX0", "bytes": 10000, "entropy": 7.8}], "imports": [{"library": "kernel32", "symbols": ["IsDebuggerPresent"]}], "symbols": []})
        self.assertFalse(result["bypass_executed"])
        names = [item["name"] for item in result["indicators"]]
        self.assertIn("upx-section-name", names)
        self.assertIn("debugger-inspection-imports", names)
        self.assertTrue(result["next_routes"])


if __name__ == "__main__":
    unittest.main()
