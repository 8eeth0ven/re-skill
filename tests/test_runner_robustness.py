import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import re_runner.execution as execution_module
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import BudgetExceeded, Cancelled, IntegrityError
from re_runner.execution import run_command
from re_runner.models import Asset, AssetRequest
from re_runner.runner import Runner
from re_runner.safety import Budget, atomic_json, load_json
from re_runner.scope import ScopePolicy

ZERO_USAGE = {"input_bytes": 0, "download_bytes": 0, "unpack_bytes": 0, "files": 0, "requests": 0}


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-robust-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for directory, _, files in os.walk(self.root):
            for name in files:
                try:
                    (Path(directory) / name).chmod(0o600)
                except OSError:
                    pass
        self.temporary.cleanup()

    def source(self, content="print('safe')\n"):
        path = self.root / "app.py"
        path.write_text(content, encoding="utf-8")
        return path

    def runner(self):
        return Runner.new(self.root / "runs", [AssetRequest(str(self.source()))], ScopePolicy(), "triage", "en")

    def prepare(self, runner):
        item = runner.request["assets"][0]
        entry = runner.state["assets"].setdefault(item["id"], {"status": "pending", "attempts": 0})
        runner._intake(item, entry)
        return item, entry, Asset(**entry["asset"])


class UsageConsumptionTests(TempCase):
    def test_cancelled_branch_consumes_usage_exactly_once(self):
        runner = self.runner()
        output = runner.root / "work" / "asset-001" / "attempt-1"
        output.mkdir(parents=True)
        atomic_json(output / "usage.json", {**ZERO_USAGE, "files": 3})
        entry = {"active_attempt_accounted": False}
        # The cancelled/budget-exceeded branch calls the same consumer with no result payload.
        runner._consume_attempt_usage(entry, output, {})
        self.assertEqual(runner.budget.used["files"], 3)
        self.assertTrue(entry["active_attempt_accounted"])
        runner._consume_attempt_usage(entry, output, {})
        self.assertEqual(runner.budget.used["files"], 3)

    def test_missing_usage_journal_marks_budget_uncertain(self):
        runner = self.runner()
        output = runner.root / "work" / "asset-001" / "attempt-1"
        output.mkdir(parents=True)
        entry = {"active_attempt_accounted": False}
        runner._consume_attempt_usage(entry, output, {})
        self.assertTrue(entry["budget_uncertain"])
        self.assertTrue(entry["active_attempt_accounted"])
        self.assertEqual(sum(runner.budget.used.values()), 0)

    def test_invalid_usage_journal_is_rejected_without_accounting(self):
        runner = self.runner()
        output = runner.root / "work" / "asset-001" / "attempt-1"
        output.mkdir(parents=True)
        atomic_json(output / "usage.json", {"files": -2})
        entry = {"active_attempt_accounted": False}
        with self.assertRaises(IntegrityError):
            runner._consume_attempt_usage(entry, output, {})
        self.assertFalse(entry["active_attempt_accounted"])
        self.assertEqual(sum(runner.budget.used.values()), 0)


class AttemptDirectoryTests(TempCase):
    def test_stale_attempt_artifacts_are_cleared_before_dispatch(self):
        runner = self.runner()
        item, entry, asset = self.prepare(runner)
        used_before = dict(runner.budget.used)  # intake usage only
        output = runner.root / "work" / item["id"] / "attempt-1"
        output.mkdir(parents=True)
        (output / "tmp").mkdir()
        atomic_json(output / "result.json", {"ok": True, "stale": True})
        atomic_json(output / "usage.json", {**ZERO_USAGE, "input_bytes": 999})
        (output / "stdout.log").write_text("STALE", encoding="utf-8")
        (output / "stderr.log").write_text("STALE", encoding="utf-8")
        seen = {}

        def fail_dispatch(argv, cwd, budget, **kwargs):
            seen.update({name: (cwd / name).exists() for name in ("result.json", "usage.json", "stdout.log", "stderr.log")})
            raise Cancelled("stop before the worker runs")

        with patch("re_runner.runner.run_command", fail_dispatch):
            with self.assertRaises(Cancelled):
                runner._invoke(asset, entry)
        self.assertFalse(any(seen.values()), seen)
        # The stale attempt's journal (999 input bytes, 99 files) must stay unconsumed.
        self.assertEqual(runner.budget.used, used_before)
        self.assertEqual(entry["attempts"], 1)

    def test_resume_rebuilds_crashed_attempt_directory(self):
        runner = self.runner()
        item, entry, _ = self.prepare(runner)
        output = runner.root / "work" / item["id"] / "attempt-1"
        # Crash window: directory created (and polluted) before the state persist.
        (output / "tmp").mkdir(parents=True)
        atomic_json(output / "result.json", {"ok": True, "stale": True})
        atomic_json(output / "usage.json", {**ZERO_USAGE, "files": 99})
        runner.persist()
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "succeeded", resumed["errors"])
        self.assertEqual(resumed["assets"][item["id"]]["attempts"], 1)
        payload = load_json(output / "result.json")
        self.assertIn("result", payload)
        self.assertNotIn("stale", payload)


class WallBudgetTests(TempCase):
    def test_wall_deadline_round_trip_and_expiry(self):
        future = time.time() + 3600
        live = Budget(dict(BUDGET_DEFAULTS), wall_deadline_epoch=future)
        self.assertEqual(live.wall_deadline_epoch, future)
        self.assertGreater(live.wall_remaining(), 3598)
        live.check()
        expired = Budget(dict(BUDGET_DEFAULTS), wall_deadline_epoch=time.time() - 5)
        with self.assertRaises(BudgetExceeded):
            expired.check()

    def test_legacy_budget_without_deadline_is_unchanged(self):
        budget = Budget(dict(BUDGET_DEFAULTS))
        self.assertIsNone(budget.wall_deadline_epoch)
        self.assertLessEqual(budget.wall_remaining(), BUDGET_DEFAULTS["max_wall_seconds"])
        budget.check()

    def test_wall_budget_persists_across_resume(self):
        runner = self.runner()
        self.assertNotIn("wall_budget", runner.state)
        deadline = time.time() + 12345
        runner.state["wall_budget"] = {"max_wall_seconds": BUDGET_DEFAULTS["max_wall_seconds"], "deadline_epoch": deadline}
        runner.persist()
        resumed = Runner.resume(runner.root)
        self.assertEqual(resumed.budget.wall_deadline_epoch, deadline)

    def test_expired_persisted_deadline_fails_the_run(self):
        runner = self.runner()
        item, entry, _ = self.prepare(runner)
        runner.state["wall_budget"] = {"max_wall_seconds": 5, "deadline_epoch": time.time() - 1}
        runner.persist()
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "failed")
        self.assertEqual(resumed["assets"][item["id"]]["attempts"], 0)
        self.assertTrue(any("wall-time" in error["message"] for error in resumed["errors"]), resumed["errors"])

    def test_fresh_execute_persists_wall_budget_for_resume(self):
        runner = self.runner()
        state = runner.execute()
        self.assertEqual(state["status"], "succeeded", state["errors"])
        stored = load_json(runner.root / "state.json")["wall_budget"]
        self.assertEqual(stored["max_wall_seconds"], BUDGET_DEFAULTS["max_wall_seconds"])
        self.assertIsInstance(stored["deadline_epoch"], float)
        self.assertEqual(Runner.resume(runner.root).budget.wall_deadline_epoch, stored["deadline_epoch"])


class EvidenceGateTests(TempCase):
    @staticmethod
    def finding(status):
        return {
            "id": "f-robust", "asset_id": "asset-001", "rule_id": "rule", "status": status,
            "severity": "high", "title": "t", "overview": "o", "technical": "tech",
            "verification": "v", "impact": "i", "remediation": "r", "evidence_ids": ["e-missing"],
        }

    def test_cancelled_gate_downgrades_unproven_verified_findings(self):
        runner = self.runner()
        runner.state["findings"] = [self.finding("verified")]
        with self.assertRaises(IntegrityError):
            runner._gate_findings(cancelled=False)  # success paths still fail loudly
        runner._gate_findings(cancelled=True)
        finding = runner.state["findings"][0]
        self.assertEqual(finding["status"], "candidate")
        self.assertIn("cancel", finding["verification"].lower())

    def test_cancelled_gate_keeps_candidate_findings(self):
        runner = self.runner()
        runner.state["findings"] = [self.finding("candidate")]
        runner._gate_findings(cancelled=True)
        self.assertEqual(runner.state["findings"][0]["status"], "candidate")

    def test_gate_passes_without_findings(self):
        runner = self.runner()
        runner._gate_findings(cancelled=False)
        runner._gate_findings(cancelled=True)


class StubJob:
    def __init__(self, memory_mb):
        self.killed = False

    def attach_and_resume(self, process):
        pass

    def kill(self):
        self.killed = True

    def close(self):
        pass


class FakePipe:
    def __init__(self, flood=False):
        self.calls, self.flood = 0, flood

    def read1(self, size):
        self.calls += 1
        # One oversized block trips the output budget without parking megabytes
        # in the capped buffers, which would make redaction needlessly slow.
        return b"X" * (8192 if self.flood and self.calls == 1 else 0)

    def close(self):
        pass


class FakePopen:
    def __init__(self, argv, **kwargs):
        self.argv, self.pid, self.returncode = argv, 4711, None
        self.stdout, self.stderr = FakePipe(flood=True), FakePipe()
        self.kills = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode

    def kill(self):
        self.kills += 1


class DyingPopen(FakePopen):
    def kill(self):
        self.kills += 1
        self.returncode = 1


class ReapTests(TempCase):
    def run_fake(self, popen_cls):
        limits = dict(BUDGET_DEFAULTS, max_tool_output_bytes=4096)
        with patch.object(execution_module, "WindowsJob", StubJob), \
                patch.object(execution_module.subprocess, "Popen", popen_cls), \
                patch.object(execution_module, "REAP_SECONDS", 0.2):
            return run_command([sys.executable, "-c", "pass"], self.root, Budget(limits))

    def test_unkillable_process_reports_unknown_exit_code(self):
        result = self.run_fake(FakePopen)
        self.assertEqual(result.status, "output-exceeded")
        self.assertIsNone(result.exit_code)
        self.assertTrue(result.reap_failed)

    def test_process_killed_after_refusal_is_reaped(self):
        result = self.run_fake(DyingPopen)
        self.assertEqual(result.status, "output-exceeded")
        self.assertEqual(result.exit_code, 1)
        self.assertFalse(result.reap_failed)


if __name__ == "__main__":
    unittest.main()
