"""Cancellation/deadline settlement through the real Runner.execute() path.

A stop condition must never erase the record of work already done: the attempt's
ToolRun, its usage journal and the accounted flag must land before the run
raises, and a resume must never count the same journal twice.
"""
import io
import os
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from re_runner import contracts
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import BudgetExceeded, Cancelled
from re_runner.execution import run_command as real_run_command
from re_runner.models import AssetRequest
from re_runner.runner import Runner
from re_runner.safety import Budget, load_json
from re_runner.scope import ScopePolicy

WATCH_SECONDS = 120  # generous: only a pathologically stalled worker hits this
KEYS = ("input_bytes", "download_bytes", "unpack_bytes", "files", "requests")


class TempCase(unittest.TestCase):
    def setUp(self):
        # ignore_cleanup_errors: an AV/indexer scan can transiently lock a fresh
        # fixture on Windows; that must not fail the test.
        self.temporary = tempfile.TemporaryDirectory(prefix="re-cancel-", ignore_cleanup_errors=True)
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

    def firmware(self, members=300):
        """A tar whose worker-side extraction consumes files/unpack_bytes gradually."""
        path = self.root / "fixture.tar"
        with tarfile.open(path, "w") as archive:
            for index in range(members):
                data = f"component-{index} configuration=fixture-{index}\n".encode("utf-8")
                info = tarfile.TarInfo(f"etc/file-{index:04d}.conf")
                info.size, info.mode, info.mtime = len(data), 0o600, 0
                archive.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def fast_polls():
        # The runner-side monitor must observe the stop signal before the worker
        # notices it and exits on its own (which would report "failed", not
        # "cancelled"). Shrinking the monitor's sleep to 1ms makes that ordering
        # deterministic (the worker needs several ms to react and exit) without
        # touching production code, while still yielding the CPU under load.
        return patch("re_runner.execution.time.sleep", lambda seconds: threading.Event().wait(0.001))

    def watch_until_working(self, action, attempt_dir):
        """Run action() once the worker is provably mid-extraction.

        The first extracted member appears only after the worker consumed
        "files"/"unpack_bytes", so the journal is guaranteed non-zero. Directory
        listings never open worker-written files, so this cannot collide with
        the worker's atomic usage.json rewrites.
        """
        def watch():
            deadline = time.monotonic() + WATCH_SECONDS
            root = attempt_dir / "rootfs"
            while time.monotonic() < deadline:
                try:
                    if root.exists() and any(root.rglob("*")):
                        break
                except OSError:
                    pass
                threading.Event().wait(0.002)
            action()
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        return thread

    @staticmethod
    def events_text(runner):
        path = runner.root / "events.jsonl"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    @staticmethod
    def intake_used(source):
        # A single-file asset consumes exactly one file and its bytes at intake.
        return {"input_bytes": source.stat().st_size, "download_bytes": 0, "unpack_bytes": 0, "files": 1, "requests": 0}


class CancelSettlementTests(TempCase):
    def test_cancel_during_worker_settles_toolrun_and_journal_exactly_once(self):
        source = self.firmware()
        runner = Runner.new(self.root / "runs", [AssetRequest(str(source))], ScopePolicy(), "triage", "en")
        cancel_path = runner.root / "cancel.request"
        attempt_dir = runner.root / "work" / "asset-001" / "attempt-1"

        def cancelling_run_command(argv, cwd, budget, **kwargs):
            thread = self.watch_until_working(lambda: cancel_path.write_text("cancel", encoding="utf-8"), attempt_dir)
            try:
                return real_run_command(argv, cwd, budget, **kwargs)
            finally:
                thread.join()

        with self.fast_polls(), patch("re_runner.runner.run_command", cancelling_run_command):
            state = runner.execute()

        self.assertEqual(state["status"], "cancelled", state["errors"])
        self.assertTrue(cancel_path.exists())  # cleared by resume, not by the run
        cancelled = [item for item in state["tool_runs"] if item["tool"] == "profile:firmware" and item["status"] == "cancelled"]
        self.assertEqual(len(cancelled), 1, state["tool_runs"])
        report = load_json(runner.root / "report.json")
        self.assertIn(cancelled[0]["id"], [item["id"] for item in report["tool_runs"]])
        entry = state["assets"]["asset-001"]
        self.assertEqual(entry["attempts"], 1)
        self.assertTrue(entry["active_attempt_accounted"])
        self.assertFalse(entry.get("budget_uncertain", False))
        journal = load_json(attempt_dir / "usage.json")
        self.assertTrue(any(journal.values()), journal)  # the killed worker's real usage
        expected = {key: self.intake_used(source)[key] + journal.get(key, 0) for key in KEYS}
        self.assertEqual(state["used"], expected)  # settled completely, exactly once
        self.assertNotIn("interrupted-attempt-recovered", self.events_text(runner))

        resumed = Runner.resume(runner.root).execute()
        self.assertIn(resumed["status"], ("succeeded", "degraded"), resumed["errors"])
        self.assertFalse((runner.root / "cancel.request").exists())
        self.assertEqual(len([item for item in resumed["tool_runs"] if item["tool"] == "intake"]), 1)
        expected_final = dict(self.intake_used(source))
        for path in sorted((runner.root / "work" / "asset-001").glob("attempt-*/usage.json")):
            for key, amount in load_json(path).items():
                expected_final[key] += amount
        # The cancelled attempt's journal was kept; nothing was counted twice.
        self.assertEqual(resumed["used"], expected_final)
        self.assertEqual(resumed["assets"]["asset-001"]["attempts"], 2)
        self.assertNotIn("interrupted-attempt-recovered", self.events_text(runner))

    def test_expired_deadline_keeps_completed_toolruns_and_exact_accounting(self):
        source = self.firmware(members=5)
        runner = Runner.new(self.root / "runs", [AssetRequest(str(source))], ScopePolicy(), "triage", "en")
        first = runner.execute()
        self.assertEqual(first["status"], "succeeded", first["errors"])
        used_before = dict(first["used"])
        tool_runs_before = [item["id"] for item in first["tool_runs"]]
        runner.state["wall_budget"] = {"max_wall_seconds": BUDGET_DEFAULTS["max_wall_seconds"], "deadline_epoch": time.time() - 1}
        runner.persist()

        resumed = Runner.resume(runner.root).execute()

        self.assertEqual(resumed["status"], "failed")
        self.assertTrue(any("wall-time" in error["message"] for error in resumed["errors"]), resumed["errors"])
        self.assertTrue(any(error["code"] == "budget-exceeded" for error in resumed["errors"]), resumed["errors"])
        self.assertEqual([item["id"] for item in resumed["tool_runs"]], tool_runs_before)
        report = load_json(runner.root / "report.json")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["budget_used"], used_before)  # no partial accounting after the stop
        self.assertEqual(resumed["used"], used_before)

    def test_midflight_deadline_expiry_settles_toolrun_and_journal_before_raising(self):
        source = self.firmware()
        runner = Runner.new(self.root / "runs", [AssetRequest(str(source))], ScopePolicy(), "triage", "en")
        attempt_dir = runner.root / "work" / "asset-001" / "attempt-1"

        def expiring_run_command(argv, cwd, budget, **kwargs):
            def expire():
                budget.wall_deadline_epoch = time.time() - 1
            thread = self.watch_until_working(expire, attempt_dir)
            try:
                return real_run_command(argv, cwd, budget, **kwargs)
            finally:
                thread.join()

        with self.fast_polls(), patch("re_runner.runner.run_command", expiring_run_command):
            state = runner.execute()

        self.assertEqual(state["status"], "failed")
        expired = [item for item in state["tool_runs"] if item["tool"] == "profile:firmware" and item["status"] == "budget-exceeded"]
        self.assertEqual(len(expired), 1, state["tool_runs"])
        report = load_json(runner.root / "report.json")
        self.assertIn(expired[0]["id"], [item["id"] for item in report["tool_runs"]])
        self.assertTrue(any(error["code"] == "budget-exceeded" for error in state["errors"]), state["errors"])
        entry = state["assets"]["asset-001"]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["attempts"], 1)
        self.assertTrue(entry["active_attempt_accounted"])
        journal = load_json(attempt_dir / "usage.json")
        self.assertTrue(any(journal.values()), journal)
        expected = {key: self.intake_used(source)[key] + journal.get(key, 0) for key in KEYS}
        self.assertEqual(state["used"], expected)

    def test_cancelled_validator_is_recorded_and_finding_stays_candidate(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        tree = self.root / "keys"
        tree.mkdir()
        key = ed25519.Ed25519PrivateKey.generate()
        (tree / "fixture.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        runner = Runner.new(self.root / "runs", [AssetRequest(str(tree))], ScopePolicy(), "verify", "en")
        cancel_path = runner.root / "cancel.request"

        def cancelling_run_command(argv, cwd, budget, **kwargs):
            if cwd.name.startswith("verify-"):
                # Fire early so the request lands while the validator subprocess
                # is alive (it spends its first ~100ms importing). If process
                # creation were pathologically slow, the executor observes the
                # request before dispatch instead - both record a cancelled run.
                threading.Timer(0.05, lambda: cancel_path.write_text("cancel", encoding="utf-8")).start()
            return real_run_command(argv, cwd, budget, **kwargs)

        with self.fast_polls(), patch("re_runner.runner.run_command", cancelling_run_command):
            state = runner.execute()
        cancel_path.unlink(missing_ok=True)

        validators = [item for item in state["tool_runs"] if item["tool"] == "validator:private-key-possession"]
        self.assertEqual(len(validators), 1, state["tool_runs"])
        self.assertEqual(validators[0]["status"], "cancelled")
        self.assertTrue(validators[0]["artifacts"])  # settled artifact enumeration was recorded
        # The run still honors the pending cancel request at its next check, but
        # only after the validator ToolRun and finding were recorded.
        self.assertEqual(state["status"], "cancelled")
        report = load_json(runner.root / "report.json")
        self.assertEqual(report["status"], "cancelled")
        self.assertIn(validators[0]["id"], [item["id"] for item in report["tool_runs"]])
        self.assertEqual([finding["status"] for finding in state["findings"]], ["candidate"])
        self.assertIn("candidate retained", state["findings"][0]["verification"])
        contracts.validate(report, contracts.REPORT_SCHEMA)


class SettlementModeBudgetTests(unittest.TestCase):
    def test_settlement_mode_records_stop_conditions_instead_of_raising(self):
        with tempfile.TemporaryDirectory(prefix="re-settle-") as name:
            cancel = Path(name) / "cancel.request"
            cancel.write_text("cancel", encoding="utf-8")
            budget = Budget(dict(BUDGET_DEFAULTS, max_files=1), cancel_path=cancel, wall_deadline_epoch=time.time() - 1)
            with self.assertRaises(Cancelled):
                budget.check()
            budget.settling = True
            budget.check()  # cancel request and expired wall clock are both ignored
            budget.consume("files", 5)
            self.assertEqual(budget.used["files"], 5)
            budget.settling = False
            with self.assertRaises(Cancelled):
                budget.check()

    def test_expired_wall_clock_is_ignored_only_while_settling(self):
        budget = Budget(dict(BUDGET_DEFAULTS), wall_deadline_epoch=time.time() - 1)
        with self.assertRaises(BudgetExceeded):
            budget.check()
        budget.settling = True
        budget.check()
        budget.consume("requests", 1)
        self.assertEqual(budget.used["requests"], 1)
        budget.settling = False
        with self.assertRaises(BudgetExceeded):
            budget.check()

    def test_over_limit_consumption_raises_normally_but_settles_fully(self):
        budget = Budget(dict(BUDGET_DEFAULTS, max_files=1))
        with self.assertRaises(BudgetExceeded):
            budget.consume("files", 2)
        self.assertEqual(budget.used["files"], 2)  # applied before the raise (unchanged behavior)
        budget.settling = True
        budget.consume("files", 2)  # real over-limit usage is recorded, not truncated
        self.assertEqual(budget.used["files"], 4)


if __name__ == "__main__":
    unittest.main()
