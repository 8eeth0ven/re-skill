"""Reports generated on non-success paths must satisfy the exported report contract."""
import json
import os
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

import jsonschema

from re_runner.contracts import BUDGET_DEFAULTS, REPORT_SCHEMA
from re_runner.execution import run_command
from re_runner.models import AssetRequest, ToolRun, utc_now
from re_runner.reporting import write_reports
from re_runner.runner import Runner
from re_runner.safety import Budget
from re_runner.scope import ScopePolicy

TOOL_STATUS_ENUM = REPORT_SCHEMA["properties"]["tool_runs"]["items"]["properties"]["status"]["enum"]
DEMO_ERROR = {"code": "tool-failed", "message": "Profile process ended without a result artifact"}


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-report-contract-")
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

    def budget(self, **values):
        return Budget({**BUDGET_DEFAULTS, **values})

    def assertReportValid(self, run_root: Path) -> dict:
        path = run_root / "report.json"
        self.assertTrue(path.is_file(), "write_reports must produce report.json")
        report = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
        for item in report["errors"]:
            self.assertIsInstance(item, dict)
        for tool in report["tool_runs"]:
            self.assertIn(tool["status"], TOOL_STATUS_ENUM)
        for entry in report["coverage"]:
            self.assertTrue(entry["error"] is None or isinstance(entry["error"], dict))
        return report


class RunnerReportContractTests(TempCase):
    def test_blocked_device_report_matches_export_schema(self):
        runner = Runner.new(self.root / "runs", [AssetRequest("android://emulator-5554")], ScopePolicy(), "triage", "en")
        state = runner.execute()
        self.assertEqual(state["status"], "blocked")
        report = self.assertReportValid(runner.root)
        self.assertEqual(report["errors"][0]["code"], "scope-denied")
        self.assertEqual(report["coverage"][0]["error"]["code"], "scope-denied")

    def test_failed_corrupt_binary_report_matches_export_schema(self):
        path = self.root / "bad.exe"
        path.write_bytes(b"MZbroken")
        runner = Runner.new(self.root / "runs", [AssetRequest(str(path))], ScopePolicy(), "verify", "en")
        state = runner.execute()
        self.assertEqual(state["status"], "failed")
        report = self.assertReportValid(runner.root)
        self.assertEqual(report["coverage"][0]["status"], "failed")
        self.assertTrue(report["errors"])


class ExecutionStatusReportTests(TempCase):
    def tool_run(self, index: int, execution, *, timed_out: bool) -> dict:
        return asdict(ToolRun(
            f"t-{index:05d}", "asset-001", "demo:boundary", "0.1.0",
            ["python", "-c", "demo"], execution.status, utc_now(), utc_now(),
            execution.exit_code, None, None, timed_out,
        ))

    def test_timeout_and_output_exceeded_reports_match_export_schema(self):
        budget = self.budget(max_tool_output_bytes=2048)
        slow = run_command([sys.executable, "-c", "import time; time.sleep(3)"], self.root, budget, timeout=1)
        self.assertEqual(slow.status, "timed-out")
        self.assertTrue(slow.timed_out)
        loud = run_command([sys.executable, "-c", "import sys; sys.stdout.write('A' * 102400)"], self.root, budget)
        self.assertEqual(loud.status, "output-exceeded")
        state = {
            "schema_version": 1,
            "run_id": "20261019T000000Z-abcdef012345",
            "status": "failed",
            "created": utc_now(), "updated": utc_now(),
            "assets": {"asset-001": {
                "asset": {"id": "asset-001", "locator": "demo://boundary", "kind": "binary", "format": "demo", "metadata": {}},
                "status": "failed", "error": dict(DEMO_ERROR),
            }},
            "findings": [],
            "tool_runs": [self.tool_run(1, slow, timed_out=True), self.tool_run(2, loud, timed_out=False)],
            "evidence": [],
            "errors": [{"asset_id": "asset-001", **DEMO_ERROR}],
            "used": {"input_bytes": 0, "download_bytes": 0, "unpack_bytes": 0, "files": 0, "requests": 0},
        }
        write_reports(self.root, state, {"demo": {"name": "demo", "available": True, "version": None, "operations": [], "reason": None}}, language="en")
        report = self.assertReportValid(self.root)
        statuses = [tool["status"] for tool in report["tool_runs"]]
        self.assertIn("timed-out", statuses)
        self.assertIn("output-exceeded", statuses)
        self.assertIsInstance(report["coverage"][0]["error"], dict)


if __name__ == "__main__":
    unittest.main()
