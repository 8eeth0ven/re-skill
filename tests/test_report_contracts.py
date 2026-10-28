"""Exported schema contracts and self-generated report compatibility on failure paths."""
import json
import os
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

import jsonschema

from re_runner.contracts import (
    BUDGET_DEFAULTS,
    MANIFEST_SCHEMA,
    REPORT_SCHEMA,
    SCOPE_SCHEMA,
    WORKER_RESULT_SCHEMA,
    export_schemas,
)
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


class SchemaExportTests(unittest.TestCase):
    def test_export_covers_all_contracts(self):
        exported = export_schemas()
        self.assertEqual(
            set(exported),
            {"manifest.schema.json", "scope.schema.json", "report.schema.json", "worker-result.schema.json"},
        )
        self.assertIs(exported["manifest.schema.json"], MANIFEST_SCHEMA)
        self.assertIs(exported["scope.schema.json"], SCOPE_SCHEMA)
        self.assertIs(exported["report.schema.json"], REPORT_SCHEMA)
        self.assertIs(exported["worker-result.schema.json"], WORKER_RESULT_SCHEMA)

    def test_manifest_schema_accepts_minimal_and_rejects_unknown(self):
        validate = jsonschema.Draft202012Validator(MANIFEST_SCHEMA)
        validate.validate({"version": 1, "assets": [{"locator": "samples/sample.exe"}]})
        with self.assertRaises(jsonschema.ValidationError):
            validate.validate({"version": 1, "assets": [{"locator": "x", "extra": 1}]})
        with self.assertRaises(jsonschema.ValidationError):
            validate.validate({"version": 2, "assets": [{"locator": "x"}]})

    def test_report_schema_accepts_minimal_report(self):
        report = {
            "schema_version": 1,
            "run_id": "20261019T090913Z-e3046caca48f",
            "status": "succeeded",
            "created": "2026-10-19T09:09:13.000+00:00",
            "updated": "2026-10-19T09:09:14.000+00:00",
            "assets": [{"id": "pe", "locator": "samples/sample.exe", "kind": "binary", "format": "pe"}],
            "coverage": [{
                "asset_id": "pe", "status": "succeeded", "checks": [],
                "error": {"code": "capability-missing", "message": "Disassembly backend unavailable"},
            }],
            "findings": [],
            "tool_runs": [{
                "id": "t-00001", "asset_id": "pe", "tool": "profile:binary", "version": "0.1.0",
                "argv": ["python", "-m", "re_runner.worker"], "status": "timed-out",
                "started": "2026-10-19T09:09:13.000+00:00", "finished": "2026-10-19T09:09:14.000+00:00",
                "exit_code": None, "stdout": "work/pe/attempt-1/stdout.log",
                "stderr": "work/pe/attempt-1/stderr.log", "timed_out": True,
                "artifacts": [], "error": None,
            }],
            "evidence": [],
            "errors": [{"asset_id": "pe", "code": "tool-timeout", "message": "Profile exceeded 90s"}],
            "budget_used": {"input_bytes": 1, "download_bytes": 0, "unpack_bytes": 0, "files": 1, "requests": 0},
            "trust_policy": "t",
            "limits": "l",
        }
        jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
        report["status"] = "not-a-state"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)

    def test_report_schema_error_shapes_and_tool_states(self):
        base = {
            "schema_version": 1,
            "run_id": "20261019T090913Z-e3046caca48f",
            "status": "failed",
            "created": "2026-10-19T09:09:13.000+00:00",
            "updated": "2026-10-19T09:09:14.000+00:00",
            "assets": [], "coverage": [], "findings": [], "tool_runs": [], "evidence": [],
            "errors": [], "budget_used": {}, "trust_policy": "t", "limits": "l",
        }
        validate = jsonschema.Draft202012Validator(REPORT_SCHEMA)
        for status in ("timed-out", "output-exceeded", "budget-exceeded", "cancelled", "succeeded", "failed"):
            base["tool_runs"] = [{
                "id": "t-00001", "asset_id": "pe", "tool": "profile:binary", "status": status,
                "started": "a", "finished": "b",
            }]
            validate.validate(base)
        for broken in (
            {"errors": ["legacy string error is no longer produced"]},
            {"errors": [{"code": "x"}]},
            {"errors": [{"code": "x", "message": "y", "extra": 1}]},
            {"coverage": [{"asset_id": "pe", "status": "failed", "checks": [], "error": "string error"}]},
        ):
            with self.subTest(broken=broken), self.assertRaises(jsonschema.ValidationError):
                validate.validate({**base, "tool_runs": [], **broken})

    def test_worker_result_schema_shape(self):
        result = {
            "analysis": {},
            "checks": [{"name": "c", "status": "degraded", "detail": "d"}],
            "candidates": [],
            "limitations": ["limit"],
        }
        jsonschema.Draft202012Validator(WORKER_RESULT_SCHEMA).validate(result)
        result["checks"][0]["status"] = "excellent"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(WORKER_RESULT_SCHEMA).validate(result)

if __name__ == "__main__":
    unittest.main()
