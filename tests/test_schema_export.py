"""Schema export contract: exported schemas stay consistent with code and real reports."""
import json
import unittest
from pathlib import Path

import jsonschema

from re_runner.contracts import (
    MANIFEST_SCHEMA,
    REPORT_SCHEMA,
    SCOPE_SCHEMA,
    WORKER_RESULT_SCHEMA,
    export_schemas,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
# Real runs produced by `re-run analyze --manifest re-runs/pe-manifest.json`.
REAL_SUCCEEDED_RUN = "20261019T095614Z-fba1a224a6bb"
REAL_DEGRADED_RUN = "20261019T090540Z-1ec4d5f2ff81"
TOOL_STATUS_ENUM = REPORT_SCHEMA["properties"]["tool_runs"]["items"]["properties"]["status"]["enum"]


def real_report_path(run_id: str) -> Path:
    return REPO_ROOT / "re-runs" / "results" / run_id / "report.json"


def validate_real_report(test: unittest.TestCase, run_id: str, expected_status: str) -> dict:
    path = real_report_path(run_id)
    report = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    test.assertEqual(report["status"], expected_status)
    return report


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


class RealReportSchemaTests(unittest.TestCase):
    def test_real_succeeded_report_validates(self):
        if not real_report_path(REAL_SUCCEEDED_RUN).is_file():
            self.skipTest(f"sample succeeded run {REAL_SUCCEEDED_RUN} is absent from re-runs/results")
        report = validate_real_report(self, REAL_SUCCEEDED_RUN, "succeeded")
        self.assertTrue(report["coverage"])
        self.assertTrue(report["tool_runs"])

    @unittest.skipUnless(real_report_path(REAL_DEGRADED_RUN).is_file(),
                         f"sample degraded run {REAL_DEGRADED_RUN} is absent from re-runs/results")
    def test_real_degraded_report_validates(self):
        report = validate_real_report(self, REAL_DEGRADED_RUN, "degraded")
        self.assertTrue(report["coverage"])
        self.assertTrue(report["tool_runs"])


if __name__ == "__main__":
    unittest.main()
