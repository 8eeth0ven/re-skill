"""Strict public input contracts; unknown fields do not silently alter behavior."""
from pathlib import Path
from typing import Any

import jsonschema

from .errors import InvalidInput
from .models import KINDS, STATES
from .safety import load_json


BUDGET_DEFAULTS = {
    "max_input_bytes": 134_217_728,
    "max_download_bytes": 16_777_216,
    "max_unpack_bytes": 268_435_456,
    "max_files": 10000,
    "max_depth": 16,
    "max_archive_ratio": 200,
    "max_requests": 12,
    "requests_per_second": 4,
    "max_wall_seconds": 300,
    "tool_timeout_seconds": 90,
    "max_tool_output_bytes": 1_048_576,
    "max_memory_mb": 768,
    "max_retries": 1,
}

_limits = {
    "max_input_bytes": (1024, 2_147_483_648),
    "max_download_bytes": (1024, 268_435_456),
    "max_unpack_bytes": (1024, 2_147_483_648),
    "max_files": (1, 100000), "max_depth": (1, 64), "max_archive_ratio": (1, 10000),
    "max_requests": (0, 1000), "requests_per_second": (1, 50),
    "max_wall_seconds": (1, 3600), "tool_timeout_seconds": (1, 600),
    "max_tool_output_bytes": (1024, 16_777_216), "max_memory_mb": (128, 4096),
    "max_retries": (0, 3),
}
_budget_schema = {
    "type": "object", "additionalProperties": False,
    "properties": {k: {"type": "integer", "minimum": v[0], "maximum": v[1]} for k, v in _limits.items()},
}
_asset_schema = {
    "type": "object", "additionalProperties": False, "required": ["locator"],
    "properties": {
        "locator": {"type": "string", "minLength": 1, "maxLength": 8192},
        "type": {"enum": ["auto", *KINDS]},
        "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"},
    },
}
MANIFEST_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "additionalProperties": False, "required": ["assets"],
    "properties": {
        "version": {"const": 1},
        "assets": {"type": "array", "minItems": 1, "maxItems": 100, "items": _asset_schema},
    },
}
SCOPE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "additionalProperties": False,
    "properties": {
        "version": {"const": 1},
        "allow_urls": {"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 8192}},
        "exclude_urls": {"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 8192}},
        "allow_paths": {"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 8192}},
        "allow_devices": {"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 512}},
        "operations": {"type": "array", "uniqueItems": True, "items": {"enum": [
            "read", "api-query", "chain-read", "device-read", "ai-test",
        ]}},
        "headers_env": {
            "type": "object", "maxProperties": 16,
            "propertyNames": {"pattern": "^[A-Za-z][A-Za-z0-9-]{0,63}$"},
            "additionalProperties": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$"},
        },
        "budgets": _budget_schema,
    },
}
WORKER_RESULT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["analysis", "checks", "candidates", "limitations"],
    "properties": {
        "analysis": {"type": "object"},
        "checks": {"type": "array", "maxItems": 1000, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["name", "status", "detail"],
            "properties": {"name": {"type": "string"}, "status": {"enum": [
                "succeeded", "degraded", "skipped", "blocked", "failed",
            ]}, "detail": {"type": "string"}},
        }},
        "candidates": {"type": "array", "maxItems": 2000, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["rule_id", "title", "technical", "location", "severity", "impact", "remediation", "validation"],
            "properties": {**{key: {"type": "string", "maxLength": 16384} for key in (
                "rule_id", "title", "technical", "location", "severity", "impact", "remediation",
            )}, "validation": {"type": ["object", "null"]}},
        }},
        "limitations": {"type": "array", "maxItems": 1000, "items": {"type": "string"}},
    },
}


# Shared structured error model. Both error sinks (per-asset entry["error"] and
# the run-level state["errors"], runner.execute) write {"code", "message"[,
# "asset_id"]} objects; the legacy bare-string form is no longer produced by any
# writer and is rejected here. Redaction rewrites values in place but never
# changes a type, so objects survive redact() unchanged in shape.
_error_schema = {
    "type": "object", "additionalProperties": False,
    "required": ["code", "message"],
    "properties": {
        "code": {"type": "string"}, "message": {"type": "string"},
        "asset_id": {"type": "string"},
    },
}
# ToolRun.status also carries terminal execution outcomes from execution.run_command
# that are not run-level STATES.
_TOOL_STATES = [*STATES, "timed-out", "output-exceeded", "budget-exceeded"]

REPORT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "run_id", "status", "created", "updated", "assets", "coverage",
                 "findings", "tool_runs", "evidence", "errors", "budget_used", "trust_policy", "limits"],
    "properties": {
        "schema_version": {"const": 1},
        "run_id": {"type": "string", "pattern": "^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$"},
        "status": {"enum": list(STATES)},
        "created": {"type": "string"}, "updated": {"type": "string"},
        "assets": {"type": "array", "items": {
            "type": "object", "required": ["id", "locator", "kind", "format"],
            "properties": {
                "id": {"type": "string"}, "locator": {"type": "string"},
                "kind": {"enum": list(KINDS)}, "format": {"type": "string"},
                "sha256": {"type": ["string", "null"]}, "snapshot": {"type": ["string", "null"]},
                "parent_id": {"type": ["string", "null"]}, "metadata": {"type": "object"},
            },
        }},
        "coverage": {"type": "array", "items": {
            "type": "object", "required": ["asset_id", "status", "checks"],
            "properties": {
                "asset_id": {"type": "string"}, "status": {"enum": list(STATES)},
                "kind": {"type": ["string", "null"]}, "format": {"type": ["string", "null"]},
                "checks": {"type": "array", "items": {"type": "object"}},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "error": {"anyOf": [_error_schema, {"type": "null"}]},
                "plan": {"type": ["object", "null"]},
                "analysis": {"type": "object"},
            },
        }},
        "findings": {"type": "array", "items": {
            "type": "object", "required": ["id", "asset_id", "rule_id", "status", "title", "evidence_ids"],
            "properties": {
                "id": {"type": "string"}, "asset_id": {"type": "string"}, "rule_id": {"type": "string"},
                "status": {"enum": ["candidate", "verified", "observed", "rejected"]},
                "severity": {"type": "string"}, "title": {"type": "string"},
                "overview": {"type": "string"}, "technical": {"type": "string"},
                "verification": {"type": "string"}, "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "evidence_ids": {"type": "array", "items": {"type": "string"}},
                "validation": {"type": ["object", "null"]},
            },
        }},
        "tool_runs": {"type": "array", "items": {
            "type": "object", "required": ["id", "asset_id", "tool", "status", "started", "finished"],
            "properties": {
                "id": {"type": "string"}, "asset_id": {"type": "string"}, "tool": {"type": "string"},
                "version": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
                "status": {"enum": _TOOL_STATES}, "started": {"type": "string"}, "finished": {"type": "string"},
                "exit_code": {"type": ["integer", "null"]}, "timed_out": {"type": "boolean"},
                "stdout": {"type": ["string", "null"]}, "stderr": {"type": ["string", "null"]},
                "artifacts": {"type": "array", "items": {"type": "object"}},
                "error": {"type": ["string", "null"]},
            },
        }},
        "evidence": {"type": "array", "items": {
            "type": "object", "required": ["id", "asset_id", "tool_run_id", "path", "sha256"],
            "properties": {
                "id": {"type": "string"}, "asset_id": {"type": "string"}, "tool_run_id": {"type": "string"},
                "path": {"type": "string"}, "sha256": {"type": "string"}, "location": {"type": "string"},
                "description": {"type": "string"}, "trust": {"type": "string"}, "redacted": {"type": "boolean"},
            },
        }},
        "errors": {"type": "array", "items": _error_schema},
        "budget_used": {
            "type": "object", "additionalProperties": False,
            "properties": {key: {"type": "integer", "minimum": 0} for key in (
                "input_bytes", "download_bytes", "unpack_bytes", "files", "requests",
            )},
        },
        "trust_policy": {"type": "string"}, "limits": {"type": "string"},
    },
}


def export_schemas() -> dict[str, dict[str, Any]]:
    """Machine-readable copies of the public input/report contracts."""
    return {
        "manifest.schema.json": MANIFEST_SCHEMA,
        "scope.schema.json": SCOPE_SCHEMA,
        "report.schema.json": REPORT_SCHEMA,
        "worker-result.schema.json": WORKER_RESULT_SCHEMA,
    }


def validate(data: Any, schema: dict[str, Any]) -> Any:
    try:
        jsonschema.Draft202012Validator(schema).validate(data)
    except jsonschema.ValidationError as exc:
        where = "/".join(str(x) for x in exc.absolute_path) or "root"
        raise InvalidInput(f"Invalid contract at {where}: {exc.message[:500]}") from exc
    return data


def read_contract(path: Path, schema: dict[str, Any]) -> dict[str, Any]:
    return validate(load_json(path, max_bytes=1_048_576), schema)
