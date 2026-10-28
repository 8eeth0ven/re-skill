"""One isolated profile invocation; emits schema-checked data, never a verdict."""
import argparse
import traceback
from pathlib import Path

from .contracts import WORKER_RESULT_SCHEMA, validate
from .errors import AnalysisError
from .models import Asset
from .profiles import analyze
from .safety import Budget, atomic_json, load_json, redact
from .scope import ScopePolicy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    result_path = Path(args.result)
    budget = None
    try:
        request = load_json(Path(args.request), max_bytes=1_048_576)
        asset = Asset(**request["asset"])
        scope = ScopePolicy.from_dict(request["scope"])
        budget = Budget(request["remaining_budgets"], Path(request["cancel_path"]), Path(request["usage_path"]))
        output = Path(request["output"])
        path = Path(request["path"]) if request["path"] else None
        result = analyze(asset, path, output, scope, budget)
        from .protections import annotate
        result.analysis["protection_analysis"] = annotate(asset.kind, result.analysis)
        validate(result.to_dict(), WORKER_RESULT_SCHEMA)
        atomic_json(result_path, {"ok": True, "result": redact(result.to_dict()), "used": budget.used})
        return 0
    except AnalysisError as exc:
        atomic_json(result_path, {"ok": False, "error": {
            "code": exc.code, "message": redact(str(exc)), "retryable": exc.retryable,
        }, "used": budget.used if budget else {}})
        return 2
    except Exception as exc:
        atomic_json(result_path, {"ok": False, "error": {
            "code": "parser-error", "message": type(exc).__name__, "retryable": False,
        }, "used": budget.used if budget else {}})
        print(redact(traceback.format_exc()))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
