import argparse
import json
import sys
from pathlib import Path

from .capabilities import probe
from .contracts import MANIFEST_SCHEMA, SCOPE_SCHEMA, export_schemas, read_contract
from .errors import AnalysisError
from .intake import detect
from .models import AssetRequest, KINDS
from .runner import Runner
from .safety import atomic_json, atomic_write, redact
from .scope import ScopePolicy
from .state import read_state, resolve_run


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="re-run", description="Bounded asset analysis with evidence and truthful coverage")
    root.add_argument("--version", action="version", version="re-skill-runner 0.1.0")
    commands = root.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Detect local format/locator without network access")
    inspect.add_argument("--asset", required=True)
    inspect.add_argument("--type", choices=["auto", *KINDS], default="auto")
    analyze = commands.add_parser("analyze", help="Create a unique run and analyze asset(s)")
    selection = analyze.add_mutually_exclusive_group(required=True)
    selection.add_argument("--asset")
    selection.add_argument("--manifest", type=Path)
    analyze.add_argument("--type", choices=["auto", *KINDS], default="auto")
    analyze.add_argument("--scope", type=Path)
    analyze.add_argument("--level", choices=["triage", "verify"], default="triage")
    analyze.add_argument("--language", choices=["zh", "en"], default="zh")
    analyze.add_argument("--output", type=Path, default=Path("re-runs"), help="Parent directory; each run has a unique child directory")
    doctor = commands.add_parser("doctor", help="Inventory actual installed capabilities")
    doctor.add_argument("--profile", choices=KINDS)
    schema = commands.add_parser("schema", help="Export input/report JSON Schemas kept in sync with contracts.py")
    schema.add_argument("--output", type=Path, help="Directory for *.schema.json files; omit to print to stdout")
    for name in ("status", "resume", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("--run-id", required=True)
        command.add_argument("--output", type=Path, default=Path("re-runs"))
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "inspect":
            kind, fmt, path, locator = detect(AssetRequest(args.asset, args.type))
            value = {"kind": kind, "format": fmt, "locator": locator, "local": path is not None, "network_contacted": False}
        elif args.command == "doctor":
            value = probe(args.profile)
        elif args.command == "schema":
            schemas = export_schemas()
            if args.output:
                args.output.mkdir(parents=True, exist_ok=True)
                for name, document in schemas.items():
                    atomic_json(args.output / name, document)
                value = {"exported": sorted(schemas), "output": str(args.output)}
            else:
                value = schemas
        elif args.command == "analyze":
            if args.manifest:
                manifest = read_contract(args.manifest, MANIFEST_SCHEMA)
                requests = []
                for item in manifest["assets"]:
                    locator = item["locator"]
                    if "://" not in locator:
                        candidate = args.manifest.absolute().parent / locator
                        if candidate.exists():
                            locator = str(candidate.absolute())
                    requests.append(AssetRequest(locator, item.get("type", "auto"), item.get("id")))
            else:
                requests = [AssetRequest(args.asset, args.type)]
            scope = ScopePolicy.from_dict(read_contract(args.scope, SCOPE_SCHEMA), args.scope.absolute().parent) if args.scope else ScopePolicy()
            runner = Runner.new(args.output, requests, scope, args.level, args.language)
            state = runner.execute()
            value = {"run_id": state["run_id"], "status": state["status"], "report": str(runner.root / "report.md"), "json": str(runner.root / "report.json"), "findings": len(state["findings"])}
        else:
            run = resolve_run(args.output, args.run_id)
            if args.command == "status":
                state = read_state(run)
                value = {"run_id": state["run_id"], "status": state["status"], "updated": state["updated"], "assets": {key: entry["status"] for key, entry in state["assets"].items()}, "report": str(run / "report.md")}
            elif args.command == "cancel":
                read_state(run)
                atomic_write(run / "cancel.request", b"cancel\n")
                value = {"run_id": args.run_id, "cancel_requested": True}
            else:
                runner = Runner.resume(run)
                state = runner.execute()
                value = {"run_id": state["run_id"], "status": state["status"], "report": str(run / "report.md"), "findings": len(state["findings"])}
        print(json.dumps(redact(value), ensure_ascii=False, indent=2, allow_nan=False))
        if args.command in ("analyze", "resume"):
            return {"succeeded": 0, "degraded": 1, "blocked": 2, "failed": 2, "cancelled": 130}.get(value["status"], 2)
        return 0
    except (AnalysisError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "io-error"), "message": redact(str(exc))}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
