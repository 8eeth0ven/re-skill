import argparse
from pathlib import Path

from .safety import Budget, atomic_json, load_json
from .validators import run_validator


def invocation_request(path: Path, budgets: dict, cancel: Path) -> dict:
    return {"validator": "private-key-possession", "path": str(path), "budgets": budgets, "cancel_path": str(cancel)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    request = load_json(Path(args.request), max_bytes=65536)
    budget = Budget(request["budgets"], Path(request["cancel_path"]))
    value = run_validator(request["validator"], Path(request["path"]), budget)
    atomic_json(Path(args.result), value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

