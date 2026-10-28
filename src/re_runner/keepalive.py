"""Optional finite legacy batch loop with kernel ownership and interruptible waits."""
import argparse
import json
import sys
import time
from pathlib import Path

from .contracts import BUDGET_DEFAULTS
from .execution import run_command
from .locking import FileLock
from .safety import Budget, atomic_write, load_json


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=["firmware", "cve"])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--interval", type=int, default=1800)
    args = parser.parse_args(argv)
    if not 1 <= args.rounds <= 40 or not 1 <= args.interval <= 3600:
        parser.error("rounds must be 1–40 and interval 1–3600")
    root = args.root.absolute()
    folder = "fw-discover" if args.profile == "firmware" else "cve-hunter"
    script = root / folder / ("fw.py" if args.profile == "firmware" else "hunter.py")
    if not script.is_file():
        parser.error("root must contain the checked-out legacy scripts")
    data = root / "data" / folder
    data.mkdir(parents=True, exist_ok=True)
    with FileLock(data / ".keepalive.lock"):
        for index in range(args.rounds):
            if args.profile == "firmware":
                queue = data / "queue.jsonl"
                if not queue.exists():
                    action = "--seed"
                else:
                    rows = [json.loads(line) for line in queue.read_text("utf-8").splitlines() if line.strip()]
                    pending = [item for item in rows if item.get("status") in ("pending", "error") and item.get("attempts", 0) < 3]
                    if not pending:
                        print("No retryable firmware entries remain; inspect blocked/failed records.")
                        break
                    action = "--once"
            else:
                progress = load_json(data / "progress.json") if (data / "progress.json").is_file() else {}
                action = "--verify" if progress.get("findings_count", 0) >= 100 else "--once"
            budget = Budget({**BUDGET_DEFAULTS, "max_wall_seconds": 900, "tool_timeout_seconds": 600})
            result = run_command([sys.executable, str(script), action], root, budget, timeout=600)
            atomic_write(data / f"keepalive-round-{index + 1}.log", (result.stdout + result.stderr).encode("utf-8"))
            print(f"Round {index + 1}/{args.rounds}: {action} {result.status}", flush=True)
            if index + 1 < args.rounds:
                until = time.monotonic() + args.interval
                while time.monotonic() < until:
                    time.sleep(min(1, until - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
