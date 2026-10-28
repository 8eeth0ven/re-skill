"""Drive local acceptance runs: start lab services, run real re-run analyses
against them, print a JSON summary with run ids and statuses.

Usage: uv run --no-sync python tools/run_local_acceptance.py [--output re-runs/results]
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from re_runner.safety import atomic_json  # noqa: E402

SCOPES = {
    "web": {"version": 1, "allow_urls": ["http://127.0.0.1:8765/"], "exclude_urls": ["http://127.0.0.1:8765/admin/"], "operations": ["read"], "budgets": {"max_requests": 6}},
    "openapi": {"version": 1, "allow_urls": ["http://127.0.0.1:8765/openapi.json"], "operations": ["read"]},
    "graphql": {"version": 1, "allow_urls": ["http://127.0.0.1:8765/graphql"], "operations": ["read", "api-query"]},
    "websocket": {"version": 1, "allow_urls": ["ws://127.0.0.1:8765/ws"], "operations": ["read", "api-query"]},
    "grpc": {"version": 1, "allow_urls": ["grpc://127.0.0.1:8766"], "operations": ["read", "api-query"]},
    "chain": {"version": 1, "allow_urls": ["http://127.0.0.1:8765/rpc"], "operations": ["read", "chain-read"]},
}


def wait_ready(proc: subprocess.Popen, timeout: float = 20) -> dict:
    """Bound startup even when a Windows/POSIX pipe has not produced a line."""
    messages = queue.Queue()

    def read_lines():
        if proc.stdout is not None:
            for line in proc.stdout:
                messages.put(line)
        messages.put(None)

    threading.Thread(target=read_lines, daemon=True).start()
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("services did not become ready")
        try:
            line = messages.get(timeout=remaining)
        except queue.Empty as exc:
            raise RuntimeError("services did not become ready") from exc
        if line is None:
            raise RuntimeError(f"service exited before readiness: {proc.poll()}")
        if line.strip().startswith("{"):
            return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("re-runs/results"))
    args = parser.parse_args()
    services = subprocess.Popen(
        [sys.executable, str(REPO / "tools" / "local_services.py")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(REPO),
    )
    results = {}
    try:
        ready = wait_ready(services)
        print("services ready:", json.dumps(ready), file=sys.stderr)
        scope_dir = REPO / "re-runs" / "local-scopes"
        scope_dir.mkdir(parents=True, exist_ok=True)
        contract = REPO / "re-runs" / "local-scopes" / "chain-descriptor.json"
        atomic_json(contract, {
            "asset_kind": "contract", "chain_id": 31337,
            "address": "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "rpc_url": "http://127.0.0.1:8765/rpc",
        })
        cases = {
            "web": (["--asset", "http://127.0.0.1:8765/", "--type", "web"], "web"),
            "openapi": (["--asset", "http://127.0.0.1:8765/openapi.json", "--type", "api"], "openapi"),
            "graphql": (["--asset", "http://127.0.0.1:8765/graphql", "--type", "api"], "graphql"),
            "websocket": (["--asset", "ws://127.0.0.1:8765/ws", "--type", "api"], "websocket"),
            "grpc": (["--asset", "grpc://127.0.0.1:8766", "--type", "api"], "grpc"),
            "chain-read": (["--asset", str(contract), "--type", "contract"], "chain"),
        }
        env = dict(os.environ)
        for name, (extra, scope) in cases.items():
            scope_path = scope_dir / f"scope.{scope}.json"
            atomic_json(scope_path, SCOPES[scope])
            command = [sys.executable, "-m", "re_runner", "analyze", *extra, "--scope", str(scope_path), "--output", str(args.output)]
            done = subprocess.run(command, cwd=str(REPO), env=env, capture_output=True, text=True, timeout=180)
            try:
                value = json.loads(done.stdout)
            except ValueError:
                value = {"parse_error": done.stdout[-400:], "stderr": done.stderr[-400:]}
            results[name] = {"exit": done.returncode, **{k: value.get(k) for k in ("run_id", "status", "findings")}}
            print(name, json.dumps(results[name]), file=sys.stderr)
        print(json.dumps(results, indent=2))
        atomic_json(REPO / "re-runs" / "local-acceptance-summary.json", results)
        return 0 if all(item.get("status") in ("succeeded", "degraded") for item in results.values()) else 1
    finally:
        if services.poll() is None:
            services.terminate()
        try:
            services.wait(timeout=5)
        except subprocess.TimeoutExpired:
            services.kill()
            services.wait()
        if services.stdout is not None:
            services.stdout.close()


if __name__ == "__main__":
    raise SystemExit(main())
