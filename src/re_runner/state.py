import os
import re
import uuid
from pathlib import Path

from .errors import IntegrityError, InvalidInput
from .models import STATES, utc_now
from .safety import atomic_json, contained, load_json, sha256_file


RUN_ID_PATTERN = r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"


def create_run(base: Path, request: dict) -> tuple[Path, dict]:
    from datetime import datetime, timezone
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
    base = base.absolute()
    if base.is_symlink():
        raise IntegrityError("Run base may not be a symlink")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = base / run_id
    root.mkdir(mode=0o700)
    for folder in ("inputs", "work", "evidence", "logs"):
        (root / folder).mkdir(mode=0o700)
    atomic_json(root / "request.json", request)
    state = {
        "schema_version": 1, "run_id": run_id, "status": "pending", "created": utc_now(),
        "updated": utc_now(), "request_sha256": sha256_file(root / "request.json"),
        "assets": {}, "tool_runs": [], "evidence": [], "findings": [], "errors": [],
        "used": {"input_bytes": 0, "download_bytes": 0, "unpack_bytes": 0, "files": 0, "requests": 0},
    }
    save_state(root, state)
    event(root, "run-created", {"run_id": run_id})
    return root, state


def save_state(root: Path, state: dict) -> None:
    if state["status"] not in STATES:
        raise ValueError("Invalid run state")
    state["updated"] = utc_now()
    atomic_json(root / "state.json", state)


def read_state(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise InvalidInput("Run directory is missing or linked")
    for file in ("state.json", "request.json"):
        contained(root, root / file)
    state = load_json(root / "state.json", max_bytes=32_000_000)
    if not isinstance(state, dict) or state.get("schema_version") != 1 or state.get("status") not in STATES:
        raise InvalidInput("Invalid/corrupt run state")
    if state.get("run_id") != root.name or not re.fullmatch(RUN_ID_PATTERN, root.name):
        raise IntegrityError("Run identity mismatch")
    if sha256_file(root / "request.json") != state.get("request_sha256"):
        raise IntegrityError("Immutable request or scope was modified")
    if not isinstance(state.get("assets"), dict) or not isinstance(state.get("tool_runs"), list):
        raise InvalidInput("Corrupt stage state")
    return state


def event(root: Path, name: str, data: dict | None = None) -> None:
    import json
    from .safety import redact
    path = contained(root, root / "events.jsonl")
    record = {"time": utc_now(), "event": name, **redact(data or {})}
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def resolve_run(base: Path, run_id: str) -> Path:
    if not re.fullmatch(RUN_ID_PATTERN, run_id):
        raise InvalidInput("Invalid run ID")
    return contained(base.absolute(), base.absolute() / run_id)


def verify_artifacts(root: Path, artifacts: list[dict]) -> None:
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not re.fullmatch(r"[a-f0-9]{64}", str(item.get("sha256", ""))):
            raise IntegrityError("Malformed artifact manifest")
        path = contained(root, root / item["path"])
        if not path.is_file() or sha256_file(path) != item["sha256"]:
            raise IntegrityError(f"Artifact missing or modified: {item['path']}")
