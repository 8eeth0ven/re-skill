import hashlib
import importlib.metadata
import os
import shutil
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .capabilities import probe
from .contracts import MANIFEST_SCHEMA, WORKER_RESULT_SCHEMA, validate
from .errors import AnalysisError, BudgetExceeded, Cancelled, IntegrityError, InvalidInput
from .execution import run_command
from .intake import snapshot, tree_hash
from .locking import FileLock
from .models import Asset, AssetRequest, Evidence, Finding, ToolRun, utc_now
from .reporting import evidence_gate, write_reports
from .safety import Budget, atomic_json, contained, load_json, redact, sha256_file
from .scope import ScopePolicy
from .state import create_run, event, read_state, save_state, verify_artifacts
from .validators import verification_gate


def _artifacts(root: Path, directory: Path, budget: Budget) -> tuple[list[dict], str | None]:
    """Enumerate produced artifacts under the run's enumeration limits.

    R1: an execution that already ran must never lose its ToolRun or usage
    settlement because its output directory cannot be fully enumerated. This
    function therefore never raises on enumeration anomalies: when a limit is
    reached or the tree yields a link/unsafe-path/device entry (or any single
    entry cannot be hashed), enumeration stops at that point and a reason
    string is returned so the caller can mark the artifact list explicitly
    incomplete. The limits themselves stay in force — an incomplete marker is
    always preferred over an unbounded scan, and no entry outside the run root
    is ever included in the returned records.
    """
    from .intake import iter_tree
    records, total = [], 0
    try:
        for path in iter_tree(directory, budget, skip_vcs=False):
            contained(root, path)
            total += path.stat().st_size
            if len(records) >= budget.limits["max_files"] or total > budget.limits["max_unpack_bytes"]:
                return records, (f"artifact enumeration stopped at run limits "
                                 f"(max_files={budget.limits['max_files']}, max_unpack_bytes={budget.limits['max_unpack_bytes']}); list is incomplete")
            records.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path, budget), "bytes": path.stat().st_size})
    except Exception as exc:  # links/reparse, unsafe path, permission, vanished file: keep the facts, mark incomplete
        reason = f"artifact enumeration incomplete: {type(exc).__name__}"
        detail = redact(str(exc))[:200]
        if detail:
            reason += f": {detail}"
        return records, reason
    return records, None


def _worker_environment(scope: ScopePolicy, output: Path) -> dict[str, str]:
    # The parser never receives unrelated credentials or arbitrary plugin paths.
    # ProgramFiles/COMMONPROGRAMFILES are needed by tooling that probes installed
    # drivers at import time (e.g. scapy looking for Npcap).
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL",
            "ProgramFiles", "ProgramFiles(x86)", "COMMONPROGRAMFILES",
            "RE_RUN_JADX", "RE_RUN_APKTOOL", "RE_RUN_UPX", "RE_RUN_7Z", "RE_RUN_SOLC")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    for variable in scope.headers_env.values():
        if variable in os.environ:
            env[variable] = os.environ[variable]
    if os.environ.get("RE_RUN_R2"):
        env["RE_RUN_R2"] = os.environ["RE_RUN_R2"]
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    temporary = output / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    env.update({"TMP": str(temporary), "TEMP": str(temporary), "TMPDIR": str(temporary)})
    return env


def _record_tool(state: dict, tool: ToolRun) -> None:
    state["tool_runs"].append(asdict(tool))


def _force_remove(func, path, exc_info) -> None:
    """rmtree error handler: intake copies are read-only (0o400) by design."""
    try:
        os.chmod(path, 0o700)
        func(path)
    except OSError:
        pass


def _add_evidence(state: dict, asset: Asset, tool: ToolRun, path: str, location: str, description: str, *, redacted: bool = True) -> str:
    artifact = next(x for x in tool.artifacts if x["path"] == path)
    eid = "e-" + hashlib.sha256((asset.id + tool.id + path + location).encode("utf-8")).hexdigest()[:20]
    if not any(x["id"] == eid for x in state["evidence"]):
        state["evidence"].append(asdict(Evidence(eid, asset.id, tool.id, path, artifact["sha256"], location, description, redacted=redacted)))
    return eid


def _verify_snapshot(root: Path, asset: Asset, budget: Budget) -> None:
    if not asset.snapshot:
        return
    path = contained(root, root / asset.snapshot)
    original = Path(asset.locator)
    if path.is_dir():
        copied, _ = tree_hash(path, budget)
        actual, _ = tree_hash(original, budget)
    else:
        copied, actual = sha256_file(path, budget), sha256_file(original, budget)
    if copied != asset.sha256 or actual != asset.sha256:
        raise IntegrityError("Original input or snapshot changed since intake")


def _aggregate_status(entries: list[dict]) -> str:
    statuses = [entry["status"] for entry in entries]
    if not statuses:
        return "failed"
    if "cancelled" in statuses:
        return "cancelled"
    if all(status == "succeeded" for status in statuses):
        return "succeeded"
    if any(status in ("succeeded", "degraded") for status in statuses):
        return "degraded"
    if all(status == "blocked" for status in statuses):
        return "blocked"
    return "failed"


class Runner:
    def __init__(self, root: Path, state: dict, request: dict):
        self.root, self.state, self.request = root, state, request
        self.scope = ScopePolicy.from_dict(request["scope"])
        self.budget = Budget(self.scope.budgets, root / "cancel.request", wall_deadline_epoch=self._stored_wall_deadline(state))
        self.budget.used.update(state["used"])
        self.capabilities = probe()
        self.resuming = False

    @staticmethod
    def _stored_wall_deadline(state: dict) -> float | None:
        stored = state.get("wall_budget")
        if isinstance(stored, dict) and isinstance(stored.get("deadline_epoch"), (int, float)):
            return float(stored["deadline_epoch"])
        return None

    def _restore_wall_budget(self) -> None:
        # The wall clock must survive cancel/resume cycles; per-construction clocks
        # would let repeated resumes extend a run indefinitely.
        deadline = self._stored_wall_deadline(self.state)
        if deadline is None:
            if self.resuming:
                return  # Legacy run directory without a persisted budget: keep the old behavior.
            deadline = time.time() + self.scope.budgets["max_wall_seconds"]
            self.state["wall_budget"] = {"max_wall_seconds": self.scope.budgets["max_wall_seconds"], "deadline_epoch": deadline}
        self.budget.wall_deadline_epoch = deadline

    @classmethod
    def new(cls, base: Path, assets: list[AssetRequest], scope: ScopePolicy, level: str, language: str) -> "Runner":
        identifiers = [request.id or f"asset-{index + 1:03d}" for index, request in enumerate(assets)]
        if len(identifiers) != len(set(identifiers)):
            raise InvalidInput("Asset IDs must be unique")
        request = {"version": 1, "assets": [{**asdict(item), "id": asset_id} for item, asset_id in zip(assets, identifiers)], "scope": scope.to_dict(), "level": level, "language": language}
        validate({"version": 1, "assets": request["assets"]}, MANIFEST_SCHEMA)
        ScopePolicy.from_dict(request["scope"])
        if level not in ("triage", "verify") or language not in ("zh", "en"):
            raise InvalidInput("Invalid level or report language")
        for item in assets:
            if "://" not in item.locator:
                original = Path(item.locator).expanduser()
                if original.is_dir() and base.resolve().is_relative_to(original.resolve()):
                    raise InvalidInput("Choose an output directory outside the original asset tree")
        root, state = create_run(base, request)
        return cls(root, state, request)

    @classmethod
    def resume(cls, root: Path) -> "Runner":
        state = read_state(root)
        request = load_json(root / "request.json", max_bytes=1_048_576)
        runner = cls(root, state, request)
        runner.resuming = True
        return runner

    def persist(self) -> None:
        self.state["used"] = dict(self.budget.used)
        save_state(self.root, self.state)

    @contextmanager
    def _settlement(self):
        # Post-stop bookkeeping (artifact hashing, usage journals) must complete
        # even though a stop condition already fired: settlement mode makes the
        # budget record real usage instead of raising mid-record. Wrap only the
        # Runner's settlement segment; never wrap new worker/validator dispatch.
        self.budget.settling = True
        try:
            yield
        finally:
            self.budget.settling = False

    def _intake(self, item: dict, entry: dict) -> Asset:
        if entry.get("asset"):
            asset = Asset(**entry["asset"])
            _verify_snapshot(self.root, asset, self.budget)
            return asset
        # R1 safe recovery: a previous attempt may have died mid-snapshot. The
        # interrupted attempt recorded its ToolRun and flagged the entry, and
        # its partial copy under inputs/<id>/ carries an explicit .incomplete
        # marker. That directory is unreferenced runner scratch (no evidence
        # cites it — evidence is only added on completed intakes), so rebuilding
        # from the original locator is safe; anything else still refuses.
        target_root = self.root / "inputs" / item["id"]
        if target_root.exists():
            if (target_root / ".incomplete").exists():
                # snapshot() drops the marker before copying and removes it on
                # success, so its presence proves this is an unreferenced
                # partial copy of a still-readable original: rebuild.
                shutil.rmtree(target_root, onerror=_force_remove)
                event(self.root, "interrupted-intake-recovered", {"asset_id": item["id"]})
            else:
                raise IntegrityError("Incomplete intake directory exists; preserve evidence and start a fresh run")
        started = utc_now()
        try:
            asset = snapshot(AssetRequest(**item), item["id"], self.root, self.scope, self.budget)
        except Cancelled:
            self._record_interrupted_intake(item, entry, target_root, started, "cancelled",
                                            "Intake snapshot was cancelled mid-copy; partial snapshot retained with an incomplete marker")
            raise
        except BudgetExceeded as exc:
            self._record_interrupted_intake(item, entry, target_root, started, "failed",
                                            f"Intake snapshot exceeded a run budget mid-copy: {redact(str(exc))[:200]}")
            raise
        except AnalysisError as exc:
            self._record_interrupted_intake(item, entry, target_root, started, "failed",
                                            f"Intake snapshot failed mid-copy: {type(exc).__name__}: {redact(str(exc))[:200]}")
            raise
        directory = self.root / "inputs" / item["id"]
        artifacts, artifact_error = _artifacts(self.root, directory, self.budget) if directory.exists() else ([], None)
        tool = ToolRun(
            f"t-{len(self.state['tool_runs']) + 1:05d}", asset.id, "intake", "0.1.0", [],
            "degraded" if artifact_error else "succeeded",
            started, utc_now(), artifacts=artifacts,
        )
        if artifact_error:
            tool.error = artifact_error
        _record_tool(self.state, tool)
        entry["asset"], entry["intake_tool_id"] = asdict(asset), tool.id
        if artifacts and not artifact_error:
            descriptor = self.root / "inputs" / asset.id / "asset.json"
            atomic_json(descriptor, {"sha256": asset.sha256, "kind": asset.kind, "format": asset.format, "files": [{"path": record["path"], "sha256": record["sha256"], "bytes": record["bytes"]} for record in artifacts]})
            tool.artifacts.append({"path": descriptor.relative_to(self.root).as_posix(), "sha256": sha256_file(descriptor), "bytes": descriptor.stat().st_size})
            self.state["tool_runs"][-1] = asdict(tool)
            _add_evidence(self.state, asset, tool, descriptor.relative_to(self.root).as_posix(), "input snapshot", "Input identity and preserved content hashes")
        from .planning import plan
        entry["plan"] = plan(asset.kind, self.request["level"])
        entry["status"] = "pending"
        self.persist()
        return asset

    def _record_interrupted_intake(self, item: dict, entry: dict, target_root: Path, started: str, status: str, message: str) -> None:
        """Leave an explicit record for an intake that stopped mid-snapshot.

        R1: snapshot() used to die before any ToolRun existed, and the partial
        inputs/<id>/ directory then poisoned every future snapshot attempt. The
        interrupted attempt now records its ToolRun with a bounded partial
        artifact list, drops an .incomplete marker into the directory and flags
        the entry so a resume can safely rebuild it from the original input.
        No evidence is cited against the partial copy, so nothing else depends
        on it.
        """
        try:
            artifacts, artifact_error = _artifacts(self.root, target_root, self.budget)
        except Exception:
            artifacts, artifact_error = [], "partial intake artifacts could not be enumerated"
        reason = artifact_error or "intake stopped before the snapshot completed; artifact list is partial by construction"
        tool = ToolRun(
            f"t-{len(self.state['tool_runs']) + 1:05d}", item["id"], "intake", "0.1.0", [], status,
            started, utc_now(), artifacts=artifacts, error=message + "; " + reason,
        )
        _record_tool(self.state, tool)
        entry["intake_interrupted"] = True
        entry["status"] = "cancelled" if status == "cancelled" else "failed"
        if status != "cancelled":
            entry["error"] = {"code": "intake-interrupted", "message": redact(message)}
        try:
            if target_root.exists():
                atomic_json(target_root / ".incomplete", {"interrupted": utc_now(), "tool_run_id": tool.id})
        except OSError:
            pass
        self.persist()

    def _invoke(self, asset: Asset, entry: dict) -> tuple[dict, ToolRun]:
        if entry.get("result") and entry.get("analysis_tool_id"):
            tool_data = next(x for x in self.state["tool_runs"] if x["id"] == entry["analysis_tool_id"])
            if tool_data["status"] != "succeeded" or tool_data["exit_code"] != 0:
                raise IntegrityError("Persisted result cites an unsuccessful stage")
            verify_artifacts(self.root, tool_data["artifacts"])
            result_path = next(record["path"] for record in tool_data["artifacts"] if record["path"].endswith("/result.json"))
            recorded = load_json(self.root / result_path)["result"]
            validate(recorded, WORKER_RESULT_SCHEMA)
            if recorded != entry["result"]:
                raise IntegrityError("Persisted stage summary differs from its hashed result artifact")
            return recorded, ToolRun(**tool_data)
        maximum = self.scope.budgets["max_retries"] + 1
        attempt = entry.get("attempts", 0)
        if attempt >= maximum:
            raise InvalidInput("Finite retry budget exhausted; start a new run after fixing input/environment")
        while attempt < maximum:
            self.budget.check()
            remaining = dict(self.scope.budgets)
            for key in ("download_bytes", "unpack_bytes", "files", "requests"):
                remaining[f"max_{key}"] = max(0, remaining[f"max_{key}"] - self.budget.used[key])
            remaining["max_wall_seconds"] = max(1, int(self.budget.wall_remaining()))
            attempt += 1
            entry["attempts"], entry["status"] = attempt, "running"
            output = self.root / "work" / asset.id / f"attempt-{attempt}"
            # A crash between this mkdir and the next persist leaves the directory on
            # disk with attempts still N-1; a resume must rebuild it, not crash on it.
            output.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Clear only known fixed artifact names so a resumed attempt can never
            # read the interrupted attempt's result/usage before its own succeed.
            for stale in ("result.json", "usage.json", "stdout.log", "stderr.log"):
                (output / stale).unlink(missing_ok=True)
            worker_request = output / "request.json"
            result_path = output / "result.json"
            atomic_json(worker_request, {"asset": asdict(asset), "path": str(self.root / asset.snapshot) if asset.snapshot else None, "output": str(output), "scope": self.scope.to_dict(), "remaining_budgets": remaining, "cancel_path": str(self.root / "cancel.request"), "usage_path": str(output / "usage.json")})
            entry["active_output"] = output.relative_to(self.root).as_posix()
            entry["active_attempt_accounted"] = False
            self.persist()
            event(self.root, "profile-started", {"asset_id": asset.id, "profile": asset.kind, "attempt": attempt})
            started = utc_now()
            argv = [sys.executable, "-m", "re_runner.worker", "--request", str(worker_request), "--result", str(result_path)]
            execution = run_command(argv, output, self.budget, env=_worker_environment(self.scope, output), stdout_path=output / "stdout.log", stderr_path=output / "stderr.log")
            # R1: the profile process really ran, so its ToolRun, execution
            # status and full usage must reach the current terminal state even
            # if the artifact tree cannot be enumerated completely. _artifacts
            # no longer raises for enumeration anomalies, but any unexpected
            # failure here still degrades to an explicitly incomplete list
            # instead of skipping the record; the ToolRun is constructed and
            # recorded BEFORE usage settlement so no failure ordering can drop
            # an executed attempt from the report.
            artifacts, artifact_error = [], None
            try:
                with self._settlement():
                    artifacts, artifact_error = _artifacts(self.root, output, self.budget)
            except Exception as exc:  # pragma: no cover - defensive, _artifacts is non-raising
                artifact_error = f"artifact enumeration failed: {type(exc).__name__}: {redact(str(exc))[:200]}"
            tool = ToolRun(
                f"t-{len(self.state['tool_runs']) + 1:05d}", asset.id, "profile:" + asset.kind,
                "re-skill-runner/0.1.0", redact(argv), execution.status,
                started, utc_now(), execution.exit_code,
                (output / "stdout.log").relative_to(self.root).as_posix(),
                (output / "stderr.log").relative_to(self.root).as_posix(), execution.timed_out,
                artifacts=artifacts,
            )
            if execution.reap_failed:
                tool.error = "Worker process could not be reaped after termination; exit code is unknown"
            if artifact_error:
                tool.error = f"{tool.error}; " if tool.error else ""
                tool.error += artifact_error
            _record_tool(self.state, tool)
            self.persist()
            if execution.status == "cancelled":
                # Account for resources the worker already consumed before dying.
                self._consume_attempt_usage(entry, output, {})
                self.persist()
                raise Cancelled("Profile process was cancelled and its process tree terminated")
            if execution.status == "budget-exceeded":
                self._consume_attempt_usage(entry, output, {})
                self.persist()
                raise BudgetExceeded("Profile exceeded run wall-time/resource budget")
            if result_path.is_file():
                payload = load_json(result_path, max_bytes=16_777_216)
            else:
                payload = {"ok": False, "error": {"code": "tool-failed", "message": f"Profile process {execution.status}; no result artifact", "retryable": False}}
            self._consume_attempt_usage(entry, output, payload)
            if execution.status == "succeeded" and payload.get("ok") is True:
                result = validate(payload["result"], WORKER_RESULT_SCHEMA)
                entry["result"], entry["analysis_tool_id"] = result, tool.id
                self.persist()
                return result, tool
            error = payload.get("error", {})
            tool.error = error.get("message", execution.status)
            self.state["tool_runs"][-1] = asdict(tool)
            self.persist()
            if error.get("retryable") is not True or attempt >= maximum:
                code = error.get("code", "tool-failed")
                exception = AnalysisError(error.get("message", execution.status))
                exception.code = code
                raise exception
            event(self.root, "retry", {"asset_id": asset.id, "attempt": attempt, "error": error})
        raise InvalidInput("Retry budget exhausted")

    def _consume_attempt_usage(self, entry: dict, output: Path, payload: dict) -> None:
        """Consume one attempt's usage journal; shared by success, failure and cancellation.

        Idempotent: the persisted flag prevents double counting when the cancelled
        path and a later resume reconciliation would both see the same journal.
        The whole journal is validated before anything is applied, so a rejection
        can never leave a partial accumulation, and application runs in settlement
        mode: a stop condition has usually already fired, and real usage must be
        recorded completely instead of truncating the journal mid-way.
        """
        if entry.get("active_attempt_accounted"):
            return
        usage_path = output / "usage.json"
        usage = load_json(usage_path, max_bytes=65536) if usage_path.is_file() else payload.get("used", {})
        if not isinstance(usage, dict):
            raise IntegrityError("Invalid worker budget accounting")
        for key, amount in usage.items():
            if key not in self.budget.used or type(amount) is not int or amount < 0:
                raise IntegrityError("Invalid worker budget accounting")
        with self._settlement():
            for key, amount in usage.items():
                self.budget.consume(key, amount)
        if not usage_path.is_file() and not payload.get("ok"):
            entry["budget_uncertain"] = True
        entry["active_attempt_accounted"] = True

    def _findings(self, asset: Asset, entry: dict, result: dict, tool: ToolRun) -> None:
        if entry.get("findings_complete"):
            return
        result_path = next(item["path"] for item in tool.artifacts if item["path"].endswith("/result.json"))
        _add_evidence(self.state, asset, tool, result_path, "analysis", "Structured profile analysis and completed coverage")
        for candidate in result["candidates"]:
            eid = _add_evidence(self.state, asset, tool, result_path, candidate["location"], candidate["technical"])
            fid = "f-" + hashlib.sha256((asset.id + candidate["rule_id"] + candidate["location"] + candidate["technical"]).encode("utf-8")).hexdigest()[:20]
            if any(finding["id"] == fid for finding in self.state["findings"]):
                continue
            finding = Finding(
                fid, asset.id, candidate["rule_id"], "candidate", candidate["severity"], candidate["title"],
                candidate["title"], candidate["technical"], "Candidate only; no successful behavioral validation has been recorded.",
                candidate["impact"], candidate["remediation"], [eid],
            )
            specification = candidate.get("validation")
            if self.request["level"] == "verify" and specification:
                self._validate(asset, finding, specification, tool)
            self.state["findings"].append(asdict(finding))
            self.persist()
        entry["findings_complete"] = True
        self.persist()

    def _validate(self, asset: Asset, finding: Finding, specification: dict, analysis_tool: ToolRun) -> None:
        from .validator_worker import invocation_request
        if specification.get("validator") != "private-key-possession" or not isinstance(specification.get("location"), str):
            return
        name = specification["location"]
        path = None
        if asset.snapshot:
            snapshot_path = self.root / asset.snapshot
            if snapshot_path.is_dir():
                path = contained(snapshot_path, snapshot_path / name)
            elif name == snapshot_path.name:
                path = snapshot_path
        if path is None or not path.is_file():
            # For extracted firmware, find the exact produced member path.
            matches = [record for record in analysis_tool.artifacts if record["path"].endswith("/" + name)]
            if len(matches) == 1:
                path = contained(self.root, self.root / matches[0]["path"])
        if path is None or not path.is_file():
            finding.verification = "Validator could not locate an unambiguous source artifact; candidate retained."
            return
        output = self.root / "work" / asset.id / ("verify-" + finding.id)
        if output.exists():
            previous = [record for record in self.state["tool_runs"] if record["asset_id"] == asset.id and record["tool"] == "validator:private-key-possession" and any(record_item["path"] == (output / "result.json").relative_to(self.root).as_posix() for record_item in record["artifacts"])]
            if previous:
                tool = ToolRun(**previous[-1])
                verify_artifacts(self.root, tool.artifacts)
                if tool.status == "succeeded":
                    value = load_json(output / "result.json", max_bytes=65536)
                    vid = _add_evidence(self.state, asset, tool, (output / "result.json").relative_to(self.root).as_posix(), name, "Recovered validator controls")
                    self._apply_validation(finding, value, tool.id, vid)
                    return
            # Preserve interrupted validator artifacts; permit only one recovery attempt.
            output = output.with_name(output.name + "-recovery")
        output.mkdir(mode=0o700)
        request_path, result_path = output / "request.json", output / "result.json"
        atomic_json(request_path, invocation_request(path, self.scope.budgets, self.root / "cancel.request"))
        started = utc_now()
        argv = [sys.executable, "-m", "re_runner.validator_worker", "--request", str(request_path), "--result", str(result_path)]
        execution = run_command(argv, output, self.budget, env=_worker_environment(self.scope, output), stdout_path=output / "stdout.log", stderr_path=output / "stderr.log")
        # R1: same settlement discipline as profile attempts — the validator
        # really ran, so its ToolRun lands with an explicitly incomplete
        # artifact list if enumeration fails, before any finding update.
        artifacts, artifact_error = [], None
        try:
            with self._settlement():
                artifacts, artifact_error = _artifacts(self.root, output, self.budget)
        except Exception as exc:  # pragma: no cover - defensive, _artifacts is non-raising
            artifact_error = f"artifact enumeration failed: {type(exc).__name__}: {redact(str(exc))[:200]}"
        validator = ToolRun(f"t-{len(self.state['tool_runs']) + 1:05d}", asset.id, "validator:private-key-possession", importlib.metadata.version("cryptography"), argv, execution.status, started, utc_now(), execution.exit_code, timed_out=execution.timed_out, artifacts=artifacts)
        if artifact_error:
            validator.error = artifact_error
        _record_tool(self.state, validator)
        if execution.status != "succeeded" or not result_path.exists():
            finding.verification = "Private-key validator failed; candidate retained."
            return
        value = load_json(result_path, max_bytes=65536)
        vid = _add_evidence(self.state, asset, validator, result_path.relative_to(self.root).as_posix(), name, "Sign/verify and changed-message negative control")
        self._apply_validation(finding, value, validator.id, vid)

    @staticmethod
    def _apply_validation(finding: Finding, value: dict, tool_id: str, evidence_id: str) -> None:
        value.update({"tool_run_id": tool_id, "evidence_id": evidence_id})
        finding.validation = value
        finding.evidence_ids.append(evidence_id)
        if verification_gate(value):
            finding.status = "verified"
            finding.title = "Usable private signing key is present in the asset"
            finding.overview = value["assertion"]
            finding.verification = "A signature verifies for the original message and fails for a changed message. Public-key fingerprint is recorded; deployment trust is unverified."
        else:
            finding.verification = value.get("reason", "Validator did not reproduce the asserted behavior; candidate retained.")

    def _gate_findings(self, *, cancelled: bool) -> None:
        """Run the evidence gate before any report is written.

        On normal paths a gate failure propagates so the run is marked failed and
        its verified findings are invalidated. A cancelled run cannot fail louder,
        so it downgrades unproven verified findings itself instead.
        """
        try:
            evidence_gate(self.root, self.state)
            return
        except Exception:
            if not cancelled:
                raise
        for finding in self.state["findings"]:
            if finding["status"] == "verified":
                finding["status"] = "candidate"
                finding["verification"] = "Run was cancelled before the evidence gate could re-confirm verification; previous verification is invalidated."

    def execute(self) -> dict:
        with FileLock(self.root / ".lock"):
            # Read state after ownership, avoiding two resumes from a stale pre-lock snapshot.
            self.state = read_state(self.root)
            if self.resuming:
                (self.root / "cancel.request").unlink(missing_ok=True)
            self.budget.used.update(self.state["used"])
            self._restore_wall_budget()
            self.state["status"] = "running"
            self.persist()
            atomic_json(self.root / "plan.json", {
                "assets": [entry.get("plan") for entry in self.state["assets"].values() if entry.get("plan")],
                "scope": redact(self.scope.to_dict()), "content_trust": "untrusted-data",
            })
            try:
                if self.resuming:
                    self._reconcile_interrupted_usage()
                for item in self.request["assets"]:
                    self.budget.check()
                    entry = self.state["assets"].setdefault(item["id"], {"status": "pending", "attempts": 0})
                    try:
                        asset = self._intake(item, entry)
                        if entry.get("budget_uncertain"):
                            raise IntegrityError("Interrupted attempt has unknown resource use; preserve this run and start a new run with a fresh budget")
                        result, tool = self._invoke(asset, entry)
                        self._findings(asset, entry, result, tool)
                        _verify_snapshot(self.root, asset, self.budget)
                        checks = [check["status"] for check in result["checks"]]
                        if checks and not any(x == "succeeded" for x in checks) and "blocked" in checks:
                            entry["status"] = "blocked"
                        else:
                            entry["status"] = "degraded" if any(x in ("degraded", "failed", "blocked") for x in checks) else "succeeded"
                        entry.pop("error", None)
                        event(self.root, "asset-completed", {"asset_id": asset.id, "status": entry["status"]})
                    except Cancelled:
                        entry["status"] = "cancelled"
                        raise
                    except AnalysisError as exc:
                        entry["status"] = "blocked" if exc.code in ("scope-denied", "capability-missing") else "failed"
                        entry["error"] = {"code": exc.code, "message": redact(str(exc))}
                        self.state["errors"].append({"asset_id": item["id"], **entry["error"]})
                        event(self.root, "asset-error", {"asset_id": item["id"], **entry["error"]})
                        if exc.code == "integrity-error":
                            raise
                    self.persist()
                self._gate_findings(cancelled=False)
                self.state["status"] = _aggregate_status(list(self.state["assets"].values()))
            except (Cancelled, KeyboardInterrupt):
                self.state["status"] = "cancelled"
                for entry in self.state["assets"].values():
                    if entry["status"] in ("running", "pending"):
                        entry["status"] = "cancelled"
                # A cancelled report must not ship verified findings the gate never saw.
                self._gate_findings(cancelled=True)
                event(self.root, "run-cancelled")
            except Exception as exc:
                self.state["status"] = "failed"
                for entry in self.state["assets"].values():
                    if entry["status"] == "running":
                        entry["status"] = "failed"
                self.state["errors"].append({"code": getattr(exc, "code", "runner-error"), "message": redact(str(exc))})
                # Failed integrity must never retain verified assertions in the final report.
                for finding in self.state["findings"]:
                    if finding["status"] == "verified":
                        finding["status"] = "candidate"
                        finding["verification"] = "Evidence integrity check failed; previous verification is invalid."
                event(self.root, "run-failed", {"error": type(exc).__name__})
            finally:
                self.persist()
                atomic_json(self.root / "plan.json", {"assets": [entry.get("plan") for entry in self.state["assets"].values() if entry.get("plan")], "scope": redact(self.scope.to_dict()), "content_trust": "untrusted-data"})
                write_reports(self.root, self.state, self.capabilities, language=self.request["language"])
                event(self.root, "run-finished", {"status": self.state["status"]})
        return self.state

    def _reconcile_interrupted_usage(self) -> None:
        for asset_id, entry in self.state["assets"].items():
            if entry.get("active_output") and entry.get("active_attempt_accounted") is False:
                output = contained(self.root, self.root / entry["active_output"])
                path = output / "usage.json"
                usage = load_json(path, max_bytes=65536) if path.is_file() else None
                if usage is None:
                    entry["budget_uncertain"] = True
                else:
                    # Validate the whole journal before applying any of it: a
                    # rejection must never leave a partial accumulation.
                    if not isinstance(usage, dict) or set(usage) != set(self.budget.used):
                        raise IntegrityError("Invalid interrupted-attempt budget journal")
                    for key, amount in usage.items():
                        if type(amount) is not int or amount < 0:
                            raise IntegrityError("Invalid interrupted-attempt resource counter")
                    # The stop condition already fired for this attempt; apply the
                    # journal in settlement mode so it lands completely or not at all.
                    with self._settlement():
                        for key, amount in usage.items():
                            self.budget.consume(key, amount)
                entry["active_attempt_accounted"] = True
                entry["status"] = "pending"
                event(self.root, "interrupted-attempt-recovered", {"asset_id": asset_id, "usage_unknown": entry.get("budget_uncertain", False)})
        self.persist()

