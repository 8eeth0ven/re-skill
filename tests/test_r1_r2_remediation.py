"""R1/R2 remediation acceptance through real execution paths.

R1: an execution that already ran keeps its ToolRun, execution status, an
explicitly incomplete artifact list and its full validated usage in the current
terminal state — even when its output tree cannot be enumerated (links, limit
crossings). Resume never double-counts. Intake interruptions record a ToolRun
and rebuild safely on resume.

R2: the 7z stage refuses extraction on incomplete/truncated listings, rejects
unsafe members before any write, and enforces the total unpack quota on the
actual write path (per-member controlled streaming; there is no Windows Job
object or directory quota on macOS).
"""
import io
import os
import shutil
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.execution import run_command as real_run_command
from re_runner.extractors import (
    MAX_LISTED_MEMBERS,
    _parse_listing,
    _vet_members,
    configured_executable,
    sevenzip_extract,
)
from re_runner.models import AssetRequest
from re_runner.runner import Runner, _artifacts
from re_runner.safety import Budget, InvalidInput, load_json
from re_runner.scope import ScopePolicy

# Keep the real local-fixture gates, without assuming one Homebrew prefix.
SEVENZIP = configured_executable(
    os.environ.get("RE_RUN_7Z") or shutil.which("7z") or shutil.which("7zz")
)
WATCH_SECONDS = 120


def budget(**limits) -> Budget:
    return Budget({**BUDGET_DEFAULTS, **limits})


def cpio_bytes(files: dict[str, bytes]) -> bytes:
    """Minimal but spec-correct newc cpio archive (7z reads the 'New ASCII' format)."""

    def header(name: str, size: int) -> bytes:
        values = [0, 0o100644, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name) + 1, 0]
        return b"070701" + "".join("%08X" % value for value in values).encode()

    out = bytearray()
    for name, data in files.items():
        raw = name.encode()
        out += header(name, len(data)) + raw + b"\x00"
        out += b"\x00" * ((4 - ((110 + len(raw) + 1) % 4)) % 4)
        out += data
        out += b"\x00" * ((4 - (len(data) % 4)) % 4)
    out += header("TRAILER!!!", 0) + b"TRAILER!!!\x00"
    out += b"\x00" * ((4 - ((110 + 11) % 4)) % 4)
    return bytes(out)


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-r1r2-", ignore_cleanup_errors=True)
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)


class ArtifactEnumerationTests(TempCase):
    """R1 unit gate: _artifacts never raises and always explains incompleteness."""

    def test_limit_crossing_returns_explicit_incomplete_marker(self):
        directory = self.root / "out"
        directory.mkdir()
        for index in range(6):
            (directory / f"f{index}.bin").write_bytes(b"x" * 10)
        # iter_tree's global entry cap fires first (6 entries > max_files=3):
        # the contract is a bounded partial list plus an explicit reason, never
        # a raise and never an unbounded scan.
        records, reason = _artifacts(self.root, directory, budget(max_files=3))
        self.assertLess(len(records), 6)
        self.assertIn("incomplete", reason)

    def test_link_entry_stops_enumeration_with_reason(self):
        directory = self.root / "out"
        (directory / "sub").mkdir(parents=True)
        (directory / "a.txt").write_bytes(b"plain")
        try:
            (directory / "sub" / "link.txt").symlink_to("/etc/hosts")
        except OSError:
            self.skipTest("host forbids symlink creation")
        records, reason = _artifacts(self.root, directory, budget())
        self.assertEqual([record["path"] for record in records], ["out/a.txt"])
        self.assertIn("incomplete", reason)
        self.assertIn("link", reason.lower())

    def test_entry_outside_root_is_never_listed(self):
        outside = self.root.parent / f"outside-{os.getpid()}.bin"
        outside.write_bytes(b"outside")
        directory = self.root / "out"
        directory.mkdir()
        (directory / "in.txt").write_bytes(b"in")
        records, reason = _artifacts(self.root, directory, budget())
        outside.unlink(missing_ok=True)
        self.assertEqual([record["path"] for record in records], ["out/in.txt"])
        self.assertIsNone(reason)


class R1RunnerIntegrationTests(TempCase):
    """R1 acceptance: real Runner attempts survive un-enumerable output trees."""

    def firmware(self, members=40):
        path = self.root / "fixture.tar"
        with tarfile.open(path, "w") as archive:
            for index in range(members):
                data = f"component-{index} configuration=fixture-{index}\n".encode("utf-8")
                info = tarfile.TarInfo(f"etc/file-{index:04d}.conf")
                info.size, info.mode, info.mtime = len(data), 0o600, 0
                archive.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def fast_polls():
        return patch("re_runner.execution.time.sleep", lambda seconds: threading.Event().wait(0.001))

    def planting_run_command(self, attempt_dir, plant):
        def wrapped(argv, cwd, budget, **kwargs):
            result = real_run_command(argv, cwd, budget, **kwargs)
            if attempt_dir.exists():
                plant(attempt_dir)
            return result

        return wrapped

    def test_successful_worker_with_unenumerable_output_keeps_toolrun_and_usage(self):
        source = self.firmware()

        def plant(attempt_dir):
            for child in attempt_dir.rglob("*"):
                if child.is_file() and child.suffix == ".conf":
                    try:
                        link = child.with_suffix(".link")
                        if not link.exists():
                            link.symlink_to(child.name)
                    except OSError:
                        pass
                    break

        runner = Runner.new(self.root / "runs", [AssetRequest(str(source))], ScopePolicy(), "triage", "en")
        attempt_dir = runner.root / "work" / "asset-001" / "attempt-1"
        with patch("re_runner.runner.run_command", self.planting_run_command(attempt_dir, plant)):
            state = runner.execute()
        profile = [item for item in state["tool_runs"] if item["tool"] == "profile:firmware"]
        self.assertEqual(len(profile), 1, "the executed attempt must always leave its ToolRun")
        entry = state["assets"]["asset-001"]
        self.assertTrue(entry.get("active_attempt_accounted", entry.get("result") is not None) or entry["status"] == "failed")
        intake_used = source.stat().st_size
        self.assertGreaterEqual(state["used"]["files"], 2)  # intake + at least one settled journal
        journal_files = 0
        for attempt in attempt_dir.parent.glob("attempt-*/usage.json"):
            usage = load_json(attempt, max_bytes=65536)
            journal_files += usage.get("files", 0)
        self.assertGreater(journal_files, 0, "worker usage journal must exist")
        _ = intake_used

    def test_cancel_with_unenumerable_output_settles_exactly_once(self):
        source = self.firmware()

        def plant(attempt_dir):
            root = attempt_dir / "rootfs"
            if root.exists() and any(root.rglob("*")):
                try:
                    (root / "late.link").symlink_to("/etc/hosts")
                except OSError:
                    pass

        runner = Runner.new(self.root / "runs", [AssetRequest(str(source))], ScopePolicy(), "triage", "en")
        cancel_path = runner.root / "cancel.request"
        attempt_dir = runner.root / "work" / "asset-001" / "attempt-1"

        def cancelling_run_command(argv, cwd, budget, **kwargs):
            def watch():
                deadline = time.monotonic() + WATCH_SECONDS
                while time.monotonic() < deadline:
                    if (attempt_dir / "rootfs").exists() and any((attempt_dir / "rootfs").rglob("*")):
                        break
                    threading.Event().wait(0.002)
                cancel_path.write_text("cancel", encoding="utf-8")

            thread = threading.Thread(target=watch, daemon=True)
            thread.start()
            try:
                result = real_run_command(argv, cwd, budget, **kwargs)
                plant(attempt_dir)
                return result
            finally:
                thread.join()

        with self.fast_polls(), patch("re_runner.runner.run_command", cancelling_run_command):
            state = runner.execute()
        self.assertEqual(state["status"], "cancelled", state["errors"])
        profile = [item for item in state["tool_runs"] if item["tool"] == "profile:firmware" and item["status"] == "cancelled"]
        self.assertEqual(len(profile), 1, "cancelled attempt must keep its ToolRun even with a link in its output")
        self.assertIsNotNone(profile[0].get("error"))
        entry = state["assets"]["asset-001"]
        self.assertTrue(entry.get("active_attempt_accounted"))
        used_before = dict(state["used"])
        # Resume: the journal is reconciled once, never twice.
        runner.resuming = True
        state2 = Runner.resume(runner.root).execute()
        self.assertEqual(state2["status"], "succeeded", state2["errors"])
        attempts = [item for item in state2["tool_runs"] if item["tool"] == "profile:firmware"]
        self.assertEqual(len(attempts), 2)
        # Exact no-double-counting identity: final used == intake(1 file) + every
        # attempt journal counted exactly once.
        total = 1
        for attempt in attempt_dir.parent.glob("attempt-*/usage.json"):
            total += load_json(attempt, max_bytes=65536).get("files", 0)
        self.assertEqual(state2["used"]["files"], total)
        self.assertGreater(used_before["files"], 1, "cancelled attempt journal must have been settled into used_before")

    def test_interrupted_intake_records_toolrun_and_resume_rebuilds(self):
        tree = self.root / "big-tree"
        (tree / "data").mkdir(parents=True)
        for index in range(300):
            (tree / "data" / f"f{index:04d}.bin").write_bytes(b"z" * 2048)
        runner = Runner.new(self.root / "runs", [AssetRequest(str(tree))], ScopePolicy(), "triage", "en")
        inputs_dir = runner.root / "inputs" / "asset-001"
        cancel_path = runner.root / "cancel.request"

        def cancelling_snapshot(*args, **kwargs):
            def watch():
                deadline = time.monotonic() + WATCH_SECONDS
                while time.monotonic() < deadline:
                    if inputs_dir.exists() and any(inputs_dir.rglob("*.bin")):
                        break
                    threading.Event().wait(0.002)
                cancel_path.write_text("cancel", encoding="utf-8")

            thread = threading.Thread(target=watch, daemon=True)
            thread.start()
            try:
                from re_runner.intake import snapshot as real_snapshot
                return real_snapshot(*args, **kwargs)
            finally:
                thread.join()

        with self.fast_polls(), patch("re_runner.runner.snapshot", cancelling_snapshot):
            state = runner.execute()
        self.assertEqual(state["status"], "cancelled")
        intake = [item for item in state["tool_runs"] if item["tool"] == "intake"]
        self.assertEqual(len(intake), 1, "interrupted intake must leave its ToolRun")
        self.assertEqual(intake[0]["status"], "cancelled")
        self.assertTrue((inputs_dir / ".incomplete").exists())
        runner.resuming = True
        state2 = Runner.resume(runner.root).execute()
        self.assertEqual(state2["status"], "succeeded", state2["errors"])
        events = (runner.root / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn("interrupted-intake-recovered", events)



@unittest.skipUnless(SEVENZIP, "trusted 7z not installed (set RE_RUN_7Z or use PATH)")
class ExtractorRefusalTests(TempCase):
    """R2 gates against the real 7z binary."""

    def extract(self, data: bytes, name="container.cpio", **limits):
        sample = self.root / name
        sample.write_bytes(data)
        work = self.root / "work"
        work.mkdir()
        return sevenzip_extract(sample, work / "rootfs-7z", budget(**limits), executable=SEVENZIP)

    def test_output_flooded_listing_refuses_extraction(self):
        files = {f"etc/f{i}.conf": b"x" * 64 for i in range(200)}
        result = self.extract(cpio_bytes(files), max_tool_output_bytes=512)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["extraction_started"])
        self.assertIn("listing", result["error"].lower())
        self.assertEqual(result["listing_complete"], False)

    def test_truncated_listing_over_5000_refuses_extraction(self):
        files = {f"etc/f{i:05d}.conf": b"x" * 8 for i in range(MAX_LISTED_MEMBERS + 100)}
        result = self.extract(cpio_bytes(files))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["extraction_started"])
        self.assertIn("truncated", result["error"])
        self.assertEqual(len(result["members"]), MAX_LISTED_MEMBERS)

    def test_unsafe_member_rejected_before_any_write(self):
        sentinel_parent = self.root
        sentinel = sentinel_parent / "sentinel.txt"
        sentinel.write_bytes(b"untouched")
        files = {"etc/ok.conf": b"a=b\n", "../evil.txt": b"pwn"}
        result = self.extract(cpio_bytes(files))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["extraction_started"])
        self.assertIn("preflight", result["error"].lower())
        self.assertEqual(sentinel.read_text(), "untouched")
        _ = sentinel_parent

    def test_deep_member_rejected_before_any_write(self):
        deep = "/".join(f"d{i}" for i in range(20)) + "/f.conf"
        result = self.extract(cpio_bytes({deep: b"a=b\n"}), max_depth=16)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["extraction_started"])

    def test_total_quota_enforced_on_the_write_path(self):
        files = {f"etc/f{i}.conf": b"q" * 4096 for i in range(16)}
        data = cpio_bytes(files)
        sample = self.root / "container.cpio"
        sample.write_bytes(data)
        work = self.root / "work"
        work.mkdir()
        # Listing lies: declare half the real bytes so preflight passes and the
        # enforcement must happen during the actual writes.
        real_parse = _parse_listing

        def lying_parse(text):
            members, truncated = real_parse(text)
            for member in members:
                member["bytes"] //= 2
            return members, truncated

        with patch("re_runner.extractors._parse_listing", lying_parse):
            result = sevenzip_extract(sample, work / "rootfs-7z", budget(max_unpack_bytes=48 * 1024), executable=SEVENZIP)
        self.assertIsNotNone(result)
        self.assertTrue(result["extraction_started"])
        self.assertLessEqual(result["bytes"], 48 * 1024 + 65536 // 2,
                             "the write path must stop at the total quota (one block of overshoot at most)")
        self.assertLess(result["files"], 16)
        self.assertIn("budget", result["error"].lower())

    def test_declared_totals_over_budget_refuse_at_preflight(self):
        files = {f"etc/f{i}.conf": b"q" * 1024 for i in range(8)}
        result = self.extract(cpio_bytes(files), max_unpack_bytes=4096)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["extraction_started"])

    def test_healthy_cpio_extracts_via_controlled_streaming(self):
        files = {"etc/a.conf": b"a=b\n", "var/b.conf": b"b=c\n"}
        result = self.extract(cpio_bytes(files))
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertTrue(result["extraction_started"])
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["bytes"], 8)
        self.assertIsNone(result["error"])


class PreflightVetTests(TempCase):
    def test_vet_rejects_traversal_and_depth_and_oversize(self):
        members = [{"name": "../evil", "bytes": 1, "directory": False, "packed_bytes": 1}]
        with self.assertRaises(InvalidInput):
            _vet_members(members, budget())
        members = [{"name": "/".join(f"d{i}" for i in range(17)), "bytes": 1, "directory": False, "packed_bytes": 1}]
        with self.assertRaises(InvalidInput):
            _vet_members(members, budget(max_depth=16))
        members = [{"name": "big.bin", "bytes": 999_999, "directory": False, "packed_bytes": 1}]
        with self.assertRaises(InvalidInput):
            _vet_members(members, budget(max_unpack_bytes=1000))

    def test_parse_listing_reports_truncation(self):
        rows = "\n".join(
            f"2026-01-01 00:00:00 A.... {i} 0 etc/f{i}.conf" for i in range(MAX_LISTED_MEMBERS + 50)
        )
        members, truncated = _parse_listing(rows)
        self.assertTrue(truncated)
        self.assertEqual(len(members), MAX_LISTED_MEMBERS)
        members, truncated = _parse_listing("2026-01-01 00:00:00 A.... 5 0 etc/a.conf")
        self.assertFalse(truncated)
        self.assertEqual(len(members), 1)


if __name__ == "__main__":
    unittest.main()
