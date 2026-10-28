"""Offline portability regressions: native host runs and explicit Windows API mocks."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from re_runner import cli, compilers, decompile, execution, extractors, ghidra_adapter
from re_runner import locking, providers, runner, scanner, unpackers, vyper_adapter
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import BudgetExceeded, Cancelled, CapabilityMissing, InvalidInput, Locked
from re_runner.safety import Budget
from re_runner.scope import ScopePolicy


class WindowsOS:
    """Change only the module's OS branch, never pathlib's host implementation."""
    name = "nt"

    def __getattr__(self, key):
        if key == "killpg":
            raise AttributeError(key)
        return getattr(os, key)


class MockProcess:
    def __init__(self):
        self.pid, self.returncode = 4711, None
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fixture", timeout)
        return self.returncode

    def kill(self):
        self.killed, self.returncode = True, 1


class MockJob:
    def __init__(self, *_):
        self.process, self.closed, self.kills = None, False, 0

    def attach_and_resume(self, process):
        self.process = process

    def kill(self):
        self.kills += 1
        if self.process:
            self.process.kill()

    def close(self):
        self.closed = True


class PortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="re-portability-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def budget(self, **limits):
        return Budget({**BUDGET_DEFAULTS, **limits})

    @contextlib.contextmanager
    def windows_flags(self):
        with patch.object(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, create=True), \
                patch.object(subprocess, "CREATE_NO_WINDOW", 0x8000000, create=True):
            yield

    def test_windows_ghidra_timeout_kills_job_and_reaps_without_posix_signals(self):
        process, job = MockProcess(), MockJob()
        with self.windows_flags(), patch.object(execution, "os", WindowsOS()), \
                patch.object(execution, "WindowsJob", return_value=job), \
                patch.object(execution.subprocess, "Popen", return_value=process) as spawn:
            result = ghidra_adapter._run_bounded(["trusted-fixture.exe"], self.root, self.budget(), 0.01)
        self.assertEqual(result.status, "timed-out")
        self.assertTrue(result.timed_out)
        self.assertIs(job.process, process)
        self.assertTrue(job.closed and process.killed)
        self.assertNotIn("preexec_fn", spawn.call_args.kwargs)
        self.assertNotIn("start_new_session", spawn.call_args.kwargs)
        self.assertEqual(spawn.call_args.kwargs["creationflags"] & 0x4, 0x4)

    def test_windows_member_attach_failure_leaves_no_suspended_child_or_job(self):
        process, job = MockProcess(), MockJob()
        job.attach_and_resume = lambda _: (_ for _ in ()).throw(CapabilityMissing("assignment failed"))
        with self.windows_flags(), patch.object(extractors, "os", WindowsOS()), \
                patch.object(extractors, "WindowsJob", return_value=job), \
                patch.object(extractors.subprocess, "Popen", return_value=process):
            with self.assertRaises(CapabilityMissing):
                extractors._spawn_member_reader(["fixture.exe"], self.root, self.budget())
        self.assertTrue(job.closed and process.killed)
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        self.assertIsNotNone(process.returncode)

    def test_windows_member_spawn_failure_closes_allocated_job(self):
        job = MockJob()
        with self.windows_flags(), patch.object(extractors, "os", WindowsOS()), \
                patch.object(extractors, "WindowsJob", return_value=job), \
                patch.object(extractors.subprocess, "Popen", side_effect=OSError("cannot spawn")):
            with self.assertRaises(OSError):
                extractors._spawn_member_reader(["fixture.exe"], self.root, self.budget())
        self.assertTrue(job.closed)

    def test_member_stream_closes_owned_pipes_after_success_and_refusal(self):
        real_spawn = extractors._spawn_member_reader
        for scenario in ("success", "nonzero", "quota"):
            with self.subTest(scenario=scenario):
                output = self.root / scenario
                output.mkdir()
                payload = b"q" * (1024 * 1024) if scenario == "quota" else b"fixture\n"
                expression = "b'q'*1048576" if scenario == "quota" else repr(payload)
                script = "import os,sys,time; os.write(1," + expression + "); "
                script += "time.sleep(30)" if scenario == "quota" else "sys.exit(" + ("3" if scenario == "nonzero" else "0") + ")"
                owned = []

                def spawn(_argv, cwd, budget):
                    # A prior member's handles must be released before another
                    # member starts, rather than waiting for garbage collection.
                    for previous in owned:
                        self.assertTrue(previous.stdout.closed and previous.stderr.closed)
                    process, job = real_spawn([sys.executable, "-c", script], cwd, budget)
                    owned.append(process)
                    return process, job

                members = [{"name": "one.bin", "directory": False}]
                if scenario == "success":
                    members.append({"name": "two.bin", "directory": False})
                budget = self.budget(max_unpack_bytes=2048 if scenario == "quota" else 8192)
                if scenario == "quota":
                    check = budget.check
                    delayed = False

                    def check_after_producer_fills_pipe():
                        nonlocal delayed
                        if not delayed:
                            delayed = True
                            time.sleep(0.1)
                        check()

                    budget.check = check_after_producer_fills_pipe
                progress = {"files": 0, "bytes": 0}
                try:
                    with patch.object(extractors, "_spawn_member_reader", side_effect=spawn):
                        omitted, error = extractors._extract_streaming(
                            "self-child-fixture", self.root / "sample", members, output, budget, progress,
                        )
                    for process in owned:
                        self.assertIsNotNone(process.poll())
                        self.assertTrue(process.stdout.closed and process.stderr.closed)
                    if scenario == "success":
                        self.assertEqual((omitted, error), (0, None))
                        self.assertEqual(progress, {"files": 2, "bytes": 16})
                        self.assertEqual(budget.used["unpack_bytes"], 16)
                        self.assertEqual((output / "one.bin").read_bytes(), payload)
                    else:
                        self.assertEqual(omitted, 1)
                        self.assertIn("budget" if scenario == "quota" else "exited 3", error)
                        self.assertEqual(progress, {"files": 0, "bytes": 0})
                        self.assertFalse((output / "one.bin").exists())
                finally:
                    for process in owned:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=execution.REAP_SECONDS)
                        process.stdout.close()
                        process.stderr.close()

    def test_member_stream_closes_owned_pipes_on_cancel_budget_and_destination_error(self):
        real_spawn = extractors._spawn_member_reader
        for scenario, expected in (("cancel", Cancelled), ("budget", BudgetExceeded),
                                   ("destination-error", FileExistsError)):
            with self.subTest(scenario=scenario):
                output = self.root / scenario
                output.mkdir()
                budget = self.budget()
                if scenario == "cancel":
                    budget.cancel_path = self.root / "cancel-request"
                    budget.cancel_path.touch()
                elif scenario == "budget":
                    budget.wall_deadline_epoch = 0
                else:
                    (output / "one.bin").write_bytes(b"preserve existing file")
                owned = []

                def spawn(_argv, cwd, budget):
                    process, job = real_spawn(
                        [sys.executable, "-c", "import time; time.sleep(30)"], cwd, budget,
                    )
                    owned.append(process)
                    return process, job

                try:
                    with patch.object(extractors, "_spawn_member_reader", side_effect=spawn):
                        with self.assertRaises(expected):
                            extractors._extract_streaming(
                                "self-child-fixture", self.root / "sample",
                                [{"name": "one.bin", "directory": False}], output,
                                budget, {"files": 0, "bytes": 0},
                            )
                    self.assertEqual(len(owned), 1)
                    self.assertIsNotNone(owned[0].poll())
                    self.assertTrue(owned[0].stdout.closed and owned[0].stderr.closed)
                    if scenario == "destination-error":
                        self.assertEqual((output / "one.bin").read_bytes(), b"preserve existing file")
                    else:
                        self.assertFalse((output / "one.bin").exists())
                finally:
                    for process in owned:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=execution.REAP_SECONDS)
                        process.stdout.close()
                        process.stderr.close()

    def test_silent_member_observes_timeout_and_midflight_cancel_or_wall_budget(self):
        real_spawn = extractors._spawn_member_reader
        for scenario, expected in (("timeout", None), ("cancel", Cancelled),
                                   ("closed-stdout-cancel", Cancelled), ("wall", BudgetExceeded)):
            with self.subTest(scenario=scenario):
                output = self.root / ("silent-" + scenario)
                output.mkdir()
                budget = self.budget(tool_timeout_seconds=1)
                owned, timers = [], []
                fallback_used = threading.Event()

                def spawn(_argv, cwd, budget):
                    script = "import os,time; "
                    if scenario == "closed-stdout-cancel":
                        script += "os.close(1); "
                    process, job = real_spawn([sys.executable, "-c", script + "time.sleep(30)"], cwd, budget)
                    owned.append(process)
                    if scenario in ("cancel", "closed-stdout-cancel"):
                        budget.cancel_path = output / "cancel-request"
                        timer = threading.Timer(0.2, budget.cancel_path.touch)
                        timers.append(timer)
                        timer.start()
                    elif scenario == "wall":
                        budget.wall_deadline_epoch = time.time() + 0.2

                    def finite_test_guard():
                        fallback_used.set()
                        extractors._kill_member_child(process, job)

                    guard = threading.Timer(4, finite_test_guard)
                    timers.append(guard)
                    guard.start()
                    return process, job

                started = time.monotonic()
                try:
                    with patch.object(extractors, "_spawn_member_reader", side_effect=spawn):
                        args = ("self-child-fixture", self.root / "sample",
                                [{"name": "silent.bin", "directory": False}], output,
                                budget, {"files": 0, "bytes": 0})
                        if expected:
                            with self.assertRaises(expected):
                                extractors._extract_streaming(*args)
                        else:
                            omitted, error = extractors._extract_streaming(*args)
                            self.assertEqual(omitted, 1)
                            self.assertIn("timed out", error)
                    self.assertFalse(fallback_used.is_set(), "silent read exceeded the independent test deadline")
                    self.assertLess(time.monotonic() - started, 4)
                    self.assertEqual(len(owned), 1)
                    self.assertIsNotNone(owned[0].poll())
                    self.assertTrue(owned[0].stdout.closed and owned[0].stderr.closed)
                    self.assertFalse((output / "silent.bin").exists())
                finally:
                    for timer in timers:
                        timer.cancel()
                        timer.join(timeout=execution.REAP_SECONDS)
                    for process in owned:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=execution.REAP_SECONDS)
                        process.stdout.close()
                        process.stderr.close()

    def test_windows_lock_owns_the_sentinel_byte_not_the_metadata(self):
        events = []
        fake = types.SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2)
        fake.locking = lambda fd, operation, size: events.append(
            (operation, size, os.lseek(fd, 0, os.SEEK_CUR)))
        path = self.root / "a space" / "run.lock"
        with patch.object(locking, "os", WindowsOS()), patch.dict(sys.modules, {"msvcrt": fake}):
            with locking.FileLock(path):
                data = path.read_bytes()
                self.assertEqual(data[:1], b"\x00")
                self.assertIn("token", json.loads(data[1:]))
        self.assertEqual(events, [(1, 1, 0), (2, 1, 0)])

    def test_native_file_lock_rejects_a_second_owner_then_releases(self):
        path = self.root / "run.lock"
        with locking.FileLock(path):
            with self.assertRaises(Locked):
                locking.FileLock(path).acquire()
        with locking.FileLock(path):
            self.assertTrue(path.is_file())

    def test_inspect_json_round_trips_nonascii_path_through_ascii_stdout(self):
        source = self.root / "\u8f93\u5165 file.py"
        source.write_text("pass\n", encoding="utf-8")
        buffer = io.BytesIO()
        output = io.TextIOWrapper(buffer, encoding="ascii", write_through=True)
        with patch.object(sys, "stdout", output):
            code = cli.main(["inspect", "--asset", str(source)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["locator"], str(source))
        self.assertFalse(json.loads(buffer.getvalue())["network_contacted"])
        output.detach()

    def test_error_json_round_trips_nonascii_diagnostic_through_ascii_stderr(self):
        buffer = io.BytesIO()
        output = io.TextIOWrapper(buffer, encoding="ascii", write_through=True)
        with patch.object(sys, "stderr", output), patch.object(
            cli, "detect", side_effect=InvalidInput("Unreadable \u8f93\u5165 path")
        ):
            code = cli.main(["inspect", "--asset", "fixture"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(buffer.getvalue())["message"], "Unreadable \u8f93\u5165 path")
        output.detach()

    def test_worker_preserves_configured_tools_and_jdk_but_not_unrelated_secrets(self):
        output = self.root / "work directory"
        output.mkdir()
        configured = {"RE_RUN_GHIDRA": "/Program Files/Ghidra", "RE_RUN_VYPER": "/tools/vyper",
                      "JAVA_HOME": "/Library/Java/JDK", "UNRELATED_SECRET": "must-not-propagate"}
        with patch.dict(os.environ, configured, clear=True):
            env = runner._worker_environment(ScopePolicy(), output)
            self.assertEqual(decompile._clean_env()["JAVA_HOME"], configured["JAVA_HOME"])
        for key in ("RE_RUN_GHIDRA", "RE_RUN_VYPER", "JAVA_HOME"):
            self.assertEqual(env[key], configured[key])
        self.assertNotIn("UNRELATED_SECRET", env)
        for key in ("TMP", "TEMP", "TMPDIR"):
            self.assertEqual(Path(env[key]), output / "tmp")
        self.assertEqual(env["PYTHONUTF8"], "1")

    def test_relative_worker_tool_configuration_survives_the_worker_cwd_change(self):
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.root)
        output = self.root / "run work"
        output.mkdir()
        configured = {"RE_RUN_SOLC": "tools/solc", "RE_RUN_GHIDRA": "tools/ghidra",
                      "RE_RUN_R2": "tools/r2", "JAVA_HOME": "tools/jdk"}
        with patch.dict(os.environ, configured, clear=True):
            env = runner._worker_environment(ScopePolicy(), output)
        for key, value in configured.items():
            self.assertEqual(Path(env[key]).resolve(), (self.root / value).resolve())

    def test_windows_ghidra_batch_rejects_reinterpreted_arguments_before_spawning(self):
        for character in '&|<>^%!"\r\n':
            with self.subTest(character=repr(character)), patch.object(ghidra_adapter, "os", WindowsOS()), \
                    patch.object(ghidra_adapter, "run_command") as execute:
                with self.assertRaises(InvalidInput):
                    ghidra_adapter._run_bounded(
                        ["C:/Trusted Ghidra/analyzeHeadless.bat", "input" + character + "name"],
                        self.root, self.budget(), 5,
                    )
                execute.assert_not_called()

    def test_windows_ghidra_batch_keeps_spaces_and_unicode_as_distinct_arguments(self):
        argv = ["C:/Trusted Ghidra/analyzeHeadless.bat", "C:/work folder/\u8f93\u5165.bin", "project name"]
        finished = types.SimpleNamespace(status="succeeded", exit_code=0, timed_out=False,
                                         stdout="fixture", stderr="", duration=0.1, reap_failed=False)
        with patch.object(ghidra_adapter, "os", WindowsOS()), \
                patch.object(ghidra_adapter, "run_command", return_value=finished) as execute:
            result = ghidra_adapter._run_bounded(argv, self.root, self.budget(), 5)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(execute.call_args.args[0], argv)

    def test_official_jadx_batch_uses_java_without_cmd_for_special_character_paths(self):
        distribution = self.root / "jadx & \u5de5\u5177"
        (distribution / "bin").mkdir(parents=True)
        (distribution / "lib").mkdir()
        launcher = distribution / "bin/jadx.bat"
        launcher.write_text("fixture must never execute", encoding="utf-8")
        output = self.root / "out & \u8f93\u51fa"
        apk = self.root / "input & \u8f93\u5165.apk"
        apk.write_bytes(b"fixture")
        calls = []

        def execute(argv, *_args, **_kwargs):
            calls.append(argv)
            if "--version" not in argv:
                source = output / "jadx/Fixture.java"
                source.parent.mkdir()
                source.write_text("class Fixture {}", encoding="utf-8")
            return types.SimpleNamespace(status="succeeded", exit_code=0, timed_out=False,
                                         stdout="fixture-version", stderr="")

        with patch.object(decompile, "_java", return_value="C:/JDK Folder/java.exe"), \
                patch.object(decompile, "run_command", side_effect=execute), \
                patch.dict(decompile._VERSION_CACHE, {}, clear=True):
            result = decompile.jadx(apk, output, self.budget(), str(launcher))
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(calls[-1][-1], str(apk))
        self.assertEqual(calls[-1][0], "C:/JDK Folder/java.exe")
        self.assertIn(str(distribution / "lib/*"), calls[-1])
        self.assertIn("jadx.cli.JadxCLI", calls[-1])
        self.assertFalse(any(argument.lower().endswith((".bat", "cmd.exe")) for argument in calls[-1]))

    def test_java_home_with_spaces_resolves_without_a_path_entry(self):
        home = self.root / "configured JDK"
        executable = home / "bin" / ("java.exe" if os.name == "nt" else "java")
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"fixture")
        with patch.dict(os.environ, {"JAVA_HOME": str(home)}, clear=True), \
                patch.object(decompile.shutil, "which", return_value=None):
            self.assertEqual(Path(decompile._java()), executable)

    def test_official_apktool_batch_uses_native_java_jar_arguments(self):
        distribution = self.root / "apktool & tools"
        distribution.mkdir()
        launcher = distribution / "apktool.bat"
        launcher.write_text("must not execute", encoding="utf-8")
        (distribution / "apktool.jar").write_bytes(b"fixture")
        output = self.root / "decoded & work"
        apk = self.root / "input & \u8f93\u5165.apk"
        apk.write_bytes(b"fixture")
        calls = []

        def execute(argv, *_args, **_kwargs):
            calls.append(argv)
            if "--version" not in argv:
                manifest = output / "apktool/AndroidManifest.xml"
                manifest.parent.mkdir()
                manifest.write_text("<manifest />", encoding="utf-8")
            return types.SimpleNamespace(status="succeeded", exit_code=0, timed_out=False,
                                         stdout="fixture-version", stderr="")

        with patch.object(decompile, "_java", return_value="C:/JDK Folder/java.exe"), \
                patch.object(decompile, "run_command", side_effect=execute), \
                patch.dict(decompile._VERSION_CACHE, {}, clear=True):
            result = decompile.apktool(apk, output, self.budget(), str(launcher))
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(calls[-1][-1], str(apk))
        self.assertIn(str(distribution / "apktool.jar"), calls[-1])
        self.assertNotIn(str(launcher), calls[-1])

    def test_unrecognized_batch_layouts_skip_without_invoking_a_shell(self):
        launcher = self.root / "custom.cmd"
        launcher.write_text("must not execute", encoding="utf-8")
        with patch.object(decompile, "run_command") as execute:
            for call in (decompile.jadx, decompile.apktool):
                with self.subTest(tool=call.__name__):
                    result = call(self.root / "input.apk", self.root / call.__name__, self.budget(), str(launcher))
                    self.assertEqual(result["status"], "skipped")
            execute.assert_not_called()

    def test_stopped_ghidra_cannot_promote_a_partial_dump_and_keeps_usage(self):
        binary = self.root / "fixture.bin"
        binary.write_bytes(b"local fixture only")
        for status in ("failed", "timed-out", "output-exceeded", "cancelled", "budget-exceeded"):
            with self.subTest(status=status):
                output = self.root / status
                budget = self.budget()

                def stopped(*_args, **_kwargs):
                    (output / "ghidra-functions.json").write_text(
                        json.dumps({"functions": [{"name": "partial"}], "decompiled": []}), encoding="utf-8",
                    )
                    if status == "cancelled":
                        budget.cancel_path = self.root / "cancel.request"
                        budget.cancel_path.touch()
                    return types.SimpleNamespace(status=status, exit_code=1, timed_out=status == "timed-out",
                                                 stdout="", stderr="fixture stopped")

                with patch.object(ghidra_adapter, "configured_headless", return_value="trusted-fixture"), \
                        patch.object(ghidra_adapter, "_run_bounded", side_effect=stopped):
                    result = ghidra_adapter.headless_decompile(binary, output, budget)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["functions"], [])
                self.assertEqual(result["decompiled"], [])
                self.assertGreater(result["derived_files"], 0)
                self.assertGreater(budget.used["unpack_bytes"], 0)
                self.assertFalse(budget.settling)

    def test_unreaped_ghidra_child_does_not_enter_artifact_settlement(self):
        binary = self.root / "fixture.bin"
        binary.write_bytes(b"local fixture only")
        stopped = types.SimpleNamespace(status="timed-out", exit_code=None, timed_out=True,
                                        stdout="", stderr="", reap_failed=True)
        budget = self.budget()
        with patch.object(ghidra_adapter, "configured_headless", return_value="trusted-fixture"), \
                patch.object(ghidra_adapter, "_run_bounded", return_value=stopped), \
                patch.object(ghidra_adapter, "_consume_derived") as collect:
            result = ghidra_adapter.headless_decompile(binary, self.root / "out", budget)
        collect.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertIn("incomplete", result["usage_marker"])
        self.assertFalse(budget.settling)

    def test_ghidra_derived_limit_records_observed_usage_and_prevents_success(self):
        binary = self.root / "fixture.bin"
        binary.write_bytes(b"local fixture only")
        output = self.root / "out"
        budget = self.budget(max_unpack_bytes=1024)

        def finished(*_args, **_kwargs):
            (output / "ghidra-functions.json").write_text(
                json.dumps({"functions": [{"name": "partial"}], "decompiled": []}), encoding="utf-8",
            )
            return types.SimpleNamespace(status="succeeded", exit_code=0, timed_out=False,
                                         stdout="", stderr="")

        with patch.object(ghidra_adapter, "configured_headless", return_value="trusted-fixture"), \
                patch.object(ghidra_adapter, "_run_bounded", side_effect=finished):
            result = ghidra_adapter.headless_decompile(binary, output, budget)
        self.assertEqual(result["status"], "degraded")
        self.assertIn("incomplete", result["usage_marker"])
        self.assertGreater(budget.used["unpack_bytes"], 1024)
        self.assertFalse(budget.settling)

    def test_relative_tool_resolvers_pin_the_caller_directory_before_child_cwd_changes(self):
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.root)
        target = Path("tool folder/trusted-helper")
        target.parent.mkdir()
        target.write_bytes(b"fixture")
        target.chmod(0o700)
        expected = target.absolute()
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(Path(scanner.resolve_executable(str(target))), expected)
            self.assertEqual(unpackers._trusted_executable(str(target)), expected)
            self.assertEqual(Path(extractors.configured_executable(str(target))), expected)
            self.assertEqual(Path(ghidra_adapter.configured_headless(str(target))), expected)
            self.assertEqual(Path(vyper_adapter._resolve_executable(str(target))[0][0]), expected)
            with patch.object(decompile.shutil, "which", return_value=str(target)):
                self.assertEqual(Path(decompile._java()), expected)

    def test_relative_radare2_path_survives_a_different_analysis_directory(self):
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.root)
        tool = Path("trusted-r2")
        tool.write_bytes(b"fixture")
        output = self.root / "analysis"
        output.mkdir()
        records = []

        def execute(argv, cwd, *_, **__):
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertTrue(Path(argv[0]).is_file())
            records.append(argv)
            text = "fixture-r2" if "-qv" in argv else '[{"addr":4096,"size":1}]'
            return types.SimpleNamespace(stdout=text, stderr="", status="succeeded", exit_code=0, timed_out=False)

        with patch.dict(os.environ, {"RE_RUN_R2": str(tool)}, clear=True), \
                patch.object(providers, "run_command", side_effect=execute):
            result = providers.radare2(self.root / "input", output, self.budget())
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(len(records), 3)

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture; Windows process branches use mocks above")
    def test_native_relative_solc_tool_runs_from_a_different_unicode_work_directory(self):
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.root)
        tool = Path("trusted-solc")
        tool.write_text(
            "#!" + sys.executable + "\nimport sys,json\n"
            "print('Version: 0.8.fixture' if '--version' in sys.argv else "
            "json.dumps({'contracts':{'fixture.sol:Vault':{'abi':'[]','bin':'6000'}}}))\n",
            encoding="utf-8",
        )
        tool.chmod(0o700)
        source = self.root / "fixture.sol"
        source.write_text("fixture only", encoding="utf-8")
        result = compilers.solc_compile(source, self.root / "\u8f93\u51fa work", self.budget(), str(tool))
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["contracts"][0]["name"], "Vault")
        self.assertEqual(result["contracts"][0]["bytecode_len"], 2)

    @unittest.skipIf(os.name == "nt", "POSIX fd limits are tested on the actual host")
    def test_native_ghidra_execution_keeps_the_jvm_descriptor_ceiling(self):
        result = ghidra_adapter._run_bounded(
            [sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_NOFILE)[0])"],
            self.root, self.budget(), 5,
        )
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.stdout.strip(), "1024")

    def test_native_ghidra_output_is_stopped_at_the_shared_output_budget(self):
        result = ghidra_adapter._run_bounded(
            [sys.executable, "-c", "import os,time; os.write(1,b'X'*100000); time.sleep(30)"],
            self.root, self.budget(max_tool_output_bytes=4096), 5,
        )
        self.assertEqual(result.status, "output-exceeded")
        self.assertLessEqual(len(result.stdout), 4096)


if __name__ == "__main__":
    unittest.main()
