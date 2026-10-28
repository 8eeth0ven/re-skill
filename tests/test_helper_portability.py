"""Offline helper portability regressions; no targets, devices, or downloaded tools."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INIT = load("helper_init", "pipeline/init_pipeline.py")
TIMEOUT = load("helper_timeout", "pipeline/run_with_timeout.py")
VALIDATOR = load("helper_validator", "scripts/validate_library.py")
DIGEST = load("helper_digest", "tools/worktree_digest.py")
CALLTREE = load("helper_calltree", "techniques/13-trace/scripts/calltree.py")


class HelperPortabilityTests(unittest.TestCase):
    def test_sdk_overrides_and_redirected_windows_localappdata(self):
        self.assertEqual(INIT.sdk_directory({"ANDROID_SDK_ROOT": "/sdk/explicit", "ANDROID_HOME": "/sdk/secondary"}), Path("/sdk/explicit"))
        self.assertEqual(INIT.sdk_directory({"ANDROID_HOME": "/sdk/secondary"}), Path("/sdk/secondary"))
        self.assertEqual(INIT.sdk_directory({"LOCALAPPDATA": "/redirected/local"}, platform_name="win32", home="/profile"), Path("/redirected/local/Android/Sdk"))
        self.assertEqual(INIT.sdk_directory({}, platform_name="darwin", home="/profile"), Path("/profile/Library/Android/sdk"))

    def test_numeric_sdk_version_selection_including_nested_d8(self):
        with tempfile.TemporaryDirectory() as td:
            sdk = Path(td)
            for version in ("9.0.0", "36.0.0", "35.0.1"):
                directory = sdk / "build-tools" / version
                (directory / "lib").mkdir(parents=True)
                (directory / "aapt2").touch()
                (directory / "lib/d8.jar").touch()
            self.assertEqual(INIT.latest_build_tool(sdk, "aapt2").parent.name, "36.0.0")
            self.assertEqual(INIT.latest_build_tool(sdk, "lib/d8.jar").parent.parent.name, "36.0.0")

    def test_windows_initializer_paths_and_existing_output_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            apk = base / "app ' $(literal).apk"
            apk.write_bytes(b"fixture")
            sdk = base / "SDK with spaces"
            (sdk / "build-tools/36.0.0").mkdir(parents=True)
            aapt = sdk / "build-tools/36.0.0/aapt2.exe"
            aapt.touch()
            venv_python = base / "skill/tools-env/.venv/Scripts/python.exe"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            output = base / "existing run"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("existing evidence", encoding="utf-8")
            result = subprocess.CompletedProcess([], 0, "package: name='org.example.fixture'\n", "")
            with patch.object(INIT.subprocess, "run", return_value=result) as probe, patch.object(INIT.shutil, "which", return_value=None):
                state = INIT.initialize(apk, output, skill_root=base / "skill", environ={"ANDROID_SDK_ROOT": str(sdk)}, platform_name="win32")
            values = state["variables"]
            self.assertEqual(values["VENV_PY"], str(venv_python))
            self.assertEqual(values["ADB_BIN"], str(sdk / "platform-tools/adb.exe"))
            self.assertEqual(values["PKG"], "org.example.fixture")
            self.assertEqual(probe.call_args.args[0], [str(aapt), "dump", "badging", str(apk)])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing evidence")
            self.assertNotEqual(Path(values["OUT"]), output)
            persisted = json.loads(Path(state["env_json"]).read_text(encoding="utf-8"))
            self.assertEqual(persisted["variables"], values)
            self.assertIn("run_to()", Path(state["env_sh"]).read_text(encoding="utf-8"))

    def test_state_reload_preserves_output_and_expired_deadline_without_probes(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            apk = base / "fixture.apk"
            apk.write_bytes(b"fixture")
            with patch.object(INIT.subprocess, "run", side_effect=FileNotFoundError), patch.object(INIT.shutil, "which", return_value=None):
                created = INIT.initialize(apk, base / "run", skill_root=ROOT, environ={})
            path = Path(created["env_json"])
            saved = json.loads(path.read_text(encoding="utf-8"))
            saved["variables"]["RE_PIPELINE_DEADLINE"] = "1"
            path.write_text(json.dumps(saved), encoding="utf-8")
            before = {str(p): p.read_bytes() for p in base.rglob("*") if p.is_file()}
            with patch.object(INIT.time, "monotonic", side_effect=AssertionError("deadline reset")), patch.object(INIT.subprocess, "run") as command:
                loaded = INIT.load_state(path)
            command.assert_not_called()
            self.assertEqual(loaded["variables"], saved["variables"])
            self.assertEqual(before, {str(p): p.read_bytes() for p in base.rglob("*") if p.is_file()})

    def test_state_rejects_unknown_system_variables_duplicates_and_nonfinite_deadlines(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            apk = base / "fixture.apk"
            apk.write_bytes(b"fixture")
            with patch.object(INIT.subprocess, "run", side_effect=FileNotFoundError), patch.object(INIT.shutil, "which", return_value=None):
                created = INIT.initialize(apk, base / "run", skill_root=ROOT, environ={})
            path = Path(created["env_json"])
            original = json.loads(path.read_text(encoding="utf-8"))
            for key, value in (("HOME", "/unexpected"), ("RE_PIPELINE_DEADLINE", "nan"), ("OUT", "relative/path")):
                payload = json.loads(json.dumps(original))
                payload["variables"][key] = value
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError, msg=key):
                    INIT.load_state(path)
            path.write_text('{"version": 1, "version": 1, "variables": {}}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                INIT.load_state(path)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "POSIX Bash-entry smoke; native Windows is covered by shared-state mocks")
    def test_bash_initializer_preserves_quoted_paths_and_device_arguments(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            apk = base / "app ' $(literal).apk"
            apk.write_bytes(b"fixture")
            output = base / "run ' with spaces"
            sdk = base / "sdk"
            aapt = sdk / "build-tools/36.0.0/aapt2"
            aapt.parent.mkdir(parents=True)
            aapt.write_text("#!/bin/sh\nprintf \"package: name='org.example.fixture'\\n\"\n", encoding="utf-8")
            aapt.chmod(0o700)
            script = ('source "$1" "$2" --output "$3" || exit $?; '
                      'run_to 5 "$RE_PYTHON" -c '
                      "'import json,os,sys; print(json.dumps([sys.argv[1:],os.environ.get(\"MSYS_NO_PATHCONV\"),os.environ.get(\"MSYS2_ARG_CONV_EXCL\")]))' "
                      '"$APK" "$OUT" /data/local/tmp/re_probe')
            env = {**os.environ, "ANDROID_SDK_ROOT": str(sdk), "RE_PYTHON": Path(sys.executable).as_posix()}
            result = subprocess.run([shutil.which("bash"), "-c", script, "helper-test", (ROOT / "pipeline/init_pipeline.sh").as_posix(), apk.as_posix(), output.as_posix()],
                                    capture_output=True, text=True, encoding="utf-8", env=env, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            received = json.loads(result.stdout)
            self.assertEqual([Path(value).resolve() for value in received[0][:2]], [apk, output])
            self.assertEqual(received[0][2], "/data/local/tmp/re_probe")
            self.assertEqual(received[1:], ["1", "*"])

    def test_validator_does_not_require_bash_for_python_library(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for route in VALIDATOR.REQUIRED_ENTRY_ROUTES:
                path = root / route
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Fixture\n", encoding="utf-8")
            (root / "optional.sh").write_text("#!/bin/bash\ntrue\n", encoding="utf-8")
            entry = "---\nname: re\ndescription: >-\n  Reverse engineering of supported assets.\n---\n"
            entry += "\n".join(f"[route]({route})" for route in VALIDATOR.REQUIRED_ENTRY_ROUTES)
            (root / "SKILL.md").write_text(entry, encoding="utf-8")
            with patch.object(VALIDATOR.shutil, "which", return_value=None), patch.object(VALIDATOR.subprocess, "run") as command:
                result = VALIDATOR.validate(root)
            self.assertTrue(result["passed"], result["errors"])
            self.assertEqual(result["stats"]["shell_files_unchecked"], 1)
            self.assertEqual(result["stats"]["shell_files"], 1)
            self.assertTrue(result["warnings"])
            command.assert_not_called()
            with patch.object(VALIDATOR.shutil, "which", return_value="C:/Git/bin/bash.exe"), \
                    patch.object(VALIDATOR.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as syntax:
                self.assertTrue(VALIDATOR.validate(root)["passed"])
            self.assertEqual(syntax.call_args.args[0], ["C:/Git/bin/bash.exe", "-n", "optional.sh"])
            self.assertEqual(syntax.call_args.kwargs["cwd"], root.resolve())

    def test_shared_markdown_routes_resolve_references_html_and_ignore_code(self):
        parser = load("helper_markdown_routes", "scripts/markdown_routes.py")
        text = ("[Full][Guide]\n[Guide][]\n[Guide]\n![Picture][image]\n"
                "[Guide]: docs/runner.md \"Guide\"\n[image]: assets/hero.svg\n"
                "<a href=\"docs/runner.md\">Guide</a><img src=\"assets/hero.svg\">\n"
                "`[hidden](missing-inline.md) <img src=\"missing-inline.svg\">`\n"
                "```md\n[hidden](missing-fence.md)\n<img src=\"missing-fence.svg\">\n```\n"
                "<!-- [hidden](missing-comment.md) -->\n")
        routes = parser.extract_routes(text)
        self.assertEqual(routes[:4], [(1, "docs/runner.md"), (2, "docs/runner.md"), (3, "docs/runner.md"), (4, "assets/hero.svg")])
        self.assertIn((7, "assets/hero.svg"), routes)
        self.assertFalse(any("missing-" in target for _, target in routes))

    def test_structural_validator_detects_broken_reference_and_html_assets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for route in VALIDATOR.REQUIRED_ENTRY_ROUTES:
                path = root / route
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Fixture\n", encoding="utf-8")
            entry = "---\nname: re\ndescription: >-\n  Reverse engineering of supported assets.\n---\n"
            entry += "\n".join(f"[route]({route})" for route in VALIDATOR.REQUIRED_ENTRY_ROUTES)
            (root / "SKILL.md").write_text(entry, encoding="utf-8")
            (root / "assets").mkdir()
            (root / "assets/hero.svg").write_text("<svg/>", encoding="utf-8")
            page = root / "README.md"
            valid = '[Guide][id]\n[id]: docs/runner.md\n<img src="assets/hero.svg">\n'
            page.write_text(valid, encoding="utf-8")
            self.assertTrue(VALIDATOR.validate(root)["passed"])
            for text, missing in ((valid.replace("docs/runner.md", "docs/missing.md"), "docs/missing.md"),
                                  (valid.replace("assets/hero.svg", "assets/missing.svg"), "assets/missing.svg")):
                page.write_text(text, encoding="utf-8")
                result = VALIDATOR.validate(root)
                self.assertFalse(result["passed"])
                self.assertTrue(any("missing link " + missing in error for error in result["errors"]))

    def test_validator_json_handles_unicode_root_when_stdout_locale_is_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "audit-π"
            directory.mkdir()
            result = subprocess.run([sys.executable, str(ROOT / "scripts/validate_library.py"), str(directory), "--json"],
                                    capture_output=True, env={**os.environ, "PYTHONIOENCODING": "cp1252:strict"}, timeout=5)
            self.assertEqual(result.returncode, 1)  # The empty fixture is structurally invalid.
            self.assertEqual(json.loads(result.stdout.decode("utf-8"))["root"], str(directory.resolve()))

    def test_digest_filters_caches_and_uses_stable_posix_relative_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, data in {"src/a.py": b"a", "tests/b.py": b"b", "examples/input.json": b"{}",
                              "src/__pycache__/ignored.pyc": b"cache", "pyproject.toml": b"project", "uv.lock": b"lock"}.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            value, count = DIGEST.digest(root)
            expected = hashlib.sha256()
            for rel in ["examples/input.json", "pyproject.toml", "src/a.py", "tests/b.py", "uv.lock"]:
                expected.update(rel.encode() + b"\0" + hashlib.sha256((root / rel).read_bytes()).hexdigest().encode() + b"\n")
            self.assertEqual((value, count), (expected.hexdigest(), 5))

    def test_trace_reader_uses_utf8_under_legacy_windows_locale(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            path.write_text(json.dumps({"type": "call", "from": "source", "to": "module!π", "depth": 1}, ensure_ascii=False) + "\n", encoding="utf-8")
            original_open = open

            def legacy_open(*args, **kwargs):
                kwargs.setdefault("encoding", "cp1252")
                return original_open(*args, **kwargs)

            stdout = io.StringIO()
            with patch("builtins.open", side_effect=legacy_open), patch.object(sys, "argv", ["calltree", str(path)]), contextlib.redirect_stdout(stdout):
                CALLTREE.main()
            self.assertIn("module!π", stdout.getvalue())
            result = subprocess.run([sys.executable, str(ROOT / "techniques/13-trace/scripts/calltree.py"), str(path)],
                                    capture_output=True, env={**os.environ, "PYTHONIOENCODING": "cp1252:strict"}, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("module!π", result.stdout.decode("utf-8"))

    @unittest.skipUnless(os.name == "posix", "Native POSIX process cleanup; Windows uses a separate behavior mock")
    def test_timeout_cli_reaps_its_real_owned_child(self):
        with tempfile.TemporaryDirectory() as td:
            pidfile = Path(td) / "child.pid"
            child = "import os,sys,time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(10)"
            completed = subprocess.run([sys.executable, str(ROOT / "pipeline/run_with_timeout.py"), "0.5", sys.executable, "-c", child, str(pidfile)],
                                       capture_output=True, text=True, timeout=5)
            self.assertEqual(completed.returncode, 124, completed.stderr)
            self.assertTrue(pidfile.is_file())
            pid = int(pidfile.read_text())
            try:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
            finally:
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass

    def test_windows_timeout_kills_only_the_created_pid_tree_and_reaps(self):
        process = Mock(pid=424242)
        process.wait.side_effect = [subprocess.TimeoutExpired(["fixture"], 1), 0]
        process.poll.return_value = None
        with patch.object(TIMEOUT.os, "name", "nt"), patch.object(TIMEOUT.subprocess, "Popen", return_value=process) as spawn, \
                patch.object(TIMEOUT.subprocess, "run") as command, contextlib.redirect_stderr(io.StringIO()):
            result = TIMEOUT.main(["1", "fixture.exe", "argument with spaces"])
        self.assertEqual(result, 124)
        self.assertFalse(spawn.call_args.kwargs["start_new_session"])
        self.assertEqual(command.call_args.args[0], ["taskkill", "/PID", "424242", "/T", "/F"])
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_macos_syscall_helper_rejects_windows_before_import_or_spawn(self):
        module = load("helper_syscall_sim", "techniques/13-trace/scripts/syscall_sim.py")
        stderr = io.StringIO()
        with patch.object(sys, "platform", "win32"), patch.object(sys, "argv", ["syscall_sim", "fixture.exe"]), \
                patch.object(module.subprocess, "Popen") as spawn, contextlib.redirect_stderr(stderr):
            self.assertEqual(module.main(), 2)
        spawn.assert_not_called()
        self.assertIn("requires macOS", stderr.getvalue())

    def test_windows_batch_launcher_is_rejected_before_asset_argument_interpretation(self):
        stderr = io.StringIO()
        with patch.object(TIMEOUT.os, "name", "nt"), patch.object(TIMEOUT.shutil, "which", return_value=r"C:\Program Files\jadx\bin\jadx.bat"), \
                patch.object(TIMEOUT.subprocess, "Popen") as spawn, contextlib.redirect_stderr(stderr):
            code = TIMEOUT.main(["5", "jadx", "C:/lab/a&b%NAME%!x.apk"])
        self.assertEqual(code, 126)
        spawn.assert_not_called()
        self.assertIn("native executable or Java", stderr.getvalue())

    @unittest.skipUnless(os.name == "posix", "POSIX signal cleanup; Windows tree cleanup has a separate behavior mock")
    def test_keyboard_interrupt_also_cleans_up_owned_child(self):
        process = Mock(pid=424242)
        process.wait.side_effect = [KeyboardInterrupt(), 0]
        with patch.object(TIMEOUT.subprocess, "Popen", return_value=process), patch.object(TIMEOUT.os, "killpg") as terminate, contextlib.redirect_stderr(io.StringIO()):
            result = TIMEOUT.main(["1", "fixture"])
        self.assertEqual(result, 130)
        terminate.assert_called_once_with(424242, TIMEOUT.signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)

    def test_local_service_readiness_does_not_block_on_silent_pipe(self):
        harness = load("helper_local_acceptance", "tools/run_local_acceptance.py")
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                harness.wait_ready(process, timeout=0.05)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            process.terminate()
            process.wait(timeout=3)
            process.stdout.close()

    def test_round3_oracle_keeps_extracted_evidence_without_installed_tools(self):
        tool = load("helper_round3", "tools/run_round3_verification.py")
        from re_runner.contracts import BUDGET_DEFAULTS

        def extractor(sample, destination, budget, executable=None):
            if budget.limits["max_tool_output_bytes"] < BUDGET_DEFAULTS["max_tool_output_bytes"]:
                return {"status": "failed", "extraction_started": False, "listing_complete": False}
            destination.mkdir(parents=True)
            (destination / "secret.key").write_bytes(b"synthetic evidence")
            return {"status": "succeeded", "files": 2, "extraction_started": True, "links_omitted": 0}

        with tempfile.TemporaryDirectory() as td, patch.object(tool, "BASE", Path(td)), patch.object(tool, "SEVENZIP", "configured-7z"), \
                patch.object(tool, "make_test_containers", return_value=Path(td) / "fixture.sqfs"), \
                patch("re_runner.extractors.sevenzip_extract", side_effect=extractor), contextlib.redirect_stdout(io.StringIO()):
            tool.r2_extractor()
            evidence = Path(td) / "r2-extractor/run-squashfs/rootfs-7z/secret.key"
            self.assertEqual(evidence.read_bytes(), b"synthetic evidence")
            self.assertFalse(tool.FAILURES, tool.FAILURES)
            self.assertTrue(json.loads((Path(td) / "r2-extractor/squashfs-tree.json").read_text(encoding="utf-8")))

    def test_legacy_timestamp_format_is_supported_by_windows_strftime(self):
        actual_strftime = time.strftime

        def windows_strftime(fmt, *args):
            if "%F" in fmt or "%T" in fmt:
                raise ValueError("Unsupported Windows format directive")
            return actual_strftime(fmt, *args)

        for name, relative in (("hunter", "cve-hunter/hunter.py"), ("firmware", "fw-discover/fw.py")):
            module = load("helper_" + name, relative)
            with tempfile.TemporaryDirectory() as td:
                directory = Path(td)
                logfile = directory / "run.log"
                with patch.object(module, "DATA", directory), patch.object(module, "LOG", logfile), \
                        patch.object(module.time, "strftime", side_effect=windows_strftime):
                    module.log("offline fixture")
                self.assertRegex(logfile.read_text(encoding="utf-8"), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} offline fixture")

    def test_legacy_lock_windows_byte_lock_preserves_lock_inode(self):
        safety = load("helper_legacy_safety", "fw-discover/_legacy_safety.py")
        locking = Mock()
        msvcrt = types.SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=locking)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "legacy.lock"
            lock = safety.KernelLock(path)
            with patch.object(safety.os, "name", "nt"), patch.dict(sys.modules, {"msvcrt": msvcrt}):
                self.assertTrue(lock.acquire())
                lock.release()
            self.assertTrue(path.is_file())
            self.assertEqual([call.args[1:] for call in locking.call_args_list], [(2, 1), (0, 1)])


if __name__ == "__main__":
    unittest.main()
