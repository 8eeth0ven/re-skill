"""Round-3 (R1/R2/R3) dedicated evidence runs with persistent, re-verifiable output.

Produces, under re-runs/r1r2r3-verification/:
  r3-redaction/   run_command settlement + reader-boundary canary oracle (R3)
  r2-extractor/   real 7z squashfs (regular-file fixture) + cpio extract runs, plus
                  refusal evidence for flooded/truncated listings (R2)
  r1-cancel/      real Runner run cancelled with an un-enumerable (linked) output tree,
                  then resumed; state.json/report + journal identities recorded (R1)

Every assertion prints PASS/FAIL. Exit 1 means failed assertions; exit 2 means
missing required tools or an unexecuted link-anomaly oracle (Windows may need
Developer Mode/symlink privilege). No environment gap is reported as ALL PASS.
Run: uv run --no-sync python tools/run_round3_verification.py
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
BASE = REPO / "re-runs" / "r1r2r3-verification"
SEVENZIP = os.environ.get("RE_RUN_7Z") or shutil.which("7z") or shutil.which("7zz")
MKSQUASHFS = os.environ.get("RE_RUN_MKSQUASHFS") or shutil.which("mksquashfs")
SKIPPED = []
FAILURES = []


def check(label, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" + (f" :: {detail}" if detail else ""))
    if not condition:
        FAILURES.append(label)


def save(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def r3_redaction():
    out = BASE / "r3-redaction"
    out.mkdir(parents=True, exist_ok=True)
    canary = "MIIEowRound3CanaryPrivateKeyBody123456"
    script = (
        "import sys\n"
        "sys.stdout.write('header line\\n')\n"
        "sys.stdout.write('-----BEGIN RSA PRIVATE KEY-----\\n')\n"
        f"sys.stdout.write('{canary}\\n')\n"
        "sys.stdout.write('A' * 65536)\n"  # END marker never sent: reader cut leaves an unclosed PEM
    )
    from re_runner.contracts import BUDGET_DEFAULTS
    from re_runner.execution import run_command
    from re_runner.safety import Budget

    budget = Budget({**BUDGET_DEFAULTS, "max_tool_output_bytes": 8192, "tool_timeout_seconds": 30})
    execution = run_command(
        [sys.executable, "-c", script], out, budget, timeout=30,
        stdout_path=out / "stdout.log", stderr_path=out / "stderr.log")
    surfaces = {
        "execution.stdout": execution.stdout,
        "stdout.log": (out / "stdout.log").read_text(encoding="utf-8"),
        "stderr.log": (out / "stderr.log").read_text(encoding="utf-8"),
    }
    save(out / "r3-oracle.json", {
        "canary": canary, "status": execution.status,
        "canary_absent": {name: canary not in text for name, text in surfaces.items()},
        "begin_header_absent": {name: "-----BEGIN RSA PRIVATE KEY-----" not in text for name, text in surfaces.items()},
        "conservative_marker_present": {name: "[REDACTED PRIVATE KEY]" in text for name, text in surfaces.items()},
    })
    for name, text in surfaces.items():
        check(f"R3 canary absent from {name}", canary not in text)
        check(f"R3 BEGIN header absent from {name}", "-----BEGIN RSA PRIVATE KEY-----" not in text)
        if text:  # an empty stderr has nothing to leak; the marker check needs content
            check(f"R3 conservative marker in {name}", "[REDACTED PRIVATE KEY]" in text)
    adapter = {"argv": ["python -c ..."], "status": execution.status, "stdout": execution.stdout, "stderr": execution.stderr}
    from re_runner.safety import redact
    adapter_redacted = redact(adapter)
    save(out / "r3-adapter-json.json", adapter_redacted)
    check("R3 canary absent from adapter JSON", canary not in json.dumps(adapter_redacted))


def make_test_containers(out: Path):
    tree = out / "sq-root"
    (tree / "etc").mkdir(parents=True, exist_ok=True)
    (tree / "etc" / "banner.conf").write_bytes(b"banner=round3-squashfs\n")
    (tree / "secret.key").write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nROUND3CANARY\n-----END RSA PRIVATE KEY-----\n")
    image = out / "round3.sqfs"
    subprocess.run([MKSQUASHFS, str(tree), str(image), "-no-progress", "-quiet",
                    "-all-root", "-comp", "gzip"], check=True, capture_output=True)
    return image


def r2_extractor():
    from re_runner.contracts import BUDGET_DEFAULTS
    from re_runner.extractors import sevenzip_extract
    from re_runner.safety import Budget

    out = BASE / "r2-extractor"
    out.mkdir(parents=True, exist_ok=True)
    image = make_test_containers(out)

    def fresh(name):
        work = out / name
        if work.exists():
            import shutil
            shutil.rmtree(work)
        work.mkdir(parents=True)
        return work

    budget = Budget(dict(BUDGET_DEFAULTS))
    squashfs_work = fresh("run-squashfs")
    result = sevenzip_extract(image, squashfs_work / "rootfs-7z", budget, executable=SEVENZIP)
    save(out / "squashfs-extract-result.json", result)
    # Accept a complete tree or an explicitly degraded extraction with omissions.
    # The locally generated sample has regular files and requires no link privilege.
    check("R2 squashfs extract succeeded-or-degraded-with-omissions",
          result and result["status"] in ("succeeded", "degraded") and
          (result["status"] == "succeeded" or result.get("links_omitted", 0) > 0),
          f"status={result and result.get('status')} omitted={result and result.get('links_omitted')} err={result and result.get('error')}")
    check("R2 squashfs extraction_started", bool(result and result["extraction_started"]))
    check("R2 squashfs files > 0", bool(result and result["files"] > 0), str(result and result.get("files")))
    link = squashfs_work / "rootfs-7z" / "secret.key"
    check("R2 extracted evidence survives oracle inspection", link.is_file())
    # Inspect the existing result; never recreate/clear the evidence directory here.
    check("R2 no symlink in extracted tree", not link.is_symlink() if link.exists() else True)
    scan = [(p.relative_to(out / "run-squashfs" / "rootfs-7z").as_posix(), p.is_symlink())
            for p in (out / "run-squashfs" / "rootfs-7z").rglob("*")]
    save(out / "squashfs-tree.json", scan)
    check("R2 tree has zero symlinks", not any(is_link for _, is_link in scan))

    # Listing-flood refusal: tiny output cap makes the member listing incomplete.
    flood_work = fresh("run-refusal-flood")
    result = sevenzip_extract(image, flood_work / "rootfs-7z",
                              Budget({**BUDGET_DEFAULTS, "max_tool_output_bytes": 512}), executable=SEVENZIP)
    save(out / "flood-refusal-result.json", result)
    check("R2 flooded listing refuses extraction", result and result["status"] == "failed" and not result["extraction_started"])
    check("R2 flooded listing marks listing_complete False", result and result["listing_complete"] is False)

    cpio = out / "round3.cpio"

    def cpio_bytes(files):
        def header(name, size):
            values = [0, 0o100644, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name) + 1, 0]
            return b"070701" + "".join("%08X" % value for value in values).encode()
        data = bytearray()
        for name, content in files.items():
            raw = name.encode()
            data += header(name, len(content)) + raw + b"\x00"
            data += b"\x00" * ((4 - ((110 + len(raw) + 1) % 4)) % 4)
            data += content
            data += b"\x00" * ((4 - (len(content) % 4)) % 4)
        data += header("TRAILER!!!", 0) + b"TRAILER!!!\x00"
        data += b"\x00" * ((4 - ((110 + 11) % 4)) % 4)
        return bytes(data)

    cpio.write_bytes(cpio_bytes({"etc/a.conf": b"a=b\n", "var/b.conf": b"b=c\n"}))
    result = sevenzip_extract(cpio, fresh("run-cpio") / "rootfs-7z", Budget(dict(BUDGET_DEFAULTS)), executable=SEVENZIP)
    save(out / "cpio-extract-result.json", result)
    check("R2 cpio extract succeeded", result and result["status"] == "succeeded" and result["files"] == 2)
    return image


def r1_cancel(image: Path):
    from re_runner.models import AssetRequest
    from re_runner.runner import Runner
    from re_runner.safety import load_json
    from re_runner.scope import ScopePolicy

    out = BASE / "r1-cancel"
    out.mkdir(parents=True, exist_ok=True)
    # A firmware tar whose worker writes files gradually, like the R1 tests.
    tar = out / "fixture.tar"
    with tarfile.open(tar, "w") as archive:
        for index in range(40):
            data = f"component-{index} configuration=fixture-{index}\n".encode()
            info = tarfile.TarInfo(f"etc/file-{index:04d}.conf")
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            archive.addfile(info, io.BytesIO(data))
    # This specific R1 oracle needs a link anomaly; ordinary Windows users may
    # lack symlink privilege. Record it as unexecuted rather than claiming a pass.
    probe_link = out / "link-capability-probe"
    try:
        probe_link.symlink_to(tar)
        probe_link.unlink()
    except OSError as exc:
        SKIPPED.append("R1 link-anomaly oracle requires symlink capability")
        save(out / "requires-environment.json", {"status": "requires-environment", "reason": str(exc)})
        return
    runner = Runner.new(BASE / "runs", [AssetRequest(str(tar))], ScopePolicy(), "triage", "en")
    cancel_path = runner.root / "cancel.request"
    attempt_dir = runner.root / "work" / "asset-001" / "attempt-1"

    def cancelling_run_command(argv, cwd, budget, **kwargs):
        from re_runner.execution import run_command as real
        def watch():
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                root = attempt_dir / "rootfs"
                if root.exists() and any(root.rglob("*")):
                    break
                threading.Event().wait(0.002)
            cancel_path.write_text("cancel", encoding="utf-8")
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        try:
            result = real(argv, cwd, budget, **kwargs)
            # Plant a link AFTER the worker dies: the output tree becomes
            # un-enumerable exactly like a hostile artifact set.
            root = attempt_dir / "rootfs"
            if root.exists():
                try:
                    (root / "late.link").symlink_to(tar)
                except OSError:
                    pass
            return result
        finally:
            thread.join()

    with patch_sleep_fast(), patch("re_runner.runner.run_command", cancelling_run_command):
        state = runner.execute()
    save(out / "cancelled-state.json", state)
    profile = [item for item in state["tool_runs"] if item["tool"] == "profile:firmware"]
    check("R1 cancelled run keeps the profile ToolRun", len(profile) == 1)
    check("R1 cancelled ToolRun explains the incomplete artifact list",
          bool(profile) and profile[0].get("error") is not None and "incomplete" in profile[0]["error"])
    entry = state["assets"]["asset-001"]
    check("R1 cancelled attempt is accounted", bool(entry.get("active_attempt_accounted")))
    check("R1 run status cancelled", state["status"] == "cancelled")
    used_before = dict(state["used"])
    runner2 = Runner.resume(runner.root)
    state2 = runner2.execute()
    save(out / "resumed-state.json", state2)
    check("R1 resume succeeds", state2["status"] == "succeeded", str(state2.get("errors")))
    total_files = 1
    for journal in attempt_dir.parent.glob("attempt-*/usage.json"):
        total_files += load_json(journal, max_bytes=65536).get("files", 0)
    check("R1 resume never double-counts (used.files == intake + sum(journals))",
          state2["used"]["files"] == total_files, f"used={state2['used']['files']} expected={total_files}")
    check("R1 cancelled journal was settled before resume", used_before["files"] >= 2, str(used_before))
    save(out / "usage-identity.json", {
        "used_before_cancel": used_before, "used_after_resume": state2["used"],
        "sum_journals_plus_intake": total_files})


def patch_sleep_fast():
    import unittest.mock as mock
    return mock.patch("re_runner.execution.time.sleep", lambda seconds: threading.Event().wait(0.001))


def main():
    import unittest.mock as mock
    missing = [name for name, executable in (("7z (RE_RUN_7Z)", SEVENZIP),
                                             ("mksquashfs (RE_RUN_MKSQUASHFS)", MKSQUASHFS))
               if not executable]
    if missing:
        print("BLOCKED: configure required local tools: " + ", ".join(missing), file=sys.stderr)
        return 2
    with mock.patch.dict(os.environ, {"RE_RUN_7Z": SEVENZIP}):
        r3_redaction()
        image = r2_extractor()
        r1_cancel(image)
    if FAILURES:
        print("\nFAILURES: " + "; ".join(FAILURES))
        return 1
    if SKIPPED:
        print("\nINCOMPLETE: " + "; ".join(SKIPPED))
        return 2
    print("\nALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
