#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pipeline branch environment check (cross-platform edition, runnable standalone)

- Platforms: macOS / Linux / Windows (sys.platform = darwin/linux/win32)
- Usage: python3 env_check.py   (report on stdout; recommended: > env_report.txt 2>&1)
- Exit code: 0 = all green  1 = has yellows / non-critical reds (the chain degrades and continues)  2 = critical red (key items like jadx+apktool missing; decompilation degrades)
- Detection items match env_check.sh (the macOS bash edition); adds ropper/frida-tools detection per setup.md §3
- Internal timeouts use subprocess(timeout=), no dependence on GNU timeout, identical on all three platforms
- Verification status: historical macOS execution; current portability edits have offline coverage. Linux/Windows are **not verified on real machines**.
"""
import datetime
import glob
import os
import shutil
import socket
import subprocess
import sys

from init_pipeline import latest_build_tool, sdk_directory

# The Windows console defaults to GBK; avoid UnicodeEncodeError on non-ASCII/table characters
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
PLATFORM_TAG = {"darwin": "macOS (historical machine checks; current readiness is probed below)", "win32": "Windows (not verified on a real machine)"}.get(
    sys.platform, "Linux (not verified on a real machine)")

VER_TIMEOUT = 10
LONG_TIMEOUT = 120  # jadx/apktool smoke test

# ---------- counters and table output (format aligned with env_check.sh) ----------
OK_N = WARN_N = FAIL_N = CRIT_N = 0
ROW_LOG = []


def _row(name, state, detail):
    print("| %-26s | %-5s | %s" % (name, state, detail))


def ok(name, detail):
    global OK_N
    OK_N += 1
    _row(name, "OK", detail)
    ROW_LOG.append("%s=OK" % name)


def warn(name, detail):
    global WARN_N
    WARN_N += 1
    _row(name, "WARN", detail)
    ROW_LOG.append("%s=WARN(%s)" % (name, detail))


def fail(name, detail):
    global FAIL_N
    FAIL_N += 1
    _row(name, "FAIL", detail)
    ROW_LOG.append("%s=FAIL(%s)" % (name, detail))


def crit(name, detail):
    global CRIT_N
    CRIT_N += 1
    _row(name, "FAIL*", detail + "  [critical]")
    ROW_LOG.append("%s=CRIT(%s)" % (name, detail))


def info(name, detail):
    _row(name, "INFO", detail)


def head(title):
    print()
    print(title)
    print("| item | state | detail |")
    print("|----|------|------|")


# ---------- generic probing ----------
def run(cmd, timeout=VER_TIMEOUT):
    """Run a command and return the CompletedProcess; None on timeout/start failure (rc semantics: probe failed)"""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def ver_line(cmd, timeout=VER_TIMEOUT):
    """First version line (first non-empty line after merging stdout+stderr, truncated to 60 chars)"""
    r = run(cmd, timeout)
    if r is None:
        return ""
    lines = (r.stdout or "") .splitlines() + (r.stderr or "").splitlines()
    for ln in lines:
        ln = ln.strip()
        if ln:
            return ln[:60]
    return ""


def first_exist(paths):
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


# ---------- platform-dependent paths ----------
USER_HOME = os.path.expanduser("~")
SDK_DIR = str(sdk_directory())

# Skill root: this script lives under <skill_root>/pipeline/, no hardcoded absolute paths
SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_ROOT = os.path.join(SKILL_ROOT, "tools-env", ".venv")
# venv python: win=Scripts\python.exe posix=bin/python, auto-pick whichever exists
VENV_PY = first_exist([
    os.path.join(VENV_ROOT, "Scripts", "python.exe"),   # Windows
    os.path.join(VENV_ROOT, "bin", "python"),           # macOS/Linux
])

print("=" * 62)
print(" pipeline branch environment check  @ %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print(" host: %s | python: %s" % (sys.platform, sys.version.split()[0]))
print(" platform branch: %s" % PLATFORM_TAG)
print("=" * 62)

# ---------- 1. command-line tools (which + version) ----------
head("## 1. Command-line tools")

for tool, vercmd in (("jadx", ["jadx", "--version"]),
                     ("apktool", ["apktool", "--version"]),
                     ("java", ["java", "-version"])):
    p = shutil.which(tool)
    if p:
        ok(tool, "%s (%s)" % (ver_line(vercmd) or p, p))
    else:
        hint = "brew install %s" % tool if not IS_WIN else \
            "see setup.md §2 (winget/scoop)"
        crit(tool, "not installed: %s" % hint)

# adb: PATH first, then the SDK platform-tools
adb_bin = shutil.which("adb") or first_exist(
    [os.path.join(SDK_DIR, "platform-tools", "adb.exe" if IS_WIN else "adb")])
if adb_bin:
    ok("adb", "%s (%s)" % (ver_line([adb_bin, "version"]) or adb_bin, adb_bin))
else:
    warn("adb", "not found (S3 dynamic degrades; SDK: %s)" % SDK_DIR)

# aapt2: scan SDK build-tools for the highest version
aapt2_tool = latest_build_tool(SDK_DIR, "aapt2.exe" if IS_WIN else "aapt2")
aapt2_bin = str(aapt2_tool) if aapt2_tool else None
if aapt2_bin:
    ok("aapt2(SDK)", "%s (%s)" % (ver_line([aapt2_bin, "version"]) or aapt2_bin,
                                  aapt2_bin))
else:
    warn("aapt2(SDK)", "SDK build-tools not found (S1-C degrades: PKG falls back to the file name)")

# Ordinary tool group: radare2 / 7z / node / uv / unzip / hashing / nm / curl
def check_tool(name, vercmd=None, warnmsg="not installed (non-critical, degrade as needed)"):
    p = shutil.which(name)
    if p:
        d = ver_line(vercmd) if vercmd else ""
        ok(name, (d or p)[:60])
    else:
        warn(name, warnmsg)

check_tool("radare2", ["radare2", "-v"])
check_tool("7z", ["7z"])
check_tool("node", ["node", "-v"])
check_tool("uv", ["uv", "--version"])
check_tool("unzip", None,
           "not installed (non-critical; A-1 can degrade to 7z or python zipfile)")
# Hashing tools (for the S4 report's SHA256): mac=shasum linux=sha256sum win=certutil
if IS_WIN:
    ok("sha256 tool", "certutil (ships in System32): certutil -hashfile <f> SHA256")
elif IS_MAC:
    check_tool("shasum", ["shasum", "-v"], "not installed (S4 degrades: openssl dgst -sha256)")
else:
    check_tool("sha256sum", ["sha256sum", "--version"],
               "not installed (S4 degrades: openssl dgst -sha256)")
check_tool("nm", None,
           "not installed (S2-4 degrades: r2 fallback; Windows usually has no nm, use llvm-nm/dumpbin)")
check_tool("curl")

# GNU timeout: win's System32\timeout.exe is an impostor; only count it if --version mentions GNU
tmo = None
for cand in ("timeout", "gtimeout"):
    p = shutil.which(cand)
    if p:
        v = ver_line([p, "--version"])
        if "GNU" in v or "coreutils" in v:
            tmo = (cand, "%s (%s)" % (v, p))
            break
if tmo:
    ok("timeout(gnu)", tmo[1])
else:
    ok("timeout(gnu)",
       "no GNU timeout (not a problem: the py edition / pipeline run_to both use the subprocess built-in timeout; run long manual bash commands in the background + kill)")

# ---------- 2. tools-env venv and python libs ----------
head("## 2. tools-env venv (%s)" % VENV_ROOT)
if VENV_PY and os.path.isfile(VENV_PY):
    ok("venv python", ver_line([VENV_PY, "--version"]) or VENV_PY)
    # Detection list follows setup.md §3 (adds frida_tools/ropper over the sh edition)
    for mod in ("frida", "frida_tools", "androguard", "unicorn", "capstone",
                "apkid", "apkleaks", "ropper"):
        r = run([VENV_PY, "-c", "import %s" % mod], timeout=30)
        if r is not None and r.returncode == 0:
            v = run([VENV_PY, "-c",
                     "import %s as m;print(getattr(m,'__version__','?'))" % mod],
                    timeout=30)
            ver = (v.stdout or "").strip() if v else "?"
            ok("venv::%s" % mod, "import OK %s" % (ver or "?"))
        else:
            warn("venv::%s" % mod, "cannot import (installing/missing → the matching stage degrades)")
else:
    warn("venv", "missing or not executable (the APKiD/apkleaks/frida lines all degrade; install steps in setup.md §3)")

# ---------- 3. Android SDK / AVD / devices ----------
head("## 3. Android SDK / AVD")
if os.path.isdir(SDK_DIR):
    bts = " ".join(sorted(os.listdir(os.path.join(SDK_DIR, "build-tools")))
                   if os.path.isdir(os.path.join(SDK_DIR, "build-tools")) else [])
    ok("SDK dir", "%s (build-tools: %s)" % (SDK_DIR, bts))
else:
    warn("SDK dir", "%s does not exist (the S3 dynamic stage degrades wholesale)" % SDK_DIR)

emu_bin = first_exist([os.path.join(SDK_DIR, "emulator",
                                    "emulator.exe" if IS_WIN else "emulator")])
if emu_bin:
    ok("emulator", (ver_line([emu_bin, "-version"], timeout=15) or emu_bin)[:50])
else:
    warn("emulator", "SDK emulator not executable")

avd_list = [os.path.splitext(os.path.basename(f))[0]
            for f in glob.glob(os.path.join(USER_HOME, ".android", "avd", "*.ini"))]
if avd_list:
    ok("AVD", " ".join(avd_list))
else:
    fail("AVD", "no AVD (S3 needs android_create_avd or manual creation, see setup.md §4)")

if adb_bin:
    r = run([adb_bin, "devices"], timeout=15)
    n = 0
    if r is not None:
        for ln in (r.stdout or "").splitlines()[1:]:
            if ln.strip().endswith("\tdevice") or ln.strip().endswith("device"):
                n += 1
    if n >= 1:
        ok("adb devices", "%d online" % n)
    else:
        info("adb devices", "0 devices (S3: the android-emulator MCP starts the emulator)")

# ---------- 4. MCP probing (py side can only probe indirectly; the agent must invoke the real MCP) ----------
head("## 4. MCP (indirect probing; the agent must separately invoke the real MCP tools to confirm)")
node_p = shutil.which("node")
if node_p:
    ok("node_repl (indirect)", "node %s online; agent side: verify by calling node_repl js with 1+1"
       % ver_line(["node", "-v"]))

# ida-pro-mcp: defaults to 127.0.0.1:13337, socket liveness probe (more cross-platform than curl)
try:
    with socket.create_connection(("127.0.0.1", 13337), timeout=2):
        ok("ida-pro-mcp (port)", "127.0.0.1:13337 responds; agent side: confirm with check_connection")
except OSError:
    info("ida-pro-mcp (port)", "127.0.0.1:13337 no response (IDA plugin not started → the chain skips it automatically, non-blocking)")

info("android-emulator MCP", "not testable from py; agent side: android_preflight (measured note: once AVD %s is ready, S3 can run)"
     % (" ".join(avd_list) or "none"))
info("fofa MCP", "not testable from py; without FOFA_KEY the chain skips it outright")

# ---------- 5. jadx/apktool small-sample self-check (build a minimal dex → zip → decompile) ----------
head("## 5. Small-sample self-check (build a minimal dex → zip → decompile)")
TMPD = None
SMOKED = False
D8_TOOL = latest_build_tool(SDK_DIR, "lib/d8.jar")
D8_JAR = str(D8_TOOL) if D8_TOOL else None
javac_bin = shutil.which("javac")

if TMPD is None:
    import tempfile
    TMPD = tempfile.mkdtemp(prefix="autore_env.")

try:
    if javac_bin and D8_JAR:
        src = os.path.join(TMPD, "T.java")
        with open(src, "w") as f:
            f.write('public class T { public static void main(String[] a)'
                    '{ System.out.println("autore-smoke"); } }\n')
        # javac compile (60s timeout)
        r1 = run([javac_bin, "-d", TMPD, src], timeout=60)
        # d8 to dex: always via java -cp d8.jar com.android.tools.r8.D8
        # (bypasses the call differences between the posix d8 script / win d8.bat; Windows not verified on a real machine)
        r2 = run([shutil.which("java"), "-cp", D8_JAR,
                  "com.android.tools.r8.D8", os.path.join(TMPD, "T.class"),
                  "--output", TMPD], timeout=60) if shutil.which("java") else None
        dex = os.path.join(TMPD, "classes.dex")
        if r1 is not None and r1.returncode == 0 and r2 is not None \
                and r2.returncode == 0 and os.path.isfile(dex):
            # build the zip: python zipfile (identical on all three platforms, no zip command needed)
            import zipfile
            sample = os.path.join(TMPD, "sample.apk")
            with zipfile.ZipFile(sample, "w") as zf:
                zf.write(dex, "classes.dex")
            SMOKED = os.path.isfile(sample)
    if SMOKED:
        sample = os.path.join(TMPD, "sample.apk")
        # jadx self-check: must decompile the T source file
        if shutil.which("jadx"):
            jout = os.path.join(TMPD, "jadx_smoke")
            shutil.rmtree(jout, ignore_errors=True)
            r = run(["jadx", "-d", jout, sample], timeout=LONG_TIMEOUT)
            found = False
            for _root, _dirs, files in os.walk(jout):
                if "T.java" in files:
                    found = True
                    break
            if found:
                ok("jadx smoke", "minimal dex zip decompiled to T.java")
            else:
                warn("jadx smoke", "rc=%s but no T.java produced (recheck jadx by hand)"
                     % (r.returncode if r else "timeout"))
        # apktool self-check: a structured error on a manifest-less sample = the toolchain (java+jar) is alive
        if shutil.which("apktool"):
            aout = os.path.join(TMPD, "apk_smoke")
            shutil.rmtree(aout, ignore_errors=True)
            r = run(["apktool", "d", "-f", "-o", aout, sample],
                    timeout=LONG_TIMEOUT)
            if r is not None and r.returncode == 0:
                ok("apktool smoke", "rc=0, decoded the minimal sample (no manifest → smali only, toolchain alive)")
            elif r is not None:
                blob = ((r.stdout or "") + (r.stderr or "")).lower()
                if any(k in blob for k in ("androidmanifest", "could not",
                                           "not a valid", "exception")):
                    ok("apktool smoke", "rc=%s and the error is structured (parses the zip and correctly pinpoints the missing manifest = toolchain alive)"
                       % r.returncode)
                else:
                    warn("apktool smoke", "rc=%s with unrecognizable output (recheck apktool by hand)"
                         % r.returncode)
            else:
                warn("apktool smoke", "execution timed out (recheck apktool by hand)")
    else:
        warn("smoke sample", "failed to build a minimal dex (%s/%s) → skipping the smoke test, version probes are authoritative"
             % ("d8-%s" % ("ok" if D8_JAR else "missing"),
                "javac-%s" % ("ok" if javac_bin else "missing")))
finally:
    shutil.rmtree(TMPD, ignore_errors=True)

# ---------- 6. summary and exit code ----------
print()
print("=" * 62)
print("## Summary")
print("green OK=%d  yellow WARN=%d  red FAIL=%d  critical-red FAIL*=%d" % (OK_N, WARN_N, FAIL_N, CRIT_N))
print("-" * 62)
print("\n".join(ROW_LOG))
print("-" * 62)
print("Degradation mapping: venv::* WARN → S1-B/S1-C fall back to signature matching/grep; adb/AVD FAIL → S3 flagged wholesale; no GNU timeout → long commands use run_to (python built-in timeout) or background+kill")
print("EXIT_CODE decision: all green = 0; any yellow or non-critical red = 1; jadx+apktool critical red = 2 (decompilation doubly degrades to unzip+aapt2)")

if CRIT_N > 0:
    EXIT = 2
elif WARN_N + FAIL_N > 0:
    EXIT = 1
else:
    EXIT = 0
print("EXIT_CODE=%d" % EXIT)
sys.exit(EXIT)
