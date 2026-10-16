#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pipeline 分支 环境体检脚本(跨平台版,可独立执行)

- 平台:macOS / Linux / Windows(sys.platform = darwin/linux/win32)
- 用法:python3 env_check.py   (stdout 输出报告;建议 > env_report.txt 2>&1)
- 退出码:0=全绿  1=有黄/非关键红(链路可降级继续)  2=关键红(jadx+apktool 等关键缺项,反编译降级)
- 与 env_check.sh(macOS bash 版)检测项一致;并按 初始化.md §3 补充 ropper/frida-tools 检测
- 内部超时用 subprocess(timeout=),不依赖 GNU timeout,三平台一致
- 验证状态:macOS 实测通过;Linux/Windows 分支同一逻辑编写,**未实机验证**
"""
import datetime
import glob
import os
import shutil
import socket
import subprocess
import sys

# Windows 控制台默认 GBK,防中文/表格符 UnicodeEncodeError
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
PLATFORM_TAG = {"darwin": "macOS(实测)", "win32": "Windows(未实机验证)"}.get(
    sys.platform, "Linux(未实机验证)")

VER_TIMEOUT = 10
LONG_TIMEOUT = 120  # jadx/apktool 冒烟

# ---------- 计数器与表格输出(格式对齐 env_check.sh) ----------
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
    _row(name, "FAIL*", detail + "  [关键项]")
    ROW_LOG.append("%s=CRIT(%s)" % (name, detail))


def info(name, detail):
    _row(name, "INFO", detail)


def head(title):
    print()
    print(title)
    print("| 项 | 状态 | 详情 |")
    print("|----|------|------|")


# ---------- 通用探测 ----------
def run(cmd, timeout=VER_TIMEOUT):
    """跑命令返回 CompletedProcess;超时/启动失败返回 None(rc 语义:探测失败)"""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def ver_line(cmd, timeout=VER_TIMEOUT):
    """版本第一行(stdout+stderr 合并后取第一个非空行,截 60 字符)"""
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


# ---------- 平台相关路径 ----------
HOME = os.path.expanduser("~")
# SDK 根:darwin=~/Library/Android/sdk  linux=~/Android/Sdk  win=%LOCALAPPDATA%\Android\Sdk
if IS_MAC:
    SDK_DIR = os.path.join(HOME, "Library", "Android", "sdk")
elif IS_WIN:
    SDK_DIR = os.path.join(HOME, "AppData", "Local", "Android", "Sdk")
else:
    SDK_DIR = os.path.join(HOME, "Android", "Sdk")

# 本技能根:本脚本在 <skill_root>/pipeline/ 下,不依赖绝对路径硬编码
SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_ROOT = os.path.join(SKILL_ROOT, "tools-env", ".venv")
# venv python:win=Scripts\python.exe posix=bin/python,自动择一
VENV_PY = first_exist([
    os.path.join(VENV_ROOT, "Scripts", "python.exe"),   # Windows
    os.path.join(VENV_ROOT, "bin", "python"),           # macOS/Linux
])

print("=" * 62)
print(" pipeline 分支 环境体检  @ %s" % datetime.datetime.now().strftime("%F %T"))
print(" 主机: %s | python: %s" % (sys.platform, sys.version.split()[0]))
print(" 平台分支: %s" % PLATFORM_TAG)
print("=" * 62)

# ---------- 一、命令行工具(which + version) ----------
head("## 一、命令行工具")

for tool, vercmd in (("jadx", ["jadx", "--version"]),
                     ("apktool", ["apktool", "--version"]),
                     ("java", ["java", "-version"])):
    p = shutil.which(tool)
    if p:
        ok(tool, "%s (%s)" % (ver_line(vercmd) or p, p))
    else:
        hint = "brew install %s" % tool if not IS_WIN else \
            "见 初始化.md §2(winget/scoop)"
        crit(tool, "未安装: %s" % hint)

# adb:PATH 优先,再探 SDK platform-tools
adb_bin = shutil.which("adb") or first_exist(
    [os.path.join(SDK_DIR, "platform-tools", "adb.exe" if IS_WIN else "adb")])
if adb_bin:
    ok("adb", "%s (%s)" % (ver_line([adb_bin, "version"]) or adb_bin, adb_bin))
else:
    warn("adb", "未找到(S3 动态降级;SDK: %s)" % SDK_DIR)

# aapt2:扫 SDK build-tools 取最高版本
aapt2_bin = None
for bt in sorted(glob.glob(os.path.join(SDK_DIR, "build-tools", "*", "aapt2*"))):
    if not bt.endswith(".txt") and os.path.isfile(bt):
        aapt2_bin = bt  # 字典序最后=最高版本
if aapt2_bin:
    ok("aapt2(SDK)", "%s (%s)" % (ver_line([aapt2_bin, "version"]) or aapt2_bin,
                                  aapt2_bin))
else:
    warn("aapt2(SDK)", "SDK build-tools 未找到(S1-C 降级:PKG 用文件名)")

# 普通工具组:radare2 / 7z / node / uv / unzip / 哈希 / nm / curl
def check_tool(name, vercmd=None, warnmsg="未安装(非关键,按需降级)"):
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
           "未安装(非关键;A-1 降级可用 7z 或 python zipfile)")
# 哈希工具(S4 报告 SHA256 用):mac=shasum linux=sha256sum win=certutil
if IS_WIN:
    ok("sha256 工具", "certutil(System32 自带):certutil -hashfile <f> SHA256")
elif IS_MAC:
    check_tool("shasum", ["shasum", "-v"], "未安装(S4 降级:openssl dgst -sha256)")
else:
    check_tool("sha256sum", ["sha256sum", "--version"],
               "未安装(S4 降级:openssl dgst -sha256)")
check_tool("nm", None,
           "未安装(S2-4 降级:r2 兜底;Windows 通常无 nm,用 llvm-nm/dumpbin)")
check_tool("curl")

# GNU timeout:win 的 System32\timeout.exe 是假货,必须验 --version 含 GNU 才算
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
       "无 GNU timeout(不影响:py 版/pipeline run_to 均用 subprocess 内建超时;bash 手工长命令改后台+kill)")

# ---------- 二、tools-env venv 与 python 库 ----------
head("## 二、tools-env venv(%s)" % VENV_ROOT)
if VENV_PY and os.path.isfile(VENV_PY):
    ok("venv python", ver_line([VENV_PY, "--version"]) or VENV_PY)
    # 检测列表以 初始化.md §3 为准(比 sh 版多 frida_tools/ropper)
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
            warn("venv::%s" % mod, "不可 import(在装/未装→对应阶段降级)")
else:
    warn("venv", "不存在或不可执行(APKiD/apkleaks/frida 线全降级;装法见 初始化.md §3)")

# ---------- 三、Android SDK / AVD / 设备 ----------
head("## 三、Android SDK / AVD")
if os.path.isdir(SDK_DIR):
    bts = " ".join(sorted(os.listdir(os.path.join(SDK_DIR, "build-tools")))
                   if os.path.isdir(os.path.join(SDK_DIR, "build-tools")) else [])
    ok("SDK 目录", "%s (build-tools: %s)" % (SDK_DIR, bts))
else:
    warn("SDK 目录", "%s 不存在(S3 动态整段降级)" % SDK_DIR)

emu_bin = first_exist([os.path.join(SDK_DIR, "emulator",
                                    "emulator.exe" if IS_WIN else "emulator")])
if emu_bin:
    ok("emulator", (ver_line([emu_bin, "-version"], timeout=15) or emu_bin)[:50])
else:
    warn("emulator", "SDK emulator 不可执行")

avd_list = [os.path.splitext(os.path.basename(f))[0]
            for f in glob.glob(os.path.join(HOME, ".android", "avd", "*.ini"))]
if avd_list:
    ok("AVD", " ".join(avd_list))
else:
    fail("AVD", "无 AVD(S3 需 android_create_avd 或手动建,见 初始化.md §4)")

if adb_bin:
    r = run([adb_bin, "devices"], timeout=15)
    n = 0
    if r is not None:
        for ln in (r.stdout or "").splitlines()[1:]:
            if ln.strip().endswith("\tdevice") or ln.strip().endswith("device"):
                n += 1
    if n >= 1:
        ok("adb 设备", "%d 台在线" % n)
    else:
        info("adb 设备", "0 台(S3 由 android-emulator MCP 起模拟器)")

# ---------- 四、MCP 探测(py 侧只能间接测;agent 侧需真调 MCP) ----------
head("## 四、MCP(间接探测;agent 须另行真调 MCP 工具确认)")
node_p = shutil.which("node")
if node_p:
    ok("node_repl(间接)", "node %s 在线;agent 侧: node_repl js 调 1+1 验证"
       % ver_line(["node", "-v"]))

# ida-pro-mcp:默认 127.0.0.1:13337,socket 探活(比 curl 更跨平台)
try:
    with socket.create_connection(("127.0.0.1", 13337), timeout=2):
        ok("ida-pro-mcp(端口)", "127.0.0.1:13337 有响应;agent 侧: check_connection 确认")
except OSError:
    info("ida-pro-mcp(端口)", "127.0.0.1:13337 无响应(IDA 未启动插件→链路自动跳过,不阻塞)")

info("android-emulator MCP", "py 侧不可测;agent 侧: android_preflight(实测评:AVD %s 就绪即 S3 可跑)"
     % (" ".join(avd_list) or "无"))
info("fofa MCP", "py 侧不可测;无 FOFA_KEY 时链路直接跳过")

# ---------- 五、jadx/apktool 小样本自验(造最小 dex→zip→反编译) ----------
head("## 五、小样本自验(造最小 dex→zip→反编译)")
TMPD = None
SMOKED = False
D8_JAR = None
for j in sorted(glob.glob(os.path.join(SDK_DIR, "build-tools", "*", "lib",
                                       "d8.jar"))):
    if os.path.isfile(j):
        D8_JAR = j  # 取最高版本
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
        # javac 编译(超时 60s)
        r1 = run([javac_bin, "-d", TMPD, src], timeout=60)
        # d8 转 dex:统一走 java -cp d8.jar com.android.tools.r8.D8
        # (绕开 posix d8 脚本 / win d8.bat 的调用差异,Windows 未实机验证)
        r2 = run([shutil.which("java"), "-cp", D8_JAR,
                  "com.android.tools.r8.D8", os.path.join(TMPD, "T.class"),
                  "--output", TMPD], timeout=60) if shutil.which("java") else None
        dex = os.path.join(TMPD, "classes.dex")
        if r1 is not None and r1.returncode == 0 and r2 is not None \
                and r2.returncode == 0 and os.path.isfile(dex):
            # 造 zip:python zipfile(三平台一致,不依赖 zip 命令)
            import zipfile
            sample = os.path.join(TMPD, "sample.apk")
            with zipfile.ZipFile(sample, "w") as zf:
                zf.write(dex, "classes.dex")
            SMOKED = os.path.isfile(sample)
    if SMOKED:
        sample = os.path.join(TMPD, "sample.apk")
        # jadx 自验:能反编译出 T 源文件
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
                ok("jadx 冒烟", "最小 dex zip 反编译出 T.java")
            else:
                warn("jadx 冒烟", "rc=%s 但未产出 T.java(手工复核 jadx)"
                     % (r.returncode if r else "timeout"))
        # apktool 自验:对无 manifest 样本报结构化错误=工具链(java+jar)活着
        if shutil.which("apktool"):
            aout = os.path.join(TMPD, "apk_smoke")
            shutil.rmtree(aout, ignore_errors=True)
            r = run(["apktool", "d", "-f", "-o", aout, sample],
                    timeout=LONG_TIMEOUT)
            if r is not None and r.returncode == 0:
                ok("apktool 冒烟", "rc=0 成功解码最小样本(无 manifest 时仅出 smali,工具链活)")
            elif r is not None:
                blob = ((r.stdout or "") + (r.stderr or "")).lower()
                if any(k in blob for k in ("androidmanifest", "could not",
                                           "not a valid", "exception")):
                    ok("apktool 冒烟", "rc=%s 且报错结构化(能解析 zip 并正确定位缺 manifest=工具链活)"
                       % r.returncode)
                else:
                    warn("apktool 冒烟", "rc=%s 无可识别输出(手工复核 apktool)"
                         % r.returncode)
            else:
                warn("apktool 冒烟", "执行超时(手工复核 apktool)")
    else:
        warn("冒烟样本", "未能造出最小 dex(%s/%s)→跳过冒烟,version 探测为准"
             % ("d8-%s" % ("ok" if D8_JAR else "missing"),
                "javac-%s" % ("ok" if javac_bin else "missing")))
finally:
    shutil.rmtree(TMPD, ignore_errors=True)

# ---------- 六、汇总与退出码 ----------
print()
print("=" * 62)
print("## 汇总")
print("绿 OK=%d  黄 WARN=%d  红 FAIL=%d  关键红 FAIL*=%d" % (OK_N, WARN_N, FAIL_N, CRIT_N))
print("-" * 62)
print("\n".join(ROW_LOG))
print("-" * 62)
print("降级映射:venv::* WARN→S1-B/S1-C 走特征匹配/grep 兜底;adb/AVD FAIL→S3 整段标注;无 GNU timeout→长命令用 run_to(python 内建超时)或后台+kill")
print("EXIT_CODE 判定:全绿=0;有黄或非关键红=1;jadx+apktool 关键红=2(反编译双降级为 unzip+aapt2)")

if CRIT_N > 0:
    EXIT = 2
elif WARN_N + FAIL_N > 0:
    EXIT = 1
else:
    EXIT = 0
print("EXIT_CODE=%d" % EXIT)
sys.exit(EXIT)
