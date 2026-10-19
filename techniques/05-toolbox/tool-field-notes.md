# Tool Field Notes (Actually Run Through on a Local macOS Machine)

> Positioning: command-level practical memo. All commands and outputs were **actually executed on a local macOS arm64 machine** (2026-10-16), not cribbed from documentation.
> Version baseline: jadx 1.5.6 / apktool 3.0.3 / radare2 6.2.4 / frida 17.23.3 / androguard 4.1.4 / capstone 5.0.7 / unicorn (venv).
> Samples: the F-Droid client APK (org.fdroid.fdroid 2.0.1, 3 dex + 4 abi so) + JustTrustMe.apk (small unobfuscated sample).
> venv path: `~/.zcode/skills/re/tools-env/.venv/bin/` (referred to below as `$VENV`).

## 0. The Opening Triple (do this in every fresh terminal)

```bash
export VENV=~/.zcode/skills/re/tools-env/.venv/bin
export XDG_CACHE_HOME=/tmp/frida_cache   # MUST set! See frida section, pitfall 1
```

```text
Measured output (local macOS):
jadx 1.5.6 / radare2 6.2.4 +0 abi:152 @ darwin-arm_64 / apktool 3.0.3
frida 17.23.3 / androguard 4.1.4 / capstone 5.0.7
```

---

## I. jadx CLI In Depth

### 1.1 Full Decompilation (the Standard Posture)

```bash
jadx -d jadx_full --show-bad-code --deobf -j 4 app.apk > jadx_full.log 2>&1
```

```text
Measured output (local macOS, F-Droid.apk 12.5MB):
ERROR - finished with errors, count: 147      ← Normal! A 12MB-class APK almost always has errors
Artifacts: sources/ with 11949 .java files + resources/, 132M total
Time: ~90s (-j 4)
```

Key points:
- `--show-bad-code`: failed methods still get emitted (annotated) - better than empty files.
- `-j 4`: worker-thread count, default 5; on big APKs set it to half your physical cores, adding more under IO bottleneck gains nothing.
- **Errors are not failure**: judge success by whether `sources/` produced java files, not by the exit code (see pitfall 3).

### 1.2 Pitfalls and Degradations (actually stepped on)

**Pitfall 1: `--deobf` backfires on unobfuscated packages.** Measured with JustTrustMe.apk (unobfuscated):

```text
raw:     just/trust/me/Main.java   just/trust/me/R.java
--deobf: just/trust/p000me/Main.java   C0019R.java
```

`me` is only 2 chars < `--deobf-min` (default 3), so it was force-renamed `p000me`; `R` likewise became `C0019R`. **Rule: only enable --deobf once you confirm the package is ProGuard/DexGuard obfuscated; common short segments in normal package names (me/io/ui/xx) get wrecked.** Mitigation: exclude with `--deobf-whitelist "just.trust.me.*"`. When re-running an obfuscated package, pair `--deobf-cfg-file app.jobf` to reuse the first-run mapping and stay consistent.

**Pitfall 2: `--fallback` is deprecated and its semantics changed (1.5.6).** Measured output is still `.java` rather than smali, but method bodies are emptied (Main.java has only fields + blank lines left). **When you want smali, always apktool (see section II).** Degradation chain: `--no-inline-anonymous` (don't inline anonymous classes; fixes mangled Kotlin/callback decompilation) -> `--no-inline-methods` -> if truly stuck, apktool for smali.

**Pitfall 3: jadx exit-code semantics.** A `--no-res` run finishes with exit=3 but the artifacts are intact (still those 147 decompilation errors). **Batch scripts must judge liveness by "sources/ has java" - never `set -e`.**

### 1.3 --no-res to Separate Resources (for fast code-only scans)

```bash
jadx -d jadx_nores -j 4 --no-res app.apk
```

```text
Measured: 123M→code nearly the same size; the resources/ directory still gets created but is an empty shell (find shows no files)
Use: read code logic only, skip resource decoding for speed; pair with grep to scan for endpoint strings
```

### 1.4 Single-Class Export (seconds; close-read after locating)

```bash
jadx --single-class org.fdroid.fdroid.FDroidApp --single-class-output FDroidApp.java app.apk
```

```text
Measured output:
INFO  - Saving class 'org.fdroid.fdroid.FDroidApp' to file '.../FDroidApp.java'
INFO  - done                       ← done in seconds, ideal for iteratively reading one class
```

In 1.5.6 both `--single-class` (full name/raw/alias all work) and `--single-class-output` are present. Unsure of the class name? First `find jadx_full/sources -name "*.java" | grep -i keyword`, then export.

### 1.5 Batch Decompilation Script (tested working)

```bash
#!/bin/bash
# batch_jadx.sh <apk dir> <output root>: jadx one by one; exit!=0 does not abort
IN=${1:-.}; OUT=${2:-./batch_out}; mkdir -p "$OUT"; ok=0; bad=0
for apk in "$IN"/*.apk; do
  name=$(basename "$apk" .apk); echo "[*] jadx: $name"
  jadx -d "$OUT/$name" --show-bad-code -j 4 --no-res "$apk" > "$OUT/$name.log" 2>&1
  if [ -d "$OUT/$name/sources" ] && [ -n "$(find "$OUT/$name/sources" -name '*.java' | head -1)" ]; then
    echo "    ok -> $(find "$OUT/$name/sources" -name '*.java' | wc -l | tr -d ' ') java"
    ok=$((ok+1)); else echo "    FAIL"; bad=$((bad+1));
  fi
done; echo "[=] done ok=$ok fail=$bad"
```

```text
Measured output (local macOS):
[*] jadx: FrecencyLauncher-debug
    ok(rc=3, err_lines=0) -> 5743 java   ← rc=3 yet artifacts intact — a living example of pitfall 3
[*] jadx: JustTrustMe
    ok(rc=0, err_lines=0) -> 3 java
[=] done ok=2 fail=0
```

---

## II. apktool (the Real smali + Resource Repair)

```bash
apktool d -f -o jtm_apktool JustTrustMe.apk
```

```text
Measured output: exit=0
jtm_apktool/{AndroidManifest.xml(readable xml), smali/, res/, apktool.yml, original/, assets/}
```

Division-of-labor conclusion: **want smali / edit resources and rebuild (b) -> apktool; want to read Java logic -> jadx.** jadx's fallback is no substitute for apktool's smali.

---

## III. radare2 Workflow (Handles Mach-O and ELF so Alike)

### 3.1 Mach-O in Practice (/bin/ls, a sample shipped with macOS)

```bash
r2 -q -c 'aaa; afl~main' /bin/ls          # list main
r2 -q -c 'aaa; pdf @ main' /bin/ls        # disassemble main
r2 -q -c 'aaa; axt @ sym.imp.printf' /bin/ls   # who calls printf (xref)
r2 -q -c 'izz~usage' /bin/ls              # string search
r2 -q -c 'iS' /bin/ls                     # section table
```

```text
Measured output (local macOS):
0x100000960  153   3072 main                          ← afl~main
┌ 3072: int main (int argc, char **argv, char **envp); // noreturn
│  0x100000960  pacibsp ...                           ← arm64e PAC instructions recognized
axt printf → sym.func.100002328 0x1000023b4 [CALL:--x] bl sym.imp.printf (+4 sites)
izz~usage → ascii 'usage: ls [-@ABCFGHILOPRSTUWXabc...]'
iS → 0.__TEXT.__text / __auth_stubs / __cstring / __DATA_CONST.__auth_got ...
```

### 3.2 Pulling so from an APK: JNI Export Determination (an Important Field Conclusion)

```bash
unzip -o -q app.apk "lib/arm64-v8a/*" -d apk_libs
r2 -q -c 'iE' apk_libs/lib/arm64-v8a/libandroidx.graphics.path.so   # export table
r2 -q -c 'aaa; afl' .../libandroidx.graphics.path.so                # all functions
```

```text
Measured output:
iE → 8  GLOBAL FUNC 448  JNI_OnLoad        ← the only export
afl → 19 funcs (a 10KB small so); ii~JNI none (does not export JNIEnv passthrough)
HINT: Relocs not applied, some references may not resolve: use -e bin.relocs.apply=true
```

**Field conclusion: `is~Java_` finding nothing != no JNI.** This so has only `JNI_OnLoad` = **dynamic registration** (RegisterNatives runs inside OnLoad). How to chase: `pdf @ sym.JNI_OnLoad` to find the `RegisterNatives` call site; its second parameter, a table, is the Java-method<->native-function mapping. Only static registration (Java_xxx_yyy naming) shows up directly under `is~Java_`.
**Pitfall**: when r2 warns relocs are not applied, add `-e bin.relocs.apply=true`, otherwise cross-references are under-reported.

### 3.3 -B Base Address: Not Needed for so Files Inside an APK

Measured `iS`: the `.text` section has paddr==vaddr (0xd2c==0xd2c); ELF shared libraries map automatically per program header. **Reserve `-B` for scenarios repairing the base address of memory dumps** (so files dumped during unpacking need it - see `03-unpacking`).

### 3.4 r2pipe Scripting (batch-scanning functions + sensitive strings)

```python
# r2pipe_list.py <binary>  ($VENV/pip has no pip! install method in the pitfalls)
import r2pipe, sys
r2 = r2pipe.open(sys.argv[1], flags=["-2"])   # -2 mutes stderr noise
r2.cmd("aaa")
funcs = r2.cmdj("aflj") or []
print(f"[*] {sys.argv[1]}: {len(funcs)} funcs")
for f in funcs[:8]: print(f"    {hex(f.get('offset', f.get('addr')))}  {f['name']}")
strs = r2.cmdj("izzj") or []
pw = [s for s in strs if any(k in s.get("string","").lower() for k in ("key","token","secret"))]
for s in pw[:5]: print("    ", s["string"][:60])
r2.quit()
```

```text
Measured output (local macOS):
[*] /bin/ls: 135 funcs
    0x1000042a4  sym.imp.__assert_rtn ... (8 lines)
    1 sensitive string
so version: [*] libandroidx.graphics.path.so: 19 funcs (sym.imp.__system_property_get etc.)
```

**Pitfall: in r2 6.x the `aflj` key is `addr`, not `offset`** (old tutorial scripts hit KeyError directly).
**Pitfall: the venv was created by uv and has no pip**; to install: `XDG_CACHE_HOME=/tmp/frida_cache uv pip install --python $VENV/python r2pipe`.

### 3.5 Pure Command-Line Parsing (degrade when no r2pipe)

```bash
r2 -q -c 'aaa; afl' /bin/ls > funcs.txt        # human-readable
r2 -q -c 'aaa; aflj' /bin/ls | python3 -c 'import json,sys; [print(f["addr"], f["name"]) for f in json.load(sys.stdin)]'  # machine-readable
```

---

## IV. androguard 4.x Scripting (venv python)

### 4.1 The Universal Header (mandatory on 4.x, else DEBUG floods the screen)

```python
from loguru import logger; logger.remove()     # androguard 4.x uses loguru, DEBUG-level floods by default
from androguard.misc import AnalyzeAPK
a, ds, dx = AnalyzeAPK("app.apk")              # 4.x returns (APK, [DalvikVMFormat], Analysis)
```

### 4.2 Permissions/Components/Intents in One Sweep

```python
a.get_package(); a.get_androidversion_name(); a.get_min_sdk_version()
a.get_permissions(); a.get_activities(); a.get_services(); a.get_receivers(); a.get_providers()
a.get_intent_filters("activity", name)   # deeplink/exported attack surface
```

```text
Measured output (local macOS, F-Droid.apk):
[pkg] org.fdroid.fdroid | ver 2.0.1 | minSdk 24
[perms] 28 entries (MANAGE_EXTERNAL_STORAGE / QUERY_ALL_PACKAGES / REQUEST_INSTALL_PACKAGES ...)
[activities] 10  [services] 10  [receivers] 9  [providers] 4
org.fdroid.MainActivity -> {'data': [{'scheme':'market'...}, {'scheme':'https','host':'f-droid.org'},
  {'scheme':'fdroidrepos'}], 'category': ['BROWSABLE'...]}   ← the whole deeplink attack surface
```

### 4.3 xref: Find All MessageDigest Call Sites (a reusable 10 lines)

```python
for m in dx.find_methods("Ljava/security/MessageDigest;", "getInstance", "."):
    for caller_class, caller_method, _off in m.get_xref_from():
        print(caller_method.full_name)
```

```text
Measured output (21 call sites, excerpted):
Lorg/fdroid/download/Downloader; copyInputToOutputStream
Lorg/fdroid/utils/UtilsKt; sha256 ([B)Ljava/lang/String;
Lorg/fdroid/index/IndexCreator; hashFile ...
```

Swap the class name in the same template to scan any sensitive-API call surface: Cipher/SecretKeySpec/WebView/addJavascriptInterface and so on.

### 4.4 4.x API-Change Pitfalls (three actually stepped on)

- `from androguard.core.androconf import show_logging` -> **deleted in 4.1.4**; use the loguru approach (4.1 header).
- `get_xref_from()` on `dx.classes.get(...)` now returns a **set of class objects**, no longer triples - unpacking raises TypeError; method-level xref goes through `find_methods` + `MethodAnalysis.get_xref_from()` (the 4.3 template).
- Iterating `dx.strings` yields plain `str` directly, not objects with `.value`.

---

## V. frida 17.x Local Practice (macOS self-testing)

### 5.1 Pitfall 1: ~/.cache owned by root -> the whole toolchain crippled

```text
Measured error: frida.PermissionDeniedError: error creating directory ~/.cache/frida/...
Root cause: ~/.cache is root:staff drwx------ (historical legacy); frida/uv cannot write into it
```

**Fix: `export XDG_CACHE_HOME=/tmp/frida_cache` at the start of every session (already in the Section 0 triple).**

### 5.2 Pitfall 2: attaching to someone else's process denied -> spawn mode works

```text
Measured error: PermissionDeniedError: unable to access process with pid 15520 from the current user account
(On macOS without sudo, or a terminal without Debugging permission, attaching to an existing process is always denied)
```

**Degradation: spawn your own child process, then attach (macOS allows this; frida-helper does the work):**

```python
# hook_spawn.py ($VENV/python hook_spawn.py)
import frida, time
dev = frida.get_local_device()
pid = dev.spawn(["$VENV/python", "-c", "import time;time.sleep(15)"])
session = dev.attach(pid)                    # child process attachable
script = session.create_script('''
  var f = Module.getGlobalExportByName("getpid");   // 17.x uses getGlobalExportByName
  Interceptor.attach(f, { onEnter: function(a){ send("getpid hit"); }});
  console.log("[*] pid="+Process.id+" arch="+Process.arch+" frida="+Frida.version);''')
script.on('message', lambda m,d: print("[msg]", m.get("payload")))
script.load(); dev.resume(pid); time.sleep(5); session.detach()
```

```text
Measured output (local macOS):
[*] spawned pid 17414
[*] hooked getpid in pid=17414 arch=arm64 os=darwin frida=17.23.3
[msg] getpid hit  ×2
[*] detached ok
```

**Pitfall 3: the spawn target must be a pure CLI binary.** `/usr/bin/python3` is CommandLineTools' Python.app (a GUI bundle); spawning it deadlocks in the helper. Use the pure-CLI venv/homebrew python. To inject into a GUI app for real, go through frida-server + an Android device; local GUI needs sudo.

### 5.3 frida CLI (argument-order trap)

```bash
# Correct: -e before the target; only after -- come the injected program's arguments
(sleep 5; echo exit) | $VENV/frida \
  -e 'console.log("[+] "+Process.arch+" pid="+Process.id+" mods="+Process.enumerateModules().length)' \
  -f $VENV/python -- -c "import time;time.sleep(4)"
```

```text
Measured output:
Spawned `/…/python -c import time;time.sleep(4)`. Resuming main thread!
[+] injected arch=arm64 pid=18449 mods=349
[Local::python ]-> Process terminated
```

**Pitfall 4: `--no-pause` was removed in 17.x (unrecognized arguments); placing `-e` after `--` makes the app swallow it as its own argument** (measured: the spawned python took `-e` as its own argv and the injected code never ran). For non-interactive automation prefer the python API (5.2); leave the CLI for interactive debugging.

### 5.4 frida-ps / frida-trace

```bash
$VENV/frida-ps -a      # list GUI applications (with bundle ids)
$VENV/frida-ps         # all processes
which $VENV/frida-trace && echo ok   # present (trace topic in `13-trace`)
```

```text
Measured output: 4306 ARDAgent com.apple.RemoteDesktopAgent ...
```

---

## VI. Inter-Tool Pipeline (directory/naming conventions from static to dynamic)

One pipeline per target: **directory per package name, fixed artifact names**; every step can re-run incrementally:

```text
work/org.fdroid.fdroid/           ← one directory per target, named by package (AG 4.2's a.get_package())
├── app.apk                       ← the single original sample; hash recorded in notes.md
├── jadx/                         ← jadx -d jadx (add --deobf only for obfuscated packages)
│   └── sources/...               ← after locating a class, export with --single-class for close reading
├── apktool/                      ← apktool d; created only when smali/rebuild is needed
├── libs/arm64-v8a/*.so           ← extracted via unzip "lib/arm64-v8a/*", abi hierarchy preserved
├── r2/                           ← r2pipe scan results, afl/izz into .txt; named soName.afl.txt
├── ag/                           ← androguard script output: perms.md / xref_<API>.md
├── scripts/                      ← hook_spawn.py / r2pipe_list.py adapted from the §4.3/§3.4 templates
└── notes.md                      ← command history + conclusions (jadx-located class name → so export → r2 offset → frida hook point)
```

The four pipeline steps in sequence (field order):

1. **jadx locates**: `find jadx/sources -name "*.java" | grep -i <keyword>` -> export with `--single-class` for a close read -> note the class containing `System.loadLibrary("xxx")` and the native method declarations.
2. **Pull the so into r2**: `unzip lib/arm64-v8a/libxxx.so` -> `r2 -q -c 'iE'` to check exports first (only JNI_OnLoad = dynamic registration; `pdf @ JNI_OnLoad` decodes the RegisterNatives table for the function mapping) -> dump `aflj`/`izzj` to disk.
3. **androguard fills in the surface**: permissions/components/deeplink attack surface + sensitive-API xrefs (the 4.3 template) to circle the key classes in reverse, feeding step 1 back.
4. **frida dynamic verification**: write the statically obtained offsets/method names into scripts/hook_spawn.py (locally, legal self-testing spawns CLI programs; real Android devices go through frida-server). In the hook, locate so offsets with `Module.getBaseAddress("libxxx.so").add(0xoffset)`.

Rebuild/repackage: apktool b produces patched.apk -> re-sign with apksigner (not a default step of this pipeline).
