# Tool Detection and Modding

> Positioning: **the adversarial chapter from the tool's perspective**. Three questions per RE tool: how to use it (pointers) | whether it can be detected (the tool's own detection surface) | how to mod it once detected.
> Division of labor within the repo: detection principles and counter-techniques live in area 04 (`../04-evasion/detection-landscape.md`, `../04-evasion/frida-anti-detection.md`, `../04-evasion/root-env-hiding.md`); this page **only aggregates at tool granularity and fills gaps** - tool usage is not expanded here (see `tool-field-notes.md` and `tool-master-table.md`); for overlapping principles only pointers are given.
> How to use: on entering a tool, first check it against the Section 1 master table; for the frida family dig into Section 2; before repackaging read Section 3 first; for general modding thinking see Section 4; for "can I just not be detected at all" see Section 5.

## 1. Three-Column Master Table (the Core)

Three questions on entry (run through them for every tool before it touches a device):

1. **What does this tool leave on the device?** - check the "detection surface" column below, matching signature names one by one;
2. **Does the target's detection library actually check these?** - statically search whether the signature strings appear in the target's code first (jadx/r2 `izz`); absent = exempt, don't pay modding costs for nothing;
3. **It checks - now what?** - the "mod/replacement" column gives the next hop; walk up the layers of Section 4; verify one layer before moving to the next (mod -> redeploy -> retest -> next layer).

| Tool/Chain | Detection Surface (how the target spots you using it) | Mod/Replacement Path |
|------|------|------|
| **frida-server** | Ports 27042/27043 (= hex 69A2, connect probing or reading `/proc/net/tcp`); process name `frida-server` (ps/cmdline walks); thread names `gmain`/`gum-js-loop`/`gdbus`/`pool-frida`; `frida-agent-64.so` and rwxp anonymous segments in the target's maps; the `linjector-` temp-pipe prefix; D-Bus handshake responses containing `frida:rpc` | L1 rename + re-port (`mv frida-server crond;./crond -l 0.0.0.0:random`) -> L2 same-length string edits via LIEF -> strongR/self-compile (Section 2/Section 4) -> switch to gadget/Zygisk-Frida form (`../04-evasion/frida-anti-detection.md` Section 1/Section 3) |
| **frida-gadget** | Under APK `lib/<abi>/`, so names `libgadget.so`/`frida-gadget` (directly visible in maps); config file name `libgadget.config.so` (JSON with a renamed file); exported symbol `frida_agent_main` (dlsym/static ELF parsing); interactive mode listens on 127.0.0.1:27042 by default; repackaging drags in signature validation (Section 3) | When repackaging, rename the so and config together (same-length, or sync the smali references); script mode opens no port; memory signatures identical to server, need stripping (Section 2); replacements: LSPatch/Zygisk-Frida avoid repackaging |
| **frida CLI / python bindings (host side)** | **Lives on the PC, zero footprint on the device - the app cannot detect it directly.** The detection surface is behavioral: USB debugging always on (`adb_enabled=1`), long-lived adb connections, constant-current USB charging state (see the adb row); what actually gets detected on-device are the server/gadget/injection leftovers it depends on | No need to mod the tool itself; treat the symptoms on the device (strip server/gadget signatures) + shrink the adb surface (wireless adb/on-device agents) |
| **objection** | The body is PC-side python; on-device signatures = the frida form it rides on (default runs an unrenamed frida-server); `objection patchapk` injects so/config names fixed as `frida-gadget` with no randomization; the injected artifacts (agent bundle referenced by the gadget config) contain the `objection` string, greppable inside the APK | After patchapk, manually do a second pass renaming so/config + stripping agent signature strings; or drop objection and cover its triple (pinning bypass/root bypass/dump) with hand-written frida scripts carrying no `objection` strings; maintenance has slowed - for new tasks switch to medusa/hand-written (Hook section of `tool-master-table.md`) |
| **Xposed / LSPosed modules** | `Class.forName("de.robv.android.xposed.XposedBridge")`; stack traces containing XposedBridge (LSPosed already scrubs stacks); maps scans for `riru`/`lspd` injection traces; ART de-optimization traces (`kAccCompileDontBother` flag); manager package `org.lsposed.manager` enumeration (`../04-evasion/detection-landscape.md` Section 5.2) | LSPosed itself scrubs stacks + randomizes the manager package; pair Shamiko+Zygisk-Assistant to hide injection traces; HideMyApplist blocks package enumeration (not pm commands/native scans); root-free scenarios use LSPatch (shifts to the repackaging surface, Section 3) |
| **LSPatch** | The output is a repackaged APK: the signature necessarily changes (`signatures[0]` shift, Section 3) + embedded LSPosed runtime so (lspd-family signatures visible in maps) + patch metadata files | Rename the embedded so and config paths; defeat signature validation per Section 3.3; still a repackaging chain at heart - output signatures as in Section 3.1 |
| **Zygisk-Frida / ZygiskNext** | No standalone server process, no listening port, no ptrace - the process-name/port/TracerPid surfaces all vanish; what remains: in-process frida memory signatures (`frida:rpc`, gum thread names, rwxp segments) and zygisk injection traces (native bridge state/mount topology) | Pair with strongR-family builds to strip memory strings (Section 2.2); environmental traces go to Shamiko/Zygisk-Assistant; against "process + port"-level detection it is a dimensional strike - only the memory layer battle remains |
| **Magisk (root)** | su path walks (`/system/bin/su`, `/system/xbin/su`, `/sbin/su`); `/data/adb/magisk/`, `magisk.db` files; `/proc/mounts` containing `magisk`/`core/mirror` overlay/tmpfs; props (`ro.debuggable`/`ro.secure=0`/`test-keys`/`verifiedbootstate=orange`); manager package historical value `com.topjohnwu.magisk`; SELinux Permissive | Hidden-app randomized package + Zygisk + Shamiko (whitelist mode optimal) + Zygisk-Assistant + HMA + resetprop/MHPC, the full set (`../04-evasion/root-env-hiding.md` Section 1/Section 4); stubborn targets switch to KSU/APatch |
| **KernelSU / APatch** | KSU: no userspace su binary, no magiskd, no overlay mounts (nothing for regular scans to hit); leftovers are the `/data/adb/ksu/` path and manager package `me.weishu.kernelsu`, plus kernel-mode execve hooks (invisible to userspace; only another root observer/kernel comparison can see them). APatch likewise + `/data/adb/apatch`; KPM kernel modules are your only weapon against svc-level detection | Naturally low detection surface; add ZygiskNext for ecosystem; hide the manager package; mask `/data/adb` leftovers with mounts; the detector's counter-play can only lean on prop leftovers (bootloader/verifiedbootstate) and device fingerprints - hand those to MHPC/fingerprint replacement (`../04-evasion/device-fingerprint-risk.md` Section 4) |
| **Emulators / AVD** | `ro.hardware=ranchu`/`goldfish`/`vbox86`; `ro.kernel.qemu=1`; `/proc/cpuinfo` Hardware field containing goldfish/ranchu; `/dev/qemu_pipe`, `/dev/socket/qemud`, `/dev/goldfish_pipe`; NAT gateway 10.0.2.2/DNS 10.0.2.3; `ro.product.model=sdk_gphone64_x86_64`; all-zero IMEI; constant/low-entropy sensors; battery stuck at CHARGING (`../04-evasion/detection-landscape.md` Section 4) | root + resetprop full set to swap in real-device values (ro.hardware->qcom etc.); mount --bind empty files over the qemu_pipe-family nodes; sensor-spoofing modules add noise; GPU/canvas fingerprints are hardest to fix - for heavily risk-controlled targets just switch to a real/cloud device (the cloud device's fatal flaws are sensor entropy + datacenter IP ranges, see `../04-evasion/device-fingerprint-risk.md` Section 3) |
| **adb debugging state** | `Settings.Global adb_enabled=1`; `/proc/net/tcp` showing 5555 LISTEN (tcp adbd); process ppid chain containing `adbd` (walk cmdline upward via /proc/self/stat); JDWP thread names of debuggable packages (task/*/comm); USB plugged + constant-current charging; `ro.debuggable` | Wireless adb (`setprop service.adb.tcp.port random`) avoids the USB state but `adb_enabled` remains; deeper: on-device agents (lamda ships server + WebRTC mirroring, replacing the adb+uiautomator channel); note: adb is the prerequisite surface for almost every tool, and "detecting adb itself" is often overlooked |
| **apktool d/b + apksigner repackaging chain** | Output signatures: all ZIP entry timestamps become one identical fixed value (each vendor build has real times); resources.arsc reordering (string-pool/entry order shifts); dex offsets/checksums all change (byte-level hash necessarily differs); manifest binary-XML attribute reordering; signer certificate change: `PackageManager.GET_SIGNATURES`'s `signatures[0]` (hash/`toCharsString`) != the vendor-hardcoded value; V1's META-INF/CERT.RSA renamed; V2 APK Signing Block rewritten; when the target's native code self-parses base.apk to hash it, Java hooks are useless | See the Section 3 deep dive: dynamic patch without touching disk (preferred)/openat feeding the original package/PMS spoofing/patching the validation function; core insight: without the vendor's private key the original signature cannot be preserved - every bypass = fooling the reader or changing the logic |
| **jadx / r2 / androguard (static)** | **Zero detection surface**: pure PC-side offline analysis; the target has no channel to perceive it | Not needed. Boundary: the artifacts (hook scripts/repackaged APK) are what create detection surfaces; usage in `tool-field-notes.md` |
| **unidbg / unicorn (offline emulation)** | **Zero detection surface**: the so executes in local emulation, never touching the target device/server; the risk-control SDK's detection code is just ordinary instructions inside the emulated process - skip or patch directly | Not needed - in fact this is the L4 endpoint (Section 4/Section 5); boundary: environment-stubbing cost, and ART/UI-dependent logic cannot be emulated (`emulation-frameworks.md`) |
| **wireshark (passive listening)** | **Zero detection surface** (PC/router side): captures without injecting or altering flows; sends no packets visible to the target | Just stay passive; boundary: running on-device (needs root + pcap capture, signatures as in the tcpdump row); active ARP spoofing/traffic injection are the exception - those leave traces |
| **Charles / mitmproxy (proxies)** | System proxy on = instant hit: `System.getProperty("http.proxyHost")`/`ProxySelector` returning non-DIRECT; default ports Charles 8888, mitmproxy 8080 (connect-probeable); CA signatures: Charles cert CN contains "Charles Proxy", mitmproxy CA CN=`mitmproxy`; Android 7+ apps distrust user CAs by default -> after root moves it into the system store, **extra non-vendor certificates in the system cert directory are enumerable** (`../04-evasion/detection-landscape.md` Section 5.1) | mitmproxy swaps CA: self-sign a CA under `~/.mitmproxy/` (openssl-generate a custom CN/SN to replace mitmproxy-ca.pem) and the CN signature vanishes; transparent mode (iptables REDIRECT) sets no system proxy variables, dodging proxyHost detection (`../04-evasion/capture-all-scenarios.md` Section 2.5); tun0-type VPN detection is hard to beat - switch to transparent proxy/physical-NIC relay; the final wall is pinning (`../04-evasion/ssl-pinning-bypass.md`) |
| **tcpdump (on-device capture)** | Needs root: process name `tcpdump` (ps walk hit); after enabling promiscuous mode the NIC carries `IFF_PROMISC` (netlink-visible); the binary at `/data/local/tmp/tcpdump` is access-scannable; pcap files carry capture info | mv rename + move off the default path; `-p` skips promiscuous mode (enough for local traffic); better: fall back to PC-side wireshark/passive listening via a middle AP (zero device surface) |
| **VirtualApp / Parallel-Space-style multi-instance** | Multiple packages on one uid: `PackageManager.getPackagesForUid(uid)` returns an array longer than 1 (normally one uid one app); `ApplicationInfo.sourceDir`/`dataDir` pointing into the virtual-framework directory (under `com.lody.virtual`/`io.virtualapp`/various cloners' packages); base.apk in maps is the host path; known cloner package enumeration; risk-control SDKs have explicit multi-instance detection items (Yidun lists VMOS/X8/51/虚拟精灵, `../04-evasion/device-fingerprint-risk.md` Section 5.2) | White-label VirtualApp source (rename package + directories wholesale - heavy work, and the uid/sourceDir structural signatures remain); for finance apps essentially unsolvable - **multi-instance is a detection disaster zone; avoid it if you can**; alternatives: real-device multi-account matrices or LSPatch (shifts to the repackaging surface) |
| **scrcpy (mirroring, appendix)** | `Display.getFlags` multi-display enumeration showing the `Overlay #0` virtual display; FLAG_SECURE pages going black is corroborating evidence | No mature mod; alternatives: lamda-family WebRTC mirroring or physical filming |

**How to read the table**: the detection-surface column = "signature names visible from the target's viewpoint"; the mod column follows Section 4's L1->L4 progression and lists the next hop, not the endpoint. "Zero detection surface" rows are structurally exempt - exploit them first (Section 5).

**Four-family mnemonic**:
- Injection family (server/gadget/objection/zygisk-frida/Xposed): all pay the "in-process signature" bill; they differ only in which extra items they also pay;
- Environment family (Magisk/KSU/emulator/multi-instance/adb): what's detected isn't a specific tool but "this device doesn't look like a normal phone" - decoupled from any particular tool;
- Network family (Charles/mitmproxy/tcpdump): what's detected is "the traffic path has been altered" - transparency/passivity is the only direction;
- Static family (jadx/r2/unidbg): structurally zero detection - the fallback when every other family hits a dead end.

## 2. frida Whole-Family Detection Surface Deep Dive

> Principles and counter-techniques live entirely in [`../04-evasion/frida-anti-detection.md`](../04-evasion/frida-anti-detection.md) and [`../04-evasion/detection-landscape.md`](../04-evasion/detection-landscape.md) Section 2; this section only adds the **form x signature** tabular reconciliation - what each of the four forms costs and what it exposes.

### 2.1 Four-Form Signature Reconciliation Table

| Form | Device-side process/port | Filesystem signatures | In-process signatures | Unique advantage/cost |
|------|------|------|------|------|
| **frida-server** | Standalone process `frida-server` (renameable); listens on 27042/27043 (changeable); /proc/net/tcp exposes 69A2 | Binary path (/data/local/tmp etc.); creates `linjector-`-prefixed temp pipes when injecting | Target's maps gain `frida-agent-64.so` mappings + rwxp anonymous segments; threads `gmain`/`gum-js-loop`/`gdbus`/`pool-frida`; memory strings `frida:rpc`/`re.frida.server`; symbol `frida_agent_main` | Best generality; the #1 sample in detection signature libraries - running it bare is certain death |
| **frida-gadget** (embedded via repackaging) | **No standalone process, no listener (script mode)**; interactive mode defaults to 127.0.0.1:27042 | so name under APK lib (gadget/libgadget renameable); config JSON filename (`libgadget.config.so` renameable); **APK signature necessarily changes** (dragging in Section 3) | Same memory/thread signatures as server (same agent); `frida_agent_main` export symbol | Root-free, no process/port scan surface; cost: one repackaging per target + the signature-validation drag-along |
| **Self-written inject / ptrace injection** | The injection action creates a transient TracerPid window (ptrace type); Zygisk type has none | Nothing on disk (the so can be deleted post-injection) | **Memory signatures identical to server** (still gum/frida-agent); with a self-built minimal agent you control the signatures yourself | Signature surface = pure memory layer; the engineering cost sits in the injector and agent maintenance |
| **CLI+RPC (host side)** | No trace on the device (the body is on the PC) | None | None (never lands on the device) | The detection surface is **behavioral** only: resident adb, USB state, plus the device-side signatures of whatever server/gadget it drives |

**Conclusion row**: detection-surface size is server > gadget ~ inject > CLI (the tool itself). But server/gadget/inject share the same set of **in-process memory signatures** - however you swap the client side, the memory-layer battle remains; that is the battlefield of Section 2.2 and L2/L3.

### 2.1b Detection-Point x Form Matrix (which form runs naked under which detection class)

| Detection point | server | gadget | inject | CLI body |
|------|------|------|------|------|
| Port connect/`/proc/net/tcp` | **Exposed** (vanishes after re-porting) | None in script mode; exposed in interactive mode | None | None |
| Process name/cmdline/ps | **Exposed** (vanishes after renaming) | No standalone process | The injector process exists briefly (ptrace type) | None |
| Thread names task/*/comm | **Exposed** (the four gum names) | **Exposed** (same set) | **Exposed** (same set) | None |
| maps filename scan | **Exposed** (frida-agent-64.so) | **Exposed** (so name, renameable) | Exposed (same agent after injection; self-built agent is self-controlled) | None |
| rwxp anonymous-segment shape | **Exposed** | **Exposed** | **Exposed** | None |
| Memory string scan (frida:rpc etc.) | **Exposed** | **Exposed** | **Exposed** | None |
| Symbol dlsym/static ELF parsing | **Exposed** (frida_agent_main) | **Exposed** (same symbol) | Exposed (self-built can omit) | None |
| TracerPid/ptrace surface | Exposed while attaching | None | ptrace type exposed/zygisk type none | None |
| Repackaging signature drag-along | None | **Exposed** (Section 3) | None | None |
| Behavioral surface (adb/USB state) | Exposed (via the adb channel) | None (purely local) | Exposed (deployment window) | Exposed |

**How to use the table**: first statically/jadx-confirm which rows the target's detection points fall into, then pick the form with "all clear in those rows" - far faster than trying forms one by one. Rows 5-7 (the three memory rows) can only be solved by signature stripping (L2/L3) or switching to a non-frida runtime (LSPosed/unidbg); converting between forms does nothing.

### 2.2 Mod Path Table (from cheapest to priciest)

| Path | Action | Which signatures it covers | Not covered | Cost/survival |
|------|------|------|------|------|
| Re-port + rename | `-l 0.0.0.0:random` + mv the process name | Port scans, ps/cmdline enumeration | maps/thread names/memory strings all remain | Minutes/entry ticket - dies once the outermost detection layer goes |
| strongR-frida prebuilt | Download a community patched build | The full signature-string list (below) | Version lag; behavioral signatures (rwxp) remain | Minutes/until the signature library catches that version |
| LIEF same-length binary string edits | lief/patchelf walking sections, swapping in same-length random strings | Same list as above (no compiling) | Must be strictly same-length or addresses break; symbol alignment needs a full self-consistent set | Hours/long-lived if the private strings never leak |
| Self-compile with source edits | git apply the strongR patch or hand-edit, then `make core-android-arm64` | Full coverage + control (incl. thread names/prgname) | rwxp memory shape; injection timing | Days/most durable - a private build hash never enters any library |
| Runtime memory substitution | Hook open/fgets to launder maps output + dlpi_name replacement | "What the reader sees" gets laundered | Readers that pread/deref directly; svc-level readers | Hours/strongly depends on the detection method |

**Source-file checklist for self-compiling** (items covered by the strongR patch, tabulated for reference; details in `../04-evasion/frida-anti-detection.md` Section 1.2):

| Signature | Source location | Patch method |
|------|------|------|
| `frida:rpc` RPC identifier | frida-core/lib/interfaces/session.vala | Same-length random string |
| `re.frida.server` working directory | frida-core/server/server.vala | Same |
| `linjector-` pipe prefix | frida-core/src/linux/linux-host-session.vala | Same |
| `frida_agent_main` export symbol | frida-agent entry (call sites synced) | Rename |
| Thread names gum-js-loop/gmain/gdbus/pool-frida | The prctl(PR_SET_NAME) call sites in GLib/Gum | Change prgname/thread names |
| GType class names FridaScriptEngine/GumScript/GDBusProxy/GLib-GIO | Type registration sites | Rename |
| `g_set_prgname("frida")` | frida-gum/gum/gum.c | Change or delete |
| adb interaction protocol OPEN/CLSE/WRTE | frida-core/lib/usb/droidy-client.vala | As needed |

### 2.3 Drag-Along Signatures of Upper-Layer frida-Ecosystem Tools (gap-filling)

| Ecosystem tool | Relationship to frida | Extra signatures (beyond frida itself) | Handling |
|------|------|------|------|
| objection | Fully dependent on server/gadget on the device | patchapk output contains the `objection` string; does not rename the server by default | Section 1 row 4 |
| frida-trace | Rides the same server channel; no extra device-side signatures | None (usage and pitfalls in `tool-field-notes.md` Section 5.4 and area 13) | Fixing the server fixes it |
| medusa/frida script frameworks | Modules are still injected JS | Strings inside scripts (module names/magic comments) stay in target memory, content-scannable | For heavily risk-controlled targets, slim the scripts + strip signature strings |
| lamda | On-device agent with frida built in and stealth patches pre-applied | Replaces the adb channel (dodges the adb detection surface); its own server is a new surface, but renameable/white-labelable | Use as an L4 replacement: solves the adb+frida double surface at once |

### 2.4 Form-Conversion Decisions (maps to Section 4 L4)

- Server surface killed (process/port changes all die) -> gadget (trade root-free for no-process surface) or Zygisk-Frida (root environment, no repackaging);
- Gadget killed (so name/signature drag-along) -> Zygisk-Frida or LSPatch (switch signature family);
- Injection killed at every layer (page-by-page memory + svc) -> abandon the runtime; go unidbg offline or pure static patching (Section 5);
- Timing problem (spawn not early enough) -> zygisk > spawn > gadget > attach; timing evidence in area 11, `../11-syscall-chain/process-memory-chain.md`;
- After every conversion, **recount the Section 2.1 table**: which rows the new form clears and which it adds - never assume "switched = won".

## 3. Repackaging-Chain Signatures and Signature-Bypass Deep Dive

> Every repackaging (apktool hand-edits / gadget embedding / LSPatch / objection patchapk) shares this chain. Every link on it is a detection point.

### 3.1 Recompiled-Output Signatures (how the target recognizes "this APK has been tampered with")

| Signature | Mechanism | Detection method |
|------|------|------|
| All-identical ZIP timestamps | After apktool b, all entries share one fixed time; vendor APKs have real per-entry build times | The app reads its own base.apk (`ApplicationInfo.sourceDir`), parses the ZIP central directory, and compares the entry timestamp distribution |
| resources.arsc reordering | After aapt2 recompiles, string-pool/entry order shifts - byte-level necessarily different; and targetSdk>=30 requires the arsc uncompressed + 4-byte aligned, mishandled and it won't even install | Whole-package or arsc hash compared against cloud/embedded constants |
| classes.dex byte-level changes | The baksmali->smali round-trip is semantically equivalent but dex offsets/checksum/signature all change; if the patch added strings, string_ids order shifts too | dex hash comparison; finer-grained per-method CRC |
| manifest binary-XML reordering | Attribute order/string-pool shifts | manifest hash |
| native lib alignment broken | zipalign skipped/page alignment lost; with `extractNativeLibs=false` the install simply fails | The install failure itself; when it doesn't fail, anomalous ZIP entry alignment fields |
| Leftover directories | apktool's `original/`, `apktool.yml` accidentally packed into the output | Directory/filename enumeration |

### 3.2 Two Generations of Signature Validation and Their Detection Points

| Dimension | V1 (jarsigner) | V2/V3 (apksigner) |
|------|------|------|
| Storage location | META-INF/: `MANIFEST.MF`+`CERT.SF`+`CERT.RSA` (alias-related filenames) | APK Signing Block: between the last file and the central directory, block-tail magic `APK Sig Block 42` |
| Coverage | File-level digests only (doesn't sign META-INF itself - a historical hole) | Full entry digest chain; one changed byte invalidates; V3 adds key rotation |
| Java-side read | `getPackageInfo(pkg, GET_SIGNATURES)` -> `signatures[0]` (certificate DER) | Same; API 28+ `PackageInfo.signingInfo` |
| native-side read | Self-parses ZIP to find the META-INF cert and hash it | Self-parses the Signing Block (the magic string is findable in the so) - **bypasses PMS, so Java hooks are useless** |
| Re-signing consequence | Certificate necessarily changes -> subject DN/public-key hash change | Same; signatures[0] necessarily changes |

**Universal iron law**: without the vendor's private key, `signatures[0]` necessarily changes after re-signing. The bypass is not "restoring the signature" but making the validator **unable to read the true value or fail its verdict**.

### 3.3 Bypass Matrix

| Bypass | Layer it hits | Positioning/landing point | Failure signature |
|------|------|------|------|
| Dynamic patch without disk (frida memory edits) | No repackaging at all; signature unchanged | Preferred route: do every small change at runtime first | When the target has CRC/anti-hook, handle them together (`../12-bypass/bypass-playbook.md` Section 2.12) |
| PMS spoofing (Java) | Hook `getPackageInfo`; the GET_SIGNATURES branch returns the vendor's original Signature object (bytes extracted from the original APK) | Ready-made code in area 02 `../02-frida/java-layer/storage-and-system.md`, the PMS signature-forgery section | Native self-hashing detection sails right past the Java layer |
| openat/read/fstat feeding the original package (native) | fd-level redirect: any open of its own base.apk is repointed at the original APK file | One framework simultaneously solves maps/status/net/tcp and other file-class detections (bypass decision Section 2.9) | When svc calls directly, libc hooks fail; inode/size/mtime must all match |
| Patching the validation function itself | Unpack -> locate -> NOP | Locating methods in Section 3.4 | Repackaging again triggers output signatures (Section 3.1) - a chain; handle it link by link |
| Signature-bound-key type (DexProtector family) | Signature/code content feeds key derivation | **Abandon runtime combat; go offline derivation** (`../04-evasion/rasp-bypass.md` Section 2.3) | The more you bypass the worse it gets - all-green symptoms but garbled business data |

**Ordering law**: if it can be dynamic, don't re-sign -> if re-signing is mandatory, prepare the PMS + feed-original-package double insurance first -> if validation is native, locate and patch directly -> if key-bound, go offline immediately.

### 3.4 Validation-Function Locating Quick Reference (static search patterns)

- **jadx/source level**: `rg "GET_SIGNATURES|signatures\[0\]|toCharsString|getPackageInfo"`; then layer on `MessageDigest`+`SHA-256` combos; in obfuscated packages, reverse-search call sites of `getPackageInfo` (the androguard `find_methods` xref template in `tool-field-notes.md` Section 4.3);
- **smali level** (degrade when jadx fails): search the constant `0x40` (the GET_SIGNATURES value, 64) and `Landroid/content/pm/Signature;->toCharsString`;
- **native level** (r2/IDA): string-search `APK Sig Block 42` (V2 validators), `META-INF`, `X509`, `EVP_Digest`, xrefs of `CERT.RSA`; java constant-pool strings (hex certificate-hash strings) are equally searchable - **a hardcoded hash string is itself the best locating anchor**;
- **Dynamic locating**: hook `getPackageInfo`, print the call stack, walk back to the verdict function, then patch the verdict point (cheaper than hooking every comparison function; aligned with the "verdict-function-first" law of `../12-bypass/bypass-playbook.md` Section 2.5).

### 3.5 Standard Operating Sequence (the detection meaning of each step)

```bash
# 1) Unpack (detection meaning: none — this step is zero-detection; the artifacts are what's dangerous)
apktool d -f -o work/ target.apk

# 2) Edit smali / inject so (gadget embedding happens in this step)
#    The injected so goes into lib/arm64-v8a/, renamed and de-signatured (§1 gadget row)

# 3) Recompile
apktool b work/ -o patched_unsigned.apk
#    Detection meaning: from here the output carries every §3.1 signature (timestamps/arsc reorder/dex changes)

# 4) Align (skip it: targetSdk≥30 + extractNativeLibs=false fails the install outright)
zipalign -f -p 4 patched_unsigned.apk patched_aligned.apk

# 5) Re-sign (V1+V2, or V2 only for minSdk≥24)
apksigner sign --ks my.keystore --out patched.apk patched_aligned.apk
#    Detection meaning: signatures[0] necessarily changes from here → have the §3.3 double insurance ready before installing

# 6) Verify self-check (mandatory before installing)
apksigner verify --print-certs patched.apk
```

Sequence key point: step 3 is the "point of no return" - every later step deepens the output signatures; everything that "can be done without repackaging" (logic a hook script can change) should be stopped before step 3. uber-apk-signer merges 4/5 into one; don't use default keystore filenames/aliases (default aliases are weak fingerprints too).

## 4. Four-Layer Modding Methodology (general, applies to any tool)

> The detection-layer theory (the bypass layer must be >= the detection layer) is in [`../12-bypass/bypass-playbook.md`](../12-bypass/bypass-playbook.md) Section 4.2; this section adds the **attacker's tool-lifetime** angle: modding is fundamentally buying time.

| Layer | Means | Tools/examples | Cost | Survival | Detector counter-play (how signature libraries chase) |
|----|------|------|------|------|------|
| **L1 deployment layer** | Rename/path/port/startup timing | frida-server renamed and re-ported; tcpdump moved; adb wireless re-port; spawn to grab early timing | Minutes | Short: mainstream risk-control SDKs never matched the strings in the first place - they scan behavior | Nearly zero cost - upgrade "process-name matching" to "rwxp/thread count/timing"; the signature library need not even update |
| **L2 binary layer** | String/symbol patching (same-length) | LIEF/patchelf/010 Editor/hex edits of signature strings inside so and server; strip symbols; patch default-port bytes | Hours | Medium: as long as your strings are private and un-leaked, their hashes never enter a library; but binary structural signatures (section layout/import table) don't change | Chase the **shape**, not the strings: rwxp anonymous segments, gum thread behavior, injection timing; or dragnet-scan every non-whitelisted so |
| **L3 source layer** | Self-compile with signature edits | frida self-compiled per the source-file checklist (Section 2.2); VirtualApp white-labeling; self-built injectors | Days | Long: a private build's hash has never been public; **but behavioral signatures don't vanish by compiling** | Same as L2 - shift to behavior/shape-layer combat; which shows modding is inherently useless against "shape-type detection" |
| **L4 replacement layer** | Swap for an equivalent tool | server<->gadget<->Zygisk-Frida<->LSPosed<->unidbg (Section 2.4); Charles<->mitmproxy with self-signed CA; adb<->on-device agent (lamda); tcpdump<->PC passive listening | Per tool (hours~days) | Lane change: different tools have different signature families, and the other side must build a new family; unidbg/static = permanently exempt | Rebuild a signature library per new tool family (that is the value of tool diversity) |

### 4.1 Per-Layer Operating Points

- **L1**: always do it first - it doubles as a **probe**: if symptoms persist after rename + re-port, the detection isn't at the process-name/port layer; jump straight to the deeper paths of Section 2.2 and save the waste of endless L1 tuning (aligned with the triage in `../12-bypass/bypass-playbook.md` Section 1.0);
- **L2**: same-length is the iron law (a lief string-patch script skeleton is in `../04-evasion/frida-anti-detection.md` Section 1.3); symbol renames must be **synced as a set** across client/server (RPC depends on symbol alignment); after patching, regression-test core functionality on your own box before going in;
- **L3**: set the build environment up once and reuse it long-term; manage patches in git for easy upstream rebases - frida's signature locations drift every release, and the strongR patch doesn't apply cleanly forever;
- **L4**: before converting, use a Section 2.1-style "form x signature" mini-table to ask what the new form's detection surface is (any replacement tool can be decomposed with Section 1's three columns).

### 4.2 Four Conclusions

1. **Modding buys time, not permanence**: L1~L3 all work only against "signature-matching" detection; against shape-type (rwxp/sensor entropy/timing) and svc-level detection, string modding is meaningless - only L4 form changes or going offline help (aligned with the detection-layer iron law of bypass decision Section 4.2).
2. **Layered combos are the most durable**: L1+L2 (rename + private string edits) is the cost/benefit sweet spot - one minute of deployment blocks the outer layer, hours of binary work blocks the string libraries; bring out L3 only after they actually update their string library; don't jump to self-compiling from the start.
3. **Private and un-leaked is the precondition for L2/L3 survival**: once a patched binary spreads publicly, it enters the signature libraries within days. Keep it to yourself.
4. **The detector's escalation direction is constant**: strings -> shapes -> behavior -> server-side cross-checks. Decide which layer your modding stack will hold before entering; cross-check against the resource dimension (no root/rooted/kernel/offline) in `../12-bypass/bypass-playbook.md` Section 3.

### 4.3 Opponent Tiers and Expected Modding Lifetime

| Opponent type | Signature-library shape | L1 rename/re-port | L2 private string edits | L3 self-compile | Conclusion |
|------|------|------|------|------|------|
| Indie-developer app (self-written detection) | Hardcoded strings/ports | **Usually already enough** (they only wrote those few ifs) | Overkill | Overkill | If L1 doesn't kill it, stop tinkering |
| Commercial packers/risk-control SDKs (Bangcle/Yidun/Shumei families) | Cloud rules + multi-signal, not dependent on specific strings | Nearly useless (they don't check names) | Medium lifetime (string-family updates roughly track major versions) | Long, but rwxp/timing behavioral signatures remain | Go straight to Section 2.1b form selection + clean the environment layer first; mod only the memory strings |
| Custom RASP (key-bound/self-destructing) | Detection coupled to business logic | Meaningless | Meaningless | Meaningless | The only solution: offline derivation/unidbg (Section 5) |

How to gauge the opponent tier: black-box differential testing of the same app version on a tool-free device vs a tooled device (basis three in `../12-bypass/bypass-playbook.md` Section 4.1); SDK names in popup copy/crash logs are also direct clues.

## 5. The "Zero Detection Surface" Tool List and Its Boundaries

### 5.1 The List (structurally exempt)

| Tool | Why it can never be detected |
|------|------|
| jadx / r2 / androguard / DexKit / the whole static family | Pure PC offline analysis; no contact channel with the target (`static-analysis-tools.md`, `tool-field-notes.md`) |
| unidbg / unicorn | Offline emulated execution - the detection code is just ordinary instructions being emulated: skip them, patch them, or never call them (`emulation-frameworks.md`) |
| wireshark passive listening (PC/middle-AP side) | Captures without injecting or altering flows; the target perceives nothing; HTTPS being ciphertext is a capability boundary, not a detection surface |
| frida CLI/python body | Installed on the PC; zero device footprint (the device-side server/gadget it depends on excepted, Section 2.1) |

### 5.2 Decision Law: Go Offline Whenever You Can

```
Got the target
├─ Is the target an algorithm (signing/encryption/token generation)?
│    → unidbg first: zero detection + skips every adversarial layer, restores the algorithm in one step
│      (scenario judgment: Scenario E in tool-master-table.md; environment-stubbing pitfalls: emulation-frameworks.md)
├─ Is the target understanding logic / finding detection points?
│    → the static trio (jadx locating + androguard xref + r2 on the so); dynamic only for verification
│      Pay the adversarial cost only at the verification moment — and count the items to pay via §1 first
└─ Dynamic is mandatory (anti-dump packers/timing-dependent/strongly interactive)?
     → Enter combat: clean the environment layer first (the root-and-environment-hiding §5.2 order)
       → pick the injection form with the lowest detection surface (§2.1, select right-to-left)
       → every tool placed on the device = a newly opened detection-surface bill; list it via §1 before entering
```

Three hard laws:
1. **Dynamic is a paid item**: every placement (server/gadget/proxy/root) is a newly opened detection-surface bill;
2. **Offline artifacts can still strike back**: an algorithm restored via unidbg can be replayed offline, but protocol signatures (JA3/timing) still need aligning with the official client (`../04-evasion/device-fingerprint-risk.md` Section 9.1);
3. **Zero-detection tools' artifacts lose the zero-detection property** (the boundary in the next section).

### 5.3 Boundary Exceptions (don't misread "zero-detection tool" as "zero-detection operation")

- **Repackaged outputs get detected**: the static tool itself is zero-detection, but its output (the APK) falls under every signature in Section 3.1/Section 3.2 - the detection surface migrates from tool to artifact;
- **mitmproxy active mode has signatures**: transparent/reverse modes still insert into traffic + self-sign certificates; the CA and iptables chains are detectable surfaces; the only truly zero-detection capture is passive listening (for plaintext/non-TLS protocols);
- **wireshark on-device (via tcpdump/pcap)**: back to the root+process surface, no longer zero-detection;
- **unidbg calling "networking functions"**: the moment the emulated environment actually sends packets, the egress IP/TLS fingerprint (JA3/JA4) enters the server-side risk-control view - reuse the self-check list in `../04-evasion/device-fingerprint-risk.md` Section 9.1;
- **Zero detection != zero traces**: cloud devices/rented hardware carry their own fingerprints and history; however clean your tools, the device itself may be blacklisted - verify by switching devices (`../12-bypass/bypass-playbook.md` Section 5 row 20).

## 6. Scenario Combo Configurations (minimal detection-surface ratios)

Recommended stacks and "bill counts" for four typical scenarios - count each tool's detection surface via the Section 1 table; combination principle: **every newly opened surface must buy equivalent capability**.

### 6.1 Cloud Device / root-free Bare Device (the fewest payable surfaces)

| Need | Choice | Surfaces paid |
|------|------|------|
| hook | frida-gadget repackaging (so/config fully renamed) | The full repackaging chain (Section 3) + gadget memory signatures |
| Capture | mitmproxy self-signed CA + transparent proxy (a root-free device can't iptables -> system proxy only, or relay at the router) | proxyHost signature + CA signature (post-self-signing, only the enumeration surface remains) |
| Automation | adb (uiautomator) | adb_enabled/USB state |
| **Total** | | 3 surfaces, all suppressible with L1/L2; the memory-layer signature is the only hard surface |

### 6.2 Local Rooted Device (the most common)

| Need | Choice | Surfaces paid |
|------|------|------|
| Root itself | Magisk+Zygisk+Shamiko whitelist+HMA+resetprop | Collapsed to mount-topology statistics + prop leftovers |
| hook | Zygisk-Frida + strongR-family agent | Only the three memory rows remain (Section 2.1b rows 5~7) |
| Capture | iptables transparent proxy + self-signed CA | No proxyHost surface; the CA enumeration + pinning wall remain |
| Automation | Wireless adb re-ported, or lamda | Just the adb_enabled item (lamda swaps in its own server surface, white-labelable) |
| **Total** | | Memory layer + environment leftovers - already near the userspace limit; beyond that only kernel (KPM) or offline |

### 6.3 Finance-Grade Stubborn Targets (the thickest detection stacks)

The order is `root 与环境隐藏.md` Section 5.2: KSU/APatch (naturally clean environment) -> Zygisk-Frida/LSPosed, pick one (pick one signature family) -> layered pinning scripts -> **risk-control leftovers handled by restraint** (if behavioral fingerprints can't be contained, don't force it). The detection-surface bill is no longer the point - the point is "even if you pass, don't operate at high frequency"; server-side behavioral clustering doesn't care which tools you use.

### 6.4 Pure Algorithm Restoration (zero bill)

unidbg offline + jadx/r2 static locating + frida only briefly, for dynamic parameter verification (withdraw after verifying) - the detection surface exists only during the verification window. Once the algorithm is in hand for offline replay, walk the JA3/timing boundary of Section 5.3.

**Stack-selection mnemonic**: first ask "can this job go offline" (Section 5.2) -> if not, ask "how many surfaces are avoidable" (Section 2.1b) -> suppress the remaining surfaces in layers per Section 4 -> the last row that won't yield (memory/svc) goes to form conversion or the kernel chapter (area 07).

## Cross-References

- Full detection-principle map: [`../04-evasion/detection-landscape.md`](../04-evasion/detection-landscape.md); frida counter-techniques and code: [`../04-evasion/frida-anti-detection.md`](../04-evasion/frida-anti-detection.md); root hiding stack: [`../04-evasion/root-env-hiding.md`](../04-evasion/root-env-hiding.md)
- Bypass selection and the detection-layer iron law: [`../12-bypass/bypass-playbook.md`](../12-bypass/bypass-playbook.md) Section 2/Section 4; ready-made Java code for signature bypass: area 02 `../02-frida/java-layer/storage-and-system.md`, PMS signature-forgery section
- Tool usage (not given in this page): `tool-field-notes.md`, `tool-master-table.md`, `dynamic-hook-frameworks.md`, `emulation-frameworks.md`; capture adversarial: [`../04-evasion/capture-all-scenarios.md`](../04-evasion/capture-all-scenarios.md) Section 2.5
- When refreshing this page, cross-check: every signature name in Section 1 stays consistent with area 04's latest conclusions; the Section 2 signature list updates with the strongR patch set; Section 3 output signatures get re-verified against apktool major versions (aapt2 behavior).
