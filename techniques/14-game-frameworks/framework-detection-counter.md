# Mobile-Game Framework Detection and Countermeasures

> Positioning: the game-specific detection layers **stacked on top of ordinary app detection** in mobile-game scenarios — engine integrity self-checks, in-game risk control (behavior collection), hardened emulator/environment detection — plus confrontation boundaries and risk statements.
> Division of labor: general detection principles (frida/root/anti-debug/RASP down to the syscall layer) are all in `../04-evasion/detection-landscape.md`; this piece **does not duplicate them** — it covers only what is game-specific and points the way. The per-framework reversing main workflows are in the first three pieces of this directory.

## 0. Layered Overview: What Game Detection Adds over Ordinary Apps

```
Ordinary app detection stack (all in detection-landscape.md):
  anti-debug / root / frida / Xposed / proxy / RASP
        ↓ three game-specific layers then stack on top
  ① engine integrity self-checks (this piece §1): metadata/so/pak/script hashes and reconciliation
  ② in-game risk control (this piece §3): input-stream/timestamp behavior collection + server-side statistics
  ③ hardened environment detection (this piece §4): emulator checks use sensor entropy and GPU fingerprints — far harsher than ordinary apps
Concrete form: commercial anti-cheat SDKs (ACE/Yidun class) often cover all three layers, with detection logic in the native + svc layers
```

The fastest way to tell which layers a given game uses: grab logcat and so strings (`strings lib*.so | grep -i -E "emulator|root|frida|integrity"`), plus APKiD to identify packer/anti-cheat SDK fingerprints (`../05-toolbox/recon-and-specials.md`).

## 1. Engine Integrity Self-Checks (by framework)

### 1.1 Unity / IL2CPP

| Detection point | Means | Countermeasure |
|---|---|---|
| `global-metadata.dat` hash | computes the file hash at startup and reconciles against the built-in / server-delivered value | Do not modify the file — dump from runtime memory (unity-il2cpp.md §3.3; the Zygisk version passes naturally) |
| libil2cpp `.text` section hash | reads `/proc/self/maps` for the base and verifies the code hash page by page | an inline patch that triggers re-verification gets you dropped; hook the verification function itself (locate via hash constants + the comparison loop in the so) |
| Memory-dump trapping | deliberately leaves fake metadata on low-permission pages; reading it flags you | when multiple candidates turn up, filter by structural plausibility (the §3.1 field cross-validation) |
| mono-injection detection (legacy form) | scans IL-injection/hook signatures | same as frida anti-detection confrontation |

Filesystem-layer integrity reads may go through direct svc calls (openat) that user-mode libc hooks cannot intercept — layer determination and bypasses all follow the difficulty table in detection-landscape.md §0.

### 1.2 UE

- pak/utoc manifest + hash reconciliation (modifying the package = detected in seconds); the AES key and manifest fingerprint are delivered server-side;
- Countermeasure: do not modify the client; read only, never write (unpacking analysis is done offline on the PC, naturally traceless); runtime memory patching follows the same idea as il2cpp — locate the FAES/manifest-verification functions inside libUE4.so.

### 1.3 Cocos / the Script-Hot-Update Family

- Per-file hashes of lua/jsc scripts (the script layer is hot-update-delivered; the server can swap algorithms at any time);
- Countermeasure: do all analysis offline (decrypt script files on copies); in-game only hook engine APIs and never touch disk;
- The hooks used while locating the xxtea key (route 3 in ue-cocos.md §3.2) only read arguments in onEnter and never write memory — the smallest detection surface.

### 1.4 Flutter / RN

- `libapp.so`/`index.android.bundle` hash self-checks (rare in games, common in finance shells);
- Business risk control is mostly server-side (§3); client-side integrity detection is weaker than the Unity family.

## 2. root / Jailbreak / frida Detection: Reuse Directly

Games and ordinary apps use the same detection function libraries (vendor-SDK wrappers), so **the bypasses are reused wholesale**:

- root/environment hiding: `../04-evasion/root-env-hiding.md` (Magisk+Shamiko/KSU/APatch; games also use finance-grade detection stacks);
- frida-signature confrontation: `../04-evasion/frida-anti-detection.md` (change signatures / take the gadget underground);
- RASP/commercial hardening: `../04-evasion/rasp-bypass.md`;
- Fallback decisions after hooks are killed: `../12-bypass/bypass-playbook.md` (the detection layer decides the minimum viable bypass).
- The one game-specific difference: detection often runs in a **standalone anti-cheat process/service** (dual-process mutual guarding); killing the guard process is easier than hooking detection functions — check for companion processes first:

```bash
adb shell ps -A | grep <package>          # Companion processes such as com.xx.game:guard or :sec indicate an anti-cheat component
adb shell ps -A | grep -i -E "ace|sec|guard|protect"
# Companion-process shared-object names often include these terms: ls /data/app/*/com.xx.game*/lib/arm64/
```

The standard playbook of companion mutual guarding (process A detects the environment, process B verifies A is alive) has its principle in the anti-debug section of detection-landscape.md; on the game side it is just wrapped in a shell process.

## 3. In-Game Risk Control (Behavior Collection) — the Layer Reverse-Engineering Tools Cannot Detect

### 3.1 Input-Stream Collection

Client and server record in sync: touch-coordinate sequences, press area/pressure, multi-touch timing, swipe curvature. Machine signatures expose themselves directly:

- Emulator mouse: pressure always 1.0, size always 0, trajectories spliced from straight segments;
- Scripted taps: intervals follow a perfectly periodic distribution (humans are approximately log-normal);
- Countermeasure idea: at the injection layer the play is not "alter detected values" but "generate humanized input" (duration jitter / Bezier trajectories) — that is gray-market tooling territory; in a security-research context you only need to **identify the collection points** to prove the risk control exists:

```js
// Observe which input dimensions the client actually collects
Java.perform(() => {
    const ME = Java.use("android.view.MotionEvent");
    ME.obtain.overloads.forEach(o => o.implementation = function () {
        const e = o.apply(this, arguments);
        try { console.log(`input t=${e.getDownTime()} p=${e.getPressure()} sz=${e.getSize()} x=${e.getX()}`); } catch (_) {}
        return e;
    });
});
// Native engines that read input queues directly, common in Unity/UE, are invisible at the Java layer; hook AInputQueue_getEvent
```

### 3.2 Timestamps and Rhythm

- Key operations are reported with `clock_gettime(CLOCK_MONOTONIC)` stamps; reaction times below the human distribution (<80ms) or resource-growth rates beyond theoretical values get flagged;
- Battle replay: the server stores the operation stream for replay verification — "values plausible but operations impossible" still gets banned.

### 3.3 Server-Side Statistics

Drop rates / damage / economic output get server-wide distribution statistics; the long tail gets audited — **this layer has no client-side counter-surface**, which is why the single-player approach (§5.1) fails completely in online games.

The generic way to locate collection/report points: capture and inspect heartbeat/log endpoints (if encrypted, go back to the algorithm layer per `../04-evasion/capture-all-scenarios.md` §2.9), or hook the engine-layer entry points from the first three pieces and watch the report fields being assembled.

## 4. Why Emulator Detection Is Stronger than in Ordinary Apps

Ordinary apps judge emulators by properties/IMEI (already covered in detection-landscape.md §4); **game engines additionally hold two hard surfaces: sensors and the GPU**:

| Layer | Game-specific criteria | Notes |
|---|---|---|
| Sensors | **entropy analysis** of the accelerometer/gyroscope (constant values / discrete value sets / zero noise = instant death sentence) | the engine samples at 60fps, so the sample size far exceeds ordinary apps and the statistical discrimination is harsher |
| GPU | `GL_RENDERER`/`GL_VENDOR` showing SwiftShader/ANGLE/Translator; the Vulkan physicalDeviceName not in the real-device library | render-pipeline fingerprints + shader-compilation behavior differences |
| Performance timing | frame-time distribution, fake GPU benchmark values | the engine ships a profiler and does performance fingerprinting on the side |
| Input | the pressure/size/trajectory signatures of §3.1 | touch-device model mismatch |
| Sensor-screen consistency | the gyroscope moves but the screen perspective does not (or vice versa) | a cross-validation unique to 3D games |

Countermeasure tiers: cloud real devices (physical sensors; remaining detection same as real devices) > well-regarded emulators + device-spoofing tools; **for protocol/algorithm reversing choose real or cloud-real devices whenever possible** — leave emulators for the unpacking/static stage.

Self-check your current environment's GPU/sensor fingerprints (replicating the detection side's view):

```js
Java.perform(() => {
    console.log(Java.use("android.opengl.GLES20").glGetString(0x1F01).value);  // GL_RENDERER
    console.log(Java.use("android.opengl.GLES20").glGetString(0x1F00).value);  // GL_VENDOR
});
// SwiftShader/ANGLE/Translator on an emulator matches the second criterion in the Section 4 table
// Sensor entropy: sample the accelerometer 200 times and count distinct values; this case observed >100 on real devices and often <10 on emulators
```

## 5. Confrontation and Boundaries

### 5.1 Value Editing in Single-Player (personal research)

- Scenario: casual/single-player games with no or weak server-side verification;
- Means: the CE/field editing of unity-il2cpp.md §4.2 is all there is; no ban surface (no risk-control reporting counterpart);
- Boundary: still no distributing modified builds / no breaking in-app purchases (red lines of the legal and authorized context).

### 5.2 Online-Game Ban-Risk Statement (read this first)

- Everything that "modifies once online" (memory value edits / speed hacks / offline protocols) is within §3's risk-control range; a ban is a **certain risk**, not a probability;
- Accounts are the testing cost: use throwaway/new accounts; never touch important accounts;
- This library's context is **authorized security research**: the goal is to locate vulnerabilities / prove the risk control can be bypassed, stopping at that point — no scaling up, no distributing tools externally, no playing matches against real players.

### 5.3 Authorization and Legal Boundaries

- Legitimate landings for mobile-game reversing: your own / authorized testing, vulnerability reporting (SRC), interoperability research; bypassing anti-cheat to grind ranked matches, selling cheats, or running private servers are all out of bounds;
- The commercial anti-cheat SDK itself is a research subject, not an attack target — report its flaws through the vendor's SRC.

## 6. Troubleshooting Quick Table

| Symptom | Location | Action |
|---|---|---|
| Crashes the moment anything injects, no frida error | engine integrity (§1) or a companion anti-cheat process (§2) | kill the companion process; the Zygisk route |
| Plays for 10 minutes then disconnects | server-side statistical risk control (§3.3) | lower the operation frequency; confirm it is a statistical ban, not client-side detection |
| Emulator banned instantly, real device fine | the §4 sensor/GPU surfaces | switch to a cloud real device |
| After modifying files, startup reports asset errors | pak/metadata hash (§1) | the all-memory route; roll the files back |
| logcat has no clues | detection sits in the native+svc layers | determine the layer via detection-landscape.md §0 |

## 7. Corpus Search Terms (data/ essence index)

「某二次元开放世界冒险游戏反作弊分析报告」「腾讯游戏安全竞赛 Android 方向题解」「浅析APP代理检测对抗」「某修仙肉鸽游戏协议逆向分析折腾记录」.
