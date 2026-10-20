# Device Fingerprint and Risk Control

> Positioning: organized around "risk-control collection and forgery" — what risk-control SDKs collect, how they collect it, how the server cross-verifies, and how black-market players forge it layer by layer.
> Detection principles (how frida/root/emulator/accessibility are checked) are not repeated; see [detection-landscape.md](detection-landscape.md);
> the five-layer identifier-domain function chain (Java→binder→libc→svc→kernel) is in [../09-function-map/android-function-layers.md](../09-function-map/android-function-layers.md) §12.

## 1. Risk-control system layering

```
┌─ Client collection SDK ─┐  ┌─ Transport ──┐  ┌─ Server side ─────────────┐  ┌─ Disposal ───────┐
│ Java layer: system APIs │  │ encrypted    │→ │ decrypt → feature extract │→ │ CAPTCHA challenge │
│ Native layer: props/    │  │ upload       │  │ → device-graph normalize  │  │ downweight/rate-  │
│ files/sensors/binder    │  │ (AES +       │  │ rule engine + model score │  │ limit             │
│ env checks (inj/root)   │  │ protobuf     │  │ gang graph (dev-acct-IP)  │  │ account ban       │
│                         │  │ custom)      │  │ blacklist / trust score   │  │ device blacklist  │
└─────────────────────────┘  └──────────────┘  └───────────────────────────┘  └───────────────────┘
```
- **Collection SDKs**: in-house at the big vendors (Alibaba mtop/mtgsig, Xiaohongshu shield, Tencent vkey) or procured (Shumei/TongDun/NetEase Yidun/Dingxiang). The form is one obfuscated so + a thin Java shell; initialized at startup; before business requests it generates the token/signature + device-fingerprint string.
- **Reporting**: the collected items are serialized (protobuf/custom) then AES-encrypted with a randomized key; some fields are assembled natively (example: NetEase Yidun's libNetHTProtect.so reports 350+ fields at once, protobuf serialization + AES).
- **Server-side device graph**: multiple identifier sources are normalized into one stable device_id (changing a single identifier doesn't collapse it), maintaining a device-account-IP graph.
- **Disposal**: progressive — first a CAPTCHA challenge (slider/click), then rate-limiting/downweighting, finally account and device bans.
**The black-market confrontation points are all in "collection" and "consistency"**:
1. Alter the collected results (L1~L2 hooks) or the data sources (L3~L4 device changing);
2. Skip the client and forge the protocol outright (off-device bots) — behavioral/sensor/environment features are then all missing and must be purely faked;
3. The server's only reliable handles are **cross-consistency** and **hardware-grade proof** (Key Attestation, §8).
A PC case homomorphic with mobile: internet-cafe billing/management systems use "hardware serial numbers (CPU/motherboard/memory/disk) + membership card" as identity; the confrontation idea is likewise to modify the hardware-serial layer (on PC via WMI/registry/SMBIOS layer modifications).

## 2. The device-fingerprint collection surface — master table (core)

Organization: 6 groups by collection channel, 66 items in total (64 rows, 2 of which contain 2 identifiers each). Columns: identifier | Java entry | Native entry | stability | forgery difficulty (the cost of fooling local collection, excluding server-side cross-checks).
Function layering (L1~L5) is detailed in the 09 area's android-function-layers.md.

### 2.1 System-property class

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| ANDROID_ID | `Settings.Secure.getString(ANDROID_ID)` | SettingsProvider binder / XML | Android 8.0+: isolated per app+signature+user; changes on factory reset | low (hooking L1 suffices, but must stay in sync with the SettingsProvider DB or it gives you away) |
| Build.SERIAL | `Build.getSerial` (10+ privileged) | the `ro.serialno` property area | immutable (hardware) | medium (modify the property shared memory; see 09 area §3) |
| Build.FINGERPRINT/MODEL/BRAND etc. | `Build.*` static fields | property-area snapshot (at boot) | ROM-inherent | low-medium (change both domains together; see the 09 area §10 note) |
| ro.* generic props | `SystemProperties.get` (reflection) | `__system_property_get` / self-mmap `/dev/__properties__` | most read-only | low (hook) → high (app self-mmap parsing; only memory can be changed) |
| ro.boot.serialno | same | property area | immutable | medium |
| Vendor-private props (ro.ril.oem.imei/persist.sys.*) | same | property area | immutable | medium; forging this value on old devices can revive a banned device (case: community post, see §5) |
| ro.boot.vbmeta.digest / verifiedbootstate | same | property area | bound to the boot image | high (tied to BL-lock state; even resetprop changes won't pass attestation) |
| IMEI | `TelephonyManager.getDeviceId/getImei` | ITelephony binder → phone process → RIL → modem | immutable | local change: low; consistency: extremely high (the modem side cannot be changed) |
| MEID | same | same | immutable | same |
| IMSI | `getSubscriberId` | same | changes with SIM swap | high (the server can cross-check with the carrier) |
| ICCID/SIM state | `getSimSerialNumber` | RIL | changes with SIM swap | high (risk control watches the "card-device binding" graph) |
| MAC address (wlan0) | `WifiInfo.getMacAddress` | `getifaddrs` (netlink) | Android 6+ returns 02:00:00:00:00:00 | low (but "the correct randomized value" is itself a consistency checkpoint) |
| Bluetooth MAC | `BluetoothAdapter.getAddress` | binder | Android 6+ randomized | low |
| OAID | MSA unified SDK / vendor SDK (Huawei HMS Ads Kit etc.) | vendor-private binder/content provider | resettable (in settings / factory reset); generated at first launch | medium (the domestic IMEI replacement's primary identifier; SDK details in §5.2) |
| VAID/AAID | vendor SDK | same | mutable (app-set/developer-scoped) | medium |
| DRM ID (Widevine) | `MediaDrm.getPropertyString("deviceUniqueId")` | dlsym libmediandrm → WVDrmPlugin (vendor process) | immutable (TEE side) | extremely high (produced in init/vendor process; see the community post §4) |
| boot_id | no Java API | read `/proc/sys/kernel/random/boot_id` | changes every reboot | a session identifier used to cross-check "uptime"; changeable with a kernel hook (APatch KPM) |
| soc serial / emmc CID | none | `/sys` nodes (paths vary per vendor) | immutable | high (root; scattered paths; collectors adapt per vendor) |

### 2.2 Hardware class

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| CPU model/hardware name | `Build.HARDWARE` | the `/proc/cpuinfo` Hardware field | immutable | medium |
| CPU core count/frequency | `Runtime.availableProcessors` | `/sys/devices/system/cpu/` | immutable | medium |
| Total memory | `ActivityManager.MemoryInfo` | `/proc/meminfo` | immutable | medium |
| Sensor list (model enumeration) | `SensorManager.getSensorList` | binder → sensorservice | immutable | medium (the list is compared against a model database) |
| Accelerometer calibration bias | `onSensorChanged` sampling | `ASensorEventQueue` (libandroid) | hardware-inherent (factory calibration error) | extremely high (noise/entropy features are hard to fake; Anquanke's "device fingerprint guide" series + Sensor ID research) |
| Gyroscope/magnetometer noise | same | same | hardware-inherent | extremely high |
| Battery (serial/health/charge-cycle count) | `BatteryManager` EXTRA | `/sys/class/power_supply/` | semi-mutable (aging) | medium |
| Screen density/resolution/refresh rate | `DisplayMetrics`/`Display` | properties + SurfaceFlinger | immutable | low |
| GPU fingerprint (GL_VENDOR/GL_RENDERER/extension table) | `GLES20.glGetString` | EGL/libEGL | immutable | medium (cross-checked against the model database; a wrong write gives you away) |
| Input-device list (touch IC) | `InputDevice.getDeviceIds` | `/proc/bus/input/devices` | immutable | medium |
| Clock skew | `System.currentTimeMillis` | vDSO (note: no svc involved; 09 area §9) | crystal-inherent | high |
| modem/baseband version | `Build.getRadioVersion` | gsm.version.baseband property | firmware-inherent | medium |

### 2.3 Network class

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| Egress IP | — | — | mutable (proxy/network change) | — (server-side view; IP reputation DB + datacenter-range detection) |
| WiFi BSSID/SSID | `WifiInfo.getBSSID` (9+ restricted in background; needs location permission) | binder wifi service | changes with movement | low (but BSSID-to-geolocation lookup is a strong signal) |
| DNS servers | `LinkProperties.getDnsServers` | netd | mutable | low |
| NIC interface list | `NetworkInterface.getNetworkInterfaces` | `getifaddrs` (netlink RTM_GETLINK) | semi-fixed | low (hook getifaddrs and change uniformly; 09 area §2) |
| VPN tun0/ppp0 | `ConnectivityManager.hasTransport(TRANSPORT_VPN)` | getifaddrs | — | medium-high (see detection-landscape.md §5.1) |
| Carrier MCC/MNC | `getNetworkOperator` | RIL | changes with SIM/network | medium |
| TCP fingerprint/port behavior | — | kernel-stack parameters (TTL/MSS/window) | OS-inherent | high (cross-checked against the declared model's OS version) |

### 2.4 Environment class

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| Installed-app list | `getInstalledPackages` (11+ constrained by package visibility, `<queries>` declaration) | binder PackageManager | mutable | low (hook L1; strong SDKs go raw binder/queryIntentActivities to cross-check) |
| Accessibility-service state | `Settings.Secure.ACCESSIBILITY_ENABLED` | settings XML | — | low-medium (detection domain; see detection-landscape.md §5.3) |
| Timezone | `TimeZone.getDefault` | property persist.sys.timezone/TZif | mutable | low (cross-checking with IP geolocation is an old check) |
| Language/Locale | `Locale.getDefault` | properties | mutable | low |
| Font list/rendering traits | no public API | `/system/etc/fonts.xml`, pixel-level measureText traits | ROM-inherent | medium |
| SD-card file seeds | `File.listFiles` | getdents64+stat | covert persistence (survives uninstall/reinstall) | extremely hard to notice |
| Install paths of WeChat and other apps | `getPackageInfo`/probing | getdents64 /data/app | randomized at install time | medium |
| /data partition file timeline | — | stat (atime/mtime/ctime+inode), directory-tree hash over a fixed 6+ directories | evolves with use | high |
| Input-method list | `InputMethodManager` | settings provider | mutable | low |
| SELinux context/mode | — | `/proc/self/attr/context`, getenforce | — | — (detection domain) |
| Bootloader unlock state | properties | a 6-prop combination (verifiedbootstate/unlock etc.) | immutable | high |
| ROM/system framework jars | — | properties + framework file CRC | ROM-inherent | high |
| Clipboard/account list | `AccountManager.getAccounts` | binder account | mutable | medium |

### 2.5 Behavioral class (the off-device bot's biggest tell)

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| touch event sampling (pressure/contact area/trajectory) | `MotionEvent.getPressure/getSize` | InputChannel recvmsg (system_server → app socketpair) | a human-inherent trait | extremely high (synthetic trajectories lack physical continuity) |
| input cadence (dwell/flight time) | text-input events | same | behavior-inherent | extremely high |
| getevent raw event sequence | none | `/dev/input/eventX` (type/code/value sequences uploaded for backend AI classification) | device + human | extremely high (AI detects simulated taps) |
| sensor-behavior correlation (pick up phone → acceleration fluctuation → screen on → touch) | multi-source event streams | sensorservice+InputChannel | physical consistency | extremely high (a script touching the screen with a silent accelerometer = a giveaway) |
| step-count accumulation | TYPE_STEP_COUNTER | sensorservice HAL | physically cumulative | high (cross-day continuity) |
| gyroscope micro-tremor (8-12Hz hand tremor while held) | onSensorChanged | same | a physiological trait | extremely high (community biometric-probe post + Sensor ID research) |

### 2.6 Application class

| Identifier | Java entry | Native entry | Stability | Forgery difficulty |
|------|------|------|------|------|
| APK signature | `PackageManager.GET_SIGNATURES` | self-parsed base.apk ZIP certificate (bypasses the Java hook) | immutable | — (repackaging detection) |
| Package name/versionName/versionCode | `getPackageInfo` | same | — | — |
| firstInstallTime/lastUpdateTime | `getPackageInfo` | stat | timeline | medium (device-age evidence) |
| /data/data directory structure (SDK layout) | — | getdents64 | target-app-inherent | medium |
| xposed/frida file traces | File.exists | filesystem walk (su/magisk/framework paths) | — | — (detection domain; see detection-landscape.md §2/§3) |
| remote-control components (minicap/minitouch/stf) | package names + files | files + processes | — | medium |
| device-changer package names/device nodes | package probing | private nodes like `/dev/wgzs` | — | medium |
| emulator files/properties/mount points | properties | qemu pipe files + mounts | — | — (see detection-landscape.md §4) |
**Collection-table mindset** (walk it item by item when confronting):
1. The same identifier has **at least two places of origin** (Java cache/property area/binder server/vendor process); changing only one always gives you away (09 area §13, rule 7);
2. The more stable the identifier (immutable + hardware-inherent), the higher the server-side weight, and the worst the cost-benefit of changing it;
3. Behavioral items cannot be "changed", only "produced" — this is the watershed between off-device bots and device-changers;
4. The collection SDK is itself a detector: environment-check fields and fingerprint fields are reported in the same package.

## 3. Consistency checks (how risk control catches forgeries)

The risk-control server doesn't bet on any single point; it relies on **cross-checking**. Seven classes of forgery-catching:
1. **Multi-source cross-checks**:
 - IMEI against the vendor's cloud records (phone swapped but not the SIM / card-device binding graph);
 - ANDROID_ID against the SettingsProvider database (changed the in-memory return but not the DB; a second query gives you away);
 - Build properties double-read against the property area inconsistent (09 area §10);
 - sensor list/GPU extensions against the model database (a budget phone reporting a Snapdragon-8-series GPU = busted; Anquanke's "device fingerprint guide");
 - CPU/memory/screen against the Build.MODEL whitelist.
2. **Timelines**: new device + old account + first-order discount; boot_id session duration vs claimed uptime; the contradiction of SD-card seed-file mtimes earlier than the "factory-reset time" (used in reverse: seed-file mtimes are evidence of "true device age"); firstInstallTime vs account-registration time.
3. **Sensor silence**: automation has no accelerometer fluctuation; a human hand touching the screen always carries micro-tremor (gyroscope 8-12Hz) and pressure that ramps along the swipe; script touch pressure constant + sensors still (suggested that detectors sample environment-event reports at a 1/9 ratio).
4. **GPU/driver fingerprints**: GLES extension order, shader precision, EGL version strings, render-result hashes (canvas hash) — compared against the model database; cloud real-devices/device-changers most easily slip on this one (web-side canvas fingerprinting is the same technique).
5. **Protocol side**: request timing perfectly even-spaced, no human thinking pauses; missing heartbeats; TLS/HTTP fingerprint not the official client (§9 JA3).
6. **Challenge-response**: when risk control is suspicious it issues a CAPTCHA (§6) or an attestation challenge (§8); a failed answer = device blacklisted.
7. **Gang graphs**: clustering by same IP range/same WiFi BSSID/same charging pattern/behavioral-sequence similarity — however well one device is disguised, a farm of structurally identical devices still gets circled by graph algorithms.

## 4. Forgery-strategy layers (L1~L4)

| Layer | Means | Cost | Survival rate | Typical detection means |
|------|------|------|------|------|
| L1 change data sources | Xposed/frida hook Java APIs to return fake values | extremely low (script-grade) | low | native-layer cross-checks (direct property-area reads/raw binder/self-parsed apk); hook-trace detection (detection-landscape.md §2/§5.2) |
| L2 change the native layer | hook libc/__system_property_get/modify the property shared memory/GOT hooks/inject so | medium (needs RE skill) | medium | function-prologue CRC, maps scans, svc direct file reads, string scans (detection-landscape.md §2.6/§2.9; the downgrade chain in the 09 area's hook-fallback-playbook.md) |
| L3 real multi-instance/device-changer tools | AWZ/ALS, RshMod (Magisk+LSPosed module), sandbox multi-instance, remote-control farms, Bit-fingerprint phones | medium (tool procurement) | medium | device-changer package names/private device nodes (e.g. /dev/wgzs); sandbox filesystem differences; framework jars mismatching the model; sensor consistency |
| L4 custom ROM/kernel injection | self-built ROM changing properties; APatch KPM kernel-hooking sysctl_bootid; init/vendor-process ptrace injection changing the DRM ID; mount --bind IO redirection for one-device-many-accounts; "leave no trace on the client; modify at the point of origin" | high (kernel-grade engineering) | high | server-side hardware proof (Key Attestation §8); vendor-cloud cross-checks; timeline statistics |
L4 is the central thesis of the community post:
- Five points of origin: system_server (hook SettingsProvider.call to change android_id, hook PackageManager to hide packages), **other APKs** (Xiaomi's OAID lives inside apps like com.miui.idprovider), kernel IDs (boot_id, APatch KPM), the init process (the DRM ID originates in android.hardware.drm@1.3-service.widevine; ptrace-inject the vendor process), the property area;
- Zero client injection: hook nothing in the target app; the traces vanish naturally;
- One device, many accounts: `mount --bind` IO redirection over /data/data/<package> and SD-card directories, giving each "account" its own data view;
- Real-world constraint: new kernels with closed-source drivers (Xiaomi etc.) make self-built kernels a dead end; APatch/KPM is the currently viable kernel path (picked up by kernel-hook-stealth.md in 07-kernel);
- Reverse advice (from the detector's viewpoint): ship a static libc, avoid std::string (a strlen hook kills all), fetch single fields in multiple forms, 1/9-ratio environment checks, anomalous logcat reporting.
Physical layer: dual-SIM dual-standby real-device farms / device farms / humans (captcha solving) — protocol traits indistinguishable from real devices; caught only by graphs + behavioral clustering (§3.7).

## 5. Risk-control SDK case index

### 5.1 Alibaba mtop / mtgsig / SecurityGuard

- mtop is Alibaba's wireless gateway protocol; the signature headers x-sign (x-mini-wua/x-sgext/x-umt etc.) are computed by the SDK's native so; umidtt (the device-fingerprint string) is generated by the SecurityGuard libsgmain system.
- Meituan mtgsig (same mtop-family naming): libmtguard is a heavily obfuscated so (see vendor-capture-countermeasures.md §6).
- Related: Alibaba Cloud's Anti-Bot SDK SGAVMP — compiles the signing logic into custom bytecode running in its own VM.
- Confrontation essentials: x-sign generation is in so; unidbg/emulated execution is the mainstream restoration path; device-side changing must simultaneously fool umid collection.

### 5.2 NetEase Yidun NetHTProtect (analysis subject; vendor attribution: inferred)

350+ fields protobuf+AES (random key) encrypted reporting (`/v4/c` initialization, `/v4/a/up` upload); collection includes: SD-card statfs, DRM ID (dlsym libmediandrm), 70+ vendor props, file stat (atime/mtime/ctime/inode), a 6-directory file-tree hash, /proc/bus/input/devices, battery, GL_VENDOR/GL_RENDERER, emmc/soc serial, boot_id, the WeChat apk path, input-method list; detection includes: frida (linjector/re.frida.server signatures), Xposed, libc .text/.rodata/.eh_frame CRC checks, lineageOS/OpenHarmony, brand framework jars vs model, the 6 bootloader-unlock props, remote control (minicap/minitouch/stf), emulators (VMOS/X8/51/Virtual Elf), device-changer software (package names + /dev/wgzs), /memfd:/jit-cache (detecting LSPosed), getevent sequences uploaded for backend AI classification of simulated taps (CSDN repost u012971339/article/details/139120729).

### 5.3 Shumei (smid / Skyeye)

- The device fingerprint generates unique IDs of the smid class, recognizing emulators/device-changers/device farms; the "Skyeye" system fuses device risk + black-market intelligence graphs.
- Slider CAPTCHA: gap recognition + trajectory simulation; see §6.
- Attacker's-view review: Tencent Cloud Developer Community's "learning a certain risk-control device-fingerprint product from an attacker's perspective" (2020) — conclusion "device fingerprints are not a silver bullet"; cross-checks depend on multiple sources.
- Note: deep public analyses of the smid generation algorithm are scarce; mostly inside paid circles.

### 5.4 TongDun (Fingerprint)

Few public deep reverse analyses; the product form is Shumei-like: device fingerprint + rule engine + lists. **Conclusion left blank; fill in on real engagement.**

### 5.5 Xiaohongshu shield

- The signature header shield (formerly x-s/shield); analysis path: jadx to locate JNI_Load → IDA to analyze the native functions (signature-check functions like sub_2e1f4 can be nopped) → unidbg emulated calls.
- Open-source assembly rules: GitHub RedNote/Xiaohongshu-Shield-Algorithm (based on v9.19.2 reversing; noted to vary by version).
- The server side is the "Ares" risk control: IP rate-limiting + device fingerprint.
- Version confrontation: the shield on the app side / x-s on the web side, two tracks.

### 5.6 Tencent vkey / R-protocol family

Tencent-family risk-control SDKs (e.g. the QIM/net family): Java+Native dual-layer collection (battery/hardware/network/location), including Xposed detection and VM recognition; vkey is its terminal-security credential header.

### 5.7 Google Play Integrity (the overseas baseline)

Replaces the SafetyNet API: device integrity (verdict: MEETS_DEVICE_INTEGRITY / STRONG) + app integrity + licensing; signal sources include the verified boot state (ro.boot.verifiedbootstate, same origin as detection-landscape.md §3.3). Domestic apps don't use it, but products going overseas align to it.

## 6. CAPTCHA confrontation

The first link of the risk-control disposal chain. Four classes:
1. **Slider**:
 - Gap recognition: OpenCV `cv2.matchTemplate`/Canny edge detection to locate the gap's x coordinate (2024 field practice).
 - Trajectory simulation: fast-then-slow (ease-out) + random jitter + end-of-path rebound, modeling the human hand's acceleration curve; constant-velocity straight lines = certain death.
 - Server-side counter: trajectory entropy, starting-x jitter, device-fingerprint linkage (the same smid challenged at high frequency).
2. **Click (point-select)**: object detection (YOLO family) + OCR to read the prompt character order; OpenCV template matching for first-pass filtering.
3. **Nine-grid/icon style**:
 - CNN image classification to recognize the target class;
 - weak implementations fall to md5 image comparison/cropped-region locating (CSDN's 20 captcha-recognition ideas, 2024).
4. **Voice/SMS**: covered by captcha-solving and SMS-receiving platforms (boundary: technical overview only — human/AI solving platforms are priced to the cent, compliance red line, operational details not expanded).
**The cost equation**: recognition cost (one CNN inference/solving fee) + trajectory-library cost < the payoff of one challenge, or the black market won't play; risk control therefore tunes challenge frequency to "imperceptible to humans, unprofitable to machines". CAPTCHAs only buy time; the device-fingerprint tag is the actual disposal.

## 7. autojs / RPA detection and confrontation

**Principle**: Auto.js is built on AccessibilityService — in the `onAccessibilityEvent` callback, `rootInActiveWindow` gets the control tree and `performAction` simulates taps.
**Detection surface** (details in detection-landscape.md §5.3; only the risk-control-side usage listed here):
1. Accessibility on-state + service-name list (`Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` containing autojs/airtest etc.);
2. autojs package names/class names/script-file traits (e.g. /sdcard/scripts, the .js project structure);
3. Abnormal control-tree traversal behavior: high-frequency `rootInActiveWindow` queries, AccessibilityNodeInfo request rates beyond human;
4. Event layer: simulated-tap MotionEvents lacking pressure/area variation; getevent sequences classified by AI.
5. Cross-reference: the systematic detection/confrontation write-ups on both ends are this section and detection-landscape.md §5.3.
**Confrontation evolution**:
- Black market: change package names/obfuscate script paths → switch to direct protocol connections (skipping the UI) → root-inject `/dev/input/eventX` (sendevent/uinput);
- Detectors: WeChat 8.0.52+ control obfuscation (scrambled node ids) makes AutoJs6 unable to analyze layouts (GitHub SuperMonster003/AutoJs6 issue #463) — the business side proactively "downgrades" its UI against accessibility; offense and defense both move up to the protocol layer.

## 8. Key Attestation (hardware-grade proof)

**Principle** (official docs on developer.android.com):
1. When the app generates a key in the Keystore it specifies `setAttestationChallenge(random)`;
2. The TEE/StrongBox (KeyMint) issues an **X.509 attestation certificate chain** for that key: root (Google's hardware root) → intermediate → leaf;
3. The leaf-certificate extension carries: verified boot state, bootloader lock, ROM patch level, screen lock, **Android 8.0+ can strictly attest hardware identifiers (serial/product name/IMEI/MEID; restricted and privileged)** — the core: Android 8.0 updated the ASN.1 structure for this;
4. The server validates the chain to the Google root + checks the challenge echo + reads the device state from the extension.
**Why it is hard to forge**:
- The private key is generated inside the TEE and non-exportable; attestation can only be signed by real hardware;
- The chain is anchored to Google's hardware root CA; a self-signed chain won't validate;
- The challenge is session-bound; replay is useless;
- Linked with "the IMEI recorded into the vendor's database at factory" = the ultimate endorsement of device identity.
**Exits (black-market room)**:
1. Old devices: Android <7 has no attestation, and masses of legacy devices have only a software keymaster — detectors forcing hardware-grade would misfire, so they can only tier it;
2. Downgrade detection: fake "device unsupported" to take the software-key path; hook `KeyGenParameterSpec`/`KeyStoreGeneratorCallback` to strip the attestation flag, tricking the app into giving up hardware attestation — the open-source implementation vvb2060/bypassKeyAttestation;
3. Counter: the server compares "the claimed model should have attestation capability" with "the actual certificate chain" — a flagship suddenly "unsupported" gives itself away; the Play Integrity verdict does the same thing (§5.7).
4. Brand-new hardware trust chains (StrongBox/pixel-grade anti-downgrade) progressively shrink the exits, but until the low-to-mid-range legacy stock clears, attestation can only be a "high-value-operation strong check", not a full gate.

## 9. The off-device bot's risk-control self-check list

Before an off-device bot (direct protocol connection, no real UI/sensors) goes live, self-check item by item:

### 9.1 Protocol and traffic traits

- [ ] Request timing: de-uniform the intervals — add thinking delays (log-normal), session gaps following human rhythms;
- [ ] Heartbeat/long-connection keepalive consistent with the official app (official has heartbeats while the script doesn't = a giveaway);
- [ ] TLS fingerprint: JA3/JA4 consistent with the official client?
 - JA3=MD5(SSL version, cipher-suite list, extension list, elliptic curves, EC point formats); JA4=a 2023 formatted string (more confusion-resistant); both already in commercial bot management at Cloudflare/AWS etc.;
 - **Mobile reality**: the BoringSSL/OpenSSL stacks of python requests/go clients differ in fingerprint from the app's OkHttp (Conscrypt/BoringSSL; cipher-suite order + ALPN + extensions); **replaying directly with a script after frida-capture analysis = the TLS fingerprint changes family outright**; with a capture proxy (mitmproxy/Burp) in the path, the egress fingerprint is the proxy's (public material is all web-side; mobile is a homomorphic inference);
 - Countermeasure: send requests through a real-device OkHttp stack (rpc forwarding) or precisely replicate the Conscrypt handshake parameters (including extension order); with HTTP/2 also match SETTINGS frame order/window;
- [ ] Header order and User-Agent consistent with the declared device (claiming Xiaomi while carrying a Huawei UA = a rookie mistake).

### 9.2 Device-fingerprint consistency

- [ ] Single-identifier double-read consistency: local return == property area == what the binder server sees (09 area §13, rule 7);
- [ ] Model-whitelist self-consistency: MODEL↔CPU↔GPU extensions↔screen↔sensor list↔baseband version all aligned (§3.1);
- [ ] Timeline self-consistency: boot_id session duration, firstInstallTime, SD-card seed-file mtimes, account-registration time without contradictions (§3.2);
- [ ] "The correct defaults": on Android 10+ don't report an IMEI you couldn't get — reporting one is itself anomalous; the randomized MAC 02:00:00:00:00:00 must be there (§2.1).

### 9.3 Missing behavior simulation (the biggest tell)

- [ ] Touch: pressure ramps + trajectory jitter + start/stop velocity curves (no constant-velocity straight lines);
- [ ] Sensors: acceleration/gyroscope fluctuate before and after operations; cross-day step accumulation is continuous;
- [ ] The getevent-layer sequence (if collected) has real multi-finger/edge events — the community post proves this sequence is uploaded for AI classification;
- [ ] Page behavior: swipe/scroll/dwell-time distributions match human distributions (not fixed values).

### 9.4 Environmental traces

- [ ] Injection traces: run the frida/xposed/root hiding chain once through (frida-anti-detection.md, root-env-hiding.md);
- [ ] Timezone and language consistent with IP geolocation; VPN/proxy tun0 hidden as needed;
- [ ] Don't appear in bulk within one IP range/BSSID (graph clustering, §3.7).

## Cross-references

- detection-landscape.md (detection surfaces), ../09-function-map/android-function-layers.md §12 (the identifier-domain five-layer chain), ../07-kernel/kernel-hook-stealth.md (L4), frida-anti-detection.md, root-env-hiding.md
