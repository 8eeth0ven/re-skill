# Big-Vendor App Capture Countermeasures Archive (per-vendor dossier)

> Positioning: **owns the "per-vendor experience library"** — each major vendor's app network-stack choices, locking layers, key functions/sos, workable capture paths, and pitfalls.
> Division of labor with the generic docs: capture-all-scenarios.md owns the end-to-end break-point matrix, ssl-pinning-bypass.md owns generic TLS-validation-layer bypasses — this doc covers only **vendor-specifics**; generic mechanics are cross-linked, never copied.
> Ethics: everything here is for **authorized penetration testing / security research on your own apps / studying and reproducing public technical articles only**; using it against unauthorized targets is illegal.

## 0. Big-vendor network-stack technology choices — master table

| Vendor | App (representative) | Network stack | TLS/locking layer | Signature system | Capture difficulty |
|------|------|------|------|------|------|
| ByteDance | Douyin/Toutiao/Fanqie | **Cronet customized (libsscronet.so)** + QUIC | native BoringSSL self-validation; ignores system CA/proxy | X-Gorgon/X-Khronos/X-Ladon/X-Argus + ttEncrypt (body) | ★★★★★ |
| Alibaba | Taobao/Tmall/Xianyu | **mtop gateway + SPDY/ANetwork (NDK)** | AMDC scheduling forces the private channel | The "Taobao Four Gods" x-sign/x-umt/x-mini-wua/x-sgext (SecurityGuard) | ★★★★☆ |
| Ant Group | Alipay/mPaaS family | mPaaS gateway (private RPC encryption) | private encryption layer (not a standard TLS surface) | gateway encryption + device fingerprint | ★★★★☆ |
| Tencent | WeChat | **mmtls (in-house TLS1.3 variant)** + mars long connection | fully in-house native handshake; non-standard cert chain | protobuf business layer + qimei device identity | ★★★★★ |
| Tencent | Mobile QQ/Tencent-family SDKs | Beacon (lighthouse) SDK | - | qimei (a QQ+imei composite device ID) | ★★★☆☆ |
| Meituan | Meituan/Food Delivery | **Shark in-house channels: WNSS/CIP/QUIC/tunnel** + HTTP downgrade | private long connection + mtgsig | mtgsig 1.2~3.0 (csel obfuscation) | ★★★★☆ |
| JD.com | JD/JD Daojia | Mostly OkHttp + native signing so | ordinary (few certificate issues) | jdgs (b1~b7)/sign/st/sv | ★★★☆☆ |
| Xiaohongshu | Xiaohongshu | In-house network layer (long connections) | **mutual certificate pinning** (checkClientTrusted) | shield (libxyass.so) | ★★★★☆ |
| Kuaishou | Kuaishou | **kQUIC (in-house QUIC)** + system proxy disabled | certificate surface ordinary outside QUIC | __NS_sig3 (kwssgmain)/__NS_hxfalcon (sig4) | ★★★☆☆ |
| Pinduoduo | Pinduoduo/mini-programs | Ordinary + native-layer protection | SSL pinning + proxy/root detection | anti_content (native/JS) | ★★★★☆ |
| Baidu | Baidu App/Baijiahao | Inferred OkHttp-family | passport-domain certificate pinning (inferred) | cuid/sign etc. in so (inferred) | ★★☆☆☆ |
| NetEase | Cloud Music/News | OkHttp/in-house mix | ordinary | weapi (params+encSecKey, modified AES+RSA) | ★★☆☆☆ |
| Weibo | Weibo/International | OkHttp-family | ordinary pinning | s/from signatures (MD5+timestamp+salt, native optional) | ★★☆☆☆ |
| Bilibili | bilibili | OkHttp + libbili.so signing | ordinary; **libmsaoaidsec.so anti-frida** | appkey + MD5 (sorted params + salt) | ★★☆☆☆ |
| Ctrip | Ctrip Travel | **SOTP (private TCP long connection)** | native encryption (libctripenc.so) | simpxxx/private token (VMP) | ★★★★☆ |
| Travel | 12306 | Mostly Web/H5 | - | _json_att (JS AES-CBC) | ★☆☆☆☆ |
| Banks | Various banks' apps | OkHttp + mTLS mutual auth | **p12 client certificate + pinning + device-fingerprint binding** | in-house sign | ★★★★☆ |
Difficulty here is the composite difficulty of "seeing plaintext traffic", not of "restoring the signature algorithm" — the latter is an independent engineering project per vendor.

## 1. The ByteDance family (Douyin/Toutiao/Fanqie/TikTok)

### 1.1 Network stack and confrontation surface

- Network layer: **customized Cronet, so name `libsscronet.so`** (the Chromium network stack statically compiled, BoringSSL bundled in). QUIC by default (HTTP/3 over UDP 443).
- Three breaks in one (mapping to capture-all-scenarios.md §2.11): the native stack **ignores the system proxy**, **carries its own certificate validation** (no system CA/TrustManager), and **QUIC bypasses TCP proxies**. Java-layer OkHttp hooks show zero reaction.
- Business signatures: request headers `X-Gorgon / X-Khronos / X-Ladon / X-Argus` (colloquially the Four Gods; newer versions add X-Medusa/X-Helios making six), with URL/header/body all participating; the request body goes through **ttEncrypt** whole-payload encryption.

### 1.2 Key functions and sos

| Item | Content | Source |
|------|------|------|
| Network-library so | `libsscronet.so` (customized Cronet) | verified |
| Certificate validation point | `SSL_CTX_set_custom_verify` (BoringSSL custom validation callback; the patch target) | CSDN "manually patching libsscronet.so for capture" series (q9r0s 2025; related: zxc979647835/byalipus "four consecutive so-layer patches") |
| Body encryption | `EncryptorUtil.ttEncrypt(byte[])` (JNI), in the so `libmetasec_ml.so` | verified |
| Request-header signatures | X-Argus/X-Gorgon/X-Ladon/X-Khronos, generated in `libmetasec_ml.so` / `libmsaoaidsec.so` (the MSA security component) | CSDN Four-Gods analyses; Zhihu lank's algorithm-restoration series (zhuanlan.zhihu.com) |
| Historical signature | X-Gorgon 0408 (VM protected), entry-locating method | verified |
| Capture signature | binary ciphertext body + `X-SS-STUB` (body MD5) + `X-SS-QUERIES` | CSDN analysis of a certain shrimp app (2021) |
| Frida bypass script | codeshare `Eltion/tiktok-ssl-pinning-bypass` (TikTok international; `frida --codeshare Eltion/tiktok-ssl-pinning-bypass -f <package>`) | codeshare.frida.re/@Eltion/tiktok-ssl-pinning-bypass |

### 1.3 Capture paths (difficulty gradient)

1. **Ordinary proxy**: basically useless — QUIC + proxy-ignoring + native validation, three gates all stuck.
2. **QUIC downgrade**: drop UDP 443 to force fallback to HTTP/2 over TCP (plan A in capture-all-scenarios.md §2.6); after the downgrade you still face the certificate gate — not enough alone.
3. **frida hook Cronet (mainstream)**: hook the `Cronet_UrlRequest_InitWithParams` family of native interfaces; take URL/body plaintext from the arguments and response plaintext from the callback layer — **the hook point is the capture point; no dependence on proxy or certificate**. Mind the so-load timing: `setTimeout(main, 3000)` to delay, or hook `dlopen`/`android_dlopen_ext` and wait for `libsscronet.so` to finish loading before installing hooks.
4. **Patch the so (frida-free)**: in IDA, make `libsscronet.so`'s `SSL_CTX_set_custom_verify` and friends always return success; build back into the apk or directly push-replace the so (chmod 777, restart the app). For when frida detection can't be passed (the ByteDance family has anti-frida: port/maps scanning; pair strongR-frida).
5. **r0capture/ecapture fallback**: the application-layer kill-all hook of SSL_read/SSL_write emits a pcap (the eBPF version needs no cert, no proxy).
6. **Protocol restoration/RPC**: to send requests off-device, emulate `libmetasec_ml.so` with unidbg to produce the Four-Gods signatures (Zhihu lank series, GitHub xgxkxaxl/X-Ladon-...-X-Helios repos). On the Web side it's `webmssdk.js` environment-completion/RPC (Tencent Cloud 2022 article).

### 1.4 Pitfalls

- Cronet versions iterate with app updates; hooked symbols/offsets must be re-confirmed against the so;
- ttEncrypt body encryption and TLS are two layers; passing the certificate still captures ciphertext — hook the `ttEncrypt` entry as well (the plaintext boundary);
- Douyin's frida detection is aggressive; the patch-so route is actually steadier.

## 2. The Alibaba family (Taobao/Tmall/Xianyu)

### 2.1 Network stack and confrontation surface

- Gateway: everything goes through **mtop** (the `mtop.taobao.*` interface family), SDK package `mtopsdk.mtop.*`.
- Channel: the private **SPDY** protocol (ANetwork, an NDK native implementation); **AMDC** (`amdc.m.taobao.com`, Alibaba's in-house scheduling service) hands down the optimal access IP and forces the app to reach the mtop gateway over the SPDY channel — so mtop requests vanish entirely from Charles/Fiddler.
- Signatures: the request-header "**Taobao Four Gods**" `x-sign / x-umt / x-mini-wua / x-sgext`, generated by Alibaba's security SDK "**SecurityGuard**" (Wireless Bodyguard); the H5 token is `_m_h5_tk`.

### 2.2 Key functions and sos

| Item | Content | Source |
|------|------|------|
| SPDY master switch | `mtopsdk.mtop.global.SwitchConfig.isGlobalSpdySwitchOpen` (internally `localConfig.enableSpdy && remoteConfig.enableSpdy`) — hook it to return false and it downgrades | cnblogs 16937818; verified |
| Signature JNI entry | `com.taobao.wireless.security.adapter.JNICLibrary.doCommandNative`; call chain `mtopsdk.security.InnerSignImpl.getUnifiedSign` → dynamic proxy `getSecurityFactors` | verified |
| Core sos | `libsgmainso-6.6.xxxxx.so` + `libsgmiddletierso-*.so` (SecurityGuard) | verified |
| Disguised so | `lib/libsgmain.so` is **not an ELF** — the first four bytes `50 4b 03 04` are the ZIP magic; unpack it to get the dex (`JNICLibrary` hides here; searching base.apk finds no class) | verified |
| VMP protection | the avmp module runs in a litevm custom virtual machine (sgmain6.3.80 ↔ sgavmp6.x) | verified |
| De-obfuscation verdict | one version of sgmain had only assembly shuffling, no VMP; thin once de-obfuscated | 0x指纹's bin4re (2023-06 libsgmain de-obfuscation) |
| Four-Gods locating method | hook libart.so's `NewStringUTF` and filter by signature substrings (x-sign contains `azU`, x-sgext contains `JB`, x-umt contains `/rA`, x-mini-wua contains `==`) | verified |
| Material collection | GitHub bytesFighting/taobao-reverse-documents (libsgmain material roundup) | GitHub |

### 2.3 Capture paths (difficulty gradient)

1. **Turn off SPDY to downgrade (mandatory first step)**: Xposed/LSPosed/frida hook `isGlobalSpdySwitchOpen` to return false; traffic falls back to HTTP(S) and Charles sees mtop requests (still needs the system certificate, ssl-pinning-bypass.md §4). The other route intercepts the scheduling response of `amdc.m.taobao.com` and forges a downgrade (the idea of several community posts; VVUSU 2023's "how to capture Taobao-family network requests on Android" gives the jadx-locate + flip-the-check-to-false flow).
2. **Certificate layer**: after the mtop downgrade it is standard HTTPS; just handle the user-CA/system-certificate problem (the odd Taobao version adds pinning; go through ssl-pinning-bypass.md §3).
3. **Four-Gods restoration**: to replay/construct requests after seeing plaintext you must restore the Four Gods — `doCommandNative` is the JNI boundary; unidbg environment-completion emulates `libsgmainso` (known pitfall: the class is dynamically loaded; frida must `Java.enumerateClassLoaders` and switch `Java.classFactory.loader` to hook it).
4. **The H5 surface**: mtop H5 endpoints use the `_m_h5_tk` token; the JS-layer signature is thinner than the native surface — hit the H5/mini-program surface first.

### 2.4 Pitfalls

- `JNICLibrary` class not found = you didn't unpack `libsgmain.so`'s ZIP skin (§2.2, disguised-so row);
- After hooking `isGlobalSpdySwitchOpen` you still capture nothing: check the AMDC cache; clear app data to re-trigger scheduling;
- The avmp part lives in litevm; static analysis is torture — just black-box-call it with unidbg; far less effort than reading VM instructions;
- For the Alipay family, see §3.

## 3. The Ant family (Alipay/mPaaS-framework apps)

- The Alipay client architecture is **mPaaS** (the mobile development platform Alibaba Cloud sells externally, derived from the native Alipay client): a unified gateway + a private RPC-encrypted channel. Every SME bank/government-enterprise app built on mPaaS has the same confrontation surface.
- Symptom: an HTTP proxy captures no business traffic at all; even the request structure isn't HTTP.
- Public material: T00ls "solving app mPaaS encryption problems" (2022-10); GitHub has mPaaS iOS-side capture hook scripts (via hooking the decryption); raingray's "Mobile Application Penetration Testing" (2025-01) rounds up mPaaS capture methods.
- Path: locate the mPaaS gateway's encrypt/decrypt boundary (before/after RPC serialization) and hook it — the same shape as capture-all-scenarios.md §2.9's encrypted payloads; the iOS side has ready-made community hook scripts to reference; on Android, locate via jadx searches for `mpaas`/`rpc` package names.
- Pitfall: in mPaaS apps the H5 offline packages/mini-program container are the weak surface; traffic inside the container may use the standard WebView stack.

## 4. The Tencent family (WeChat)

### 4.1 Network stack and confrontation surface

- **mmtls**: WeChat's in-house secure transport protocol, rebuilt from a TLS1.3 draft (ECDH key agreement + ECDSA signature verification + AES-GCM + HKDF); the design was officially published: GitHub WeMobileDev/article "Introduction to mmtls, WeChat's secure communication protocol based on TLS 1.3", plus the Tencent Cloud Developer Community reposts (parts 1/2).
- Position: between the business layer (protobuf serialization) and the connection layer (mars), analogous to http+tls. **Charles/Wireshark see ciphertext** — it is not standard TLS; MITM tools cannot even parse the handshake.
- Long/short connections: short connections run mmtls over HTTP ports; the long connection (mars/longlink) uses private binary frames.
- Device identity: **qimei** (assigned by the Beacon lighthouse SDK; a portmanteau of QQ+imei) — the Java layer collects the device fingerprint (partly from so) → POSTs the report via `com.tencent.*.d` (obfuscated class names) (2026 analysis).

### 4.2 mmtls protocol essentials (2020, from PC-version reversing)

- ClientHello: version + 32 random bytes + timestamp + PSK data (for 0-RTT negotiation) + **two ECDH public keys** (one for encryption, one for signature verification, **replacing certificate-chain validation** — this is why it can't be pinned or MITM'd: there is no forgeable certificate step; server identity is hard-bound to the ECDH public key) + sequence number; the whole thing SHA256'd first.
- ServerHello, four blocks: server public key → the client's ECDH yields a 32-byte shared key → HKDF-Expand to 56 bytes, cut per (16,16,12,12) into two AES-GCM key+IV pairs → decrypt block 2 (encrypted extensions)/block 3 (**PSK data**, cached for the next 0-RTT direct connection)/block 4 (server finish).
- Client Finish: encrypted with the negotiated key; the IV is XOR-incremented to prevent replay.
- Business key: derived via HKDF-Expand from label `"application.data.key.expansion"` + handshake_hash.
- PC version (2.6.2.31) symbol names — **the class/function names have public provenance; Android so symbols may be stripped and need relocating**: `BuildWriteBuffer`, `GenEcdhPublicKey/GenEcdhPriKey`, `ClientChannelReceive`, `AesGcmCrypterCrypt(/Finish)`, `OpenSslCryptoUtilHkdfExpand(/Finish)`, `OpenSslCryptoUtilEcdh(/Finish)`, `OpenSslCryptoUtilSHA256Update/Final(/Finish)`, `OpenSslCryptoUtilHMacSHA256(/Finish)`; `__RunConnect`/`MakesureLonglinkConneted` were used to suppress the long connection and force the short one (no longer suppressible in newer versions).
- Methodology: **follow the data** — hook all of ECDH/HKDF/AES-GCM/SHA256/HMAC and map out where every byte comes from and goes.

### 4.3 Capture paths (difficulty gradient)

1. **Ordinary proxy/certificate**: all useless against mmtls — non-standard TLS, no certificate to forge.
2. **Java-layer plaintext-boundary hook (the practical mainstream; "theoretically kills all versions")**: skip the network layer and directly hook the protobuf plaintext **before serialization / after deserialization** (2024 automotive-version practice):
 - Request side, hook `cJG.Ep` (its `toByteArray`) to dump the request body; response side, hook the callback and take `cJH.cJP.toByteArray`;
 - Locating method: hook the log class `com.tencent.mm.sdk.platformtools.n`'s `i/d` and watch for the `MicroMsg.Cgi`/`MicroMsg.RunCgi` signatures (every packet passes through); the cgi number is in `jType`, the route in `uri`;
 - Automotive-version specific: Jadx-search the resource string "合法性" (legality) to locate `LauncherFloatView`; hook `b(boolean,boolean,String)` to force `z2=true` to pass the device check;
 - Why it "kills all": locating relies on log signature strings and the request/response wrapper-class structure; across versions only the obfuscated class/field names change. **(Note: the class names above are the obfuscated names of the 2021 automotive version 1.0.13; after a major-version update, relocate by signature.)**
3. **Native algorithm hook to decrypt traffic**: hook the AES-GCM/HKDF/ECDH functions for session keys and decrypt the captured ciphertext offline (a public route; walked end-to-end on the PC version, same flow on Android).
4. **r0capture/ecapture**: the SSL_read/SSL_write boundary hook — note mmtls has an in-house handshake; if encryption doesn't go through standard SSL_read/write, the r0capture surface fails; fall back to §4.3-2/3.
5. **Protocol restoration**: fully restore the mmtls handshake + protobuf fields (take the public protocol docs straight to the protobuf fields).

### 4.4 Pitfalls

- The long connection can no longer be suppressed (newer versions); accept that both channels must be analyzed;
- protobuf fields are many and evolve fast; work against the public protocol material before reversing;
- WeChat mini-program traffic does not use mmtls (standard TLS inside the container) — an easier surface; see capture-all-scenarios.md §2.10.

## 5. The Tencent family (Mobile QQ/Beacon qimei/game ACE)

- **qimei/Beacon**: qimei is the unique device identifier of Tencent's Beacon SDK, serving Mobile QQ/WeChat/all Tencent games; the generation chain is in §4.1. In capture confrontation it shows up as a risk-control parameter, not a transport-layer fight.
- **Tencent game ACE (Anti-Cheat Expert)**: the mobile anti-cheat component (ACE-Basic client anti-cheat, Replay system), focused on memory editors/speedhacks/damaged-environment detection; **public reversing material is scarce** (the official site and Tencent Cloud product pages have only marketing intros), orthogonal to capture confrontation; for Tencent games follow the generic anti-debug/anti-root flow (frida-anti-detection.md, root-env-hiding.md).

## 6. Meituan (Meituan/Meituan Food Delivery)

### 6.1 Network stack and confrontation surface

- The in-house network-channel SDK **Shark** (the official Meituan tech article "Meituan-Dianping mobile network optimization in practice"): a multi-channel selection strategy — private protocols first, automatic fallback to HTTP on error. **The downgrade mechanism is itself the breakthrough**.
- Channel types (constants from decompilation, v8.69.3, CSDN 2026-04 "analysis/HTTP capture of protocol downgrade in a Meituan-family app and development of an LSPosed downgrade module" weixin_59616601/159985045): `SOURCE_HTTP=0 / SOURCE_HTTPS=8 / SOURCE_TUNNEL=1 / SOURCE_UTN=3 / SOURCE_WNSS=4`; `TUNNEL_CIP=2 / TUNNEL_HTTP=3 / TUNNEL_WNSS=4 / TUNNEL_QUIC=5` — i.e. **WNSS / CIP / QUIC / tunnel (utn) coexisting**.
- HTTP requests carry the **mtgsig** signature (the in-repo device-fingerprint-risk.md already has the mtgsig dossier; algorithm details not repeated here): the 1.2 → 2.4 → 3.0 evolution, with 3.0's key functions under csel control-flow obfuscation; the community consensus is "the hard part is risk control, not the algorithm" (comment-section discussions; CSDN studypy1024's mtgsig1.2 analysis, 2025-01).

### 6.2 Key functions

| Item | Content | Source |
|------|------|------|
| Channel verdict | the `tunnel` method: `i==2→"cip", 3→"http(shark)", 4→"wns", 5→"quic"`; the `from` method returns the source per source | CSDN 159985045 (locate the class by jadx-searching `wns`/`cip`) |
| Downgrade hook point | Mutate the instance fields `this.source`/`this.tunnel` to the HTTP/HTTPS values, forcing a stable downgrade | CSDN 159985045 |
| mtgsig | csel obfuscation + environment detection; public unidbg emulation attempts exist (not fully successful) | verified |
| Mini-program surface | _token + mtgsig double encryption | cnblogs zichliang 2025 |

### 6.3 Capture paths

1. **Capture without downgrading**: you only see scattered HTTP (images and other static assets); the business data is all inside the private long connection.
2. **Protocol downgrade (mainstream)**: hook the source/tunnel fields behind `tunnel/from` to force HTTP — frida or an LSPosed module (Xposed api-82; three meta-data entries in the manifest + assets/xposed_init pointing at the hook class) both work; after the downgrade, pass the standard certificate flow.
3. **frida/LSPosed risk control**: the Meituan family detects frida and LSPosed environments and bans readily — test with a burner account and isolate the device fingerprint (device-fingerprint-risk.md).
4. **mtgsig restoration**: the RPC/unidbg route; risk-control confrontation takes priority over algorithm restoration.

### 6.4 Pitfalls

- After the downgrade the captured requests still carry mtgsig — **seeing plaintext is easy; replaying/constructing requests is hard**; don't mistake "can capture" for "can leave the app";
- The iOS side encrypts/decrypts network traffic in the Native layer (Fiddler got nowhere; chenqi.app 2021 iOS analysis); the two platforms' confrontation surfaces differ.

## 7. JD.com

### 7.1 Network stack and confrontation surface

- The network stack is **mostly OkHttp**; the TLS layer is ordinary (few certificate/pinning problems) — the capture side is low-difficulty; **the difficulty is all in the signature parameters**.
- Parameter family: `functionId` (endpoint identifier) + body + `sign/st/sv` (newer) + **jdgs** (the risk-control signature, JSON containing fields b1~b7); the Web side additionally has h5st.

### 7.2 Key functions and structure

- **jdgs structure** (community post "jdgs algorithm analysis of a certain Dongdong app — good for intermediate learners"):
 - b1: an assets `.jdg.xbt` resource filename (fixed); b2/b3 fixed; b7 a millisecond timestamp;
 - b4: e1=eid, e2=fingerprint+constant, e3=timestamp, joined into JSON → zlib-compressed → an RC4 state table (0x100) built with "timestamp+0x28 fixed bytes" as salt, stream-encrypted → Base64;
 - b5: the fixed 64 bytes of `xbt_eny` XOR b1 gives body_eny → XOR comm_body → MD5 → AES-CBC (in-memory constant key/iv) → SHA1;
 - b6: b1~b5+b7 joined into JSON and run through the same construction as b5; the comment-section correction says b5/b6 actually take the "sha256 twice → append url → sha1" branch.
 - JNI entry: `main(I[Ljava/lang/Object)[Ljava/lang/Object;`, **i2=103 is init, 101 is the main algorithm** (also 102/104); the resource files `.jdg.jpg`/`.jdg.xbt` must be read in.
- Three unidbg pitfalls: 103 before 101; HookZz writes both resource files into memory; patch one CBZ→CBNZ + NOP one free (else `Error pp not init`); fix the timestamp with HookZz.
- The algorithm body is unobfuscated and unmodified; IDA Findcrypt recognizes it directly.
- Others: Zhihu 2023 sign/cipher analyses (zhuanlan.zhihu.com); GitHub cv-cat/JdApis (Web-side h5st wrapper).

### 7.3 Capture paths

1. **Ordinary proxy + system certificate**: most likely just works (low difficulty).
2. **Replay rejected after capture** → the sign/jdgs problem: hook the `main` JNI boundary for input/output, or emulate the so with unidbg (§7.2 pitfalls).
3. The Web/H5 surface: h5st is relatively independent; a JS-reversing surface.

## 8. Xiaohongshu

### 8.1 Network stack and confrontation surface

- The network layer is in-house (mobile long-connection sends); an ordinary proxy captures no business packets; **mutual certificate pinning**: beyond the client pinning the server certificate, the server also validates the client certificate (the checkClientTrusted surface) — the client certificate must be imported into the proxy software (51CTO's Xiaohongshu DES analysis).
- Signature: **shield** (the `shield` request-header field), generated natively by **`libxyass.so`** and verified server-side (GitHub RedNote/Xiaohongshu-Shield-Algorithm).

### 8.2 Capture paths

1. **VPN global-proxy takeover** (cnblogs badbear "notes on Xiaohongshu protocol analysis", 2021: ordinary capture failed, VPN global proxy succeeded) — solves "won't follow the system proxy".
2. **Mutual certificates**: after passing one-way pinning, the server 403/bad_certificate → dump the client certificate into the proxy per ssl-pinning-bypass.md §3.4 (the p12/pem import method from Anquanke).
3. **shield restoration**: locate the signature-generation logic in `libxyass.so` (RPC environment completion or algorithm restoration; CSDN 2025 "reverse engineering Xiaohongshu: algorithm offense and defense in practice, from anti-debug to protocol signatures").
4. QUIC surface: some Xiaohongshu versions use Cronet-family QUIC (handle per capture-all-scenarios.md §2.6; several community posts mention Xiaohongshu QUIC signatures).

## 9. Kuaishou

### 9.1 Network stack and confrontation surface

- In-house **kQUIC** (Kuaishou's QUIC; InfoQ has Kuaishou's official kQUIC talk) + a **system-proxy-disabled** setting.
- Clarification (Tencent Cloud 2022 "analysis of Kuaishou capture problems"): **not every endpoint uses kQUIC** — many merely disable the system proxy, which transparent-proxy mode solves; don't headbutt QUIC from the start.
- Signatures: `__NS_sig3` (JNI/native, in the kwssgmain-related so), the newer `__NS_hxfalcon` (Sig4); the early 7.5 versions had sign=md5(uriString) (Juejin 2020).

### 9.2 Capture paths

1. **Transparent proxy first** (Tencent Cloud 2022): iptables transparent-proxy takeover (capture-all-scenarios.md §2.5); first verify how much traffic actually runs QUIC.
2. **QUIC downgrade**: drop UDP 443 / hook cronet to disable QUIC, forcing fallback to HTTPS (Kuaishou v8.x analysis hyb.life/archives/203; CSDN 2025 "fixing Kuaishou capture failures: the QUIC protocol").
3. **sig3/sig4**: native so analysis + unidbg (51CTO's __NS_sig3 guide; the Bilibili video BV14x4y1s7HR).
4. nebula CDN: Kuaishou's self-built CDN scheduling domains (a `*.` wildcard family); **public material is scarce**; no written analysis of the signature-bound details exists — not fabricating here.

## 10. Pinduoduo

### 10.1 Network stack and confrontation surface

- Layered protection (overview from the Tencent Cloud 2026 "bypassing the Pinduoduo app's anti-capture mechanisms" article; note **that article's code looks schematic and its class names are low-credibility**): proxy detection (http_proxy environment variable/common capture ports 8888/8080/routing table) + SSL pinning (built-in CA-hash comparison) + parameter obfuscation + root/debugger/emulator detection. The real main protection is in the native layer (an in-house SSL library, so hardening).
- The core parameter: **anti_content** — the anti-crawler content field in requests, generated on both the native and JS sides.

### 10.2 anti_content essentials

- The mini-program version: the core JS files are less obfuscated than the web version (2024-08 conclusion).
- Web version: Juejin 7357716989782343707 (2024-04, with GitHub code attached); CSDN studypy1024 "extracting webpack code in practice" (2025-02); CSDN flighting019 (2025-04, locating where the `g.sent` parameter is generated); Tencent Cloud 2014564 (2022, early obfuscation reversing).
- Brief verdict: **material on the JS surface (web/mini-program) far outweighs the app-native surface** — when attacking Pinduoduo, prefer the H5/mini-program surface.

### 10.3 Capture paths

1. Ordinary proxy + certificate: pass pinning + de-fang proxy detection (Java-layer detection is hookable; for the native layer sink to iptables/r0capture; capture-all-scenarios.md §2.5/§4).
2. After capture, anti_content is the hard gate: on the app side, so reversing (unidbg); on the web side, extract the JS.
3. Schemes whose detection chain is entirely in the Java layer fit only old versions; don't copy class names blindly.

## 11. Baidu (Baidu App/Baijiahao)

- **Public material is scarce** (only the GitHub cv-cat/BaijiaApis Baijiahao scraping project is directly reusable).
- Generic inferences (labeled: inferred): the network stack is OkHttp-family; the passport login domain has certificate pinning; `cuid`/`sign` etc. are generated in the so layer. Attack in the order capture-all-scenarios.md §2.1→§2.2→§2.5; for signatures, use the §2.9 plaintext-boundary hook.
- The Baijiahao creator platform's Web/H5 surface is thinner than the app surface (GitHub BaijiaApis goes the web algorithms).

## 12. NetEase (Cloud Music/News)

- **NetEase Cloud Music**: the main battlefield is **weapi encryption** (`params` + `encSecKey`, modified AES+RSA), not transport-layer confrontation — capture works ordinarily (OkHttp-family); the hard part is body encryption.
 - Public material: GitHub malinkang/AndroidNote's netease-cloud-music-reverse.md (song-recognition API reversing; a roundup of Reqable capture decryption); the community post "crawling a certain cloud-music app — anti-debug bypass, JS call-stack backtracking, web algorithm reversing" (2024-12; web-side anti-debug + stack backtracking); Juejin 2018 Java-layer static analysis (jadx to find the weapi entry).
 - Path: on the app side, hook the encrypt/decrypt functions (capture-all-scenarios.md §2.9); on the web side, extract the JS and complete the environment.
- **NetEase News**: little systematic public analysis; handle with the generic flow.

## 13. Weibo (including the International version)

- The network stack is OkHttp-family; capture difficulty is low; **the hard part is the signature parameters**:
 - Main client: the `from`/`s` parameters — Weibo 12.5.1: a structure of parameter-concatenation MD5 + timestamp + salt, then encrypted; the Lite version's modified parameters get server-rejected → reverse the signature protocol.
 - Native surface: the `s` parameter with unidbg+IDA in practice (cnblogs Eeyhan 17337827).
 - GitHub cv-cat/WeiboApis (algorithm-reversing wrapper).
- **Weibo International (Weico)**: the international version's encryption is simplified relative to the domestic one (experience-based judgment); old APKs can be fetched from the uptodown archive for version comparison.

## 14. Bilibili

### 14.1 Network stack and confrontation surface

- OkHttp + JNI signing; **the core confrontation is not certificates but `libmsaoaidsec.so`'s anti-frida** (the so starts its detection threads at the init_proc stage during load — frida is discovered before it finishes hooking).

### 14.2 Key functions and sos

| Item | Content | Source |
|------|------|------|
| Signature entry | `com.bilibili.nativelibrary.LibBili.so(SortedMap, int, int)` → `SignedQuery`; MD5 inside libbili.so | CSDN qq_40360069/142523875 "bili app sign algorithm analysis" (2024-09) |
| Signature algorithm | `md5(sorted urlencoded parameters + salt)`, example salt `560c52ccd288fed045859ed18bffd973`, example appkey `1d8b6e7d45233436` (**appkey/salt change per client; re-extract with this method, don't copy**) | same |
| Anti-frida | `libmsaoaidsec.so` `.init_proc` → `__system_property_get("ro.build.version.sdk")` → `pthread_create` starts detection threads (7.26.1 two threads: 0x010AE4/0x113F8; 7.76.0 three threads: 0x1c544/0x1b8d4/0x26e5c; 8.14.0 detection function sub_1B924) | cnblogs ovo-fisherman/18755887 (2025-03) + CSDN 142523875 |
| Bypass | `Interceptor.replace` nulling the detection-thread entries / `Memory.patchCode` NOPs / hook dlsym so the first N pthread_create calls get an empty function; timing: hook `android_dlopen_ext` riding the `__system_property_get` moment (so mapped but init not finished) | same |
| unidbg | Complete Map->isEmpty/get, SignedQuery->r, the constructor; traceCode verifies the MD5 | CSDN 142523875 |

### 14.3 Capture paths

1. Ordinary proxy + system certificate: works.
2. For frida analysis, first pass the msaoaidsec anti-detection (§14.2 bypass), or spawn + early hooks.
3. Signatures: LibBili JNI-boundary hook / unidbg / reproduce the MD5 flow directly in Python.

## 15. Ctrip/Fliggy/12306 (travel)

### 15.1 Ctrip

- **SOTP private protocol**: a TCP socket long connection (protobuf-serialized request header + business parameters), with encryption/decryption in native (`libctripenc.so`, `System.loadLibrary("ctripenc")`, AES-128/CBC) — a complete black box to Charles (CSDN 128149616, 2023-07).
- Key classes: `SOTPConnection` (unified send/receive management, `sendRequest`), `ProcoltolHandle` (the pack/unpack gateway), `ctrip.foundation.util.EncodeUtil` (the native encrypt/decrypt entry) (CSDN 128149616 + cnblogs super19911115/14353957).
- Additionally `libmsaoaidsec.so` security checks (comment-section addendum) — the MSA component again (see rule three in §17).
- Detection surface: anti-frida + socket-capture locating + `simpxxxxxx` parameter computation (community post "detection and parameter-calculation analysis of a certain travel app", 2023-08); the car-rental token under **VMP virtualization** (51CTO 2026-08, a complete code-extraction plan); slider captcha `captcha/v4/risk_inspect` (Juejin).
- Path: hook `getOutputStream/getInputStream` and follow the thread to SOTPConnection → hook the EncodeUtil native boundary for plaintext → protocol restoration. The app code is unobfuscated and directly readable.

### 15.2 Fliggy

- Alibaba family: mtop + the full Taobao Four-Gods set (same as §2); no independent conclusions — attack per the Alibaba flow.

### 15.3 12306

- The main surface is Web/H5: `_json_att` and other parameters JS AES-CBC-encrypted; DevTools breakpoints + Python reproduction (Tencent Cloud 2025-11 "countering 12306 anti-crawler: reverse-engineering the JS-encrypted parameters"); the app side's confrontation is weak and ordinary capture works.

## 16. Banking/finance (generic)

### 16.1 The confrontation trio

1. **mTLS mutual authentication**: the client certificate (p12) preset in res/raw or delivered dynamically; the server validates the client cert — Burp, past pinning, still gets 403/`handshake_failure`/`bad_certificate`.
2. **SSL pinning + tightened system certificates**: NSC distrusting user CAs + public-key/certificate pinning.
3. **Device fingerprint bound to the certificate**: some banks bind the client certificate to the device fingerprint/phone number; changing environment invalidates it outright.

### 16.2 Public paths

- **Extract the static p12**: jadx/JEB to find the res/raw p12 + the password in code (JEB memory for big APKs; Ascotbe 2020 "solving Android one-way/two-way authentication blocking capture").
- **Runtime p12 dump**: r0capture (r0ysue) hooks the KeyManager dump; default password `r0ysue`; import into Burp (Settings→Network→TLS→User certificates) (ssl-pinning-bypass.md §3.4).
- **Certificate into the system**: Burp CA to PEM → subject_hash_old naming → push into the system cert directory (community post "breaking two-way authentication in Android app capture", 2021; the eet-china 2022 roundup).
- Generic roundups: Anquanke 190080 "a record of two-way-authentication app capture"; CSDN 151968209 "HTTPS mutual-auth capture in practice" (2025-09; includes the right way to swap a capture-friendly certificate chain in a test environment).
- Defense-view references: GitHub yangchong211/YCCaptureTool (a composite app anti-capture practice), WanAndroid "design and practice of mobile anti-capture solutions".
- Pitfalls: finance apps often stack encrypted payloads (capture-all-scenarios.md §2.9) + anti-root detection; triage by the chain layer by layer; **the fingerprint-bound certificate failing after a device change is a common cause of "the certificate is clearly right but it still won't connect"** (inferred).

## 17. Distilled generic confrontation rules

### Rule one: the endgame for top apps is always "abandon standard TLS, roll your own transport"

ByteDance (Cronet+QUIC), WeChat (mmtls), Alibaba (SPDY/ANetwork), Meituan (WNSS/CIP), Ctrip (SOTP) all converge. Reasons (repeatedly corroborated by public articles):
1. **The MITM tool ecosystem is too mature** — as long as it is still "standard TLS + system proxy", the Charles/Burp + Magisk cert module + generic unpinning script trio can always assemble plaintext; a proprietary protocol makes the entire MITM toolchain (proxy takeover, certificate forgery, protocol parsing) fail on all three layers at once.
2. **QUIC/UDP is a natural moat** — HTTP proxies only handle TCP; UDP 443 bypasses outright; and QUIC's handshake-encryption semantics are natively embedded (ByteDance/Kuaishou/Meituan TUNNEL_QUIC).
3. **Native-layer deployment** — the Java-layer hook ecosystem (hooking network libraries/TrustManager) is the richest; sinking the network stack into C++ makes every frida Java-layer script whiff; the attacker must know IDA + native hooking to even enter, raising the barrier by an order of magnitude.
4. **Private protocols carry business semantics natively** — serialization (protobuf) + compression (zlib) + encryption (AES) + signing (salt cascades) can be customized to the vendor's own risk control (JD's jdgs b1~b7 and Ctrip's protobuf header + so encryption are both this pattern).

### Rule two: the signature system is decoupled from the transport layer; "captured plaintext" ≠ "can construct requests"

Every vendor has a request-signature layer unrelated to TLS (the Four Gods/Taobao Four Gods/mtgsig/jdgs/shield/sig3/anti_content/weapi/sign). Decision implications:
- If the goal is just to **see the protocol / map the business surface** → passing the transport layer is enough (downgrade/hook the plaintext boundary);
- If the goal is to **replay off the app** → the signatures must be restored, an independent project (unidbg/RPC), usually harder than the capture itself (Meituan mtgsig's "the hard part is risk control, not the algorithm" is the community consensus).

### Rule three: third-party security components are reused industry-wide — hook once, kill many

- **`libmsaoaidsec.so`** (the security component of the MSA OAID SDK of the Mobile Smart-device Alliance): Bilibili's anti-frida main force (§14.2), Ctrip's security checks (§15.1), ByteDance X-Argus-adjacent (§1.2) — **one supplier's component, highly similar detection logic** (init_proc + pthread_create spawning detection threads + strcmp/openat/strstr signature scans). Recognizing it = you can port published bypass scripts with adjusted offsets.
- SecurityGuard (Alibaba), Beacon (Tencent), Shumei/MSA (industry-wide) likewise: **identifying the third-party security sos in an app saves far more effort than reversing each vendor** — read the so list + package-name prefixes in jadx (`com.taobao.wireless.security`/`com.tencent.qimei`/`msaoaid`) to identify the supplier first.

### Rule four: the decision points for "capture fails → switch to RPC/algorithm restoration"

Ordered by input/output; escalate when these signals appear:
1. **A downgrade switch exists and is hookable** (the SPDY switch/QUIC packet drop/tunnel fields) → always try the downgrade first; lowest cost (the Alibaba/Meituan/Kuaishou routes).
2. **After the downgrade you're stuck on pinning/proxy detection** → frida unpinning + de-fang the detection (ssl-pinning-bypass.md §3); still at the script layer.
3. **The protocol isn't HTTP at all (WeChat/Ctrip)** → stop fussing with proxies; find the **plaintext boundary** directly: Java pre/post-serialization (WeChat toByteArray/parseFrom), native encrypt/decrypt function boundaries (EncodeUtil/ttEncrypt); the hook point is the capture point.
4. **You need to send requests off the device (automation/batch)** → emulate the so with unidbg or RPC (frida-rpc resident on the device); the time cost is now measured in weeks — confirm the business really needs it, or whether seeing the protocol suffices.
5. **unidbg fails repeatedly (the so actively anti-debugs/checks resources/VMP)** → return to a device-resident RPC (a semi-permanent hook service), abandoning pure offline emulation (JD's three unidbg pitfalls and Meituan's unfinished unidbg are both instances).
6. **VMP/litevm-grade protection (Alibaba avmp, Ctrip car-rental token)** → don't read the VM instructions; black-box-call (unidbg driving the whole so) or extract the code (the 51CTO Ctrip-post route).

### Rule five: plaintext-boundary hooking is the universal solvent against proprietary protocols

The methodology of the WeChat automotive-version analysis (§4.3) deserves its own emphasis: **don't break the protocol — move the breakpoint**. Every app necessarily has a stretch of plaintext residency between "business object serialized into bytes" and "bytes fed into encryption/sending" (hook toByteArray / the JNI boundary / the encryption function entry). Follow the data, compare the buffers of every send/receive pair; an order of magnitude faster than reversing the protocol format. r0capture/ecapture are precisely this rule productized (the SSL_read/SSL_write universal boundary).

### Rule six: the evidence chain — when to give up capture and switch to algorithm restoration

| Signal | Meaning | Action |
|------|------|------|
| Proxy/VPN/certificate all bypassed yet the tool still shows only ciphertext | encryption is at the application layer | switch to the §2.9 plaintext-boundary hook (no algorithm restoration needed yet) |
| Hooking the plaintext boundary reveals the key is negotiated per request | offline decryption infeasible | only runtime hooking/RPC; abandon the offline-decryption route |
| Business requests are honored only with a device-bound signature | capture is only an observation surface | switch to unidbg/RPC signature restoration (weeks of investment) |
| The signing so has VMP and unidbg init fails repeatedly | offline emulation cost out of control | device-resident RPC, or abandon that endpoint for a weaker surface (H5/mini-program/old versions) |
| The server validates device fingerprint + certificate binding | changing environment invalidates everything | operate only on/in the original device/environment (the banking norm) |

### Rule seven: weak-surface priority (H5/mini-programs/old versions/international versions)

For nearly every major vendor, the app-native surface is strongest, the Web/H5 surface next, the mini-program surface after that: Pinduoduo anti_content's JS surface has far more material than the app surface (§10.2), NetEase weapi's main battlefield is the Web (§12), Weibo International/Lite is weaker than the main version (§13), 12306's main force is the Web (§15.3), mtop's H5 token surface is weaker than the native Four Gods (§2.3). **Before attacking a big vendor, always ask: does the H5/mini-program/Lite/International/old version expose the same business endpoint** — that is the highest-ROI single step.
