# Android Traffic Capture in All Scenarios

> Positioning: **owns the end-to-end capture chain and every scenario** — from the app sending a request to the capture tool producing plaintext; where each layer can break, and which combination reconnects it.
> Division of labor with ssl-pinning-bypass.md: that one owns the **TLS validation layer** (pinning classification/bypass scripts/mTLS dump/four paths for system certificates); this doc only points to it from within scenarios and does not copy the scripts.

## 1. Capture-chain overview (text diagram)

```
App sends a request
 │
 ├─ ① Application-code layer  OkHttp / Retrofit / Cronet / Flutter(dart:io) / WebView / private socket
 │     ├ Break A: request body wholly encrypted; even captured it's ciphertext   → §2.9 plaintext plans for encrypted payloads
 │     └ Break B: the network library bypasses the Java stack (Flutter/Cronet)  → §2.7 / §2.11
 │
 ├─ ② Proxy-takeover layer  system proxy (manually set on WiFi) / VPN (tun0) / iptables transparent proxy / direct if none used
 │     ├ Break C: the app detects the proxy and refuses to send requests        → §2.5 proxy-detection countermeasures
 │     └ Break D: the target is a foreign-web site; unreachable without a proxy → §2.4 Postern+Clash+Charles
 │
 ├─ ③ TLS handshake layer  certificate trust (system CA/user CA/NSC) → pinning → mTLS
 │     ├ Break E: handshake failure; user CA not trusted                        → §2.2 / ssl-pinning-bypass.md §4
 │     ├ Break F: Certificate pinning failure                                   → ssl-pinning-bypass.md §3
 │     └ Break G: server 403 mutual authentication                              → ssl-pinning-bypass.md §3.4 dump p12
 │
 ├─ ④ Transport layer  TCP:443 (HTTPS) vs UDP:443 (QUIC/HTTP3)
 │     └ Break H: the traffic never shows up; it went UDP                       → §2.6 QUIC
 │
 └─ ⑤ Capture-tool layer  Charles / Burp / Reqable / mitmproxy decrypt-and-display
       ├ Break I: the tool gets the TLS stream but doesn't know the protocol (private) → §2.13 r0capture to pcap
       └ Break J: no root, can't install a system certificate                   → §2.2 frida route / Magisk
```

| Break | One-line criterion | Where the fix lands |
|------|------|------|
| A | Packet captured but the body is base64/garbage | §2.9 hook the encrypt/decrypt functions |
| B | Java-layer hooks show zero reaction | §2.7 Flutter / §2.11 Cronet |
| C | The moment the system proxy goes on, the app loses network/errors | §2.5 iptables/VPN/r0capture |
| D | The app's foreign requests time out; no traffic without a ladder | §2.4 |
| E | Handshake fails outright; no pinning strings in logs | ssl-pinning-bypass.md §4 |
| F | Log shows `Certificate pinning failure!` | ssl-pinning-bypass.md §3.1 |
| G | Server 403 / handshake_failure | ssl-pinning-bypass.md §3.4 |
| H | Wireshark sees heavy UDP:443, Charles empty | §2.6 |
| I | Long-lived private TCP protocol; tools all blind | §2.13 |
| J | No root; can't install a system certificate | §2.2 frida unpinning / Magisk cert module |
Triage mindset: **eliminate layer by layer, top down** — first confirm the traffic left the device (Wireshark/iptables counters), then confirm it entered the proxy (the tool's connection log), then confirm TLS passed (the handshake error type), and only then the plaintext layer (encrypted payloads).

## 2. Scenario matrix

Each scenario is given as "symptom | root cause | tool combo | steps | pitfalls".

### 2.1 Plain HTTPS (user CA; Android 7 and below, or apps that trust user certificates)

- **Symptom**: Charles/Burp on a manually-proxied WiFi, install the cert, HTTPS plaintext flows. The baseline scenario — get this working before talking countermeasures.
- **Root cause**: On Android 6.0 (API 23) and earlier, apps trust user-installed CAs by default; some newer apps' NSC explicitly declares `<certificates src="user"/>` (common in debug builds) and also passes directly.
- **Tool combo**: any of Charles / Reqable / mitmproxy / Burp + an emulator (an Android 6 image) or an old real device.
- **Steps**:
 1. Start the tool's proxy; on the phone's WiFi advanced options fill in host:port;
 2. On the phone visit the tool's certificate download page (Charles `chls.pro/ssl`, Burp `http://burpsuite`) and install the profile;
 3. On Android 6 and below it is trusted the moment it's installed; enable SSL decryption for the target domain in the tool.
- **Pitfalls**:
 - The emulator's WiFi proxy setting lives under "long-press the connected network → modify → advanced"; the entry point differs across Android versions;
 - A cert installed as "VPN/credential" instead of "CA certificate" doesn't work; pick DER/PEM under "Settings → Security → Install from storage (encrypted credentials)";
 - Charles only decrypts whitelisted domains by default; the rest show `<unknown>`.

### 2.2 Android 7+ user certificates not trusted (API 24+; the most common break)

- **Symptom**: cert installed, proxy working, but all HTTPS gets handshake failure; HTTP plaintext captures fine, HTTPS doesn't.
- **Root cause**: since API 24, apps by default trust only system CAs + the anchors their own NSC declares; the user-store CA is excluded (see ssl-pinning-bypass.md §4 for background and the four paths).
- **Tool combo** (pick one of four; pros and cons below):
 1. **Magisk module** (MoveCertificate / MagiskTrustUserCerts; the conscrypt adapted version for Android 14) — recommended, no repackaging;
 2. **Repackage the NSC** (apktool adds `res/xml/nsc.xml` trusting user CAs, re-sign) — apps with signature checks blow up;
 3. **Root, manually write the system cert directory** (naming rules in §3; effective before Android 14);
 4. **frida generic unpinning script** (ssl-pinning-bypass.md §3.1; checkTrustedRecursive returning an empty list incidentally bypasses the certificate-trust issue — no cert install needed at all).
- **Steps**: see ssl-pinning-bypass.md §4.1-4.4; not copied here.
- **Pitfalls**:
 - Magisk module + Shamiko DenyList: when the target app is on the DenyList the unmount also restores the cert mounts → capture fails (ssl-pinning-bypass.md §4.3);
 - Every time Burp/Charles regenerates its certificate, the hash filename changes and the module must be reinstalled;
 - Emulator (Android 7+) images have a remountable /system, manual writing is easier; on real devices use a module.

### 2.3 Android 14/15 (certificate storage moved into an APEX)

- **Symptom**: the old way — `mount -o remount,rw /system` then push the cert into `/system/etc/security/cacerts/` — still fails the handshake; some Magisk cert modules don't take effect on Android 14 (MoveCertificate issue #21: under the apex, the conscrypt@340090000 directory holds no reserved certificates).
- **Root cause**: from Android 14, the primary store for system root certificates moved to the **conscrypt APEX** (`/apex/com.android.conscrypt/cacerts`), read-only and verified; the system reads from the apex first, so writes to the old directory don't take effect (the Conscrypt module page on source.android.com, official docs).
- **Correcting a common myth**: **targetSdk 34 did not add any new tightening of app-side certificate trust** — "user CAs untrusted by default" has held since API 24; the Android 14 change is in the **system-side storage location**, not in app-side behavior (developer behavior-changes-14 + httptoolkit's Android 11 CA analysis).
- **Tool combo**: root + `mount --bind`, or the conscrypt-adapted Magisk module; on a test device, just using Android 13- is easier.
- **Steps** (the bind-mount route, from the community post "Android packet capture, covering 14 and 15"):

  ```bash
  # After naming the certificate per §3 rules, first put it into the old system directory (remount rw or via a module)
  mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
  # On some versions you must also chmod 777 the directory inside the apex before copying in
  ```
- **Pitfalls**:
 - bind mounts are temporary and lost on reboot — either a boot script (Magisk module post-fs-data/service.d) or the adapted module;
 - the apex-internal directory structure differs across 14/15 minor versions (conscrypt@version subdirectories); scripts must cope;
 - WebView follows chromium's own certificate logic; occasionally WebView still errors after the system cert is fine — restart the app/reboot to take effect.

### 2.4 Foreign-web apps (VPN chain): Postern + Clash + Charles

- **Symptom**: analyzing a foreign app; without a ladder the device can't reach the target server — there's no traffic to speak of capturing; with the ladder on, the traffic exits straight through it and the capture tool can't slot in.
- **Root cause**: the capture proxy and the overseas proxy are two different needs that must be **chained**, not either-or.
- **Tool combo** (Charles + Clash + Postern for foreign-web app capture):

  ```
  App → Postern (phone-side VPN takeover, rules forward all) → Clash (PC side, split-routing + overseas exit)
        Clash uses Charles as upstream (or Charles hangs between Clash and the exit) → target server
  ```

  Variant: on the PC, Clash enables "allow LAN"; the phone's Postern points at Clash's mixed-port; Charles sits behind Clash as a chained proxy (or Clash's rules forward the target domain to Charles).
- **Steps**:
 1. On the PC start Clash (LAN access on) + Charles (fixed port; note the CA certificate);
 2. Install Postern on the phone; configure the proxy server as the PC's Clash entry;
 3. Postern rules: MATCH-all forwarding (don't use its split-routing);
 4. In the Clash config, route the target app's domains through "proxy: Charles port", everything else direct;
 5. Install the Charles CA on the phone (through the §2.2/§2.3 trust issues).
- **Pitfalls**:
 - Postern and VPN-type capture tools like HttpCanary on the phone are **mutually exclusive** (Android allows only one VPN at a time) — to also capture on the phone side, use the PC-side Charles; don't stack two VPNs on the phone;
 - Clash TUN mode conflicts with Charles over port occupancy; stagger the ports;
 - Don't put Charles in front of Clash (i.e., phone → Charles directly, Charles upstream Clash): you still have to install cert trust, and the TLS exit domain is at SNI granularity — the chain order affects how you write the routing rules.

### 2.5 Proxy detection (the app ignores the system proxy)

- **Symptom**: with the WiFi proxy set, the app drops network/errors wildly/flash-exits on the first request; turn the proxy off and it recovers instantly. Or the app simply ignores the system proxy and Charles shows only other apps' traffic.
- **Root cause** (detection-surface details in detection-landscape.md §5.1):
 - Java layer reads `System.getProperty("http.proxyHost"/"http.proxyPort")`; if set, it goes `Proxy.NO_PROXY` direct or refuses the request;
 - OkHttp honors the system proxy via `ProxySelector.getDefault` by default, but one line of `.proxy(Proxy.NO_PROXY)` bypasses it;
 - native libraries (Cronet/curl) don't look at the system proxy at all.
- **Tool combo and steps** (light to heavy):
 1. **VPN-layer takeover**: Postern / Drony / HttpCanary — build a tun device and force-route; the app's proxy-property check is empty but the traffic is already taken over; Drony can even route **only the target app** through the proxy;
 2. **iptables transparent proxy** (root): evilpan's "clever uses of iptables in Android packet capture" — `REDIRECT` to the proxy's transparent port (mitmproxy `--mode transparent` supports it natively); never touches the system proxy setting, a smaller detection surface:

     ```bash
     iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner <target app uid> -j REDIRECT --to-port 8080
     ```

     Targeted by uid: hijack only the target app; other apps unaffected;
 3. **r0capture** (root + frida): no proxy needed at all; hooks the application-layer send/receive functions and emits a pcap directly (see §2.13);
 4. **frida de-fang the detection**: hook `System.getProperty` to return null for proxy keys, `ProxySelector.select` to return DIRECT (the bypass in detection-landscape.md §5.1).
- **Pitfalls**:
 - When the detection escalates to **VPN detection** (`tun0` interface / `NetworkCapabilities.TRANSPORT_VPN`), Postern/HttpCanary become the exposure — switch to iptables (no tun) or r0capture (no proxy, no tun);
 - iptables REDIRECT doesn't work for UDP (REDIRECT only forwards TCP); QUIC traffic still goes direct — pair with §2.6 to disable QUIC first;
 - `--uid-owner` needs the app's uid (`dumpsys package <package> | grep userId`); multi-process apps (WeChat/Douyin) need every uid range covered.

### 2.6 QUIC / HTTP3 (UDP 443)

- **Symptom**: Charles/Burp shows blank, but Wireshark/tcpdump see heavy `UDP 443` traffic; or you capture some HTTP but the core endpoints (video/long connections) are missing.
- **Root cause**: the app uses Cronet (ByteDance/Kuaishou/Xiaohongshu etc.) or a Chromium-family WebView over HTTP/3 (QUIC over UDP); a traditional HTTP proxy only handles TCP, so QUIC traffic simply bypasses the proxy.
- **Plan A: disable QUIC to force a downgrade (mainstream, simple)** — when QUIC is unavailable the client automatically falls back to HTTP/2 over TCP:
 1. **Network-layer packet drop**: the router/PC firewall drops UDP 443 (`iptables -A FORWARD -p udp --dport 443 -j DROP`); effective when the phone's traffic is relayed through a hotspot (the latter is this idea put into practice);
 2. **Hook-layer disable**: frida-hook Cronet's `CronetEngine.Builder`/native config and turn `enableQuic` off (for apps that build CronetEngine in the Java layer); for ByteDance's customized so, hook the native config entry (handled together in §2.11) (hook script idea from the cnblogs eliwang app-capture series);
 3. **Browser/WebView**: turn QUIC off in `chrome://flags`, or via WebView kernel build options; some apps' embedded Chromium can use the same idea.
 After the downgrade, capture HTTP/2 normally per §2.1/§2.2.
- **Plan B: QUIC decoding (when you must see native HTTP/3 behavior)**: the community route "a capture scheme for the QUIC protocol (practicing on a well-known app)" — background: QUIC comes in the Google and IETF flavors, encrypted with 1-RTT after the handshake; the idea is **not to decrypt the transport layer, but to hook the QUIC plaintext send/receive boundary inside the app process** (grab plaintext at Cronet's stream-callback layer), or take TLS keys and decrypt the pcap offline (by cronet hook experience, inferred to land in `Cronet_UrlRequest`'s read/write callbacks);
 Wireshark can parse QUIC frames, and with a TLS keylog can decrypt them.
- **Pitfalls**:
 - Behavior captured after the downgrade (timeout/retransmission parameters) differs slightly from native QUIC; risk-sensitive apps occasionally flag "abnormal network environment";
 - Some apps cache the "QUIC unavailable" state after the probe fails; after removing the drop rule you must clear app data to restore QUIC;
 - Newer mitmproxy versions have experimental HTTP/3 proxy listening, but the Android client-cert + QUIC combination is unstable — prefer plan A.

### 2.7 Flutter (bundles its own BoringSSL)

- **Symptom**: Java-layer unpinning scripts have zero effect; the system proxy often captures nothing either (dart:io does its own DNS and ignores the system proxy by default); requests with UA `Dart/x.x` are the ones Flutter sent.
- **Root cause**: Flutter's network stack lives inside `libflutter.so` — bundled BoringSSL does the full certificate validation (no dependence on the Java-layer TrustManager), and dart:io's HttpClient validates system CAs with independent proxy behavior. Java hooks and system certificates may both be irrelevant.
- **Tool combo**: IDA (locate offsets) + frida (offset replace) + iptables/VPN (force into the proxy).
- **Steps**:
 1. **First solve "getting into the proxy"**: if the system proxy doesn't work, use §2.5's iptables/Postern forced takeover; or set the dart-side proxy via frida (hook around `HttpClient.findProxy`; version-dependent and unstable — prefer the former);
 2. **Then solve "the certificate"**: open `libflutter.so` in IDA (confirm 32/64-bit first); search the string `ssl_client` to locate the `session_verify_cert_chain` function and get the offset;
 3. In frida, `Interceptor.replace` at `libflutter.so` base + offset, always returning 1 (true);
 4. For the concrete scripts and version-dependent offset handling, see the Flutter part of ssl-pinning-bypass.md §3.3 (the re-frida-flutter-pinning idea); not copied here.
- **Pitfalls**:
 - **Offsets don't port**: every Flutter version's so offsets differ; don't hard-copy tutorial patterns — run `strings libflutter.so | grep -i 'dart'` to confirm the version before locating;
 - 32/64-bit so offsets are two completely different sets;
 - Old Flutter (1.x) generated its own keystore with Mozilla NSS; a separate bypass exists;
 - Request-body encryption is also common in Flutter apps (beyond BoringSSL there may be a business-layer cipher); after the certificate layer, still check §2.9.
- **Locating encrypted parameters at the Dart layer** (not just capture): after blutter/dae restore the libapp.so symbols, hook dart functions directly for plaintext; the end-to-end flow is in `../14-game-frameworks/rn-flutter-re.md` §4.

### 2.8 Mutual authentication (mTLS)

- **Symptom**: pinning all passed, but Burp's handshake is rejected by the server at the client-certificate step: 403 / `handshake_failure` / `bad_certificate`.
- **Root cause and fix**: the essence is **stealing the app's client certificate for Burp to use** — static p12 extraction (res/raw + find the password in jadx) or runtime KeyManager dump (works even with native-computed passwords/dynamically delivered certs).
- The full route is in ssl-pinning-bypass.md §3.4 (r0capture dump p12, default password `r0ysue`); not copied here.
- Scenario-side addendum: after importing the dumped p12 into Burp (Settings→Network→TLS→User certificates), if the app also has pinning, remember both layers must pass; finance/government apps often stack the mTLS+pinning+encrypted-payload trio — walk the §1 chain layer by layer.

### 2.9 Encrypted payloads (request body wholly encrypted): the Burp plaintext plan

- **Symptom**: packet captured, TLS passed, but the body is a blob of base64/hex/garbage; the POST JSON has only a `data` field holding an RSA/AES-encrypted value + a `digest`/`sign` signature. Nowhere to start modifying.
- **Root cause**: encryption happens at the **application layer** (① application-code layer, break A), below TLS; the transport-layer capture tool naturally sees only ciphertext. The man-in-the-middle idea is useless here — you must **move the break point to before encryption / after decryption**.
- **Core idea** (the community post "a Burp plaintext capture scheme for app-encrypted payloads" / the same-text CSDN owlteset post, 2024-03):
 1. **Hook the encryption function for plaintext**: on the request side, intercept before the plaintext enters the encryption function — frida-hook the encryption function (e.g. `Cipher.doFinal`, the app's in-house `encrypt`), print/forward the plaintext, modify it, then let it through;
 2. **Hook the decryption function for modified plaintext**: on the response side, hook the decryption function to get the plaintext result, modify it, then return it to the app;
 3. **Bridge with Burp** (plaintext visible and editable in both directions):
 - Idea one (one-way observation): console.log / write the hooked plaintext to a file; read the protocol first;
 - Idea two (bridging): the frida side runs an RPC/local HTTP service; a Burp extension (or mitmproxy script) calls the RPC as a request passes to fetch "the plaintext for this request" for display/modification — the Burp panel shows plaintext, and it is re-encrypted before sending;
 - Idea three (jsrpc): the hooked data streams to the Burp side in real time, is tampered with, then sent to the server (the T00ls route "a certain financial app: FRIDA hooking the encrypt/decrypt algorithms + jsrpc = wrecking them").
 - Ready-made tools: **FridaHookAppTool** (G-Security-Team; no algorithm reversing needed — hook before data enters the encryption function and modify plaintext), Algorithm Assistant (the "penetrating fully encrypted apps: three practical methods" post uses it to print encryption/decryption stacks).
- **Steps**:
 1. Locate the encrypt/decrypt functions in jadx: search `Cipher.getInstance`, `doFinal`, `AES`, `RSA`, in-house class names (the `EncryptUtil`/`CryptoHelper` naming habit); for native-layer encryption, find the JNI functions in IDA (the decompile-and-locate flow in `../05-toolbox/static-analysis-tools.md`);
 2. frida-hook that function; dump only input/output first to confirm "this is the business plaintext boundary";
 3. Once the boundary is right, decide: read-only → just log; need to modify requests → set up the bridge (the Burp plaintext plan/jsrpc);
 4. Signature fields (`sign`/`digest`) the same way: hook the signing function's input to see which fields participate; whether re-signing after modification is mandatory (the server's check decides).
- **Pitfalls**:
 - When the encryption function is in a native so, hooking costs more; a fallback: hook OkHttp's `RequestBody`/interceptor chain to grab "the plaintext at the last moment before encryption" or "the plaintext at the first moment after decryption";
 - Some apps rotate the key per request (key negotiation); purely offline decryption is infeasible and runtime hooking is mandatory;
 - Encrypted payloads on long connections (WebSocket/private protocols) can't be displayed by Burp; use a mitmproxy script or modify at the frida layer;
 - This idea also covers "hook capture and obfuscation confrontation" — the latter part of 正己's "All About Android Reverse Engineering" strings hook capture, low-level network self-disclosure, eBPF capture, and encrypt/decrypt protocol practice into one progression line; use it as the pedagogical companion to this section.

### 2.10 UNI-APP / mini-programs

- **Symptom**: hybrid-framework apps with some pages native, some WebView; the mini-program container runs its own network stack; PC WeChat mini-programs need separate handling.
- **Root cause and fixes**:
 1. **uni-app Android packages**: the network layer is mostly still **OkHttp** (visible in jadx decompilation; confirmed by the community post "a relatively general capture scheme for uni-app") — just follow the §2.1/§2.2 standard flow + pinning handling; the JS business layer (vue) runs in a WebView/in-house JS engine, and the crypto logic may live in JS (a bundle run by v8/quickjs); when Java-layer hooks can't reach it, hook the engine or extract the JS for analysis ("UNI-APP penetration testing - packet capture");
 2. **Mini-programs (phone)**: WeChat mini-programs run in an isolated process (container WebView), and traffic still follows the system proxy — with the certificate installed you can usually capture; the odd container with pinning goes through frida;
 3. **Mini-programs (PC WeChat; the recommended test surface)**: the mini-program process (`WeChatAppEx.exe`/the old WMPFRuntime) **does not follow the system proxy** — on the PC use **Proxifier** to force that process through Charles/Burp, with the cert installed into the Windows "Trusted Root Certification Authorities"; the new WeChatAppEx (Chromium kernel) behaves differently, and some versions do follow the system proxy;
 4. **Cloud-hosted/cloud-function APIs**: mini-program backends are often Tencent Cloud hosting; the custom domains beyond `api.weixin.qq.com` are the business surface — separate them by domain when capturing.
- **Pitfalls**:
 - PC WeChat iterates fast; process names and proxy behavior change often and tutorials go stale quickly; confirm the process with `tasklist` before working;
 - Fiddler's cert must be manually imported into the Windows store on some machines before WeChatAppEx trusts it;
 - Decompiling the mini-program package (wxapkg unpacker) for the JS source and reading the endpoint signing logic alongside the capture is faster than pure capture.

### 2.11 The ByteDance family (full-chain Cronet confrontation)

- **Symptom**: Douyin/Toutiao-family apps — QUIC + certificate validation + proxy detection all present (§1 breaks B/C/H three-in-one), and the ordinary combos all wiped out; frida may even hit "so not yet loaded" errors right at attach.
- **Root cause**: the ByteDance network layer uses **Cronet** (customized `libsscronet.so`) — the native stack carries its own certificate validation, defaults to QUIC, and ignores the system proxy; the Java layer can't get in at all.
- **Tool combo and steps** (the community routes "a general capture scheme for ByteDance-family apps" + "capturing the whole ByteDance app family"):
 1. frida-hook Cronet's native request interfaces (the `Cronet_UrlRequest_InitWithParams` family) or their upper wrappers; take URL/body plaintext from the arguments and response plaintext from the callback layer — **the hook point is the capture point; no dependence on proxy or certificate**;
 2. **Injection-timing pitfall**: executing the hook before the so loads fails — `setTimeout(main, 3000)` to delay, or hook `dlopen`/`android_dlopen_ext` and wait for `libsscronet.so` to finish loading before installing hooks (the two fixes the original post gives);
 3. Usage: `frida -U -f <package> -l script.js` spawn start;
 4. **The patch-so route** (frida-free): directly modify `libsscronet.so`'s certificate-validation logic and build it back into the apk ("a capture scheme for new versions of a certain short-video app"); for when frida detection can't be passed;
 5. **The r0capture route**: the application-layer kill-all script can likewise hook Cronet's SSL send/receive into a plaintext pcap (§2.13), as the fallback.
- **Pitfalls**:
 - The ByteDance family also has **anti-frida detection** (port/maps scanning); pair strongR-frida + renaming + port change (the "anti-detection" row in `../05-toolbox/tool-master-table.md` §1);
 - Cronet versions change with app updates; the hooked native symbols/offsets must be re-confirmed against the so;
 - Force the QUIC downgrade first (§2.6), then capture — business endpoints are steadier on HTTP/2.

### 2.12 WebView

- **Symptom**: in-app H5 page traffic mixed with native traffic; individual WebView pages throw certificate errors (the page won't open) while native endpoints work.
- **Root cause**: WebView uses the system WebView kernel (Chromium-family); certificate trust by default follows the system CAs (the Android 7+ user-CA distrust shows up in WebView the same as native); the app can override `onReceivedSslError` and intercept itself.
- **Fixes**:
 1. The system-certificate problem goes through §2.2 (installing the system CA works for WebView too);
 2. The app overrode `onReceivedSslError` without proceeding → frida-hook to force `handler.proceed` (already included in ssl-pinning-bypass.md §3.1-D);
 3. WebView traffic follows the system proxy by default (chromium respects proxies); for the proxy-detection variant of WebView, use iptables;
 4. The Tencent X5 kernel (SDK-integrated) has its own certificate logic; occasionally it still fails with the system cert installed — clear the X5 kernel data / downgrade the SDK.
- **Pitfall**: local H5 (offline packages) has no network traffic; modifying offline packages goes the resource-dump route, not capture.

### 2.13 Non-HTTP private protocols (custom TCP/long connections)

- **Symptom**: IM/push/game apps whose main channel is a custom binary protocol over a long TCP connection (or private frames other than WebSocket); Charles/Burp don't recognize it at all and show only a binary stream.
- **Root cause**: HTTP proxy tools only parse HTTP semantics; a private protocol must be intercepted **lower (raw bytes) or higher (the plaintext boundary)**.
- **Tool combo and steps**:
 1. **r0capture** (supports Android 7~16): hooks application-layer send/receive (Java-layer SSLSocket/OkHttp + native-layer SSL_read/SSL_write), **regardless of certificate validation or protocol type**, outputting a pcap for Wireshark — in ciphertext scenarios it hooks the encrypt/decrypt boundary, so what comes out is plaintext;
 2. **hook send/recv and read hex**: frida-attach `libc send/recv/recvfrom` or the so's internal send/receive functions; hexdump frame by frame and manually restore the protocol format (frame header/length/command word);
 3. **Raw Wireshark**: tcpdump over adb or capture on the PC; `Follow TCP Stream` to view the binary stream (no decryption; used to confirm ports/protocol traits/whether TLS);
 4. Custom dissector: once the protocol format is mapped out, write a Lua dissector for Wireshark so later captures parse automatically.
- **Pitfalls**:
 - Private protocols usually stack business encryption — when the pcap is still ciphertext, go back to §2.9 and find the encrypt/decrypt boundary to hook;
 - Long connections have many heartbeat frames; don't filter only by the largest traffic when picking command words;
 - r0capture's pcap is stitched from "the reassembled application-layer data"; TCP seq is not fully restored, and Wireshark showing one-way streams is normal.

## 3. Certificate system quick reference

> Full principles (X.509/DER/PEM/trust chain) in the community post "the principles of configuring capture certificates on Android" (2024-03; a monograph on certificate formats and storage mechanics).

| Item | Content |
|------|------|
| System certificates (Android 13-) | `/system/etc/security/cacerts/`; write via root remount rw or a Magisk module |
| System certificates (Android 14+) | `/apex/com.android.conscrypt/cacerts` (read-only APEX); bind mount or an adapted module (§2.3) |
| User certificates | `/data/misc/user/0/cacerts-added/`; "Settings → Security → Install" lands here; API 24+ apps distrust them by default |
| File naming | `<subject_hash_old>.0` — get the hash with `openssl x509 -subject_hash_old -in ca.pem`; content in PEM format |
| DER→PEM | `openssl x509 -inform DER -in ca.der -out ca.pem` |
| Trust-decision chain | NSC (manifest) → trust-anchors (system/user/pin-set) → conscrypt `TrustManagerImpl` chain validation (ssl-pinning-bypass.md §0) |
| Version behavior | API 23-: user CAs trusted by default; API 24+: only system CAs by default; Android 14: storage moved into the APEX (app-side behavior unchanged; §2.3 has the correction) |
| The debug-build special case | An NSC `debug-overrides` can declare that only debug builds trust user CAs — with a debug build in hand, installing a user certificate is enough to capture |

## 4. Counter-detection for capture

The detection-function landscape is in detection-landscape.md §5.1 (proxy/VPN); this section lists only the confrontation points relevant to capture:

| Detection surface | How the app checks | Capture-side counter |
|------|------|------|
| System proxy | `System.getProperty("http.proxyHost")` non-empty / `ProxySelector` returns a proxy | Switch to an iptables transparent proxy/Postern (no system proxy set); or hook both read points to return empty (§2.5) |
| VPN | `NetworkInterface` shows `tun0`/`ppp0`; `NetworkCapabilities.TRANSPORT_VPN` | The iptables plan has no tun; r0capture has no proxy and no tun; tun-detection bypasses detailed in detection-landscape.md §5.1 |
| Certificates | Walk the system/user CA stores looking for capture-tool CNs (Burp/Charles CA subject names are public signatures) | If detection is in the Java layer, hook the enumeration function; or use a custom CA |
| Capture-tool ports | Scan common ports 8080/8888/9090 | Move the tool to an unconventional port (symptomatic); at the iptables layer nothing listens on the phone's local ports (transparent mode listens on the PC) |
| Magisk cert-module traces | Detect new files/mount points in the system cert directory | The clash with Shamiko DenyList unmount is in ssl-pinning-bypass.md §4.3; the hook bypass for certificate detection is the same as above |
Principle: **if the detection is in the Java layer, de-fang it with frida; if it reads the interface natively/in-kernel, sink the takeover layer (iptables) or skip takeover (r0capture/ecapture)** — ecapture (eBPF on the `SSL_read/SSL_write` boundary; no CA certificate, no proxy, no tun; works out of the box on kernel 5.10+; see `../07-kernel/android-kernel-ebpf.md`) is the ultimate "no man in the middle at any point" form, at the cost of root + a kernel version requirement.

## 5. Tool-chain combination recommendation table

| Scenario | First-choice combo | Alternative | Where it lands |
|------|------|------|------|
| Plain HTTPS (API 23- / debug builds) | Charles/Reqable + user certificate | Burp, mitmproxy | §2.1 |
| Android 7-13 certificate issues | Magisk cert module + Charles | Repackage the NSC; frida unpinning | §2.2 |
| Android 14/15 | conscrypt-adapted module / bind mount + mitmproxy | Test device downgraded to Android 13 | §2.3 |
| Foreign-web apps | Postern + Clash + Charles | Clash TUN + mitmproxy | §2.4 |
| Proxy detection | iptables transparent proxy (root) + mitmproxy transparent | Drony targeted; r0capture | §2.5 |
| QUIC/HTTP3 | Drop UDP 443 to downgrade + ordinary capture | Hook Cronet to disable QUIC; in-process hook of the QUIC plaintext boundary | §2.6 |
| Flutter | IDA for offsets + frida replace + iptables takeover | re-frida-flutter-pinning ready-made script | §2.7 / ssl-pinning-bypass.md §3.3 |
| mTLS | r0capture dump p12 + import into Burp | Static p12 extraction | ssl-pinning-bypass.md §3.4 |
| Encrypted payloads | frida hook of the encrypt/decrypt boundary + Burp/jsrpc bridge | FridaHookAppTool; Algorithm Assistant for locating | §2.9 |
| uni-app/mini-programs | Phone: standard flow; PC: Proxifier + Charles | wxapkg decompile as an adjunct | §2.10 |
| ByteDance family | frida hook Cronet (mind the so-load timing) | Patch libsscronet.so; r0capture | §2.11 |
| WebView | System certificate + onReceivedSslError hook | iptables (the proxy-detection variant) | §2.12 |
| Private protocols | r0capture to pcap + Wireshark | frida hook send/recv hexdump | §2.13 |
| All-detection environment (proxy+VPN+cert all checked) | r0capture / ecapture (no MITM) | iptables + de-fang the detection hooks | §4 |

## References

- Community posts: "a general capture scheme for ByteDance-family apps", "capturing the whole ByteDance app family", "a Burp plaintext capture scheme for app-encrypted payloads", "penetrating fully encrypted apps: three practical methods", "a capture scheme for the QUIC protocol (practicing on a well-known app)", "a general QUIC solution for short-video apps dy and ks", "Android packet capture, covering 14 and 15", "the principles of configuring capture certificates on Android", "three common Android app capture scenarios and case analysis", "first look at Flutter reverse engineering", "UNI-APP penetration testing - packet capture", "a relatively general capture scheme for uni-app"; the T00ls jsrpc article
- Community: 正己's "All About Android Reverse Engineering", lessons 20-22, "capture well and you'll eat prison food well", parts 1-3 (hook capture and obfuscation confrontation, low-level network self-disclosure, eBPF capture, encrypt/decrypt protocol practice)
- Chaitin Baichuan Cloud "capturing foreign-web apps with Charles + Clash + Postern"; "introduction to Flutter Android reverse engineering"; evilpan "clever uses of iptables in Android packet capture"; Volcano Engine "a brief analysis of app proxy-detection confrontation" (Proxy.NO_PROXY)
- developer (conscrypt APEX / behavior-changes-14); httptoolkit (Android 11 CA analysis); MoveCertificate issue #21
