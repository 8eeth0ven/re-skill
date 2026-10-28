# Full Protocol Offlining: From frida RPC to Pure Protocol Rewriting

> Offlining = not running the app client; the protocol stack talks to the server directly. "Full protocol offlining complete" = any business request can be constructed, sent, and session-maintained offline, with the server unable to distinguish the offline client from a real device at the protocol layer.
> Cross-references: algorithm-layer restoration → algo-restoration-methodology.md in the same directory (this doc is the full expansion of its L3 layer + protocol-layer completion); the capture chain → `../04-evasion/capture-all-scenarios.md`; unidbg basics → 《../05-toolbox/emulation-frameworks.md》.

## 0. Whole-Doc Map

```
Target app
 │ ①Capture (plaintext-ize) ──→ ②Parameter locating (signed-parameter diff) ──→ ③Algorithm restoration (pure-computation methodology)
 │                                                        │
 │    ┌─────────────────── where can the algorithm run ──────────────────┤
 │    │                                                                  │
 │  frida RPC (runs on device)   unidbg (emulated locally)   pure rewrite (offline recomputation)
 │    └── three-stage rocket: choose by ascending cost, ascending stability ──┘
 │
 ├─ ④Protocol-structure restoration (headers/serialization/protobuf/long connections)
 ├─ ⑤Session & state (tokens/device registration/risk-control fields)
 ├─ ⑥Anti-replay confrontation (nonce/timestamp/sign check inference)
 └─ ⑦Offlining engineering (queues/fingerprint pools/humanized pacing/TLS fingerprint)
        ──→ ⑧Acceptance: all parameters replayable + session maintainable + risk control clean for N hours
```

## 1. The Offlining Three-Stage Rocket

### 1.1 The three stages defined (aligned with the L1/L2/L3 of `algo-restoration-methodology.md`)

| Stage | Name | Where the algorithm runs | App needed | Device needed | Pure-computation doc level |
|---|---|---|---|---|---|
| R1 | frida RPC | inside the app process on a device/emulator | Yes (resident) | Yes | L3 |
| R2 | unidbg emulation | local JVM (Unicorn emulating the so) | only the so + apk context | No | L2 |
| R3 | pure rewrite | local python/go reproducing the algorithm | No | No | L1 |
The meaning of "three-stage rocket": **start at R1 because it's cheapest; advance R1→R2→R3 step by step; each stage up sheds one layer of Android-runtime dependency**. R1 works in five minutes; R3 may take two weeks — but R3 is the only true "protocol offlining"; the first two stages are merely means of algorithm supply.

### 1.2 Selection Table

| Dimension | R1 frida RPC | R2 unidbg | R3 pure rewrite |
|---|---|---|---|
| Development cost | Hours (hook + export) | Days (environment completion) | Days to weeks (incl. customized-algorithm restoration) |
| Deployment form | Device pool + resident frida-server | JVM service (unidbg-boot-server) | Any-language process |
| Concurrency/QPS | Low per device (app main thread / internal-lock bottleneck), scaled by stacking devices | Medium (per-instance thread safety is on you; if unstable, go single-thread queue); scales horizontally with containers | High (pure computation, no emulation overhead) |
| Risk-control exposure | **A real device fingerprint online long-term — once flagged, the whole pool is scrapped**; frida itself is detectable | Produces no real device behavior, doesn't pollute the fingerprint pool; but if the algorithm's input contains strong device fingerprints, you can't get them | Same as R2; and unsolvable when inputs contain dynamic challenges/TEE (pure-computation methodology §1.3) |
| Stability | Worst: app crashes/gets killed/version upgrades break it | Medium: a version change means re-completing the environment | Best: only key rotation forces a redo |
| Version-iteration maintenance | Hook-point offsets change → dead; re-locate at every upgrade | JNI call sequence changes → re-complete | Key rotated = re-extract the key (the DFA workflow is scriptable) |
| Fit | Probing parameters / low-frequency calls / quick verification; the persistent fallback when the algorithm is unreadable | The mainstream production endpoint: a signature server supplying in bulk | The ultimate form; first choice when the algorithm is identifiable (standard/customized/white-box-attackable) |
Rule of thumb (inherited from `algo-restoration-methodology.md`): **first R1 to understand, then R2 to consolidate, R3 whenever possible; if you can't collect all inputs (strong device fingerprints / server-side challenges), stop right there at R1/R2 — don't force R3**.

### 1.3 When R1 must be kept (never decommissioned)

- The algorithm's input contains sensors/TEE attestation/dynamically delivered challenges (the input can't be constructed offline);
- The algorithm iterates extremely fast — the pure-computation depreciation period is shorter than the restoration period;
- You only need low-frequency calls (e.g., log in once for a token); device-idling cost is acceptable.
In these cases R1 must be engineered per §2.3 "the pro's RPC", pushing device failure rates down to a usable SLA.

## 2. frida RPC Engineering

### 2.1 The basic form (your RPC)

Zhengji's "Android Reverse Engineering Matters", lesson 17, "Your RPC vs the Pro's RPC":
"Your RPC" = the minimal implementation that runs:
- frida spawns the target app, resumes then attaches;
- the injected script does `rpc.exports = { sign: function(...) { ... } }` to export the crypto function;
- the python side calls `script.exports_sync.sign(...)` for the return value;
- single device, single instance, no concurrency control — one app crash kills the whole service.
Typical uses: verifying algorithm input/output; low-frequency parameter fetching. Its fatal flaws: seconds of cold-start cost per spawn, no concurrency, no self-healing.

### 2.2 The advanced form (the pro's RPC)

The community's distilled consensus:

| Capability | How |
|---|---|
| Resident | Don't exit after spawn; the process stays; `enable_child_gating` for multi-process apps |
| Bulk concurrency | Within one device, queue via the JS side (signature functions mostly have internal locks — true concurrency just gets serialized); across devices, dispatch via a device pool |
| Multi-device load | One worker process per device, routed above by load/health; device-fingerprint-to-account bindings stay fixed (see §6.2) |
| Multiple script instances | One process can create multiple scripts each with its own rpc.exports, split by function (one each for sign/token/device info) |
| Self-healing | `script.on('detached')` + process-death detection → auto respawn and re-attach; a watchdog process monitors frida-server liveness (the core selling point of the Sekiro scheme; the 91fans/CSDN tutorials both stress that app-crash probability must be backstopped by a watchdog) |
| Heartbeat | Export `ping` and call it on a timer; timeout = declared dead, triggering self-healing (Sekiro long connections carry heartbeat semantics natively; direct frida solutions must DIY) |
| Networking | frida defaults to USB/local; for remote scenarios use `frida-server -l 0.0.0.0` + `get_device_manager.add_remote_device(ip:port)`, or simply go Sekiro (long connection + registry + cluster routing; the official docs state its difference from frida-rpc: frida rpc goes over USB, sekiro is long-connection based and suits remote persistence) |
| HTTP interface | Arida: FastAPI wrapping frida-RPC, directly yielding HTTP endpoints; or write your own flask/fastapi gateway |

### 2.3 The performance math

- Per-RPC-call overhead: milliseconds (local USB) / tens of milliseconds (remote). The bottleneck is never transport — it is the **serialized execution of the signature function inside the app** and the device CPU.
- Bulk amortization: batch inputs per call, loop them out JS-side, return once (RPC round trips drop from N to 1) — batching is frida RPC's biggest free speedup.
- Cold-start spawn (seconds) happens once only; afterwards everything is resident hot calls; never the "spawn once per request" anti-pattern.

### 2.4 A complete runnable skeleton: RPC server (JS) + Python client (device pool / self-healing / heartbeat)

```javascript
// agent.js: RPC server injected into the target application
// Assume com.xxx.security.SignUtil.sign(Map) -> String has already been located
var SIGN_CLASS = "com.xxx.security.SignUtil";

function doSign(paramsObj) {
    var Clz = Java.use(SIGN_CLASS);
    var Map = Java.use("java.util.HashMap");
    var m = Map.$new();
    for (var k in paramsObj) m.put(k, paramsObj[k]);
    return Clz.sign(m);            // Return the signature string
}

rpc.exports = {
    ping: function () { return Date.now(); },
    sign: function (paramsObj) {
        var out = null, err = null;
        Java.perform(function () {
            try { out = doSign(paramsObj); }
            catch (e) { err = "" + e; }
        });
        if (err) throw new Error(err);
        return out;
    },
    // Amortize overhead by producing N signatures per round trip
    signBatch: function (list) {
        var results = [];
        Java.perform(function () {
            for (var i = 0; i < list.length; i++) {
                try { results.push(doSign(list[i])); }
                catch (e) { results.push({ "__err__": "" + e }); }
            }
        });
        return results;
    }
};
```

```python
#!/usr/bin/env python3
# rpc_client.py: persistent device-pool client skeleton with heartbeat and crash recovery
# pip install frida frida-tools
import frida, time, threading, queue, pathlib, itertools

AGENT_JS = pathlib.Path(__file__).with_name("agent.js").read_text(encoding="utf-8")
PKG = "com.xxx.app"

class DeviceWorker(threading.Thread):
    """One worker per device: persistent spawn, heartbeat, and crash recovery."""
    def __init__(self, device):
        super().__init__(daemon=True)
        self.device, self.api, self.alive = device, None, False
        self.q = queue.Queue()
        self._stop = False

    def _boot(self):
        pid = self.device.spawn([PKG])          # Cold-start once
        self.device.resume(pid)
        time.sleep(8)                           # Wait for splash-screen and self-check completion; tune for the target
        session = self.device.attach(pid)
        session.on("detached", self._on_detached)
        script = session.create_script(AGENT_JS)
        script.load()
        self.api = script.exports_sync          # Frida >=12.3; older versions use script.exports
        self.pid, self.session = pid, session

    def _on_detached(self, reason, *a):
        self.alive = False                      # Trigger recovery in the main loop

    def _heartbeat(self, timeout=10):
        try: return time.time() - self.api.ping() / 1000 < timeout
        except Exception: return False

    def run(self):
        while not self._stop:
            if self.api is None or not self.alive or not self._heartbeat():
                try:
                    self._boot(); self.alive = True
                except Exception as e:
                    time.sleep(5); continue     # Back off and retry if recovery fails
            try:
                params, result_q = self.q.get(timeout=5)
            except queue.Empty:
                continue
            try:
                result_q.put(("ok", self.api.sign(params)))
            except Exception as e:
                result_q.put(("err", str(e)))
        # Post-stop cleanup omitted

    def call(self, params, timeout=30):
        rq = queue.Queue()
        self.q.put((params, rq))
        return rq.get(timeout=timeout)

class RpcPool:
    """Distribute device-pool requests round-robin among healthy workers."""
    def __init__(self, serials):
        self.workers = []
        for s in serials:
            dev = frida.get_device(s) if s else frida.get_usb_device()
            w = DeviceWorker(dev); w.start(); self.workers.append(w)
        self._rr = itertools.cycle(self.workers)

    def sign(self, params):
        for _ in range(len(self.workers) * 2):
            w = next(self._rr)
            if w.alive:
                st, val = w.call(params)
                if st == "ok": return val
        raise RuntimeError("no healthy worker")

if __name__ == "__main__":
    pool = RpcPool(serials=["emulator-5554", "emulator-5556"])  # List device serials with frida-ps -D
    for _ in range(3):
        print(pool.sign({"ts": str(int(time.time() * 1000)), "path": "/api/list", "body": "{}"}))
```

Skeleton essentials: the worker thread consumes serially (naturally dodging the signature function's internal locks), the `detached` callback + heartbeat double-insurance death detection, backoff on boot failure, pooled round-robin. For production add: worker circuit-breaker counts, device-fingerprint-bound routing (§6.2), metrics reporting.

### 2.5 Sekiro: ready-made persistent RPC infrastructure

When you don't want to run your own pool, Sekiro is the community mainstream: frida injects the sekiro client inside the app → a long connection registers with the sekiro server (group + clientId) → the business side calls the sekiro server over HTTP, which forwards to the device. The official docs state its positioning: frida-rpc suits short USB connections; sekiro is long-connection based and suits remote persistence. Companion watchdog tutorials and heartbeat/disconnect handling are in community posts; yint-tech/sekiro-samples provides multi-language samples. Selection: devices in the same room / USB-reachable → self-run pool; devices scattered across sites → sekiro.

## 3. The Protocol-Restoration Workflow

### 3.1 The overall flow

1. **Capture**: the full-scenario chain and breakpoint troubleshooting are in 《../04-evasion/capture-all-scenarios.md》 (encrypted body → §2.9 hook the crypto; QUIC → §2.6; private TCP → §2.13 r0capture yielding pcap). Output: a corpus of plaintext request/response samples (normal flows + boundary flows).
2. **Parameter locating**: in the captures, find the "changes per request, can't be recomputed locally" fields — the signed-parameter diff method: same endpoint, fixed business parameters, only time changed, sent twice — the changed fields are the time-sensitive signature; change UA/device fields and send twice, watching whether the signature follows (to judge whether device fields enter the input).
3. **Algorithm restoration**: the full `algo-restoration-methodology.md` flow (locate the generation point → fingerprint identification → customized/white-box routing → DFA/unidbg/pure computation).
4. **Protocol rewriting**: expanded in this section.

### 3.2 Request-structure restoration

- **Header generation rules**: User-Agent (OkHttp ships OkHttp/x.y.z by default; some apps customize the UA with the model), device headers (device-id/imei/oaaid/umid — sources in §4 device registration), language/timezone/channel number. Restore as a template function: `build_headers(ctx)` filled from the session context.
- **Parameter serialization**:
 - json: `Content-Type: application/json` + when the serialized body participates in signing, mind the **serialization byte order** (key sorting, whether nulls are dropped, number formats 1 vs 1.0) — signature and body must match byte for byte;
 - form: URL-encoding variants (`%20` vs `+`, CJK encodings) and parameter ordering (sort-by-key is a pre-signature rule, not a body rule — the two often differ);
 - protobuf: see 3.3.
- **Signature coverage domain**: confirm whether sign's input is "the body, or path+query+body+timestamp" — read it directly from the crypto function's input buffer via hook (pure-computation methodology §4.4); don't guess.

### 3.3 protobuf reversing (no .proto file)

Tool matrix:

| Scenario | Tool | Notes |
|---|---|---|
| Pure black box (only binary traffic) | `protoc --decode_raw < body.bin` / protoscope syntax | prints a tree of field numbers/wire types/values; no definitions needed |
| Black-box decode + re-encode | `blackboxprotobuf` | auto-infers the structure → python dict round-trip decode/re-encode; supports exporting the inference as .proto |
| Have the APK/jar | `pbtk` | extracts descriptors from Java/C++ into .proto; GUI edit + replay + fuzz; **with LITE_RUNTIME compilation the descriptors are stripped — unusable** |
| LITE_RUNTIME/descriptors stripped | IDA static restoration | community piece "protobuf restoration — recovering .proto files from IDA" |
Black-box inference pitfalls: varint/int32/bool get conflated; repeated detection depends on sample coverage; nested messages need layered decode_raw. **Collect enough samples before letting blackboxprotobuf infer, then verify field semantics with "change one field, replay, watch the server's reaction"** — protobuf reversing is accepted by the server, not by local parsing success.

### 3.4 Long-connection protocols

- **websocket**: capture tools support it directly; when rewriting, mind the Sec-WebSocket-Key randomness in the headers, auth tokens riding the query or the first frame, ping/pong intervals.
- **Private TCP**:
 - Capture side: 《capture-all-scenarios.md》 §2.13 (r0capture yielding pcap);
 - Structure restoration: frame headers (magic + version + cmd + seq + body_len), sequence-number increment rules, heartbeat frame intervals, seq realignment after reconnect (some protocols require carrying the last-acked seq on resume);
 - Rewrite side: python asyncio/tcp or netty, implementing the protocol state machine; **seq and heartbeats must be strictly emulated, or the server silently drops the connection**.

## 4. Session and State Management

The half-life of protocol offlining depends on state management, not on the signature algorithm. The states to maintain:

| State | Source | Maintenance points |
|---|---|---|
| Login token | login/SMS/one-tap login endpoints | Refresh before expiry (passively re-refreshing on a 401 earns a risk-control mark; proactively refresh ahead by expires_in) |
| Device identity | **the device registration endpoint (do this flow first)** | see §4.1 — this is the first thing, in order |
| Risk-control token (t/q/shield class, refreshed per request) | delivered in response headers/body | check every response for a new token being returned; hot-swap locally |
| cookie/session | Set-Cookie | requests.Session manages these; mind domain scoping |
| Business context (cart/browsing trail) | business endpoints | some risk controls verify behavioral-chain integrity (list-before-detail ordering) |

### 4.1 Device registration goes first

The ordering iron law: **get device registration/activation working and obtain a legitimate device identity before touching business endpoints**. Typical flow:
1. First launch: report device info (model/OS/resolution/install-list features) → the server issues device-id/device-token;
2. Some risk controls require passing "device-fingerprint SDK initialization" first (the umid/oaid systems); the fingerprint parameters themselves may then be supplied by R1 RPC;
3. The device-token binds to the device headers of all subsequent requests — swapping the token without swapping device features gets you correlated.
What the offline rig must do: **replay the full registration flow once per "virtual identity"**, sampling device parameters from a "legitimate parameter space" (real model library + real UA library), not random strings.

### 4.2 Risk-control tokens refresh every time

Parameters of the t/q/anti_content class commonly use a rolling scheme: "the response carries a new value; the next request must use the new value". Implementation: a response interceptor uniformly scans the known token fields → writes them back into the session context; on a token jump (forced logout/remote login), immediately halt that identity and alert — continuing to send requests with a flagged token is self-incriminating evidence collection.

## 5. Replay and Anti-Replay Confrontation

### 5.1 Inferring the server's verification logic

Server-side check shapes for the nonce/timestamp/sign trio (inferred, by common gradient):

| Shape | Server behavior | Probing method |
|---|---|---|
| No check | sign correct = accepted | Fire the same nonce 3 times; all 200 → the signature is decoration |
| Nonce dedup | same nonce rejected | Reuse one nonce → from the second time, 4xx "duplicate request" |
| Sliding window | timestamp offset beyond the window (commonly 5-10 min) rejected | Set ts to ±30min/±1h to probe the window boundary |
| Nonce + identity binding | nonces deduped per uid | Reuse the same nonce under a different uid |
| Body binding | sign covers the body; flipping one body byte breaks the signature | Change the body without recomputing sign → rejection means sign covers the body |
**Fixed-nonce probing is the first shot**: cheapest, most informative. Countless "signature checks" actually only verify the timestamp, or nothing at all.

### 5.2 Bypassing and compliant implementation

- Clock alignment: the offline rig calibrates its local clock via NTP; the timestamp uses the offset calibrated against the server's Date response header (record one clock_skew per identity);
- Nonce generation: pick the generation domain per the server's dedup key (uid? device? global?); uuid/counter/random all work — the key is **no repetition**, not "looking random";
- In-window replay: in authorized testing, demonstrating "replayable within the window" already counts as a finding — no need to actually go bulk (see §8 boundaries).

## 6. Offline-Rig Engineering

### 6.1 Task queues

- Two tiers: the **business task queue** (scraping/load-test task granularity) + **request rate shaping** (an independent token bucket per identity);
- Idempotent dedup: task-level fingerprints (target + parameter hash) to prevent re-sends;
- Failure-classified retries: network errors retryable; risk-control blocks (specific business codes) immediately halt the identity into cooldown — never blind retries.

### 6.2 Proxy pools and device-fingerprint binding

Iron law: **one identity = one long-term-bound set of (device fingerprint + exit IP)**. Swapping IP without swapping fingerprint, or fingerprint without IP, both get clustered by graph-based risk control. Implementation: the identity object holds {device_profile, proxy, cookies, tokens}; proxy-quality probing links to identity cooldown. Device fingerprints include: the device-id family, UA, TLS fingerprint (§6.4), HTTP/2 settings (the akamai fingerprint).

### 6.3 Behavior emulation: humanized request pacing

- Interval distribution: no fixed sleep — sample from real-user rhythm (log-normal fit; page dwell → bursts of 3-5 API calls → long pauses); requests carry business causal order (list→detail, not random pings);
- Circadian rhythm: shape the traffic curve to the target user base's schedule; precise on-the-second bursts (except flash-sale scenarios) are a bot fingerprint;
- This section is the highest cost-effectiveness in risk-control confrontation — however good the pure computation, a pacing tell still gets the whole pool flagged.

### 6.4 TLS fingerprint preservation

The essence of the problem: OkHttp (app-native) and python requests have completely different ClientHellos (cipher suites/extensions/ALPN/HTTP2 settings); the server can tell them apart via JA3/JA4/akamai fingerprints before HTTP semantics even begin (Scrapfly measured multiple Python clients' fingerprints).
Solutions (curl_cffi official docs + issues):
- **curl_cffi** (lexiforest/curl_cffi): based on curl-impersonate. Officially supports custom fingerprints: set the `ja3` + `akamai` strings (akamai = the HTTP2 settings fingerprint), then fine-tune with `extra_fp` — the official docs' example is literally "how to impersonate okhttp" (curl-cffi readthedocs impersonate/customize);
- When the built-in presets lag (e.g., chrome133a vs the latest chrome), just update ja3/akamai manually (issue #529 has full steps);
- Getting the target fingerprint: capture the real device's ClientHello (JA3/JA4) or pull from community fingerprint repos; JA4 is more stable than JA3 on extension ordering (Cloudflare official docs) — servers increasingly use JA4, so align JA4+akamai first when impersonating;
- The extreme-consistency school: write the offline client directly in OkHttp (JVM) — the TLS/HTTP2 stack naturally matches the app; trade away the python ecosystem for zero fingerprint error — an option for large projects.

## 7. Case Retrospectives

### 7.1 A certain news app (news category: full-flow practice on a simple signature)

Reversing a certain news app (2024-07).
The deduced path: news-app signatures are usually "path + params + timestamp + fixed salt → MD5/custom hash", Java layer or a light so; the flow = capture → jadx to locate the signature function → frida hook verification → pure rewrite. The teaching value is the "fullness": capture to offline replay in one pass — a good scoring target for the three-stage rocket on-ramp. News endpoints have weak risk control; fixed-nonce probing (§5.1) often exposes "no check" directly.

### 7.2 A membership-store api (e-commerce: unfolding the endpoint surface and state machine)

E-commerce key points: ① inventory the endpoints (product list/detail/stock/order/coupons) — build the "endpoint-parameter-state" matrix first, then restore one by one; ② heavy session state (cart/coupon state affects business checks beyond the signature); ③ order-type endpoints have the strictest anti-replay (orderId server-generated means the client only guards re-sending); ④ points/coupon endpoints are a logic-fl vulnerability hotspot — after protocol offlining they're convenient to traverse systematically for testing.

### 7.3 Payment QR-code URI (funds category: flow analysis and safety boundaries)

Analysis of the payment-scan transfer URI generation flow (2024-12, frida form).
That piece's shape is "frida analyzing the generation flow" — an R1-stage artifact: hooks locate the URI-generation function and dissect the concatenation rules of payee identifier/amount/currency/checksum segments. **Boundary statement (hard)**: such targets are for technical analysis only (protocol format/generation flow/check logic); **no real funds operations, no bulk transfer construction, no touching other people's accounts**; "replay" verification of funds-category endpoints stops at test environments or refusal-semantics analysis. "Using frida to actively call mini-program cloud-hosted APIs" (2024-12) is a direct exemplar of the R1 active-invocation form — frida RPC calling container APIs in the mini-program cloud-function scenario; a low-confrontation, high-reuse sample.
Also: instant upload on a certain netdisk (2024-12) is the representative of **protocol-layer (algorithm untouched) offlining** — instant upload only needs the report protocol carrying the file hash + chunk hashes to construct; no so reversing at all. Lesson: if protocol-semantics exploitation works, take it first — don't fire the three-stage rocket right away.

## 8. Boundary Statement

- Offlining techniques are used only for: **authorized penetration testing / SRC bug hunting (within the target's authorization)**, **load and compatibility testing of your own products**, **protocol security research (anti-replay / risk-control effectiveness proof)**;
- Bulk account registration/account farming, funds operations (transfers/ordering/payment/coupon abuse), bypassing paywalls — **written authorization is mandatory**; without authorization it is illegal (relevant provisions of Criminal Law articles 285/286); this doc's methodology does not constitute support for such uses;
- In the case retrospectives, funds-category targets (7.3) are analyzed only to the depth of "generation flow and check logic"; replay verification stops at test environments;
- "Risk control clean" in the acceptance checklist (§9) means verifying your own defenses' effectiveness within authorized testing — not incitement to evade risk control.

## 9. Acceptance Checklist: Judging Protocol-Offlining Completion

| # | Item | Passing standard |
|---|---|---|
| 1 | All parameters replayable | **All** header/body parameters of any business request (incl. signature/device/risk-control tokens) can be generated in a process detached from the app; no "only the real device can compute it" leftovers (R1-supplied inputs excluded — must be annotated in the doc) |
| 2 | Signature cross-check | On a fixed input set, the offline implementation vs real-device output match 100% (incl. frozen-timestamp comparison, pure-computation methodology §7.1) |
| 3 | Session maintainable | Login state held continuously ≥24h: proactive token refresh with no 401s, risk-control tokens rolling without jumps, cookie domain scoping correct |
| 4 | Long-connection stability | (if applicable) heartbeat/seq/reconnect state machine implemented; after a network drop and reconnect the server doesn't silently drop you |
| 5 | TLS fingerprint match | The offline client's JA3/JA4/akamai match the target app's real-device capture (JA4 prioritized) |
| 6 | Anti-replay conclusions explicit | Each trio item's check shape probed and recorded (none / nonce dedup / window / body binding) |
| 7 | Risk control clean for N hours | Within the authorized test window (≥24h suggested): no captcha escalation, no forced logout, no anomalous business codes, account state normal |
| 8 | Version-upgrade plan | A list of algorithm dependency points recorded (hook offsets/so version/keys); on upgrade, rerun the trio per `algo-restoration-methodology.md` §7.3 version regression |

## 10. Reference Cases

- RPC cases: a certain ride-hailing APP (frida-detection confrontation → frida-RPC call wrapping); Xiudong APP (modified frida passing detection + Python restoring getToken/Crpsign)
- Tools: unidbg-boot-server (Spring Web wrapping/docker/high concurrency; multithreading unstable → switched to single-thread queue), blackboxprotobuf, pbtk (incl. the LITE_RUNTIME limitation), protoscope/decode_raw, curl_cffi (okhttp fingerprint example/extra_fp)
