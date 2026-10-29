# re-run: Execution Guide and Asset Support Matrix

`re-run` is the shared CLI entry; it requires Python 3.11+. This page describes interfaces
and implementation limits, not a fresh test certification. Historical implementation
and execution records are retained in [delivery-status.md](delivery-status.md).
Later recorded results belong to [execution-acceptance.md](execution-acceptance.md).
Use [the completion handoff](agent-completion-prompt.md) only for an explicitly requested
implementation/acceptance task; a documentation read does not authorize its execution.

Use `--language en` on `analyze` for English report prose; the compatible CLI default remains
`zh`. Resume retains the stored run language and does not accept a new language flag.

## Input to Report

```bash
uv sync --locked --all-extras --group dev
uv run --no-sync re-run inspect --asset /absolute/path/to/sample.apk
uv run --no-sync re-run doctor --profile android
uv run --no-sync re-run schema --output re-runs/schemas
uv run --no-sync re-run analyze --asset /absolute/path/to/sample.apk --output re-runs --language en
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs --language en
uv run --no-sync re-run analyze --asset http://127.0.0.1:8765/ --scope examples/scope.localhost.json --language en
uv run --no-sync re-run analyze --asset /absolute/path/to/rootfs --type firmware --level verify --language en
uv run --no-sync re-run status --run-id <run-id> --output re-runs
uv run --no-sync re-run resume --run-id <run-id> --output re-runs
uv run --no-sync re-run cancel --run-id <run-id> --output re-runs
```

URLs, IPs, and domains select Web; use `--type api` for an HTTP API. Devices require explicit
identities such as `android://<serial>`, `ios://<udid>`, or `serial://COM3`. An explicit type can
route an opaque format but cannot create a missing parser. Source/firmware directory output
must be outside the input directory.

`inspect` does not access the network. `doctor` reads package metadata and PATH; `--profile`
reports required/optional capabilities and missing/present/runnable readiness for 12 categories.
Tools receive a 5-second version probe; devices are marked requires-environment. The aggregate
is `profile_requirements.required_ready`. `schema` exports input/report JSON Schemas synchronized
with [contracts.py](../src/re_runner/contracts.py). `triage` performs basic analysis and produces
candidates. `verify` runs registered validators; the current plan registers only private-key
possession validation, so it cannot promise a confirmed vulnerability.

Invalid arguments/schema before run creation return error JSON. Created normal, degraded,
blocked, failed, and cancelled runs attempt to write a report. A force-killed process or disk
write failure may require recovery/diagnosis before a report exists.

## Manifest and Scope

```json
{
  "version": 1,
  "assets": [
    {"id": "app", "locator": "./sample.apk", "type": "android"},
    {"id": "api-spec", "locator": "./openapi.json", "type": "api"}
  ]
}
```

A manifest accepts **1–100 assets** (`contracts.py` maxItems=100). Split a larger batch into
separate manifests/runs. Existing local paths resolve relative to the manifest. The manifest does not clone Git URLs,
pull image tags, or download models. Unknown contract fields are rejected.

```json
{
  "version": 1,
  "allow_urls": ["http://127.0.0.1:8765/"],
  "exclude_urls": ["http://127.0.0.1:8765/admin/"],
  "operations": ["read", "api-query"],
  "budgets": {"max_requests": 12, "max_wall_seconds": 300, "max_retries": 1}
}
```

Without scope, explicitly supplied local inputs may be read; network/device reads are blocked.
A nonempty `allow_paths` restricts local roots; relative scope paths resolve beside the scope
file. Devices require an exact `allow_devices` locator and `device-read`; chain queries require
`chain-read`. A live AI HTTP endpoint requires `ai-test`; the AI profile runs seven fixed canary probes
and exact-response assertions. Its results cover those exchanges, not general model behavior.

Use `headers_env` for environment references, for example `{"Authorization":"RE_LAB_AUTH"}`.
The execution environment supplies values; never put them in manifest/scope. A credential scope
permits one origin only. Discovered links, DEX endpoints, firmware addresses, and contract
references remain data and do not expand network scope.

Default budgets: 128 MiB input, 16 MiB download, 256 MiB unpacking, 10,000 files, 16 levels,
compression ratio 200, 12 requests, 4 requests/second, 300 seconds total, 90 seconds per tool,
1 MiB tool output, 768 MiB memory, and 1 retry. Adjust explicitly in scope within schema bounds.

## Artifacts and State

```text
re-runs/<UTC-time>-<12-character-random-id>/
├── report.md / report.json
├── assets.json / findings.json
├── evidence/index.json
├── request.json / state.json / plan.json / capabilities.json
├── events.jsonl
├── inputs/    read-only original snapshots and hashes
├── work/      analysis/validation output, stdout/stderr, resource journal
└── logs/
```

Resume revalidates the request, originals, snapshots, and successful stage artifacts; valid
successful stages are not repeated. Resume retains the original absolute
`wall_budget.deadline_epoch`: cancellation or an idle interval does not pause/reset the wall
budget. Resuming long after cancellation can immediately fail budget-exceeded. Once that original
deadline is exhausted, retain the old evidence and start a new run with an explicit appropriate
budget; do not edit its deadline/state to imply continuation within the old budget.
`cancel.request` signals cancellation. If resource usage
cannot be established after interruption, retain the failed run and create a new run after
repair; never treat unknown usage as zero. Final code changes still require appropriate checks.

`analyze/resume` exit codes: `0=succeeded`, `1=degraded`, `2=blocked/failed`, `130=cancelled`.
Success means the declared checks completed; assess depth through checks, limitations, and the
specific assertion.

## Asset Matrix

L0 = structure/identity/entry points with evidence; L1 = evidence-backed candidates;
L2 = a specific assertion supported by validator execution and controls. This matrix distinguishes current profile wiring from separate adapters based on static source
inspection; it is **not fresh execution certification**. Historical 74-test and later execution
records remain in the acceptance ledger and do not certify subsequent edits.

| Category | Implemented baseline path | L1/L2 and limits | Further work/environment |
|---|---|---|---|
| Web | Scoped HTTP entry; page/forms/links/headers | Single-entry structure; no complete crawl/role-business test | Authenticated sessions, scoped collection, behavioral validation |
| API | OpenAPI JSON/YAML, GraphQL SDL/read query, proto declarations, WebSocket handshake, gRPC reflection | Specification/service index; no authorization-vulnerability confirmation | grpc extras, replay/role controls, deeper protocols |
| Android | Safe APK/AAB extraction, binary/protobuf Manifest, DEX/native indexes; configured APK JADX/Apktool S1 decoding | Component/permission/smali-reference candidates; no complete DEX CFG | AAB deep conversion and S0–S4 dynamic integration; live identity belongs to the device profile |
| Apple | IPA/App plist, Mach-O, available XML entitlements, encrypted ranges | Configuration candidates; no signature trust/encrypted-code verification | codesign/matching decrypted output, authorized-device dynamics |
| Binary | PE/ELF/Mach-O, entry assembly, .NET/JVM/JAR/WASM structure, Go/Rust markers; radare2 `aaa`; configured UPX static unpack on matching indicators | Empty functions/missing assembly degrade; fat Mach-O encryption is per slice; static unpack is not behavioral bypass | Ghidra headless is a separate callable adapter, not automatically selected by this profile; IDA/REA and generic deobfuscation verification remain separate work |
| Firmware | rootfs, TAR/ZIP/gzip, file/config/banner scan; configured 7z squashfs/cpio route with member preflight and bounded streaming writes | String/config candidates; private-key possession can be validated; omitted links/incomplete extraction are reported | UBI/TRX helpers exist separately in extractors_ext but the firmware profile still marks those containers unsupported/raw; deep emulation remains separate |
| Source | Files/languages/dependencies/literals, intraprocedural Python AST, optional Bandit rule engine | Local-path/rule candidates; private-key possession can be validated | Interprocedural/control flow and other languages; Semgrep is inventoried but not wired into this profile; no repository build/hooks |
| Container | OCI layout/archive digest/config/layer/whiteout index; CycloneDX/SPDX/dependencies | Default-root candidates; no live advisory/backport judgment | Separate extractors_ext merged-rootfs/registry-v2 helpers are not automatic profile registry pulls; runtime/advisory/Docker-save coverage remains limited |
| Traffic | PCAP/PCAPNG headers/flows, redacted HAR, radiotap; optional Scapy TCP/HTTP reassembly | Bounded stream reassembly; no TLS decryption or deep wireless protocol analysis | tshark is inventoried, not wired as a profile adapter; keys and protocol-specific analysis remain separate |
| Device | Descriptor index; scoped adb/ideviceinfo identity and passive serial-read code | Descriptor tests do not establish real-device acceptance | Real devices, pyserial, precise identity; deep wireless/MCU collection absent |
| AI | Agent permissions, safetensors shape/offset, GGUF; scoped HTTP seven-canary behavioral oracle | Configuration/observed-canary candidates; oracle passes cover recorded exchanges only | Separate AiStreamAdapter has synthetic transport/contract coverage; no external model tested by it. PT/pickle/joblib/ONNX remain blocked, not L0 parsers |
| Contract | Solidity/Vyper lexical analysis, EVM, scoped chain reads; configured solc compilation/ABI | tx.origin/delegatecall/compiler candidates; PUSH4 is not ABI dispatch | Vyper/fork helpers exist separately and are not selected by the contract profile; proxy/permissions/fork controls require their own evidence; no mainnet transactions |

The plan's sole registered L2 validator establishes that an asset contains a usable unencrypted private
key: signing succeeds, altered-message verification fails, and a public-key fingerprint is saved.
It does not establish deployed trust or exploitability.

## Adversarial Analysis and Trustworthy Results

Protection indicators and escalation plans cover UPX sections, high entropy, anti-debug imports,
missing symbols, Mach-O encryption, and native-heavy Android. `bypass_executed: false` means no
automated dynamic bypass occurred. Further work follows hypothesis → failure evidence → bounded
alternative → isolated validation → evidence reassociation.

The runner has bounded extraction, strict JSON/YAML/XML, argument-list subprocesses,
output/time limits, process-tree cleanup, kernel locks, DNS pinning/redirect-scope rechecks,
redaction, and evidence/hash gates. Windows Job and Linux rlimits control resources; macOS hard
memory limits are unavailable. These controls are not a malicious-code sandbox; dynamic samples
require a separate isolation backend.

Each finding contains overview, technical root cause/trigger/attack surface, validation, impact,
and remediation/detection. Version strings, co-occurrence, zero keyword hits, and model prose
cannot promote a candidate to verified.


## Separate Adapter Modules

[ghidra_adapter.py](../src/re_runner/ghidra_adapter.py),
[extractors_ext.py](../src/re_runner/extractors_ext.py),
[frida_adapter.py](../src/re_runner/frida_adapter.py),
[vyper_adapter.py](../src/re_runner/vyper_adapter.py),
[s3_adapter.py](../src/re_runner/s3_adapter.py), and
[ai_adapter.py](../src/re_runner/ai_adapter.py) expose independent Python interfaces tested in
specialist lanes. A helper's presence or historical direct test is not automatic `re-run analyze`
integration. Inspect its contract and prerequisites before an explicitly requested invocation.
Frida's probe targets its own harmless child; S3's probe uses a configured local moto endpoint;
AI streaming uses injected synthetic transport. Those scopes do not authorize arbitrary process,
cloud, or model-service interaction. The [historical ledger](execution-acceptance.md) records
which direct runs were performed and which environments were absent.
