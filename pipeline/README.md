# pipeline branch: fully automated APK reverse-engineering executor

**One line**: given an APK path, run the five stages "environment check → information gathering → static → dynamic → report" with zero human effort, automatic degradation on failure, and a fixed directory structure for the output. **This branch is an executor, not a knowledge base.**

## Usage (agent entry)

When asked to run the full chain on `<apk>` (in the re skill entry: "fully automated RE / run the pipeline / run the full chain on `<apk path>`"):

1. Read `pipeline.md` in this directory (the single workflow definition; execute stages in order);
2. Run the full chain on the APK path: `S0 check → S1 parallel information gathering → S2 static → S3 dynamic → S4 report`;
3. Artifacts land under `输出/<package>-<date>/` (next to the APK, or in a user-specified directory);
4. A stage's acceptance gate (files exist and are non-empty) must pass before entering the next stage; on failure take the degradation path — **never ask the user, never halt**;
5. At the end, return the `03-report.md` path to the user, together with a list of "skipped items and reasons".

All commands are real commands a subagent can run directly via Bash (baseline environment: macOS arm64).

## Position and hand-off

This branch = **executor** (a fixed DAG that runs automatically to a report); the report is the **starting point**: to expand its "risks and next steps" or "unpacking route advice", go to the matching article under `../techniques/` (03-unpacking/, 02-frida/java-layer/, etc., via INDEX) and open it by name; for historical articles / technical corroboration use the corpus indexes under `../data/`.

Rule: never duplicate technique-library knowledge in this branch.

## File list

| File | Purpose |
| -------------- | ---------------------------------- |
| `pipeline.md` | Core: the five-stage DAG, commands / artifacts / acceptance gates / degradations in four-column tables |
| `env_check.sh` | Standalone environment-check script (exit 0 = all green / 1 = has yellows / 2 = critical red) |

## Environment baseline (as actually measured by env_check.sh)

- Available: jadx 1.5.6 / apktool 3.0.3 / adb+SDK (~/Library/Android/sdk) / radare2 / 7z / java 24 / node / uv / timeout (coreutils 9.9) / aapt2 (inside SDK build-tools 36.0.0)
- Installing (probed dynamically, degrade on absence): the frida suite and python libs (unicorn/capstone/androguard/apkid/apkleaks) → venv `~/.zcode/skills/re/tools-env/.venv`
- MCP: android-emulator ✓ (AVD `Medium_Phone_API_36.0` ready), node_repl ✓, WebSearch/WebFetch ✓, ida-pro-mcp (needs IDA with the plugin started manually; skipped if not running), fofa (skipped without a key)
