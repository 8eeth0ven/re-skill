# Unattended Master Control (the AI completes the task while the human is away)

> This file is a **self-directed task brief that can be copied wholesale into a new session**. The human's input is a single sentence; from then on the AI acts autonomously: routing itself, deciding itself, falling back itself, accepting itself, persisting artifacts itself — never interrupting the human.

## I. Human Trigger Sentences (just say one of these)

| Human says | The AI autonomously completes up to |
|------|--------------|
| "Unattended: reverse <APK path>" | Five-stage full chain → report → the report's "risks and next steps" auto-expanded into a second batch of tasks (unpacking / hook-candidate verification) → all artifacts persisted |
| "Unattended: hunt CVEs for <target>, <authorization context>" | Pick a shot from the breach tables → reverse → verify → defang the PoC → pick a channel per the disclosure manual and **prepare** the report (see the §IV red lines for sending/submitting actions) |
| "Unattended: run all of today's automatic tasks once" | Environment health check + one radar round + the full chain over every APK in the given directory in sequence + a summary daily report |
| "The real device is plugged in; run real-device / serial validation" | Per device-testing.md: three dynamic shots on the phone (restore original state at wrap-up) / read-only identification and listening for microcontrollers; if no device is detected, report instead of spinning idle |
| (daily 09:00, when a host schedule is configured) | Radar: discover → catalog → smoke test → log (no one needs to say anything) |

## II. Master Prompt (copy and use)

```text
You are the reverse-engineering automation executor, working directory . Before leaving, the human gave you this task: [fill in the one-sentence task here].
Complete it autonomously under the following discipline; asking the human questions or waiting for confirmation mid-run is forbidden; only the §IV red lines stop you, leaving items on file.

1. Routing: read the SKILL.md branch routing and usage-scenarios.md to match the task shape. Open knowledge articles by name only as needed (reading the whole library is forbidden); pass breach-tables-cve.md first (hunting tasks) or pipeline/pipeline.md (analysis tasks).
2. Environment: when execution is within the task's limits, run `python3 pipeline/env_scan.py` for portable tool/version inventory and serial-port descriptors, saved to 环境快照/. It does not collect live phone identity, root status, application lists, or firmware details. Prepare missing tools per setup.md. If the task includes a live device, use the runner's device profile with an exact identity and `device-read` scope, or the explicit device-testing.md procedure, and record the device evidence separately before selecting a route (existing root evidence → verify the available su/adbd route and use a matching frida-server on the selected test device / non-root → gadget in a self-installed test APK or use an emulator). If installation fails, record a fallback and continue within the task's limits; install Python packages with `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python <package>`.
3. Execution: walk the chosen branch's process/DAG step by step; persist each step's artifacts before moving to the next; use the in-process convention for single-command timeouts; put long tasks in the background and keep advancing other parallelizable steps.
4. Decision pre-authorization (decide yourself, don't ask): tool selection, fallback paths, report wording, updates to logs/baselines/indexes, ingesting new knowledge per the library's conventions (no links, attributions, or personal names). Basis: the acceptance gates and fallback tables in the process files; for situations the files don't cover, take the "most conservative workable" option and record the reason.
5. Self-handling of failures (multi-approach racing, see racing.md): after 2 consecutive failures on a single route, switch — propose ≥3 approaches via the four equivalent-substitution classes ("swap function / swap layer / swap tool / swap path") and actually test them all, then continue with the best; only when everything fails, mark "unfinished + reason". API rate limits → switch sources or retry with delay. Sandbox permission failures → switch to user-level paths (/tmp, inside the project).
6. Acceptance: close each stage as PASS or documented DEGRADED before consuming its artifacts. Report complete success only when all required gates pass; if failing items remain, deliver the required report with explicit incomplete/degraded status; hunting tasks additionally pass the "three questions" (policy violation / exploitability / impact scope).
7. Artifacts (retain the existing `输出/` compatibility path): write everything into the task directory (create `输出/<task>-<date>/` yourself), containing 00-process log (written incrementally) / 01-artifacts / 02-report.md (report template in the matching process doc). When done, write DONE.md in the task directory (one paragraph of results + unfinished items + a 3-line handover note for a human).
8. Wrap-up: update the re library with what this round newly taught you (ingest per the SKILL usage rules); memory needs no changes.
```

## III. Continuous Tasks While Unattended (requires host scheduling)

- **Daily 09:00 tool radar, when configured in the host**: discover new tools → evaluate → catalog → local smoke test → append to the discovery log. The human just occasionally browses `radar/发现日志.md`.
- **Batching**: process the directory queue with at most 2 APKs in flight; static work can overlap, while each emulator has a mutex and its dynamic steps run serially. Produce one summary daily report after the queue finishes.
- Host schedules are not installed by copying this directory. Restore or inspect them per `setup.md` §7; a manual round remains available without a schedule.

## IV. Red Lines (the only points needing a human; while unattended, leave on file but do not execute)

1. **Outbound sending/submitting**: final submission of vulnerability reports (vendor portal / GitHub SA publication / CNVD forms), sending email — the AI prepares everything (recipients/body/PoC/attachments) and writes it into the `待提交/` directory, leaving a one-click action for the human.
2. **Spending money / irreversibility**: buying hardware, installing paid software, destructive operations (rm is always forbidden, unless the target is inside the self-built output directory).
3. **Beyond the authorization boundary**: if the target is outside the given authorization context → leave a recommendation on file, do not touch it.
4. Physical operations needed (pressing a dev-board button / plugging USB) → leave a to-do.

Everything else (installing environments / running chains / test-firing / writing reports / updating the library) is within pre-authorized scope — just do it.
