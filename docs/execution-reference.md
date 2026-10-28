# Execution Readiness and Maintenance

Read this reference only when executing tools, preparing a machine, or maintaining the library.

## CLI Runner and Execution Readiness

The repository includes the `re-run` CLI (`src/re_runner/`), `pyproject.toml`,
and `uv.lock`. The runner requires Python 3.11+; skill discovery alone does not
install its dependencies, external engines, or MCP connections. Follow
[setup.md](../setup.md) and the user's installation/testing limits.

When execution is requested, inspect the asset and use the runner's profile
readiness report before analysis. Refer to the [runner guide](runner.md)
for actual CLI options and profile coverage. Network and live-device reads use
its explicit scope mechanism; APK-derived URLs are not automatically follow-up
targets. Agent-driven APK analysis remains the separate staged workflow above.

Distinguish observations, heuristic candidates, and reproduced findings. A
private-key string, source/sink co-occurrence, version match, zero NVD hits, or
exit code zero does not prove exploitability or novelty. The runner's protection
routes are indicators/plans with `bypass_executed: false`; deeper work belongs in
the [completion handoff](agent-completion-prompt.md). Compare a baseline
and negative control before claiming a successful bypass.

## Tool Environment

- Common CLI tools: `jadx`, `apktool`, `r2`, `adb`, and `7z`; detect availability before use.
- Python environment: `tools-env/.venv`. On this machine, use `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python <package>`; the venv has no pip and this cache path avoids known sandbox cache failures. Windows equivalents are in [setup.md](../setup.md).
- Prefer `python3 pipeline/env_check.py` for cross-platform health checks. Keep `pipeline/env_check.sh` as the legacy macOS Bash fallback.
- Optional local MCP observations: `../radar/mcp-test-report.md`; tool observations: `../radar/tool-test-report.md`. These machine-local records are excluded from Git and may be absent in a fresh clone. They are dated observations, not a live capability guarantee. Check the installed client/server version and architecture before a dynamic session; prepared server binaries are under `tools-env/frida-server/` when installed.

## Maintenance Rules

1. Route through this entry and the selected INDEX; read relevant articles progressively. Each INDEX owns its branch's file list.
2. Method bodies contain methods and code, without new external links, attributions, or personal names. Preserve existing source lookup metadata and historical evidence; use the data index to locate original corpus material.
3. APK full-chain requests enter `pipeline/pipeline.md`; acceptance and artifact structure come from that workflow.
4. Apply `test-values.md` to probes, hooks, and output, including the verification and cleanup loop.
5. Ingest techniques into the matching `techniques/` area, domain knowledge into `platforms/`, and tools into the selection table plus radar baseline. Smoke-test installable tools before marking them usable.
6. Before maintenance, read [maintenance.md](../maintenance.md) for current conventions and any available local historical audit for known regressions. Do not turn old smoke tests into current results.
7. [SSL pinning bypass](../techniques/04-evasion/ssl-pinning-bypass.md) is the primary methodology. [Java certificate snippets](../techniques/02-frida/java-layer/sslpinning-and-certificates.md), [capture scenarios](../techniques/04-evasion/capture-all-scenarios.md), and the [vendor archive](../techniques/04-evasion/vendor-capture-countermeasures.md) are subordinate; the primary article resolves conflicts.
8. On a new machine, follow `setup.md` first and restore the optional radar schedule separately. Leave raw corpus data, installed tools, and existing historical records intact during documentation maintenance.
