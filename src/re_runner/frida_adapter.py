"""Frida dynamic-analysis adapter (real execution against a self-spawned child).

Scope boundary (declared, not negotiable): the only target this adapter
attaches to is a child process it started itself via ``subprocess.Popen``
(the repo's own interpreter running a harmless snippet). No third-party or
system process is ever touched. macOS notes baked in for frida 17.x:
``Module.findExportByName`` was removed — export resolution goes through
``Module.getExportByName`` with an ``ApiResolver('symbol')`` fallback, and
module enumeration is done script-side via ``Process.enumerateModules()``.

Every run returns a ToolRun-compatible dict. ``verification_state`` is
"real-run" only when a live attach actually happened; a missing frida
install yields "not-run" (never a mock success).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .errors import InvalidInput
from .safety import atomic_json, redact

_RESOLVE_JS = """
// frida 17 macOS resolution chain (measured on 17.23.3):
//   Module.getExportByName(null, name)  -> removed ("not a function")
//   ApiResolver('symbol')               -> unavailable on hardened macOS hosts
//   working: Module.getGlobalExportByName / module-instance getExportByName /
//            enumerateExports filter
var CANDIDATE_MODULES = ["libsystem_kernel.dylib", "libsystem_c.dylib", "libsystem.dylib"];
function resolveExport(name) {
    try {
        var p = Module.getGlobalExportByName(name);
        if (p && !p.isNull()) return { addr: p, via: "Module.getGlobalExportByName", ok: true };
    } catch (e) {}
    for (var i = 0; i < CANDIDATE_MODULES.length; i++) {
        try {
            var mod = Process.getModuleByName(CANDIDATE_MODULES[i]);
            var p2 = mod.getExportByName(name);
            if (p2 && !p2.isNull()) return { addr: p2, via: mod.name + ".getExportByName", ok: true };
        } catch (e2) {}
    }
    try {
        for (var j = 0; j < CANDIDATE_MODULES.length; j++) {
            try {
                var mod2 = Process.getModuleByName(CANDIDATE_MODULES[j]);
                var hits = mod2.enumerateExports().filter(function (x) { return x.name === name; });
                if (hits.length > 0) return { addr: hits[0].address, via: mod2.name + ".enumerateExports", ok: true };
            } catch (e3) {}
        }
    } catch (e4) {}
    try {
        var resolver = new ApiResolver("symbol");
        var matches = resolver.enumerateMatches("*!" + name);
        if (matches.length > 0) return { addr: matches[0].address, via: "ApiResolver('symbol')", ok: true };
    } catch (e5) {}
    return { addr: null, via: "unresolved", ok: false };
}
"""

_HOOK_JS = (
    _RESOLVE_JS
    + """
var hitCount = 0;
var resolveInfo = { name: "getuid", via: "unresolved", ok: false };
var resolved = resolveExport("getuid");
if (resolved.addr !== null) {
    resolveInfo = { name: "getuid", via: resolved.via, ok: true };
    Interceptor.attach(resolved.addr, {
        onEnter: function (args) { hitCount += 1; }
    });
}
rpc.exports = {
    hookInfo: function () { return resolveInfo; },
    hitCount: function () { return hitCount; },
    modules: function () {
        var mods = Process.enumerateModules();
        return { total: mods.length, sample: mods.slice(0, 64).map(function (m) {
            return { name: m.name, base: m.base.toString(), size: m.size };
        }) };
    }
};
"""
)

_CHILD_SNIPPET = (
    "import os, sys, time\n"
    "sys.stderr.write('re-blane-child-ready\\n')\n"
    "sys.stderr.flush()\n"
    "for _ in range(400):\n"
    "    os.getuid()\n"
    "    time.sleep(0.02)\n"
)


def _ensure_frida_cache_env() -> None:
    """Frida writes runtime caches under ~/.cache/frida; when the host's cache
    root is unwritable (seen on sandboxed macOS hosts where ~/.cache is root-
    owned), redirect via XDG_CACHE_HOME to a private temp dir before frida is
    imported. Never touches contents of the unwritable directory."""
    cache_home = Path.home() / ".cache"
    try:
        probe = cache_home / ".re-blane-write-probe"
        probe.touch()
        probe.unlink()
        return
    except OSError:
        import tempfile  # noqa: PLC0415

        os.environ.setdefault("XDG_CACHE_HOME", tempfile.mkdtemp(prefix="re-blane-frida-cache-"))


def tool_available() -> tuple[bool, str]:
    """Report whether the frida python binding is importable in this interpreter."""
    _ensure_frida_cache_env()
    try:
        import frida  # noqa: PLC0415
    except Exception as exc:  # ImportError or broken binding
        return False, f"frida import failed: {exc}"
    return True, str(frida.__version__)


def _base_record(tool: str, version: str, argv: list[str], started: float) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "id": f"toolrun-{uuid.uuid4().hex[:12]}",
        "asset_id": "blane-dynamic-local",
        "tool": tool,
        "version": version,
        "argv": argv,
        "status": "failed",
        "started": now,
        "finished": now,
        "exit_code": None,
        "stdout": None,
        "stderr": None,
        "timed_out": False,
        "artifacts": [],
        "error": None,
        "verification_state": "real-run",
        "scope": "self-spawned child process only (subprocess.Popen of this interpreter); "
        "no third-party or system process is targeted",
    }


def trace_self_child(output_dir: Path, *, hold_seconds: float = 1.5) -> dict:
    """Spawn a harmless child, attach frida, enumerate modules, hook getuid, detach.

    Returns a ToolRun-compatible record. status "succeeded" requires: real
    attach, script loaded, at least one module enumerated, the export resolved
    through the frida-17 API, and hit_count > 0. Any weaker outcome is recorded
    as failed/degraded with the concrete reason.
    """
    if hold_seconds <= 0 or hold_seconds > 30:
        raise InvalidInput("hold_seconds must be within (0, 30]")
    available, version_or_reason = tool_available()
    if not available:
        return {
            **_base_record("frida", "unknown", ["frida-trace-self-child"], time.monotonic()),
            "status": "not-run",
            "verification_state": "not-run",
            "error": version_or_reason,
        }
    import frida  # noqa: PLC0415

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, "-c", _CHILD_SNIPPET]
    record = _base_record("frida", str(frida.__version__), argv, time.monotonic())
    child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    session = None
    script = None
    try:
        # Wait for the child's ready marker so attach lands on live code.
        marker = child.stderr.readline()
        if b"re-blane-child-ready" not in marker:
            record["error"] = "child did not report ready"
            return record
        session = frida.get_local_device().attach(child.pid)
        script = session.create_script(_HOOK_JS)
        script.load()
        exports = getattr(script, "exports_sync", None) or script.exports
        modules = exports.modules()
        hook_info = exports.hook_info()
        time.sleep(hold_seconds)
        hit_count = int(exports.hit_count())
        record.update(
            {
                "status": "succeeded" if (modules["total"] > 0 and hit_count > 0 and hook_info["ok"]) else "degraded",
                "exit_code": 0,
                "mode": "attach",
                "target_pid": child.pid,
                "modules_total": modules["total"],
                "modules_sample": modules["sample"],
                "hook": hook_info,
                "hit_count": hit_count,
                "frida_api_note": "frida 17 macOS: Module.getGlobalExportByName / module-instance "
                "getExportByName; findExportByName and null-form Module.getExportByName are gone, "
                "ApiResolver('symbol') unavailable on hardened hosts",
            }
        )
    except Exception as exc:  # frida.ProcessNotFoundError, script errors, ...
        record["error"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        for closer in (
            lambda: script.unload(),
            lambda: session.detach(),
        ):
            try:
                closer()
            except Exception:
                pass
        child.kill()
        child.wait(timeout=10)
        record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_json(output_dir / "frida-trace-self-child.json", redact(record))
    record["artifacts"].append({"path": str(output_dir / "frida-trace-self-child.json"), "kind": "json"})
    return record


def trace_missing_pid(output_dir: Path, *, pid: int = 999999) -> dict:
    """Failure path: attach to a pid that cannot exist on this host.

    macOS pid_max is 99998, so 999999 is guaranteed absent — no real process
    can be matched by accident. The record is still "real-run": the attach
    attempt genuinely executed and genuinely failed.
    """
    available, version_or_reason = tool_available()
    if not available:
        return {
            **_base_record("frida", "unknown", ["frida-attach-missing-pid"], time.monotonic()),
            "status": "not-run",
            "verification_state": "not-run",
            "error": version_or_reason,
        }
    import frida  # noqa: PLC0415

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    record = _base_record("frida", str(frida.__version__), ["frida-attach", str(pid)], time.monotonic())
    try:
        session = frida.get_local_device().attach(pid)
        try:
            session.detach()
        except Exception:
            pass
        record["error"] = f"unexpectedly attached to pid {pid}"
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"[:500]
        record["exit_code"] = 1
    record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_json(output_dir / "frida-attach-missing-pid.json", redact(record))
    record["artifacts"].append({"path": str(output_dir / "frida-attach-missing-pid.json"), "kind": "json"})
    return record
