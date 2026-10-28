#!/usr/bin/env python3
# Autonomous firmware vulnerability discovery (0day candidates) · zero-touch batch continuation
# Sources: DD-WRT betas (real router firmware, public directory) + OpenWrt factory images (unpack-chain validation channel)
# Pipeline: seed queue → download → magic scan (TRX/uImage/squashfs/gzip) → unsquashfs (falls back to sasquatch) → analyzer discovery rules → findings.jsonl + ledger
# Difference from ../cve-hunter: that side matches known CVEs by version (N-day ledger); this side mines candidates with our own rules (0day candidate ledger)
# Red line: candidates are for local research only; external reporting goes through a human + the disclosure process
import argparse
import hashlib
import json
import re
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from analyzers import scan_rootfs, test_des_creds  # noqa: E402
from _legacy_safety import KernelLock, atomic_bytes, atomic_text, bounded_gzip, http_get as safe_http_get, safe_name  # noqa: E402

DATA = ROOT.parent / "data" / "fw-discover"
FWDIR = DATA / "fw"          # raw firmware
ROOTFS = DATA / "rootfs"     # unpack trees
CACHE = DATA / "cache"
QUEUE = DATA / "queue.jsonl"
FINDINGS = DATA / "findings.jsonl"
LEDGER = DATA / "台账.md"
PROGRESS = DATA / "progress.json"
LOCK = DATA / ".lock"
LOG = DATA / "fw.log"
TARGET = 100
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-re-lab"}
MAX_FW_MB = 64
MAX_ATTEMPTS = 3
_LOCK_OWNER = None

DDWRT = "https://download1.dd-wrt.com/dd-wrtv2/downloads/betas/"
OPENWRT = "https://downloads.openwrt.org/releases/"

# ---------- Basics ----------

def log(msg):
    DATA.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%F %T')} {msg}\n")


def http_get(url, timeout=60):
    blob = safe_http_get(url, UA, timeout=timeout, limit=MAX_FW_MB << 20)
    if b"anubis" in blob[:600].lower() and len(blob) < 4096:
        raise RuntimeError(f"anti-bot challenge page {url}")
    return blob


def http_cached(url):
    cp = CACHE / hashlib.sha1(url.encode()).hexdigest()
    if cp.exists() and cp.stat().st_size:
        return cp.read_bytes()
    blob = http_get(url)
    CACHE.mkdir(parents=True, exist_ok=True)
    atomic_bytes(cp, blob)
    return blob


def list_html(url):
    """Directory page → list of relative links"""
    html = http_cached(url).decode("utf-8", "replace")
    links = re.findall(r'href="([^"?/][^"?]*)"', html)
    from urllib.parse import unquote
    return [link for link in links if not link.startswith((".", "/"))
            and ":" not in link and "\\" not in unquote(link)
            and ".." not in unquote(link).split("/")]


def acquire_lock():
    global _LOCK_OWNER
    owner = KernelLock(LOCK)
    if not owner.acquire():
        print("instance already running; kernel lock is held")
        return False
    _LOCK_OWNER = owner
    return True


def queue_load():
    if QUEUE.exists():
        return [json.loads(line) for line in QUEUE.read_text("utf-8").splitlines() if line.strip()]
    return []


def queue_save(items):
    atomic_text(QUEUE, "\n".join(json.dumps(x, ensure_ascii=False) for x in items) + "\n")


# ---------- Seeds ----------

def seed_ddwrt(years=("2023", "2024"), dates=2, models=6, cap=40):
    """betas/year/date-rXXXXX/model-dir/firmware.bin (real router firmware)"""
    out = []
    for y in years:
        try:
            dlist = list_html(f"{DDWRT}{y}/")
        except Exception:
            continue
        dlist = [d for d in dlist if re.match(r"^\d{2}-\d{2}-", d)]
        for d in sorted(dlist)[-dates:]:
            try:
                mdirs = [m for m in list_html(f"{DDWRT}{y}/{d}") if m.endswith("/")][:models]
            except Exception:
                continue
            for md in mdirs:
                try:
                    files = list_html(f"{DDWRT}{y}/{d}{md}")
                except Exception:
                    continue
                bins = sorted(f for f in files if f.lower().endswith((".bin", ".trx"))
                              and "webflash" not in f.lower())
                if bins and len(out) < cap:
                    f0 = bins[0]
                    out.append({"url": f"{DDWRT}{y}/{d}{md}{f0}", "src": "ddwrt",
                                "name": f"ddwrt-{y}-{d[:5]}-{md.strip('/').replace('%20', '-')[:36]}"})
    return out


def seed_openwrt(rels=("21.02.0", "22.03.0", "23.05.0"), targets=("ath79/generic", "ramips/mt7621"), per_t=3, cap=18):
    out = []
    for rel in rels:
        for t in targets:
            try:
                files = list_html(f"{OPENWRT}{rel}/targets/{t}/")
            except Exception:
                continue
            fac = sorted(f for f in files if "squashfs-factory" in f and f.endswith(".bin"))[:per_t]
            for f in fac:
                if len(out) < cap:
                    out.append({"url": f"{OPENWRT}{rel}/targets/{t}/{f}", "src": "openwrt",
                                "name": f"owrt{rel}-{f[:-4]}"})
    return out


def cmd_seed():
    items = queue_load()
    have = {i["url"] for i in items}
    for s in (seed_ddwrt(), seed_openwrt()):
        for it in s:
            if it["url"] not in have:
                items.append({**it, "status": "pending"})
                have.add(it["url"])
    queue_save(items)
    print(f"seed queue: {len(items)} entries (ddwrt+openwrt), pending {sum(1 for i in items if i['status']=='pending')}")


# ---------- Unpacking ----------

SQ_MAGIC = (b"hsqs", b"sqsh", b"qshs", b"shsq")  # LE/BE squashfs 3/4


def find_magics(blob):
    """Returns [(name, offset)] by priority: squashfs/TRX/uImage/gzip"""
    found = []
    for m in SQ_MAGIC:
        i = blob.find(m)
        while i != -1 and i < 8 * 1024 * 1024 and all(i != x[1] for x in found):
            found.append(("squashfs", i))
            i = blob.find(m, i + 4)
        if found:
            break
    if blob[:4] == b"HDR0":
        found.append(("trx", 0))
    if blob[:4] == b"\x27\x05\x19\x56":
        found.append(("uimage", 0))
    if blob[:2] == b"\x1f\x8b" and not found:
        found.append(("gzip", 0))
    return found


def extract_squashfs(slice_path, outdir):
    """Opaque filesystem extraction requires an isolated provider; never run on host implicitly."""
    log(f"isolated squashfs provider required: {slice_path.name}; use re-run --type firmware")
    return None


def extract_firmware(binpath, out_root):
    """Unpack one firmware → (rootfs dir | None, unpacker, note)"""
    if binpath.stat().st_size > MAX_FW_MB << 20:
        return None, None, "input byte budget exceeded"
    blob = binpath.read_bytes()
    fwdir = out_root.parent
    fwdir.mkdir(parents=True, exist_ok=True)
    tmp = fwdir / "_slice.bin"
    for depth in range(3):  # strip at most 3 container layers
        magics = find_magics(blob)
        if not magics:
            return None, None, "no known magic"
        kind, off = magics[0]
        if kind == "gzip":
            try:
                blob = bounded_gzip(blob, limit=128 << 20)
                continue
            except Exception:
                return None, None, "gzip decompression failed"
        if kind == "trx":
            # TRX header is 28 bytes; the len field gives the image length; find squashfs directly inside the TRX
            ln = struct.unpack("<I", blob[4:8])[0] if len(blob) >= 8 else len(blob)
            sub = blob[:min(ln or len(blob), len(blob))]
            for m in SQ_MAGIC:
                i = sub.find(m)
                if i != -1:
                    blob = sub[i:]
                    kind = "squashfs"
                    break
            if kind == "trx":
                return None, None, "no squashfs inside TRX"
        if kind == "uimage":
            sub = blob[64:]
            for m in SQ_MAGIC:
                i = sub.find(m)
                if i != -1:
                    blob = sub[i:]
                    kind = "squashfs"
                    break
            if kind == "uimage":
                return None, None, "no squashfs inside uImage"
        if kind == "squashfs":
            tmp.write_bytes(blob[off if off else 0:])
            rd = extract_squashfs(tmp, fwdir / "rootfs")
            tmp.unlink(missing_ok=True)
            if rd:
                return fwdir / "rootfs", rd, f"depth{depth}"
            return None, None, "squashfs unpack failed (needs sasquatch?)"
    return None, None, "layer-stripping exhausted"


# ---------- Ledger ----------

def read_findings():
    if not FINDINGS.exists():
        return []
    out = []
    for line in FINDINGS.read_text("utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def append_finding(rec):
    with FINDINGS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_ledger():
    rows = read_findings()
    by_cls, by_fw = {}, {}
    for r in rows:
        by_cls[r["cls"]] = by_cls.get(r["cls"], 0) + 1
        by_fw[r["fw"]] = by_fw.get(r["fw"], 0) + 1
    rows.sort(key=lambda r: (-r["pri"], r["fw"]))
    L = ["# Autonomous Firmware Vulnerability Discovery Ledger (0day candidates)\n",
         f"> generated {time.strftime('%F %T')} | cumulative **{len(rows)}/{TARGET}** | firmware: {len(by_fw)} | "
         f"rules: analyzers.py (account files / private keys / command-injection flows / telnetd / default passwords) — **every entry is autonomously discovered on this machine, not matched against a CVE database**",
         "> Red lines: candidates are for local research prioritization only; external reporting goes through a human + `../../disclosure-cve.md`; dynamic emulation (FirmAE/qemu) is next stage.\n"]
    L.append("| Class | Count | Description |")
    L.append("|---|---|---|")
    desc = {"verified-weak-cred": "factory weak password hit by wordlist (verified locally)", "shipped-private-key": "private key shipped in firmware",
            "cmdi-candidate": "network parameter and exec strings co-occur; flow and reachability unverified", "cmdi-script": "CGI/shell script eval consuming external parameters",
            "telnetd-enabled": "boot script enables telnetd by default", "default-cred": "nvram/config default-password literal",
            "hardcoded-account": "passwd/shadow account with an active hash"}
    for k, v in sorted(by_cls.items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} | {desc.get(k, '')} |")
    L.append("\n| Firmware | Count |")
    L.append("|---|---|")
    for k, v in sorted(by_fw.items(), key=lambda x: -x[1])[:40]:
        L.append(f"| {k} | {v} |")
    L.append("\n## Details (by priority, top 400)\n")
    L.append("| # | Priority | Firmware | Class | Path | Evidence |")
    L.append("|---|---|---|---|---|---|")
    for i, r in enumerate(rows[:400], 1):
        ev = r["evidence"].replace("|", "\\|")[:120]
        path = r["path"].replace("|", "\\|")
        L.append(f"| {i} | {r['pri']} | {r['fw']} | {r['cls']} | {path} | {ev} |")
    atomic_text(LEDGER, "\n".join(L) + "\n")


def load_progress():
    if PROGRESS.exists():
        try:
            return json.loads(PROGRESS.read_text("utf-8"))
        except Exception:
            pass
    return {"target": TARGET, "findings_count": 0, "done": 0, "failed": 0, "phase": "run"}


def save_progress(p):
    p["target"] = TARGET
    p["updated"] = time.strftime("%F %T")
    atomic_text(PROGRESS, json.dumps(p, ensure_ascii=False, indent=1))


# ---------- Main flow ----------

def process_one(item, prog):
    """Download → unpack → analyze one firmware"""
    url, name = item["url"], item["name"]
    from urllib.parse import urlsplit
    if urlsplit(url).hostname not in ("download1.dd-wrt.com", "downloads.openwrt.org"):
        return "blocked-scope: catalog host is not allowed"
    name = safe_name(name)
    fwfile = FWDIR / (name + ".bin")
    fwfile.parent.mkdir(parents=True, exist_ok=True)
    if not fwfile.exists():
        try:
            blob = http_get(url, timeout=180)
            if len(blob) > MAX_FW_MB << 20:
                return "blocked-too-large"
            atomic_bytes(fwfile, blob)
        except Exception as e:
            return f"error-download-failed {type(e).__name__}"
    rootfs, tool, note = extract_firmware(fwfile, ROOTFS / name / "rootfs")
    if rootfs is None:
        return f"blocked-extract: {note}"
    # analyze
    keys = {hashlib.sha1((r["fw"] + r["cls"] + r["path"] + r["evidence"]).encode()).hexdigest() for r in read_findings()}
    rows = scan_rootfs(rootfs, name)
    acc = [r for r in rows if r["cls"] == "hardcoded-account"]
    rows += test_des_creds(acc)
    added = 0
    for r in rows:
        k = hashlib.sha1((r["fw"] + r["cls"] + r["path"] + r["evidence"]).encode()).hexdigest()
        if k in keys:
            continue
        keys.add(k)
        append_finding({**r, "src": item["src"], "ts": time.strftime("%F %T")})
        added += 1
    write_ledger()
    n = len(read_findings())
    log(f"OK {name} unpack={tool} found+{added} total={n}")
    print(f"[fw] {name} unpack={tool}/{note} found+{added}, total {n}/{TARGET}")
    return f"ok+{added}"


def run_once(batch=4):
    items = queue_load()
    prog = load_progress()
    if not items:
        print("queue is empty, run --seed first")
        return
    did = 0
    for it in items:
        if did >= batch:
            break
        if it.get("status") in ("done", "blocked") or it.get("attempts", 0) >= MAX_ATTEMPTS:
            continue
        it["attempts"] = it.get("attempts", 0) + 1
        try:
            res = process_one(it, prog)
        except Exception as exc:
            res = "error-analysis: " + type(exc).__name__
        it["status"] = "done" if res.startswith("ok") else "blocked" if res.startswith("blocked") else "error"
        it["result"] = res
        did += 1
        queue_save(items)
    queue_save(items)
    prog["findings_count"] = len(read_findings())
    prog["done"] = sum(1 for i in items if i.get("status") == "done")
    prog["failed"] = sum(1 for i in items if i.get("status") == "error")
    save_progress(prog)
    retryable = [i for i in items if i.get("status") in ("pending", "error") and i.get("attempts", 0) < MAX_ATTEMPTS]
    if not retryable:
        prog["phase"] = "queue-finished-with-gaps" if any(i.get("status") != "done" for i in items) else "queue-empty"
        save_progress(prog)
        print(f"queue finished: candidates {prog['findings_count']}; blocked/failed items retain their reasons")
    else:
        print(f"[batch done] candidates {prog['findings_count']}, {sum(1 for i in items if i.get('status') == 'pending')} left in queue")


def show_status():
    prog = load_progress()
    items = queue_load()
    rows = read_findings()
    print(f"progress: found {len(rows)}/{prog['target']} | queue {len(items)} (pending {sum(1 for i in items if i.get('status')=='pending')}) | updated={prog.get('updated')}")
    for r in sorted(rows, key=lambda x: -x["pri"])[:5]:
        print(f"  top: [{r['pri']}] {r['fw']} {r['cls']} {r['path']}")
    print(f"ledger: {LEDGER}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", action="store_true", help="pull sources and build the seed queue")
    ap.add_argument("--once", action="store_true", help="process a small batch of firmware (download → unpack → discover)")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--reset", action="store_true", help="clear findings/queue/progress (rootfs/fw/cache kept)")
    a = ap.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    if a.reset:
        if not acquire_lock():
            sys.exit(3)
        try:
            for p in (FINDINGS, PROGRESS, QUEUE, LEDGER):
                p.unlink(missing_ok=True)
        finally:
            _LOCK_OWNER.release()
        print("cleared")
        return
    if a.seed:
        if not acquire_lock():
            sys.exit(3)
        try:
            cmd_seed()
        finally:
            _LOCK_OWNER.release()
        return
    if not a.once:
        show_status()
        return
    if a.once:
        if not acquire_lock():
            sys.exit(3)
        try:
            run_once()
            write_ledger()
        finally:
            _LOCK_OWNER.release()


if __name__ == "__main__":
    main()
