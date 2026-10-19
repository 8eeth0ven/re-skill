#!/usr/bin/env python3
# Autonomous firmware vulnerability discovery (0day candidates) · zero-touch batch continuation
# Sources: DD-WRT betas (real router firmware, public directory) + OpenWrt factory images (unpack-chain validation channel)
# Pipeline: seed queue → download → magic scan (TRX/uImage/squashfs/gzip) → unsquashfs (falls back to sasquatch) → analyzer discovery rules → findings.jsonl + ledger
# Difference from ../cve-hunter: that side matches known CVEs by version (N-day ledger); this side mines candidates with our own rules (0day candidate ledger)
# Red line: candidates are for local research only; external reporting goes through a human + the disclosure process
import argparse, gzip, hashlib, json, re, shutil, struct, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from analyzers import scan_rootfs, test_des_creds  # noqa: E402

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

DDWRT = "https://download1.dd-wrt.com/dd-wrtv2/downloads/betas/"
OPENWRT = "https://downloads.openwrt.org/releases/"

# ---------- Basics ----------

def log(msg):
    DATA.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%F %T')} {msg}\n")


def http_get(url, timeout=60):
    # DD-WRT sits behind the Anubis anti-bot; python urllib's UA gets blocked by the challenge page, curl's default UA passes in practice
    r = subprocess.run(["curl", "-sL", "--max-time", str(timeout), url],
                       capture_output=True, timeout=timeout + 15)
    if r.returncode != 0 or not r.stdout:
        raise RuntimeError(f"curl {url} rc={r.returncode}")
    if b"anubis" in r.stdout[:600].lower() and len(r.stdout) < 4096:
        raise RuntimeError(f"anti-bot challenge page {url}")
    return r.stdout


def http_cached(url):
    cp = CACHE / hashlib.sha1(url.encode()).hexdigest()
    if cp.exists() and cp.stat().st_size:
        return cp.read_bytes()
    blob = http_get(url)
    CACHE.mkdir(parents=True, exist_ok=True)
    cp.write_bytes(blob)
    return blob


def list_html(url):
    """Directory page → list of relative links"""
    html = http_cached(url).decode("utf-8", "replace")
    return re.findall(r'href="([^"?/][^"?]*)"', html)


def acquire_lock():
    DATA.mkdir(parents=True, exist_ok=True)
    if LOCK.exists():
        try:
            pid = int(LOCK.read_text().strip() or "0")
            import os
            os.kill(pid, 0)
            print(f"instance already running (pid={pid}), exiting")
            return False
        except (ValueError, ProcessLookupError):
            pass
        except PermissionError:
            return False
    LOCK.write_text(str(__import__("os").getpid()))
    return True


def queue_load():
    if QUEUE.exists():
        return [json.loads(l) for l in QUEUE.read_text("utf-8").splitlines() if l.strip()]
    return []


def queue_save(items):
    QUEUE.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in items) + "\n", encoding="utf-8")


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
    """unsquashfs → sasquatch fallback. Success is judged by produced content, not rc: as non-root, failing device nodes can give rc!=0 while the files are already unpacked"""
    if shutil.which("unsquashfs"):
        r = subprocess.run(["unsquashfs", "-d", str(outdir), "-f", "-n", str(slice_path)],
                           capture_output=True, text=True, timeout=300)
        got = outdir.exists() and sum(1 for _ in outdir.rglob("*")) > 20
        if got:
            return "unsquashfs"
        log(f"unsquashfs failed {slice_path.name}: {(r.stderr or r.stdout).strip()[-160:]}")
    if shutil.which("sasquatch"):
        r = subprocess.run(["sasquatch", "-d", str(outdir), str(slice_path)],
                           capture_output=True, text=True, timeout=300)
        if r.returncode == 0 and outdir.exists() and any(outdir.iterdir()):
            return "sasquatch"
    return None


def extract_firmware(binpath, out_root):
    """Unpack one firmware → (rootfs dir | None, unpacker, note)"""
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
                blob = gzip.decompress(blob)
                binpath.write_bytes(blob[:1])  # placeholder, not needed
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
    for l in FINDINGS.read_text("utf-8").splitlines():
        try:
            out.append(json.loads(l))
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
         "> Red lines: candidates are for local research prioritization only; external reporting goes through a human + `../disclosure-cve.md`; dynamic emulation (FirmAE/qemu) is next stage.\n"]
    L.append("| Class | Count | Description |")
    L.append("|---|---|---|")
    desc = {"verified-weak-cred": "factory weak password hit by wordlist (verified locally)", "shipped-private-key": "private key shipped in firmware",
            "cmdi-candidate": "network parameter × exec function in the same file (command-injection flow candidate)", "cmdi-script": "CGI/shell script eval consuming external parameters",
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
        L.append(f"| {i} | {r['pri']} | {r['fw']} | {r['cls']} | {r['path'].replace('|', '\\|')} | {ev} |")
    LEDGER.write_text("\n".join(L) + "\n", encoding="utf-8")


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
    PROGRESS.write_text(json.dumps(p, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------- Main flow ----------

def process_one(item, prog):
    """Download → unpack → analyze one firmware"""
    url, name = item["url"], item["name"]
    fwfile = FWDIR / (name + ".bin")
    fwfile.parent.mkdir(parents=True, exist_ok=True)
    if not fwfile.exists():
        try:
            blob = http_get(url, timeout=180)
            if len(blob) > MAX_FW_MB << 20:
                return "skip-too-large"
            fwfile.write_bytes(blob)
        except Exception as e:
            return f"skip-download-failed {e}"
    if fwfile.suffix == ".zip":
        subprocess.run(["unzip", "-o", "-q", str(fwfile), "-d", str(fwfile.with_suffix(""))], capture_output=True, timeout=120)
        zips = list(fwfile.with_suffix("").rglob("*"))
        inner = [z for z in zips if z.is_file() and z.suffix.lower() in (".bin", ".img", ".trx")]
        if not inner:
            return "skip-no-bin-in-zip"
        fwfile = inner[0]
    rootfs, tool, note = extract_firmware(fwfile, ROOTFS / name / "rootfs")
    if rootfs is None:
        return f"skip-extract: {note}"
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
    shutil.rmtree(ROOTFS / name / "rootfs" / "rootfs", ignore_errors=True)  # clean nested dir
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
        if it.get("status") == "done":
            continue
        res = process_one(it, prog)
        it["status"] = "done" if res.startswith(("ok", "skip")) else "error"
        it["result"] = res
        did += 1
    queue_save(items)
    prog["findings_count"] = len(read_findings())
    prog["done"] = sum(1 for i in items if i.get("status") == "done")
    prog["failed"] = sum(1 for i in items if i.get("status") == "error")
    save_progress(prog)
    if not sum(1 for i in items if i.get("status") == "pending"):
        prog["phase"] = "queue-empty"
        save_progress(prog)
        print(f"queue exhausted: cumulative candidates {prog['findings_count']}")
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
        for p in (FINDINGS, PROGRESS, LOCK, QUEUE, LEDGER):
            p.unlink(missing_ok=True)
        print("cleared")
        return
    if a.seed:
        cmd_seed()
        return
    if not (a.once or a.status):
        show_status()
        return
    if a.once:
        if not acquire_lock():
            sys.exit(3)
        try:
            run_once()
            write_ledger()
        finally:
            LOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
