#!/usr/bin/env python3
# 固件自主漏洞发现(0day 候选)·零人工续批
# 源: DD-WRT betas(真路由器固件,公开目录) + OpenWrt 工厂镜像(解包链验证通道)
# 流程: 种子队列 → 下载 → 魔数扫描(TRX/uImage/squashfs/gzip) → unsquashfs(失败降级 sasquatch) → analyzers 发现规则 → findings.jsonl + 台账.md
# 与 ../cve-hunter 的区别: 那边是已知 CVE 版本比对(N-day 台账);这边是我们自己规则挖出来的候选(0day 候选台账)
# 红线: 候选仅本地研究,外报走人工+披露流程
import argparse, gzip, hashlib, json, re, shutil, struct, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from analyzers import scan_rootfs, test_des_creds  # noqa: E402

DATA = ROOT.parent / "data" / "fw-discover"
FWDIR = DATA / "fw"          # 原始固件
ROOTFS = DATA / "rootfs"     # 解包树
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

# ---------- 基础 ----------

def log(msg):
    DATA.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%F %T')} {msg}\n")


def http_get(url, timeout=60):
    # DD-WRT 前面有 Anubis 反爬,python urllib UA 会被挑战页挡;curl 默认 UA 实测可过
    r = subprocess.run(["curl", "-sL", "--max-time", str(timeout), url],
                       capture_output=True, timeout=timeout + 15)
    if r.returncode != 0 or not r.stdout:
        raise RuntimeError(f"curl {url} rc={r.returncode}")
    if b"anubis" in r.stdout[:600].lower() and len(r.stdout) < 4096:
        raise RuntimeError(f"反爬挑战页 {url}")
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
    """目录页 → 相对链接列表"""
    html = http_cached(url).decode("utf-8", "replace")
    return re.findall(r'href="([^"?/][^"?]*)"', html)


def acquire_lock():
    DATA.mkdir(parents=True, exist_ok=True)
    if LOCK.exists():
        try:
            pid = int(LOCK.read_text().strip() or "0")
            import os
            os.kill(pid, 0)
            print(f"已有实例(pid={pid}),退出")
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


# ---------- 种子 ----------

def seed_ddwrt(years=("2023", "2024"), dates=2, models=6, cap=40):
    """betas/年/日期-rXXXXX/型号目录/固件.bin(真路由器固件)"""
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
    print(f"种子队列 {len(items)} 条(ddwrt+openwrt),pending {sum(1 for i in items if i['status']=='pending')}")


# ---------- 解包 ----------

SQ_MAGIC = (b"hsqs", b"sqsh", b"qshs", b"shsq")  # LE/BE squashfs 3/4


def find_magics(blob):
    """返回 [(名称, 偏移)] 按优先: squashfs/TRX/uImage/gzip"""
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
    """unsquashfs → sasquatch 降级。判定看产出内容不看 rc:非 root 时设备节点建不了会 rc!=0 但文件已解出"""
    if shutil.which("unsquashfs"):
        r = subprocess.run(["unsquashfs", "-d", str(outdir), "-f", "-n", str(slice_path)],
                           capture_output=True, text=True, timeout=300)
        got = outdir.exists() and sum(1 for _ in outdir.rglob("*")) > 20
        if got:
            return "unsquashfs"
        log(f"unsquashfs 失败 {slice_path.name}: {(r.stderr or r.stdout).strip()[-160:]}")
    if shutil.which("sasquatch"):
        r = subprocess.run(["sasquatch", "-d", str(outdir), str(slice_path)],
                           capture_output=True, text=True, timeout=300)
        if r.returncode == 0 and outdir.exists() and any(outdir.iterdir()):
            return "sasquatch"
    return None


def extract_firmware(binpath, out_root):
    """解一个固件 → (rootfs 目录|None, 解包器, 备注)"""
    blob = binpath.read_bytes()
    fwdir = out_root.parent
    fwdir.mkdir(parents=True, exist_ok=True)
    tmp = fwdir / "_slice.bin"
    for depth in range(3):  # 容器最多剥 3 层
        magics = find_magics(blob)
        if not magics:
            return None, None, "无已知魔数"
        kind, off = magics[0]
        if kind == "gzip":
            try:
                blob = gzip.decompress(blob)
                binpath.write_bytes(blob[:1])  # 占位不需要
                continue
            except Exception:
                return None, None, "gzip 解压失败"
        if kind == "trx":
            # TRX 头 28 字节,len 字段取镜像长;直接在 TRX 内找 squashfs
            ln = struct.unpack("<I", blob[4:8])[0] if len(blob) >= 8 else len(blob)
            sub = blob[:min(ln or len(blob), len(blob))]
            for m in SQ_MAGIC:
                i = sub.find(m)
                if i != -1:
                    blob = sub[i:]
                    kind = "squashfs"
                    break
            if kind == "trx":
                return None, None, "TRX 内无 squashfs"
        if kind == "uimage":
            sub = blob[64:]
            for m in SQ_MAGIC:
                i = sub.find(m)
                if i != -1:
                    blob = sub[i:]
                    kind = "squashfs"
                    break
            if kind == "uimage":
                return None, None, "uImage 内无 squashfs"
        if kind == "squashfs":
            tmp.write_bytes(blob[off if off else 0:])
            rd = extract_squashfs(tmp, fwdir / "rootfs")
            tmp.unlink(missing_ok=True)
            if rd:
                return fwdir / "rootfs", rd, f"depth{depth}"
            return None, None, "squashfs 解包失败(需 sasquatch?)"
    return None, None, "剥层耗尽"


# ---------- 台账 ----------

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
    L = ["# 固件自主漏洞发现台账(0day 候选)\n",
         f"> 生成 {time.strftime('%F %T')} | 累计 **{len(rows)}/{TARGET}** | 固件 {len(by_fw)} 个 | "
         f"规则: analyzers.py(帐号文件/私钥/命令注入流/telnetd/默认口令)——**每条都是本机自主发现,非 CVE 库比对**",
         "> 红线: 候选仅供本地研究排序;外报走人工+`../漏洞披露与CVE申请.md`;动态仿真(FirmAE/qemu)下阶段。\n"]
    L.append("| 类别 | 条数 | 说明 |")
    L.append("|---|---|---|")
    desc = {"verified-weak-cred": "字典命中的出厂弱口令(已本地验证)", "shipped-private-key": "固件自带私钥",
            "cmdi-candidate": "网络参数×执行函数同体(命令注入流候选)", "cmdi-script": "CGI/shell 脚本 eval 吃外部参数",
            "telnetd-enabled": "启动脚本默认开 telnetd", "default-cred": "nvram/配置默认口令字面量",
            "hardcoded-account": "passwd/shadow 带活动哈希账号"}
    for k, v in sorted(by_cls.items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} | {desc.get(k, '')} |")
    L.append("\n| 固件 | 条数 |")
    L.append("|---|---|")
    for k, v in sorted(by_fw.items(), key=lambda x: -x[1])[:40]:
        L.append(f"| {k} | {v} |")
    L.append("\n## 明细(按优先级,前 400)\n")
    L.append("| # | 优先级 | 固件 | 类别 | 路径 | 证据 |")
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


# ---------- 主流程 ----------

def process_one(item, prog):
    """下载→解包→分析 一个固件"""
    url, name = item["url"], item["name"]
    fwfile = FWDIR / (name + ".bin")
    fwfile.parent.mkdir(parents=True, exist_ok=True)
    if not fwfile.exists():
        try:
            blob = http_get(url, timeout=180)
            if len(blob) > MAX_FW_MB << 20:
                return "skip-过大"
            fwfile.write_bytes(blob)
        except Exception as e:
            return f"skip-下载失败 {e}"
    if fwfile.suffix == ".zip":
        subprocess.run(["unzip", "-o", "-q", str(fwfile), "-d", str(fwfile.with_suffix(""))], capture_output=True, timeout=120)
        zips = list(fwfile.with_suffix("").rglob("*"))
        inner = [z for z in zips if z.is_file() and z.suffix.lower() in (".bin", ".img", ".trx")]
        if not inner:
            return "skip-zip内无bin"
        fwfile = inner[0]
    rootfs, tool, note = extract_firmware(fwfile, ROOTFS / name / "rootfs")
    if rootfs is None:
        return f"skip-解包: {note}"
    # 分析
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
    log(f"OK {name} 解包={tool} 发现+{added} 累计={n}")
    print(f"[fw] {name} 解包={tool}/{note} 发现+{added},累计 {n}/{TARGET}")
    shutil.rmtree(ROOTFS / name / "rootfs" / "rootfs", ignore_errors=True)  # 清嵌套
    return f"ok+{added}"


def run_once(batch=4):
    items = queue_load()
    prog = load_progress()
    if not items:
        print("队列为空,先 --seed")
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
        print(f"队列挖空:累计候选 {prog['findings_count']}")
    else:
        print(f"[批完] 候选 {prog['findings_count']},队列剩 {sum(1 for i in items if i.get('status') == 'pending')}")


def show_status():
    prog = load_progress()
    items = queue_load()
    rows = read_findings()
    print(f"进度: 发现 {len(rows)}/{prog['target']} | 队列 {len(items)}(pending {sum(1 for i in items if i.get('status')=='pending')}) | updated={prog.get('updated')}")
    for r in sorted(rows, key=lambda x: -x["pri"])[:5]:
        print(f"  高优: [{r['pri']}] {r['fw']} {r['cls']} {r['path']}")
    print(f"台账: {LEDGER}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", action="store_true", help="拉源建种子队列")
    ap.add_argument("--once", action="store_true", help="处理一小批固件(下载→解包→发现)")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--reset", action="store_true", help="清 findings/queue/进度(rootfs/fw/cache 保留)")
    a = ap.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    if a.reset:
        for p in (FINDINGS, PROGRESS, LOCK, QUEUE, LEDGER):
            p.unlink(missing_ok=True)
        print("已清空")
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
