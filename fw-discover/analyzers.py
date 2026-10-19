# 固件自主漏洞发现规则(非 CVE 版本比对——每条都是本机静态分析"自己发现"的候选)
# 输入: 解包后的 rootfs 树; 输出: [(类别, 证据dict, 优先级 0-4, 说明)]
# 优先级: 4=已验证弱凭证/私钥 3=命令注入流候选(网络面) 2=telnetd/默认口令 1=硬编码账号 0=信息类
import os, re, stat
from pathlib import Path

NET_MARKERS = (b"QUERY_STRING", b"REQUEST_METHOD", b"websGetVar", b"nvram_get", b"REQUEST_URI")
EXEC_MARKERS = (b"system", b"popen", b"execve", b"execl", b"execv")
DEFAULT_CRED_RE = re.compile(rb"(?:http_passwd|http_username|admin_password|user_passwd|login_password|pass)\s*[=:]\s*([!-~]{3,32})")
WORDLIST = ["admin", "password", "root", "toor", "123456", "12345", "admin123", "default", "guest", "dreambox"]


def is_elf(p):
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def scan_file(path):
    """单文件发现规则(字节级,兼容任何可读文件)"""
    try:
        if path.stat().st_size > 12 * 1024 * 1024:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    out = []
    low = data.lower()

    # 1) 出厂私钥
    if b"-----begin" in low and b"private key" in low:
        out.append(("shipped-private-key", {"path": str(path), "evidence": "PEM 私钥块"}, 4))

    # 2) nvram/配置默认口令(非空字面量)
    for m in DEFAULT_CRED_RE.finditer(data):
        v = m.group(1)
        if v.lower() not in (b"none", b"none)", b"false", b"none;", b"none\r"):
            out.append(("default-cred", {"path": str(path), "evidence": m.group(0)[:96].decode("latin1", "replace")}, 2))
        if len(out) > 24:
            break

    # 3) 命令注入流候选: 网络参数来源标记 × 执行函数标记 同文件共现(ELF/脚本一体适用)
    net = [x for x in NET_MARKERS if x in data]
    ex = [x for x in EXEC_MARKERS if b"%s\x00" % x in data or b"%s(" % x in data or x in data]
    if net and ex:
        out.append(("cmdi-candidate", {
            "path": str(path), "evidence": f"net={net[0].decode()} × exec={ex[0].decode()}",
            "net_markers": [x.decode() for x in net], "exec_markers": [x.decode() for x in ex],
            "elf": is_elf(path)}, 3))

    # 4) 脚本 eval/反引号吃外部参数
    if low.endswith((b".sh", b".cgi")) or b"#!/bin/sh" in data[:64]:
        for i, line in enumerate(data.split(b"\n")):
            if b"eval" in line and any(x in line for x in (b"QUERY_STRING", b"POST", b"$1", b"$*")):
                out.append(("cmdi-script", {"path": str(path), "evidence": line.strip()[:160].decode("latin1", "replace")}, 3))
                break
    return out


def parse_account_file(path):
    """passwd/shadow 解析: 返回 [(user, hash, 空/锁/无)]"""
    rows = []
    try:
        for line in path.read_text("utf-8", "replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[0] and not parts[0].startswith("#"):
                rows.append((parts[0], parts[1], path))
    except OSError:
        pass
    return rows


ACTIVE_HASH_RE = re.compile(r"^(?:\$1\$|\$5\$|\$6\$|\$2[aby]\$|[./0-9A-Za-z]{13}$)")


def scan_rootfs(root, fw_name):
    """整个 rootfs 树 → 发现列表"""
    root = Path(root)
    out = []
    accounts = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            # 帐号文件
            if fn in ("passwd", "shadow", "shadow-") and p.parent.name == "etc":
                for user, h, fp in parse_account_file(p):
                    if ACTIVE_HASH_RE.match(h):
                        accounts.append({"fw": fw_name, "user": user, "hash": h, "path": str(fp)})
            for f in scan_file(p):
                cls, ev, pri = f
                out.append({"fw": fw_name, "cls": cls, "pri": pri, **ev})

    # passwd/shadow 中的活动哈希账号 = 硬编码账号候选
    for a in accounts:
        out.append({"fw": fw_name, "cls": "hardcoded-account", "pri": 1,
                    "path": a["path"], "evidence": f"{a['user']}:{a['hash']}"})

    # telnetd 后门: 扫启动脚本
    for rc in list(root.rglob("rcS")) + list(root.rglob("inittab")) + \
              [p for p in root.rglob("*") if p.suffix in (".sh", ".rc", ".init") and p.is_file()]:
        try:
            if rc.stat().st_size > 256 * 1024:
                continue
            for line in rc.read_text("utf-8", "replace").splitlines():
                s = line.strip()
                if "telnetd" in s and not s.startswith("#"):
                    out.append({"fw": fw_name, "cls": "telnetd-enabled", "pri": 2,
                                "path": str(rc), "evidence": s[:160]})
                    break
        except OSError:
            pass
    return out


def test_des_creds(candidates):
    """本地可做的真测试: 对 DES crypt(13 位)哈希跑小字典,命中则提级为 verified-weak-cred"""
    import subprocess
    hits = []
    for c in candidates:
        h = c["evidence"].split(":", 1)[1]
        if len(h) != 13:
            continue
        for w in WORDLIST:
            try:
                r = subprocess.run(["openssl", "passwd", "-crypt", "-salt", h[:2], w],
                                   capture_output=True, text=True, timeout=5)
                if r.stdout.strip() == h:
                    hits.append({**c, "cls": "verified-weak-cred", "pri": 4,
                                 "evidence": f"{c['evidence']} ← 字典命中: {w}"})
                    break
            except Exception:
                break
    return hits
