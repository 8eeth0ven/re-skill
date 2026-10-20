# Autonomous firmware vulnerability discovery rules (not CVE version matching — every entry is a candidate "discovered by us" through local static analysis)
# Input: an unpacked rootfs tree; output: [(class, evidence dict, priority 0-4, description)]
# Priority: 4 = verified weak credential / private key; 3 = command-injection flow candidate (network-facing); 2 = telnetd / default password; 1 = hardcoded account; 0 = informational
import os
import re
from pathlib import Path

NET_MARKERS = (b"QUERY_STRING", b"REQUEST_METHOD", b"websGetVar", b"nvram_get", b"REQUEST_URI")
EXEC_MARKERS = (b"system", b"popen", b"execve", b"execl", b"execv")
DEFAULT_CRED_RE = re.compile(rb"(?:http_passwd|http_username|admin_password|user_passwd|login_password|pass)\s*[=:]\s*([!-~]{3,32})")
WORDLIST = ["admin", "password", "root", "toor", "123456", "12345", "admin123", "default", "guest", "dreambox"]


def is_elf(p):
    try:
        if p.is_symlink() or not p.is_file():
            return False
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def scan_file(path):
    """Per-file discovery rules (byte-level, works on any readable file)"""
    try:
        if path.is_symlink() or not path.is_file():
            return []
        if path.stat().st_size > 12 * 1024 * 1024:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    out = []
    low = data.lower()

    # 1) Factory private key
    if b"-----begin" in low and b"private key" in low:
        out.append(("shipped-private-key", {"path": str(path), "evidence": "PEM private-key block"}, 4))

    # 2) nvram/config default passwords (non-empty literals)
    for m in DEFAULT_CRED_RE.finditer(data):
        v = m.group(1)
        if v.lower() not in (b"none", b"none)", b"false", b"none;", b"none\r"):
            out.append(("default-cred", {"path": str(path), "evidence": m.group(0)[:96].decode("latin1", "replace")}, 2))
        if len(out) > 24:
            break

    # 3) String co-occurrence observation only; no caller, flow or reachability is proven.
    net = [x for x in NET_MARKERS if x in data]
    ex = [x for x in EXEC_MARKERS if b"%s\x00" % x in data or b"%s(" % x in data or x in data]
    if net and ex:
        out.append(("cmdi-candidate", {
            "path": str(path), "evidence": f"net={net[0].decode()} × exec={ex[0].decode()}",
            "net_markers": [x.decode() for x in net], "exec_markers": [x.decode() for x in ex],
            "elf": is_elf(path), "evidence_class": "string-cooccurrence",
            "reachability": "unknown", "status": "candidate"}, 1))

    # 4) Script eval/backticks consuming external parameters
    if path.suffix.lower() in (".sh", ".cgi") or b"#!/bin/sh" in data[:64]:
        for i, line in enumerate(data.split(b"\n")):
            if b"eval" in line and any(x in line for x in (b"QUERY_STRING", b"POST", b"$1", b"$*")):
                out.append(("cmdi-script", {"path": str(path), "evidence": line.strip()[:160].decode("latin1", "replace")}, 3))
                break
    return out


def parse_account_file(path):
    """passwd/shadow parser: returns [(user, hash, empty/locked/none)]"""
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
    """Whole rootfs tree → discovery list"""
    root = Path(root)
    out = []
    accounts = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if not (Path(dirpath) / name).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            # account files
            if fn in ("passwd", "shadow", "shadow-") and p.parent.name == "etc":
                for user, h, fp in parse_account_file(p):
                    if ACTIVE_HASH_RE.match(h):
                        accounts.append({"fw": fw_name, "user": user, "hash": h, "path": str(fp)})
            for f in scan_file(p):
                cls, ev, pri = f
                out.append({"fw": fw_name, "cls": cls, "pri": pri, **ev})

    # accounts with active hashes in passwd/shadow = hardcoded-account candidates
    for a in accounts:
        out.append({"fw": fw_name, "cls": "hardcoded-account", "pri": 1,
                    "path": a["path"], "evidence": f"{a['user']}:{a['hash']}"})

    # telnetd backdoor: scan boot scripts
    for rc in list(root.rglob("rcS")) + list(root.rglob("inittab")) + \
              [p for p in root.rglob("*") if p.suffix in (".sh", ".rc", ".init") and p.is_file()]:
        try:
            if rc.is_symlink() or not rc.is_file() or rc.stat().st_size > 256 * 1024:
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
    """A real test doable locally: run a small wordlist against DES crypt (13-char) hashes; hits get promoted to verified-weak-cred"""
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
                                 "evidence": f"{c['evidence']} ← wordlist hit: {w}"})
                    break
            except Exception:
                break
    return hits
