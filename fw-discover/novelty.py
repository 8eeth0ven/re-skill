#!/usr/bin/env python3
"""Search NVD keywords for disclosure deduplication; zero hits do not prove novelty.

Usage: python3 novelty.py <component> [extra terms ...]
"""
# Evidence gate ②: cached keyword search with rate limiting
# Usage: python3 novelty.py bpalogin [fstools openwrt ...]
# Output: keyword hit counts/CVEs; NEW means no keyword matches, not proof of novelty. ERR takes precedence when any query is incomplete.
import json, sys, time, urllib.request, urllib.parse
from pathlib import Path

CACHE = Path(__file__).parent.parent / "data" / "fw-discover" / "nvd-cache"
UA = {"User-Agent": "research-re-lab"}
PROXY = {"https": "http://127.0.0.1:7897", "http": "http://127.0.0.1:7897"}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler(PROXY))


def nvd(keyword):
    CACHE.mkdir(parents=True, exist_ok=True)
    safe_keyword = keyword.replace(" ", "_")
    if any(value in safe_keyword for value in ("/", "\\", "..")):
        safe_keyword = __import__("hashlib").sha256(keyword.encode()).hexdigest()
    cp = CACHE / (safe_keyword + ".json")
    if cp.exists():
        try:
            return json.loads(cp.read_text())
        except (OSError, ValueError):
            print(f"NVD-CACHE-ERR {keyword}: invalid cache; querying again")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"keywordSearch": keyword})
    req = urllib.request.Request(url, headers=UA)
    for _ in range(3):
        try:
            with OPENER.open(req, timeout=30) as r:
                data = json.loads(r.read())
            cp.write_text(json.dumps(data, ensure_ascii=False))
            time.sleep(6)  # no-key rate limit: 5 requests / 30s
            return data
        except Exception as e:
            log = f"NVD-ERR {keyword}: {e}"
            print(log)
            time.sleep(10)
    return None


def summarize_verdict(verdicts):
    """A failed keyword search must never be promoted to a novelty conclusion."""
    if not verdicts or "ERR" in verdicts:
        return "ERR (incomplete search; manual recheck required)"
    if "KNOWN" in verdicts:
        return "KNOWN (keyword matches; manual root-cause/affected-version comparison needed)"
    return "NEW (no keyword matches; novelty is not established)"


def main():
    words = sys.argv[1:]
    if not words:
        print(__doc__)
        return
    verdicts = []
    for w in words:
        data = nvd(w)
        if data is None:
            print(f"{w}: query failed (network), manual recheck")
            verdicts.append("ERR")
            continue
        n = data.get("totalResults") if isinstance(data, dict) else None
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            print(f"{w}: incomplete/malformed NVD result; manual recheck")
            verdicts.append("ERR")
            continue
        entries = data.get("vulnerabilities")
        valid_entries = isinstance(entries, list) and all(
            isinstance(entry, dict) and isinstance(entry.get("cve"), dict)
            and isinstance(entry["cve"].get("id"), str) and entry["cve"]["id"].strip()
            for entry in entries)
        if not valid_entries or bool(n) != bool(entries) or len(entries) > n:
            print(f"{w}: malformed/incomplete vulnerability list; manual recheck")
            verdicts.append("ERR")
            continue
        ids = [entry["cve"]["id"] for entry in entries[:8]]
        print(f"{w}: hits {n} {ids}")
        verdicts.append("KNOWN" if n else "NEW")
    print("verdict:", summarize_verdict(verdicts))


if __name__ == "__main__":
    main()
