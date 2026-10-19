#!/usr/bin/env python3
# Kill-gate ② novelty dedupe: component/product name → NVD keywordSearch, with local cache and rate limiting
# Usage: python3 novelty.py bpalogin [fstools openwrt ...]
# Output: per keyword hit count + CVE list; overall verdict: NEW (all 0) / KNOWN (hits, manual semantic comparison)
import json, sys, time, urllib.request, urllib.parse
from pathlib import Path

CACHE = Path(__file__).parent.parent / "data" / "fw-discover" / "nvd-cache"
UA = {"User-Agent": "research-re-lab"}
PROXY = {"https": "http://127.0.0.1:7897", "http": "http://127.0.0.1:7897"}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler(PROXY))


def nvd(keyword):
    CACHE.mkdir(parents=True, exist_ok=True)
    cp = CACHE / (keyword.replace(" ", "_") + ".json")
    if cp.exists():
        return json.loads(cp.read_text())
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
        n = data.get("totalResults", 0)
        ids = [v["cve"]["id"] for v in data.get("vulnerabilities", [])][:8]
        print(f"{w}: hits {n} {ids}")
        verdicts.append("KNOWN" if n else "NEW")
    print("verdict:", "KNOWN (manual semantic comparison needed)" if "KNOWN" in verdicts else ("NEW" if "NEW" in verdicts else "ERR"))


if __name__ == "__main__":
    main()
