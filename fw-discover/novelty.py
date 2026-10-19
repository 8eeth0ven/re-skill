#!/usr/bin/env python3
# 四杀门② 新颖性查重:组件/产品名 → NVD keywordSearch,带本地缓存与限速
# 用法: python3 novelty.py bpalogin [fstools openwrt ...]
# 输出: 每词 命中数+CVE 列表;总 verdict: NEW(全 0)/KNOWN(有命中,人工比对语义)
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
            time.sleep(6)  # 无 key 限速 5/30s
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
            print(f"{w}: 查询失败(网络),人工复核")
            verdicts.append("ERR")
            continue
        n = data.get("totalResults", 0)
        ids = [v["cve"]["id"] for v in data.get("vulnerabilities", [])][:8]
        print(f"{w}: 命中 {n} {ids}")
        verdicts.append("KNOWN" if n else "NEW")
    print("verdict:", "KNOWN(需人工语义比对)" if "KNOWN" in verdicts else ("NEW" if "NEW" in verdicts else "ERR"))


if __name__ == "__main__":
    main()
