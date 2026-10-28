#!/usr/bin/env python3
"""NVD context lookup. Zero keyword hits never establishes vulnerability novelty."""
import hashlib
import json
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from _legacy_safety import KernelLock, atomic_text, read_bounded  # noqa: E402

CACHE = Path(__file__).parent.parent / "data" / "fw-discover" / "nvd-cache"
UA = {"User-Agent": "research-re-lab"}
OPENER = urllib.request.build_opener()
CACHE_TTL = 86400


def valid_result(value, require_entries=True):
    """Reject malformed/incomplete NVD payloads without converting them to zero hits."""
    if not isinstance(value, dict):
        return False
    count = value.get("totalResults")
    if type(count) is not int or count < 0:
        return False
    if "vulnerabilities" not in value:
        return not require_entries
    entries = value["vulnerabilities"]
    if not isinstance(entries, list) or len(entries) > count or bool(entries) != bool(count):
        return False
    return all(isinstance(entry, dict) and isinstance(entry.get("cve"), dict)
               and isinstance(entry["cve"].get("id"), str)
               and bool(entry["cve"]["id"].strip()) for entry in entries)


def aggregate(results):
    # Accept count-only summaries for callers, but nvd/main require complete payloads.
    if not results or any(not valid_result(value, require_entries=False) for value in results):
        return "UNKNOWN (lookup failed; semantic/advisory comparison required)"
    if any(value.get("totalResults", 0) > 0 for value in results):
        return "RELATED-ADVISORIES (compare root cause, affected version and patches)"
    return "NO-KEYWORD-HITS (novelty remains unknown)"


def summarize_verdict(verdicts):
    """Compatibility helper: old labels never restore a claim that zero hits prove novelty."""
    if not verdicts or any(value not in ("NEW", "KNOWN") for value in verdicts):
        return aggregate([None])
    return aggregate([{"totalResults": 1 if value == "KNOWN" else 0} for value in verdicts])


def nvd(keyword):
    if not keyword.strip() or len(keyword) > 256 or any(ord(c) < 32 for c in keyword):
        raise ValueError("Keyword must contain 1–256 printable characters")
    CACHE.mkdir(parents=True, exist_ok=True)
    cp = CACHE / (hashlib.sha256(keyword.encode("utf-8")).hexdigest() + ".json")
    if cp.is_file() and not cp.is_symlink() and cp.stat().st_size < 8 << 20 and time.time() - cp.stat().st_mtime < CACHE_TTL:
        try:
            data = json.loads(cp.read_text("utf-8"))
            if valid_result(data):
                return data
        except (OSError, ValueError, AttributeError):
            pass
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 50})
    req = urllib.request.Request(url, headers=UA)
    for attempt in range(3):
        lock = KernelLock(CACHE / ".rate-lock")
        if not lock.acquire():
            time.sleep(1)
            continue
        try:
            timestamp = CACHE / "last-request.txt"
            try:
                previous = float(timestamp.read_text("ascii"))
            except (OSError, ValueError):
                previous = 0
            delay = min(6.1, max(0, 6.1 - (time.time() - previous)))
            if delay:
                time.sleep(delay)
            atomic_text(timestamp, str(time.time()))
            with OPENER.open(req, timeout=20) as r:
                data = json.loads(read_bounded(r, 8 << 20))
            if not valid_result(data):
                raise ValueError("Invalid NVD response")
            atomic_text(cp, json.dumps(data, ensure_ascii=False))
            return data
        except Exception as exc:
            print(f"NVD-ERR {keyword}: {type(exc).__name__} (attempt {attempt + 1}/3)")
        finally:
            lock.release()
    return None


def main():
    words = sys.argv[1:]
    if not words:
        print(__doc__)
        return 2
    results = []
    for w in words:
        try:
            data = nvd(w)
        except (OSError, ValueError) as exc:
            print(f"{w}: query failed ({type(exc).__name__}), manual recheck")
            data = None
        if not valid_result(data):
            data = None
        results.append(data)
        if data is None:
            print(f"{w}: lookup failed or response incomplete; manual recheck")
            continue
        n = data.get("totalResults", 0)
        ids = [v.get("cve", {}).get("id") for v in data.get("vulnerabilities", [])][:8]
        print(f"{w}: hits {n} {ids}")
    print("verdict:", aggregate(results))
    return 2 if any(value is None for value in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
