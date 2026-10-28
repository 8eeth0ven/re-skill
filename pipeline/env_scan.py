#!/usr/bin/env python3
"""Portable environment inventory. Device collection requires separate explicit scope."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main():
    from re_runner.inventory import snapshot
    text, _ = snapshot(ROOT)
    print(text)
    print(f"Saved: {ROOT / '环境快照' / 'latest.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
