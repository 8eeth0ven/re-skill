#!/usr/bin/env python3
"""Record a tiny local Python observation; no target, device or network access."""
import datetime as dt
import hashlib
import json
import platform
from pathlib import Path
import sys


def main():
    payload = bytes.fromhex("000a0dff")
    lossy_control = payload.decode("utf-8", errors="replace").encode("utf-8")
    record = {
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "observation_mode": "host",
        "host": {"system": platform.system(), "release": platform.release(),
                 "macos_version": platform.mac_ver()[0], "machine": platform.machine()},
        "runtime": {"implementation": platform.python_implementation(), "version": platform.python_version()},
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "arithmetic": {"input_hex": "0x80000000", "increment_hex": "0x1000",
                       "result_decimal": int("0x80000000", 16) + int("0x1000", 16),
                       "zero_increment_control": int("0x80000000", 16)},
        "encoding": {"input_hex": payload.hex(), "length": len(payload),
                     "hex_roundtrip": bytes.fromhex(payload.hex()).hex(),
                     "lossy_utf8_replace_control_hex": lossy_control.hex()},
        "scope": "This Python process and generated inputs only. No Android shell, ADB, mksh, external target or device was tested.",
    }
    sys.stdout.buffer.write((json.dumps(record, ensure_ascii=True, indent=2) + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
