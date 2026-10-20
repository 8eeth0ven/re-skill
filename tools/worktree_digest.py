"""Worktree identity digest, matching the acceptance reviewer's algorithm:

Scope: src/ tests/ examples/ pyproject.toml uv.lock, excluding caches
(__pycache__, *.pyc, .venv). Sort relative paths by UTF-8 ordinal; concatenate
`UTF-8 path + NUL + lowercase SHA256(content) hex + LF`; SHA256 the result.

Usage: python tools/worktree_digest.py [--root .]
"""
import argparse
import hashlib
import sys
from pathlib import Path

ROOTS = ("src", "tests", "examples")
EXCLUDE_DIRS = {"__pycache__", ".venv", "node_modules"}
EXCLUDE_SUFFIX = (".pyc", ".pyo")


def collect(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in ROOTS:
        base = root / name
        if base.is_file():
            files.append(base)
            continue
        for directory, subdirs, names in base.walk():
            subdirs[:] = [d for d in subdirs if d not in EXCLUDE_DIRS]
            for item in sorted(names):
                if item.endswith(EXCLUDE_SUFFIX):
                    continue
                files.append(directory / item)
    for name in ("pyproject.toml", "uv.lock"):
        path = root / name
        if path.is_file():
            files.append(path)
    return sorted(set(files), key=lambda p: p.relative_to(root).as_posix().encode("utf-8"))


def digest(root: Path) -> tuple[str, int]:
    accumulator = hashlib.sha256()
    files = collect(root)
    for path in files:
        content = hashlib.sha256(path.read_bytes()).hexdigest().lower().encode("ascii")
        accumulator.update(path.relative_to(root).as_posix().encode("utf-8"))
        accumulator.update(b"\x00")
        accumulator.update(content)
        accumulator.update(b"\n")
    return accumulator.hexdigest(), len(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    value, count = digest(args.root)
    print(f"files: {count}")
    print(f"worktree-digest: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
