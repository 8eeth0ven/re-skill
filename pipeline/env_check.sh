#!/usr/bin/env bash
# Compatibility entry point; the Python implementation is the single authority.
# No GNU timeout/coreutils dependency. Bash is optional when calling env_check.py.
set -euo pipefail
re_pipeline_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
re_python=${RE_PYTHON:-$(command -v python3 || command -v python || true)}
if [[ -z "$re_python" ]]; then
  printf 'Python 3.11+ is required; set RE_PYTHON to its executable.\n' >&2
  exit 127
fi
exec "$re_python" "$re_pipeline_dir/env_check.py" "$@"
