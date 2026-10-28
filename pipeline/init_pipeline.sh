#!/usr/bin/env bash
# Optional Bash entry point. Native Windows uses init_pipeline.ps1; state is shared.
# Usage: source /absolute/skill-root/pipeline/init_pipeline.sh "/absolute/path/app.apk"
re_pipeline_init() {
  local re_skill_root re_python re_state re_env_file
  re_skill_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || return 2
  re_python=${RE_PYTHON:-$(command -v python3 || command -v python || true)}
  [[ -n "$re_python" ]] || return 127
  re_state=$("$re_python" "$re_skill_root/pipeline/init_pipeline.py" "$@") || return $?
  re_env_file=$(printf '%s' "$re_state" | "$re_python" -c 'import json,sys; print(json.load(sys.stdin)["env_sh"].replace("\\", "/"))') || return 2
  source "$re_env_file"
}
re_pipeline_init "$@"
re_pipeline_init_rc=$?
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return "$re_pipeline_init_rc"
fi
exit "$re_pipeline_init_rc"
