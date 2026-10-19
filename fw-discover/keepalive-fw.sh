#!/bin/bash
# Autonomous firmware discovery · half-hour keepalive v2 (dispatch one batch every 1800s; stop gate = queue exhausted, not candidate count)
cd "$(dirname "$0")" || exit 1
LOG=../data/fw-discover/keepalive.log
LOCK=../data/fw-discover/.keepalive
if [ -f "$LOCK" ]; then echo "$(date '+%F %T') keepalive-fw already running, exiting" >>"$LOG"; exit 0; fi
echo $$ >"$LOCK"
trap 'rm -f "$LOCK"' EXIT
say() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
cnt() { python3 -c "import json;print(sum(1 for _ in open('../data/fw-discover/findings.jsonl')))" 2>/dev/null || echo 0; }
pend() { python3 -c "
import json
items=[json.loads(l) for l in open('../data/fw-discover/queue.jsonl') if l.strip()]
print(sum(1 for i in items if i.get('status')=='pending'))" 2>/dev/null || echo 0; }
for i in $(seq 1 40); do
  if [ "$(pend)" -eq 0 ]; then
    say "round $i: queue empty ($([ "$(cnt)" ])/candidates), appending seeds"
    python3 fw.py --seed >>"$LOG" 2>&1
    if [ "$(pend)" -eq 0 ]; then say "still no seeds after appending: queue exhausted, wrapping up with $(cnt) cumulative candidates — entering the batch four-kill-gates stage"; exit 0; fi
  fi
  if pgrep -f 'fw.py --once' >/dev/null 2>&1; then
    say "round $i: fw instance already running, skipping (candidates $(cnt), $(pend) left in queue)"
  else
    say "round $i: dispatching --once (candidates $(cnt), $(pend) left in queue)"
    python3 fw.py --once >>"$LOG" 2>&1
    say "round $i: done, candidates $(cnt), $(pend) left in queue"
  fi
  sleep 1800
done
say "40 rounds (~20 hours) reached, exiting"
