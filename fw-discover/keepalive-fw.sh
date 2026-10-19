#!/bin/bash
# 固件自主发现·半小时保活 v2(每 1800s 下发一批;停止门=队列挖空,不是候选数)
cd "$(dirname "$0")" || exit 1
LOG=../data/fw-discover/keepalive.log
LOCK=../data/fw-discover/.keepalive
if [ -f "$LOCK" ]; then echo "$(date '+%F %T') keepalive-fw 已在跑,退出" >>"$LOG"; exit 0; fi
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
    say "轮$i: 队列空($([ "$(cnt)" ])/候选),追加种子"
    python3 fw.py --seed >>"$LOG" 2>&1
    if [ "$(pend)" -eq 0 ]; then say "追加后仍无种子:队列挖空收尾,累计候选 $(cnt)——进入批量四杀门阶段"; exit 0; fi
  fi
  if pgrep -f 'fw.py --once' >/dev/null 2>&1; then
    say "轮$i: fw 实例在跑,跳过(候选 $(cnt),队列剩 $(pend))"
  else
    say "轮$i: 下发 --once(候选 $(cnt),队列剩 $(pend))"
    python3 fw.py --once >>"$LOG" 2>&1
    say "轮$i: 完成,候选 $(cnt),队列剩 $(pend)"
  fi
  sleep 1800
done
say "40 轮(约20小时)到顶退出"
