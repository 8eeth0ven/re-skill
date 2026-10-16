#!/usr/bin/env python3
"""Stalker 块级/调用事件跟踪驱动(macOS arm64 本机实测通过,frida 17.23.3)。

用法:
  ./stalker_trace.py --target <可执行> --args "-c,import time;..." \
      [--events call,block] [--limit 500] [--exclude-all-but-main] \
      [--queue-capacity 8192] [--drain-interval 250] [--out events.jsonl]

输出:JSONL 事件流(type/location/target/depth/module/off),stdout 打统计。
事件格式(Stalker.parse stringify=false):
  call  -> ["call", from, to, depth]
  block -> ["block", blockAddr] (annotate=false 时为 [from, to, depth] 形态视版本)
  ret   -> ["ret", from, to, depth]
Stalker 线程选择(macOS 实测):Process.enumerateThreads() 只回主线程,
tid 不等于 pid,直接 [0] 即主线程;spawn 挂起期 follow 不生效,
必须 resume 后收到 'go' 再 follow(本脚本已内置)。
"""
import argparse
import json
import subprocess
import sys
import time

import frida

JS = r"""
'use strict';
const opts = %s;   // {events, limit, excludeAllButMain, queueCapacity, queueDrainInterval}

const mainThread = Process.enumerateThreads()[0].id;
const mainMod = Process.enumerateModules()[0];

// ---- 控量参数 1:模块排除(防事件爆炸)----
if (opts.excludeAllButMain) {
  let excluded = 0;
  Process.enumerateModules().forEach(m => {
    if (m.path !== mainMod.path) {
      Stalker.exclude({ base: m.base, size: m.size });
      excluded++;
    }
  });
  send({tag: 'cfg', excluded: excluded, keep: mainMod.name});
}

// 模块归属缓存:地址->name!off(避免每事件查表卡死)
const modCache = new Map();
function locate(addr) {
  const a = addr.toString();
  if (modCache.has(a)) return modCache.get(a);
  const m = Process.findModuleByAddress(addr);
  const r = m ? (m.name + '!0x' + addr.sub(m.base).toString(16)) : 'anon@' + a;
  if (modCache.size < 4096) modCache.set(a, r);
  return r;
}
// locate 结果属于主模块?(macOS 实测:dyld 共享缓存模块的 Stalker.exclude
// 可能不生效,exclude 之后事件照样来,JS 侧过滤是最终兜底)
function inMain(loc) { return loc.indexOf(mainMod.name + '!') === 0; }

let seen = 0;
let counts = {};   // 热点统计:块/调用目标频次
let t0 = null;

// ---- 控量参数 2:事件开关(call/ret/block/exec)----
const ev = {};
opts.events.forEach(k => ev[k] = true);

// ---- 控量参数 3:队列缓冲(queueCapacity/queueDrainInterval)----
const followOpts = {
  events: ev,
  onReceive: function (blob) {
    if (t0 === null) t0 = Date.now();
    // annotate:true 才有类型名('call'/'ret'/'block' 在 e[0]),实测必开
    const evs = Stalker.parse(blob, { annotate: true, stringify: false });
    const out = [];
    for (const e of evs) {
      if (seen >= opts.limit) break;
      seen++;
      const type = e[0];
      counts[type] = (counts[type] || 0) + 1;
      if (type === 'call' || type === 'ret') {
        const loc = locate(e[1]);
        const tgt = locate(e[2]);
        if (opts.filterMain && !inMain(loc) && !inMain(tgt)) continue;
        counts[tgt] = (counts[tgt] || 0) + 1;
        out.push({ type: type, from: loc, to: tgt, depth: e[3] });
      } else if (type === 'block') {
        const loc = locate(e[1]);
        if (opts.filterMain && !inMain(loc)) continue;
        counts[loc] = (counts[loc] || 0) + 1;
        out.push({ type: 'block', at: loc });
      } else {
        const loc = locate(e[1]);
        if (opts.filterMain && !inMain(loc)) continue;
        out.push({ type: type, at: loc });
      }
    }
    if (out.length) send({tag: 'events', data: out});
    if (seen >= opts.limit) {
      const ms = Date.now() - t0;
      send({tag: 'done', seen: seen, elapsed_ms: ms, counts: counts});
      Stalker.unfollow(mainThread);
      Stalker.garbageCollect();
    }
  }
};
if (opts.queueCapacity) followOpts.queueCapacity = opts.queueCapacity;
if (opts.queueDrainInterval) followOpts.queueDrainInterval = opts.queueDrainInterval;

// 脚本在 resume 之后才 load(attach 语义),follow 直接在 load 时做。
// macOS 实测:spawn 挂起期 load 的脚本,resume 后 recv 回调不触发、
// 挂起期 follow 也不出事件;resume 后 load 一切正常。
Stalker.follow(mainThread, followOpts);
send({tag: 'follow', tid: mainThread, module: mainMod.name, base: mainMod.base.toString(),
      events: opts.events, limit: opts.limit});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--args', default='', help='逗号分隔的程序参数')
    ap.add_argument('--events', default='call,block')
    ap.add_argument('--limit', type=int, default=500)
    ap.add_argument('--exclude-all-but-main', action='store_true')
    ap.add_argument('--filter-main', action='store_true', help='JS 侧只保留主模块事件(exclude 对共享缓存模块可能失效)')
    ap.add_argument('--queue-capacity', type=int, default=0)
    ap.add_argument('--drain-interval', type=int, default=0)
    ap.add_argument('--out', default='')
    ap.add_argument('--wait', type=float, default=8.0)
    a = ap.parse_args()

    argv = [a.target] + ([x for x in a.args.split(',')] if a.args else [])
    # macOS 实测:spawn 挂起期 load 的脚本 follow 不出事件、recv 不触发
    # (frida 17.23.3);唯一稳定路径 = 自起进程后 attach。
    proc = subprocess.Popen(argv)
    time.sleep(0.4)            # 等主线程进入负载
    sess = frida.attach(proc.pid)
    cfg = {
        'events': a.events.split(','),
        'limit': a.limit,
        'excludeAllButMain': a.exclude_all_but_main,
        'filterMain': a.filter_main,
        'queueCapacity': a.queue_capacity,
        'queueDrainInterval': a.drain_interval,
    }
    script = sess.create_script(JS % json.dumps(cfg))

    fout = open(a.out, 'w') if a.out else None
    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            tag = p.get('tag')
            if tag == 'events':
                for e in p['data']:
                    line = json.dumps(e, ensure_ascii=False)
                    if fout:
                        fout.write(line + '\n')
                    else:
                        print(line)
            elif tag in ('follow', 'cfg'):
                print('[cfg]', json.dumps(p, ensure_ascii=False), file=sys.stderr)
            elif tag == 'done':
                print('[done] seen=%d elapsed=%dms' % (p['seen'], p['elapsed_ms']), file=sys.stderr)
                top = sorted(p['counts'].items(), key=lambda kv: -kv[1])[:15]
                for k, v in top:
                    print('  %6d  %s' % (v, k), file=sys.stderr)
                done['v'] = True
        elif msg['type'] == 'error':
            print('[script-error]', msg.get('description'), file=sys.stderr)
            done['v'] = True

    script.on('message', on_message)
    script.load()
    t0 = time.time()
    while not done['v'] and time.time() - t0 < a.wait and proc.poll() is None:
        time.sleep(0.2)
    if fout:
        fout.close()
        print('[out] written', a.out, file=sys.stderr)
    try:
        sess.detach()
    except Exception:
        pass
    if proc.poll() is None:
        proc.terminate()


if __name__ == '__main__':
    main()
