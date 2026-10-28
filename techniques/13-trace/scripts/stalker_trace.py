#!/usr/bin/env python3
"""Bounded Stalker block/call tracer; host mode was tested on macOS arm64, Frida 17.23.3.

Default host mode starts --target locally with Popen and attaches after 0.4 seconds.
Device mode requires both --device-serial and --pid, attaches without spawning, and
never falls back to a local or arbitrarily selected device. Use only the task-owned
test APK permitted by device-testing.md; device mode has offline mock coverage but
has not been verified on physical Android hardware.

Use --thread-id to select an enumerated target thread. Without it, device mode
verifies that the Linux process-leader TID equals the requested PID and exists in
the thread list; only host mode retains the recorded macOS first-thread heuristic.
--events block --limit N accepts at most N received block events before filtering;
module filters or an early process exit/timeout can produce fewer JSONL rows.

Output schema remains {type, from, to, depth} or {type, at}; metadata goes to stderr.
"""
import argparse
import json
import math
import subprocess
import sys
import time

import frida

JS = r"""
'use strict';
const opts = %s;   // {events, limit, excludeAllButMain, queueCapacity, queueDrainInterval}

const threads = Process.enumerateThreads();
if (opts.deviceMode && (Process.platform !== 'linux' || Process.id !== opts.targetPid)) {
  throw new Error('Device target must be the requested Android/Linux PID');
}
let mainThread;
if (opts.threadId !== null) {
  mainThread = opts.threadId;
} else if (opts.deviceMode) {
  // Linux process-leader TID equals PID; verify membership instead of choosing threads[0].
  mainThread = Process.id;
} else {
  if (!threads.length) throw new Error('No target threads are available');
  mainThread = threads[0].id;  // Recorded macOS host heuristic only; --thread-id overrides it.
}
if (!threads.some(t => t.id === mainThread)) {
  throw new Error('Requested target thread is absent: ' + mainThread);
}
if (mainThread === Process.getCurrentThreadId()) {
  throw new Error('Refusing to follow the Frida agent thread');
}
const mainMod = Process.enumerateModules()[0];
if (!mainMod) throw new Error('No target module is available');
let finished = false;
function stopTrace() {
  if (finished) return;
  finished = true;
  Stalker.unfollow(mainThread);  // Only the thread selected by this script.
  Stalker.garbageCollect();
}
rpc.exports = { stop: stopTrace };

// ---- Volume control 1: exclude modules to limit event volume ----
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

// Cache address -> name!offset to avoid a module lookup for every event.
const modCache = new Map();
function locate(addr) {
  const a = addr.toString();
  if (modCache.has(a)) return modCache.get(a);
  const m = Process.findModuleByAddress(addr);
  const r = m ? (m.name + '!0x' + addr.sub(m.base).toString(16)) : 'anon@' + a;
  if (modCache.size < 4096) modCache.set(a, r);
  return r;
}
// Does the resolved address belong to the main module? In the recorded macOS test,
// dyld shared-cache modules could still emit events after Stalker.exclude; JS filtering is the fallback.
function inMain(loc) { return loc.indexOf(mainMod.name + '!') === 0; }

let seen = 0;
let counts = {};   // Hotspot counts: block/call-target frequency
let t0 = null;

// ---- Volume control 2: event selection(call/ret/block/exec) ----
const ev = {};
opts.events.forEach(k => ev[k] = true);

// ---- Volume control 3: queue buffering(queueCapacity/queueDrainInterval) ----
const followOpts = {
  events: ev,
  onReceive: function (blob) {
    if (finished) return;
    if (t0 === null) t0 = Date.now();
    // annotate:true supplies type names('call'/'ret'/'block' at e[0]); required in the recorded test.
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
      stopTrace();
    }
  }
};
if (opts.queueCapacity) followOpts.queueCapacity = opts.queueCapacity;
if (opts.queueDrainInterval) followOpts.queueDrainInterval = opts.queueDrainInterval;

// Load after the selected process is running; follow starts at script load.
// Recorded macOS behavior: scripts loaded while Frida spawn was suspended produced neither
// recv callbacks after resume nor follow events; loading after resume worked.
Stalker.follow(mainThread, followOpts);
send({tag: 'follow', tid: mainThread, module: mainMod.name, base: mainMod.base.toString(),
      events: opts.events, limit: opts.limit});
"""


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--target', help='Host executable to start (default mode)')
    ap.add_argument('--args', default='', help='Comma-separated host program arguments')
    ap.add_argument('--device-serial', help='Exact non-local Frida device ID; requires --pid')
    ap.add_argument('--pid', type=int, help='Existing task-owned test-APK PID on the selected device')
    ap.add_argument('--thread-id', type=int, help='Existing target TID; device default verifies the PID/main TID')
    ap.add_argument('--events', default='call,block')
    ap.add_argument('--limit', type=int, default=500, help='Maximum received events before JS filtering')
    ap.add_argument('--exclude-all-but-main', action='store_true')
    ap.add_argument('--filter-main', action='store_true', help='Keep only main-module events in JS; exclude may miss shared-cache modules')
    ap.add_argument('--queue-capacity', type=int, default=0)
    ap.add_argument('--drain-interval', type=int, default=0)
    ap.add_argument('--out', default='')
    ap.add_argument('--wait', type=float, default=8.0)
    a = ap.parse_args(argv)

    if a.device_serial is not None:
        if not a.device_serial.strip():
            ap.error('--device-serial must be a nonempty exact device ID')
        if a.target is not None or a.args:
            ap.error('--target/--args are host-only and cannot be combined with --device-serial')
        if a.pid is None or a.pid <= 0:
            ap.error('--device-serial requires a positive --pid')
    else:
        if not a.target:
            ap.error('provide --target, or both --device-serial and --pid')
        if a.pid is not None:
            ap.error('--pid requires --device-serial; host mode starts its own target')
    if a.thread_id is not None and a.thread_id <= 0:
        ap.error('--thread-id must be positive')
    a.event_types = [value.strip() for value in a.events.split(',')]
    if any(value not in {'call', 'ret', 'block', 'exec', 'compile'} for value in a.event_types):
        ap.error('--events accepts a comma-separated selection of call,ret,block,exec,compile')
    if len(set(a.event_types)) != len(a.event_types):
        ap.error('--events must not contain duplicate event names')
    if a.limit <= 0:
        ap.error('--limit must be positive')
    if a.queue_capacity < 0 or a.drain_interval < 0:
        ap.error('--queue-capacity and --drain-interval must be nonnegative')
    if not math.isfinite(a.wait) or a.wait <= 0:
        ap.error('--wait must be a finite positive duration')
    return a


def run(a):
    proc = None
    sess = None
    script = None
    fout = None
    script_loaded = False
    result = {'done': False, 'failed': False}
    try:
        if a.device_serial is not None:
            device = frida.get_device(a.device_serial, timeout=10)
            if device.id != a.device_serial or device.type == 'local':
                raise ValueError('The selected device must match the exact non-local device ID')
            sess = device.attach(a.pid)
        else:
            argv = [a.target] + (a.args.split(',') if a.args else [])
            # Preserve the recorded host workflow: start locally, wait, then attach.
            proc = subprocess.Popen(argv)
            time.sleep(0.4)
            sess = frida.attach(proc.pid)

        cfg = {
            'events': a.event_types,
            'limit': a.limit,
            'excludeAllButMain': a.exclude_all_but_main,
            'filterMain': a.filter_main,
            'queueCapacity': a.queue_capacity,
            'queueDrainInterval': a.drain_interval,
            'deviceMode': a.device_serial is not None,
            'targetPid': a.pid,
            'threadId': a.thread_id,
        }
        script = sess.create_script(JS % json.dumps(cfg))
        fout = open(a.out, 'w', encoding='utf-8') if a.out else None

        def on_message(msg, data):
            if msg['type'] == 'send':
                p = msg['payload']
                tag = p.get('tag')
                if tag == 'events':
                    for event in p['data']:
                        line = json.dumps(event, ensure_ascii=False)
                        if fout:
                            fout.write(line + '\n')
                        else:
                            print(line)
                    if fout:
                        fout.flush()
                elif tag in ('follow', 'cfg'):
                    print('[cfg]', json.dumps(p, ensure_ascii=False), file=sys.stderr)
                elif tag == 'done':
                    print('[done] seen=%d elapsed=%dms' % (p['seen'], p['elapsed_ms']), file=sys.stderr)
                    top = sorted(p['counts'].items(), key=lambda kv: -kv[1])[:15]
                    for key, value in top:
                        print('  %6d  %s' % (value, key), file=sys.stderr)
                    result['done'] = True
            elif msg['type'] == 'error':
                print('[script-error]', msg.get('description'), file=sys.stderr)
                result['failed'] = True

        script.on('message', on_message)
        script.load()
        script_loaded = True
        started = time.monotonic()
        while (not result['done'] and not result['failed']
               and time.monotonic() - started < a.wait
               and (proc is None or proc.poll() is None)):
            time.sleep(0.2)
        if not result['done'] and not result['failed']:
            print('[partial] target exited or wait expired before the received-event cap', file=sys.stderr)
        return 1 if result['failed'] else 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print('[error]', exc, file=sys.stderr)
        return 1
    finally:
        if script is not None:
            if script_loaded:
                try:
                    script.exports_sync.stop()
                except Exception:
                    pass  # The selected process/session may already have ended.
            try:
                script.unload()
            except Exception:
                pass
        if sess is not None:
            try:
                sess.detach()  # Detach only this task's session, never a global device session.
            except Exception:
                pass
        if fout is not None:
            fout.close()
            print('[out] written', a.out, file=sys.stderr)
        if proc is not None and proc.poll() is None:
            proc.terminate()  # Only the process created above, never the attached device target.
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def main(argv=None):
    return run(parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
