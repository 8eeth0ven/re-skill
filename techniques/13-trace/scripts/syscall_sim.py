#!/usr/bin/env python3
"""macOS syscall-level trace simulation: Interceptor on libsystem_kernel function families.

macOS has no strace; the observed svc/mach_trap paths were few and forwarded through libsystem_kernel.
Hooking its BSD syscall wrappers provides user-space syscall-like observation, not direct kernel tracing.
Previously tested locally with frida 17.23.3 on macOS arm64.

Usage:
  ./syscall_sim.py <target-program> [arguments...] # Start with Popen, attach, observe for 20 seconds
  ./syscall_sim.py --attach <pid> [--seconds 20]
"""
import subprocess
import sys
import time


JS = r"""
'use strict';
const K = 'libsystem_kernel.dylib';
const fam = {
  // File operations
  open: 1, open_nocancel: 1, openat: 1, close: 1, close_nocancel: 1,
  read: 1, pread: 1, write: 1, pwrite: 1, mmap: 1, munmap: 1,
  // Metadata operations
  stat64: 1, lstat64: 1, fstat64: 1, fstatat64: 1, getattrlist: 1,
  // Process/directory operations
  posix_spawn: 1, fork: 1, vfork: 1, execve: 1, chdir: 1, fchdir: 1,
  getcwd: 1, mkdir: 1, rmdir: 1, unlink: 1, rename: 1, link: 1, symlink: 1,
  access: 1, faccessat: 1, dup2: 1, pipe: 1, syscall: 1,
};
let hooked = 0;
Object.keys(fam).forEach(name => {
  // Frida 17 removed the two-argument static Module.findExportByName; use findGlobalExportByName.
  const a = Module.findGlobalExportByName(name);
  if (!a) return;
  hooked++;
  Interceptor.attach(a, {
    onEnter: function (args) {
      this.name = name;
      // Read argument 0 as a string for path calls; for fstat* it is an fd(do not match with generic stat first).
      try {
        if (/(open|[^f]stat|access|chdir|unlink|rename|link|symlink|exec|mkdir|rmdir|getcwd)/.test(name)) {
          this.path = args[0].readUtf8String();
        } else {
          this.fd = args[0].toInt32();
        }
      } catch (e) { /* Non-pointer argument */ }
    },
    onLeave: function (rv) {
      const ret = rv.toInt32();
      const ps = this.path !== undefined ? ('"' + this.path + '"') : ('fd=' + this.fd);
      send({ tag: 'sc', fn: this.name, arg: ps, ret: ret });
    }
  });
});
send({tag: 'ready', hooked: hooked});
"""


def main():
    if sys.platform != 'darwin':
        print('This helper requires macOS libsystem_kernel; use a platform-appropriate trace route.', file=sys.stderr)
        return 2
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    import frida

    if sys.argv[1] == '--attach':
        pid = int(sys.argv[2])
        secs = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
        proc = None
    else:
        proc = subprocess.Popen(sys.argv[1:])
        pid = proc.pid
        secs = 20.0
        time.sleep(0.3)
    sess = frida.attach(pid)
    sc = sess.create_script(JS)
    n = [0]

    def on_msg(m, d):
        if m['type'] == 'send':
            p = m['payload']
            if p['tag'] == 'ready':
                print('[ready] hooked %d functions in libsystem_kernel' % p['hooked'])
            else:
                n[0] += 1
                print('%-14s %-40s ret=%d' % (p['fn'], p['arg'], p['ret']))
        elif m['type'] == 'error':
            print('[error]', m.get('description'))

    sc.on('message', on_msg)
    sc.load()
    t0 = time.time()
    while time.time() - t0 < secs and (proc is None or proc.poll() is None):
        time.sleep(0.2)
    try:
        sess.detach()
    except Exception:
        pass
    print('--- %d syscalls in %.1fs' % (n[0], time.time() - t0))
    if proc and proc.poll() is None:
        proc.terminate()


if __name__ == '__main__':
    raise SystemExit(main())
