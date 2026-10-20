#!/usr/bin/env python3
"""macOS syscall 级 trace 模拟:Interceptor 挂 libsystem_kernel 函数族。

macOS 上没有 strace;svc/mach_trap 数量极少且经 libsystem_kernel 转发,
Interceptor 挂该模块的 BSD syscall 包装函数 = 用户态 syscall trace 等价物。
本机实测通过(frida 17.23.3, macOS arm64)。

用法:
  ./syscall_sim.py <目标程序> [参数...]          # Popen 后 attach,跟 20 秒
  ./syscall_sim.py --attach <pid> [--seconds 20]
"""
import subprocess
import sys
import time

import frida

JS = r"""
'use strict';
const K = 'libsystem_kernel.dylib';
const fam = {
  // 文件面
  open: 1, open_nocancel: 1, openat: 1, close: 1, close_nocancel: 1,
  read: 1, pread: 1, write: 1, pwrite: 1, mmap: 1, munmap: 1,
  // 元数据面
  stat64: 1, lstat64: 1, fstat64: 1, fstatat64: 1, getattrlist: 1,
  // 进程/目录面
  posix_spawn: 1, fork: 1, vfork: 1, execve: 1, chdir: 1, fchdir: 1,
  getcwd: 1, mkdir: 1, rmdir: 1, unlink: 1, rename: 1, link: 1, symlink: 1,
  access: 1, faccessat: 1, dup2: 1, pipe: 1, syscall: 1,
};
let hooked = 0;
Object.keys(fam).forEach(name => {
  // frida 17 删了两参静态 Module.findExportByName,改 findGlobalExportByName
  const a = Module.findGlobalExportByName(name);
  if (!a) return;
  hooked++;
  Interceptor.attach(a, {
    onEnter: function (args) {
      this.name = name;
      // path 类第一参读字符串;fstat* 第一参是 fd(注意别被 stat 正则吞了)
      try {
        if (/(open|[^f]stat|access|chdir|unlink|rename|link|symlink|exec|mkdir|rmdir|getcwd)/.test(name)) {
          this.path = args[0].readUtf8String();
        } else {
          this.fd = args[0].toInt32();
        }
      } catch (e) { /* 非指针参数 */ }
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
    if sys.argv[1] == '--attach':
        pid = int(sys.argv[2]); secs = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
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
    main()
