# hook 降级实战:上层被干,往哪走

> 配套《[安卓函数分层全景.md](安卓函数分层全景.md)》。前提:先判失效原因,再选降级动作,不盲降。
> 代码以 frida(JavaScript API)为主,eBPF/命令行为辅;寄存器约定按 arm64。
> syscall 号均为 arm64:x8=调用号,x0-x5=参数,返回值 x0(内核返回 -errno,libc 包装层转 errno)。

## 1. 降级决策树:先诊断,再动手

hook 失效四种原因,对应四类动作:

```
hook 没效果/被反制
│
├─ A. 检测到 hook 本身(inline hook 改字节被 CRC、GOT 表被校验、
│     frida 运行时特征:27042 端口/gum 线程名/maps 里 re.frida.server)
│     → 动作:隐蔽化(改 frida-server 名/端口/用 gadget 注入)
│            + 痕迹清理(maps/status/task 目录读过滤,见案例 1/6)
│            + 若仍被字节校验发现 → 换层:放弃 L3 inline,改 L2 导出 hook 或 L4 断点
│
├─ B. 函数被复制/自带实现(so 静态编译 libc/boringssl、Java 再包一层壳方法)
│     → 动作:定位真实执行体(特征码/字符串/调用链),在执行体上 hook(案例 5)
│
├─ C. 目标行为不经过你 hook 的层(直调 svc 绕 libc、走 vDSO 绕 syscall、
│     属性直读共享内存绕 libc 函数)
│     → 动作:按特例选层——
│            直调 svc → L4:Stalker 抓 svc / ptrace 断点 / eBPF(案例 1/2/6)
│            vDSO 时间 → patch vDSO 代码或补偿返回值(案例 4)
│            属性自解析 → 直接改共享内存(案例 3)
│
└─ D. hook 生效但副作用穿帮(时间双读差值、errno 风格不符、
      线程/内存突然变化、返回值与系统侧交叉校验不一致)
      → 动作:不换层,修副作用(补偿时间、同步系统侧状态、删多余线程)
```

**判层五法**(引自全景文档 §0):看 so 依赖 / 导入表 / 内存扫 svc / Stalker 统计 x8 分布 / root strace 比对。降级前先跑一遍,避免在没被走的层上白费劲。

## 2. 六个完整降级案例

### 案例 1:文件检测——hook Java File 被检 → libc openat → Stalker 抓 svc → eBPF

**场景**:app 检测 root/调试:读 `/proc/self/maps` 找 frida、读 `/proc/self/status` 看 TracerPid、枚举 `/proc/self/task`。
**上层写法(L1,最易被检)**:

```js
Java.perform(() => {
  const File = Java.use("java.io.File");
  File.exists.implementation = function () { /* 过滤敏感路径 */ };
});
```

**被干原因**:Xposed/frida Java 层痕迹(loaded hooks、调用栈异常、`exists` 返回时机过慢)。
**降级 1(L3:libc openat + read,内容过滤)**——不拦"打开",拦"读到什么":

```js
const openat = Module.findExportByName("libc.so", "openat");
const readf  = Module.findExportByName("libc.so", "read");
const hotFds = new Set();

Interceptor.attach(openat, {
  onEnter(args) { this.p = args[1].readCString(); },
  onLeave(retval) {
    if (this.p && /^\/proc\/(self|\d+)\/(maps|status|task)/.test(this.p))
      hotFds.add(retval.toInt32());
  }
});

Interceptor.attach(readf, {
  onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
  onLeave(retval) {
    const n = retval.toInt32();
    if (!hotFds.has(this.fd) || n <= 0) return;
    const s = this.buf.readUtf8String(n);
    const cleaned = s.split("\n")
      .filter(l => !/frida|gum|re\.frida|linjector|TracerPid:\s*[1-9]/.test(l))
      .join("\n");
    if (cleaned.length !== s.length) {
      this.buf.writeUtf8String(cleaned);   // 覆盖原 buffer
      retval.replace(cleaned.length);
    }
  }
});
```

要点:fd 用 Set 跟踪,避免对全量 read 下毒;TracerPid 只放行 `0`。
**再被干**:app 的 so 里是**静态编译 + svc 直调**读 maps(L3 完全无感)。
**降级 2(L4:Stalker 跟 svc)**:

```js
function traceSyscalls(tid) {
  Stalker.follow(tid, {
    transform(iterator) {
      let insn;
      while ((insn = iterator.next()) !== null) {
        if (insn.mnemonic === "svc") iterator.putCallout(onSvc);
        iterator.keep();
      }
    }
  });
}
function onSvc(ctx) {
  const nr = ctx.x8.toInt32() & 0xffffffff;
  if (nr === 56) {                    // __NR_openat
    const path = ctx.x1.readCString(); // openat(dirfd, pathname, ...)
    if (/\/proc\/(self|\d+)\/(maps|status)/.test(path)) {
      console.log("[svc openat]", path, "from",
        Thread.backtrace(ctx).map(DebugSymbol.fromAddress).join("\n  "));
    }
  }
}
```

Stalker 开销大:用 `Stalker.exclude` 排除 libc/系统库缩小跟的范围,并只在关键线程/短窗口开。
**降级 3(L5:eBPF,root)**——审计直调也逃不掉:

```
# bpftrace(GKI 内核一般可用,机型待验证)
tracepoint:syscalls:sys_enter_openat /str(args->filename) =~ /proc/ {
  printf("%s(%d) %s\n", comm, pid, str(args->filename));
}
```

eBPF 只读不写,定位到直调点后回到用户态(如 frida attach 到该地址)做改写。

### 案例 2:端口扫描检测 frida——connect 被直调

**场景**:app native 线程对 127.0.0.1:27042/27043 发 `connect`,连上后 `read` 看 D-Bus `REJECTED` banner;或解析 `/proc/net/tcp`(27042=0x69A2)。
**先做免降级处理**(成本最低):`frida-server -l 127.0.0.1:1337` 改端口、二进制改名、或改用 **gadget 模式随 so 注入**(不监听 TCP)。
**L3 写法**(app 走 libc 时有效):

```js
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
  onEnter(args) {
    const sa = args[1];
    if (sa.readU16() === 2 /*AF_INET*/) {          // sockaddr_in: sin_port 是网络序
      const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      if (port === 27042 || port === 27043) {
        this.block = true;
      }
    }
  },
  onLeave(retval) { if (this.block) retval.replace(-1); }
});
```

**被干原因 C**:app 直调 `svc`(x8=203)扫端口,hook libc 无感;且 frida 无论如何都监听着一个端口,`/proc/net/tcp` 解析照样曝露。
**降级**:①L4 Stalker 抓 `x8==203`(同案例 1 的 `onSvc`,看 connect 目标);②读过滤 `/proc/net/tcp`(同案例 1 的 read 过滤,删掉 frida 监听行);③L5 eBPF `kprobe:__sys_connect` 全局审计(含直调):

```
kprobe:__sys_connect { @[comm, pid] = count(); }
```

**根治**:gadget/`frida-server -l` 换非回环 + SELinux 域或直接内核层注入,不给 TCP 面留痕。

### 案例 3:属性检测——__system_property_get 被 hook,app 自解析共享内存

**场景**:改 `ro.build.tags`(test-keys)、`ro.debuggable` 骗 root/模拟器检测;app 不调 libc,自己 mmap `/dev/__properties__` 走 trie 解析。
**上层写法(L3,会被"自解析"整体绕过)**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
  onEnter(args) { this.name = args[0].readCString(); this.value = args[1]; },
  onLeave(retval) {
    if (this.name === "ro.build.tags") {
      this.value.writeUtf8String("release-keys");
      retval.replace(1);
    }
  }
});
```

**降级(正解:直接改共享内存,一次覆盖所有读法)**——读方无论走 libc 还是自解析,看的都是同一份内存:

```js
const find = new NativeFunction(
  Module.findExportByName("libc.so", "__system_property_find"),
  "pointer", ["pointer"]);          // (地址, returnType, argTypes):const prop_info* (const char*)

function patchProp(name, newval) {
  const pi = find(Memory.allocUtf8String(name));
  if (pi.isNull()) throw new Error("prop not found: " + name);
  // P+ 序列化布局:serial(4字节) 之后紧跟 value 槽(92字节 PROP_VALUE_SIZE)
  // 偏移随版本有过变化:先 dump 验证再写(待验证项)
  const val = pi.add(4);
  Memory.protect(val, 96, "rw-");
  const old = val.readCString();
  val.writeUtf8String(newval.substr(0, 91));
  console.log(`[prop] ${name}: ${old} -> ${newval}`);
}
patchProp("ro.build.tags", "release-keys");
```

要点:
- 用 libc 的 `__system_property_find` 只是**借它解析 trie 定位 prop_info**(不是 hook 它),自解析的 app 看到的也是这块内存;
- 属性区是共享只读映射,写同长度最稳,变长写可能破坏 trie 布局;
- 更彻底:hook `mmap` 拦 app 对 `/dev/__properties__` 的映射(降级成本高,一般不用)。

### 案例 4:时间风控——vDSO clock_gettime,hook libc 不够

**场景**:风控"双读差值":一段纯计算前后各取一次时间,差值异常判 hook/调试;Java 层 `System.currentTimeMillis` 每次都真实落 libc。
**坑**:bionic `clock_gettime` 优先调 **vDSO 函数指针**(`__libc_globals->vdso[]`),若 app/ART 缓存了指针直调,hook libc 导出函数也拦不全。
**降级 1(patch vDSO 本体)**——所有直调 vDSO 的都过这里:

```js
const vdso = Process.enumerateModules().find(m => m.name.includes("vdso"));
// frida 一般把 [vdso] 列为模块;不行就扫 /proc/self/maps 找 [vdso] 段
const sym = Module.enumerateSymbols(vdso.name)
  .find(s => s.name === "__vdso_clock_gettime");
Memory.protect(sym.address, 0x1000, "rwx");   // vDSO 代码页只读,先放开
Interceptor.attach(sym.address, {
  onLeave(retval) { /* 见下降级2:在此做时间补偿 */ }
});
```

**降级 2(时间补偿,对付双读差值的本质)**——不是拦读取,而是让返回值"像没被调试":

```js
let lastReal = null, fakeElapsed = 0;   // 伪造时钟累计值(ms)
Interceptor.attach(getTimeFn, {           // libc 或 vDSO 的 clock_gettime
  onEnter() { this.ts = this.context.x1; },
  onLeave() {
    // tv_sec=*ts,tv_nsec=*(ts+8),折算 ms(演示;正式版按需改写两个字段)
    const now = this.ts.readU64().toNumber() * 1e3
              + this.ts.add(8).readU64().toNumber() / 1e6;
    if (lastReal !== null) {
      const realDelta = now - lastReal;   // 含 hook/调试开销的真实增量
      fakeElapsed += realDelta / 10;      // 压缩真实耗时,伪装成未调试
      this.ts.writeU64(Math.floor(fakeElapsed / 1e3)); // 写回伪造 tv_sec,增量恒小且单调
    }
    lastReal = now;
  }
});
```

思路:维护一个"伪造时钟",每次返回伪造累计值(增量恒定且小),双读差值即恒定。L5 方案(内核 time skew/KernelPatch)在无 root 不可行时的最后手段。

### 案例 5:加密——so 静态编译 boringssl,无 EVP_* 导出

**场景**:app so 自带整套 BoringSSL,`Module.findExportByName("libcrypto.so","EVP_CipherUpdate")` 找不到符号;L3 整层报废。
**降级 0(先想偷懒:L1 反而最省)**——明文在 Java 层一定出现过:

```js
Java.perform(() => {
  const Cipher = Java.use("javax.crypto.Cipher");
  Cipher.doFinal.overload("[B").implementation = function (input) {
    const out = this.doFinal(input);
    console.log(`[Cipher] algo=${this.getAlgorithm()}\n in=${hex(input)}\nout=${hex(out)}`);
    return out;
  }
});
```

若 Java 层也被混淆/反射壳挡住,再走 native 定位:
**降级 1(特征码定位)**:

```js
const mod = Process.getModuleByName("libtarget.so");
// ① 版本字符串:boringssl 静态链接常残留标识
Memory.scanSync(mod.base, mod.size, "42 6F 72 69 6E 67 53 53 4C")  // "BoringSSL"
  .forEach(h => console.log("[str]", h.address));
// ② arm64 crypto 指令:AESE = 0x4E2848xx → 字节 ?? 48 28 4E(小端)
mod.enumerateRanges("r-x").forEach(r => {
  Memory.scanSync(r.base, r.size, "?? 48 28 4E").forEach(h => {
    console.log("[AESE] @", h.address,
      DebugSymbol.fromAddress(h.address));   // 无符号时手工回溯函数头
  });
});
```

拿到函数内地址后,向上找函数序言(`stp x29, x30, [sp, #-...]`)定入口,`Interceptor.attach` 直接按地址 hook(静态编译也能 inline hook,它只是没有符号,不是不能 hook)。
**降级 2(Stalker 跟数据流)**:从已知 java 入口(`SecretKeySpec` 构造、native 方法)下断,`Stalker.follow` 记录 call 链,观察密钥缓冲地址在哪些函数间流动,定位 update 类函数。
**该域提醒**:加密无 syscall(全景 §6),L4/L5 无物可拦——静态 boringssl 的对抗终点就是特征码 + 内存 hook。

### 案例 6:线程检测——pthread_create hook 被 clone 直调绕过

**场景**:app 检测线程数异常/frida 线程名(gum-js-loop、gmain、pool-frida-*):枚举 `/proc/self/task`(getdents64)+ 逐个读 `<tid>/comm`。
**上层写法(只防新增,防不了已存在)**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
  onEnter(args) { console.log("[pthread_create] fn=", args[2]); }
});
```

**被干原因 C**:app(或壳)用 `syscall(__NR_clone)` 直调建线程,pthread hook 无感;且 frida 自身线程早已存在。
**降级 1(L3:getdents64 过滤,把 frida 线程从目录里抹掉)**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "getdents64"), {
  onEnter(args) { this.buf = args[1]; },
  onLeave(retval) {
    let len = retval.toInt32(); if (len <= 0) return;
    let off = 0;
    while (off < len) {
      // struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2,+16) d_type(1,+18) d_name(+19)
      const reclen = this.buf.add(off + 16).readU16();
      const name   = this.buf.add(off + 19).readCString();
      if (/^(gum-js-loop|gmain|pool-frida-|linjector)/.test(name)) {
        Memory.move(this.buf.add(off), this.buf.add(off + reclen), len - off - reclen);
        len -= reclen; retval.replace(len);   // 删掉该目录项
        continue;                              // off 不动,重读本位
      }
      off += reclen;
    }
  }
});
```

**降级 2(L4/L5,审计直调 clone)**:Stalker 抓 `x8==220`(clone);root 下 eBPF tracepoint `sched/sched_process_fork` 观测全部新建线程(含直调)。若要拦 app 建"检测线程",配合 ptrace 断点在 svc 返回处改返回值为 -1。
**连带动作**:线程名也可从源头改——`pthread_setname_np` 最终 `prctl(PR_SET_NAME)`(PR_SET_NAME=15,svc 号 167),hook prctl 过滤 name 参数只对新建线程有效;frida 自身线程靠 getdents64/read 过滤(文件域)兜底。

## 3. svc 指令拦截大全(L4 通用工具箱)

### 3.1 arm64 约定

| 项 | 值 |
|---|---|
| 指令 | `svc #0`,编码 `0xD4000001`,小端字节 `01 00 00 D4` |
| syscall 号 | `x8`(32 位) |
| 参数 | `x0`-`x5`(对应 C 原型第 1~6 参) |
| 返回 | `x0`;内核返回 `-errno`,bionic 包装层转 `errno` 并返回 -1 |
| 特殊 | `svc #0x8xxxx` 等高编号是内核带 tag 的变体(常见于开启 MTE/PAC 的内核,具体语义待查) |

### 3.2 Stalker 抓 svc(标准姿势)

```js
Stalker.follow(Process.getCurrentThreadId(), {
  transform(iterator) {
    let insn;
    while ((insn = iterator.next()) !== null) {
      if (insn.mnemonic === "svc") iterator.putCallout(onSvc);
      iterator.keep();
    }
  }
});
```
- callout 的 `context.x8/x0..x5` 即现场寄存器;
- 性能三律:①`Stalker.exclude(Process.getModuleByName("libc.so"))` 排除高频库;②只 follow 目标线程;③短窗口采集(几秒)后 `Stalker.unfollow`。
- 典型过滤器:`x8==56`(openat,`x1`=路径)、`x8==203`(connect,`x1`=sockaddr)、`x8==220`(clone)、`x8==113/169`(时间,直调即异常——正常路径走 vDSO!)、`x8==278`(getrandom)。

### 3.3 内存扫 svc:证明"直调 syscall"存在

```js
const mod = Process.getModuleByName("libtarget.so");
mod.enumerateRanges("r-x").forEach(r => {
  Memory.scanSync(r.base, r.size, "01 00 00 D4").forEach(h => {
    // 向上回看 movz x8, #imm16 : 0xD2800008 | (imm<<5)
    let nr = -1;
    for (let back = 4; back <= 24; back += 4) {
      const w = h.address.sub(back).readU32();
      if ((w & 0xffe0001f) === 0xd2800008) { nr = (w >>> 5) & 0xffff; break; }
    }
    console.log(`[svc] ${h.address} nr=${nr}`);
  });
});
```

统计出的 syscall 号集合 = 该 so 的直调面;若含 56/63(读文件)或 203(connect),则 L3 hook 必然漏,直接上 3.2。注意区分动态生成代码(扫不到)。

### 3.4 其他 svc 级手段

| 手段 | 做法 | 适用 |
|---|---|---|
| ptrace 断点 | 在 svc 地址插 `BRK #0`(0xD4200000),SIGTRAP 里 PTRACE_GETREGS 改参/改返回,单步跳过 | 离线/无 frida,单点精改 |
| eBPF tracepoint | `syscalls/sys_enter_xxx`(自带 args 结构体)、`sys_exit_xxx`(看 ret) | root + GKI 内核,全局审计 |
| eBPF kprobe | `__sys_connect`/`kernel_clone` 等 L5 函数,`bpf_override_return` 仅限内核白名单函数 | 改返回受限,多为观测 |
| KernelPatch/内核模块 | 内核态改 sys_* 行为 | root + 解锁内核,终极手段 |

### 3.5 为什么 seccomp 不能当 hook 用

- seccomp BPF 的判决动作只有:`KILL_PROCESS / KILL_THREAD / TRAP(ERR SIGSYS) / ERRNO / LOG / ALLOW`,外加 `TRACE`(交给 ptrace tracer)和 `USER_NOTIF`(用户态通知)——**没有"修改寄存器后无痕继续"这个动作**,所以它天生是过滤器/审计器,不是 hook。
- `SECCOMP_RET_TRACE + ptrace` 可以在 tracer 里 `PTRACE_SETREGS` 改参再继续——但要求一个 tracer 进程且每次 syscall 都陷入,慢且痕迹重;
- `USER_NOTIF`(SECCOMP_RET_USER_NOTIF)+`SECCOMP_IOCTL_NOTIF_ADDFD` 只能替 app 塞 fd,改普通参数要绕道 `process_vm_writev` 改其内存,延迟高;
- 且 filter 必须**目标进程自己安装**(或创建时刻注入),攻击者无法外部强加。
- 结论:要"改",用户态用 Stalker/ptrace,内核态用 kprobe/KP;seccomp 留给**拒绝**(比如反沙箱用它断调试器)。

## 4. 每层反检测强度对照表

| 层 | hook 形态 | 典型检测手段 | 对抗成本(攻击者) | 备注 |
|---|---|---|---|---|
| L1 | Xposed/LSPosed、frida Java.use | 扫 XposedBridge/加载的 dex、调用栈回溯、`isDebuggerConnected`、隐性 API 调用告警 | 低(工具成熟但痕迹最多) | 改机/返回值替换仍首选,快 |
| L2 | libart/libjavacore 导出符号 hook | 导出函数 CRC(少见)、Java 栈里多出的 native 帧 | 低-中 | `JVM_*`/`Java_libcore_io_*` 好用且少人防 |
| L3 | Interceptor inline / GOT / PLT | libc 函数头字节 CRC、GOT 表项比对、寄存器现场异常、`dl_iterate_phdr` 校验段哈希 | 中 | 最常用层,也是被防得最狠的层 |
| L4 | Stalker 抓 svc、ptrace BRK、svc 地址 inline | 时间双读差值(Stalker 拖慢执行)、`/proc/self/status` voluntary_ctxt_switches 异常、per-CPU 计数差异 | 中-高 | 对直调 svc 的唯一用户态解 |
| L5 | eBPF kprobe/tracepoint、内核模块、KernelPatch | 用户态基本无检测面;仅 root 检测(Magisk 痕迹)可间接暴露 | 高(root+内核门槛) | 观测强、改写受限(override 白名单) |
**组合建议**:对抗弱的目标 L1/L3 一把过;中等对抗 maps/status 过滤(L3)+ 改机联动;强对抗(直调 svc + CRC + 双读时间)上 L4 Stalker/ptrace;有 root 才考虑 L5。

## 5. 收尾清单(每次降级自检)

1. 确认降的是**真正在走的层**(判层五法),不是猜的;
2. 三个"不落 svc"特例(属性读/vDSO 时间/加密)别往 L4 硬怼;
3. hook 生效 ≠ 穿帮为 0:查时间差、errno 风格、线程数、返回值与系统侧一致性;
4. Stalker 用完 `unfollow` + `garbageCollect`,长驻脚本把 exclude 配好;
5. 产出沉淀:命中的函数/层回填《安卓函数分层全景.md》对应域的「hook 要点」列。
