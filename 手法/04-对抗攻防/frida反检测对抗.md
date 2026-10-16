# Frida 反检测对抗

> 按「对抗层级」组织：改特征 → hook 检测函数 → 转地下（换注入方式）→ 对抗升级（svc/内核）。
> 检测原理见《检测原理全景.md》§2，本文只写对抗侧。

## 0. 心法：先定位检测点，再选对抗层

对抗不是堆脚本。流程：
1. **定位**：app 闪退/卡住时，先看是哪类检测杀的（logcat、`frida-trace`、或脱壳后 IDA 搜特征字符串）；
2. **分层**：Java 层检测 → Java hook 秒杀；libc 层 → Interceptor；svc 层 → patch/stalker；
3. **最小侵入**：能改特征过就不 hook（hook 本身也留痕迹），能 hook 就不 patch（patch 要脱壳重打包，可能触发签名校验）。

## 1. 改特征（让检测的字符串/端口匹配落空）

### 1.1 改端口与进程名（过最外层）

```bash
# 改监听端口：27042 → 随机
./fs -l 0.0.0.0:6666
# 客户端
frida -H 127.0.0.1:6666 ...   # 或 adb forward tcp:6666 tcp:6666
# 改进程名：直接 mv，对付 ps 遍历 + /proc/<pid>/cmdline 检测
mv frida-server crond
./crond -l 0.0.0.0:6666 &
```

局限：只过「端口扫描 + 进程名枚举」这一层；`/proc/self/maps` 里的 frida-agent、内存里的 `frida:rpc`、线程名 `gum-js-loop` 全都还在。改端口是「入场券」，不是免死金牌。

### 1.2 strongR-frida / hluda：预编译去特征版

- **strongR-frida-android**：跟随 frida 上游版本自动打 patch，发布改好的 frida-server。拿来即用，缺点是版本更新滞后于官方。
- **hluda**：同一思路的社区别称/分发。
原理（patch 到底改了什么，社区帖逐条给出）：

| 特征 | 位置（frida 源码） | patch |
|------|------|------|
| `frida:rpc` RPC 标识符 | `frida-core/lib/interfaces/session.vala` | 替换为随机等长串 |
| `re.frida.server` 工作目录 | `frida-core/server/server.vala` | 同上 |
| `linjector-` 临时管道前缀 | `frida-core/src/linux/linux-host-session.vala` | 同上 |
| `frida_agent_main` 导出符号 | frida-agent 入口 | 改名（调用点同步改） |
| 线程名 `gum-js-loop`/`gmain`/`gdbus`/`pool-frida` | GLib/Gum 的 `prctl(PR_SET_NAME)` 调用点 | 改 prgname/线程名 |
| GType 类名 `FridaScriptEngine`/`GumScript`/`GDBusProxy`/`GLib-GIO` | 类型注册处 | 改名 |
| `g_set_prgname("frida")` | `frida-gum/gum/gum.c` | 改或删（否则 `g_get_prgname` 一查一个准） |
| adb 交互协议 `OPEN/CLSE/WRTE` | `frida-core/lib/usb/droidy-client.vala` | 视情况 |
自编译路线（社区帖的完整流程）：

```bash
# 环境罩住：WSL Ubuntu 20.04，官方 build 文档 + ndk
git clone https://github.com/frida/frida && cd frida
# 逐文件改上述特征（或 git apply strongR 的 patch）
make core-android-arm64   # 产出 build/frida-android-arm64/bin/frida-server
```

### 1.3 二进制层改串（不编译，直接改 so/frida-server）

对已编译 frida-server / frida-agent 用 lief/patchelf 级别操作：遍历 sections，把特征串原地替换成**等长**随机串（长度不能变，否则地址全错）：

```python
# 思路（博客园 19172251 的脚本骨架）
import lief
bin = lief.parse("frida-server")
for s in ["frida-server", "frida_agent_main", "frida:rpc", "re.frida.server",
          "gum-js-loop", "gmain", "gdbus", "linjector"]:
    # 在 .rodata 等段内找 ASCII，替换为同长度混淆串
    ...
bin.write("fs_patched")
chmod +x fs_patched
```

注意：符号表改名后，frida 客户端与 server 之间靠这些符号对齐的部分要一致（自己用要整套自改）；线程名改串只影响 `prctl(PR_SET_NAME)` 的参数，不影响功能。

### 1.4 运行时内存替换（注入后改名，附 frida 脚本思路）

不改二进制，attach 后第一时间在内存里把 so 名改掉，骗过 maps 扫描：

```javascript
// 思路：遍历 maps，对每个含 "frida" 的映射，把路径字符串在内存里逐字节改写
// 注意 maps 本身是内核按 dentry 生成的，改内存文件内容无效——
// 正确姿势是改 linker 的 soinfo->name 与 /proc/<pid>/maps 不可行，
// 实操是配合 §2.4 hook open/fopen，把读到的 maps 行内容在用户态缓冲区里重写。
```

内存里替换 so 显示名的常见做法（`libfrida-agent` → `libwzdnb-agent`）本质是两件事：
1. hook `fopen/open/read(fgets)`，凡是读 `/proc/self/maps` 的返回，把缓冲区里的 `frida-agent` 替换成等长无害串——**用户态文件视图重写**；
2. 对 dlsym/`dl_iterate_phdr` 返回的 `dlpi_name`/符号做同样替换。
这不是真改内核 dentry（做不到），是让检测函数「读到的内容」被洗过。

## 2. Hook 检测函数（用户态对抗主力）

### 2.1 通用骨架：先于检测跑

用 `frida -f`（spawn 模式）而不是 attach，配合 `--no-pause`，保证 hook 在 app 的检测代码之前生效。检测一般跑在 `JNI_OnLoad` / `Application.onCreate` / 首页 Activity，spawn + 立即 `Java.perform` 抢先。

### 2.2 hook 常被滥用的 libc 函数

```javascript
// strstr/strcmp：让 "frida" 匹配永远失败
Interceptor.replace(Module.findExportByName("libc.so", "strstr"),
    new NativeCallback(function (hay, needle) {
        var n = needle.readCString();
        if (n && (n.indexOf("frida") >= 0 || n.indexOf("gum") >= 0
               || n.indexOf("xposed") >= 0 || n.indexOf("su") == 0))
            return ptr(0);
        return new NativeFunction(Module.findExportByName("libc.so", "strstr"),
                                  'pointer', ['pointer','pointer'])(hay, needle);
    }, 'pointer', ['pointer', 'pointer']));
```

同类目标：`strcmp`、`strncmp`、`strcasestr`、`memmem`（内存特征扫描用得多）、`fopen`/`open`（重定向 `/proc/self/maps`、`/proc/net/tcp` 到伪造文件）、`access`/`stat`（su 文件检测返回 -1）、`connect`（27042 探测返回 -1）。
**坑**：`kill`/`exit`/`abort` 也常被检测当退出通道，hook 掉只解症状不解病根——检测已经跑完判定命中了，杀进程只是执行手段。正确姿势是把「判定函数」的返回值改掉，而不是拦「处决函数」。定位判定函数：hook `kill` 后 `Thread.backtrace(this.context)` 回溯调用者，IDA 打开对应 so 找上层函数。

```javascript
// pthread_create：拦检测方开的 watchdog 线程 + 隐藏 frida 自己的线程
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function (args) {
        var start = args[2];
        var mod = Process.findModuleByAddress(start);
        if (mod && mod.name.indexOf("frida") >= 0) {
            // 可选：记录/改名，让新线程 prctl 名不露 gum-js-loop
        }
    }
});
```

### 2.3 干掉 ptrace 反调试

```javascript
// 让 PTRACE_TRACEME / PTRACE_ATTACH 全部失败
Interceptor.replace(Module.findExportByName("libc.so", "ptrace"),
    new NativeCallback(function (req, pid, addr, data) {
        if (req == 0 || req == 16 /*TRACEME/ATTACH*/) return -1;
        return 0;
    }, 'long', ['int','int','pointer','pointer']));
```

配合 hook `prctl`（PR_SET_DUMPABLE 返回 0 且不执行）、改 `/proc/self/status` 读取的 TracerPid 行。

### 2.4 soinfo 摘链（从 linker 的 solist 里摘掉 frida so）

bionic linker 维护已加载 so 的链表（soinfo 结构，`solist`/`sonext`），`dlopen`/`dlsym`/`dl_iterate_phdr` 都遍历它。把 frida-agent 的 soinfo 节点从链上摘下：
1. 定位 linker 内部符号：`Module.enumerateSymbolsSync(linkerso)` 找 `solist`、`soinfo`（linker 导出被 strip，需按版本找偏移，不同 Android 版本结构体布局不同——这是这招麻烦的地方）；
2. 沿链遍历，找到 `dt_soname` 或 pathname 含 frida 的节点，改 `prev->next = node->next`；
3. 效果：`dlsym("frida_agent_main")` 失败、`dl_iterate_phdr` 不再吐出 frida-agent。
副作用：frida 自身后续 lazy 符号解析如果还要走这条链会崩，一般注入完成后 agent 已自解析完，时机卡在 attach 完成后立刻做。网传脚本（如「frida 隐藏自身 so」各种 gist）都是这个思路的变体，**不同 Android 版本要换偏移**，使用前先在目标系统版本验证。

### 2.5 延迟与时机

- `setImmediate` / `setTimeout` 里再做一次 hook 补位：有的检测在 `JNI_OnLoad` 里起线程延迟 10s 才扫，太早 hook 会被检测方「先记录再比对」绕过；
- 用 `Java.choose` / `Java.enumerateClassLoaders` 处理加固 app 的 ClassLoader（_detect 类在壳的 dex 里，默认 ClassLoader 找不到）。

## 3. 转地下：不用 frida-server 的注入方式

当对方连「attach 行为本身」都能感知（ptrace 占位、maps rwxp 段扫到）时，换注入形态：

### 3.1 Gadget 模式（无 server，重打包内嵌）

- 把 `frida-gadget-<arch>.so` 塞进 APK（`lib/<arch>/libgadget.so`），并让它被自动加载：改名劫持一个必被 load 的 so（如 `libnative-lib.so` 场景做 so 转发），或在 smali 里插 `System.loadLibrary("gadget")`；
- gadget 以**内置库**身份活在 app 进程里：没有 frida-server 进程、没有外连端口、没有 ptrace attach 动作；
- 配 `libgadget.config.so`（JSON，实际是改名文件）走 script 模式自动加载 JS。
- 代价：要重打包（触发签名校验则还要过签名检测）、每个目标 app 都要改一次。常见「某 app 无法 frida-server 注入」问题的最终方案多半是 gadget。

### 3.2 Zygisk 注入（root 环境王炸）

- 写一个 Zygisk 模块（或直接用 ZygiskNext/LSPatch 的注入位），在 zygote fork 出目标进程时把 frida/gum 注进去；
- 注入发生在 app 代码运行之前（比 spawn 抢得更早），且不经过 ptrace；
- 代表项目：**ZygiskNext（zygisknext）** 把注入从 magisk 的 zygisk 实现里解耦；**Zygisk-Frida**（github 搜 zygisk-frida）：把 frida-server 功能以 zygisk 模块形式内置，每个 app 进程内自动起 frida runtime，进程名为空、无独立 server。
- 这条路对「frida-server 进程检测 + attach 检测」是降维打击，剩下的对抗点只有内存特征（还要配合 §1 去特征）。

### 3.3 ptrace 注入（传统手工注入）

- 自写 injector：`ptrace(PTRACE_ATTACH)` → `remote mmap` 写 so 路径 → 远程 `dlopen`/`linker` 调用 → detach；
- 注入的是精简 gum/自研 agent，不是全家桶 frida——特征自己控制；
- 对抗强度取决于自研代码，工程量大，用于 APT 级研究或 frida 特征被杀干净时的兜底。

### 3.4 LSPatch / 免 root 方案

- **LSPatch**：把 LSPosed 框架与模块直接 patch 进 APK，免 root 运行 Xposed 模块（把「hook 能力」作为 app 的一部分分发）；配合 objection/frida 桥接的模块可实现免 root frida 类能力；
- 适合分发样本/长期挂机场景，重打包代价同 §3.1。

## 4. 对抗升级循环：检测方上 svc 之后

### 4.1 Stalker 跟踪 svc 指令

检测方用内联汇编 `svc #0` 直接 syscall（读 maps、读 status、内存扫描），用户态没有函数边界可 hook。frida 的对策是**指令级跟踪**：
- `Stalker.follow(threadId, {events: {call: true}, onReceive...})` 跟踪目标线程指令流；
- 用 `Stalker` 的 transform 回调扫描基本块，遇到 `svc #0` 指令时：改写其后的返回值寄存器（x0），或把 svc 替换为 call 到我们代理函数再模拟原语义；
- 性能代价大（每条指令翻译执行），只对检测线程开，定位到检测线程后 `Stalker.exclude` 掉无关模块。

```javascript
// 思路骨架：拦 svc 后处理 openat 的返回
Stalker.follow(tid, {
  transform: function (iterator) {
    let insn;
    while ((insn = iterator.next()) !== null) {
      if (insn.mnemonic === "svc") {
        iterator.putCallout(function (context) {
          // syscall 号在 x8 (arm64)，返回值在 x0
          // openat("/proc/self/maps") → 让它打开伪造文件描述符
          if (context.x8.toInt32() === 56 /*openat*/) { /* 改 path 指针或事后改 fd */ }
        });
      }
      iterator.keep();
    }
  }
});
```

### 4.2 硬件断点

arm64 的 `BRP`（breakpoint registers）可以在不改一字节指令的情况下断在地址：通过 `PTRACE_SETHBPREGS`（调试器侧）或内核接口设置。检测方的 CRC 校验读到的仍是原始指令，但执行流会在断点处走我们的 handler。frida 本身没直接暴露硬件断点 API，要自写（配合 ptrace 或内核模块）。x86 上等价物是 `DR0-DR7` 调试寄存器。

### 4.3 直接 patch so（物理消灭）

- 终极方案：脱壳拿到目标 so → IDA 定位检测函数（搜字符串 `xref`：`/proc/self/maps`、`frida:rpc`、`gum-js-loop` 的引用点就是检测函数）→ 把函数入口 patch 成 `mov w0, #0; ret`（arm64）→ 回编译回 APK 重签名；
- 代价：触发签名校验就得连签名校验一起 patch（自校验在 native 层的话同轮处理）；app 更新就要重做；
- 好处：svc 也好 CRC 也好，函数都物理没了，一劳永逸。

### 4.4 内核态（KernelSU + KPM / APatch）

- APatch 的 KPM（Kernel Patch Module）能在内核里 hook syscall：对 `sys_openat` 的结果做改写（把 maps 内容在内核返回时重定向），用户态无感知；
- 属于「研究级/工程重」路线，实际 SRC/逆向场景少用，但要知道存在这层。

## 5. Frida 检测对抗 checklist（四阶段排查）

**阶段一：进程能活（不闪退）**
- [ ] 改端口 + 改名启动 frida-server，排除端口/进程名检测
- [ ] 仍闪退 → spawn 启动 + 立即 hook `kill/exit/abort`，backtrace 定位「谁杀的」
- [ ] IDA 搜 so：`/proc/self/maps`、`frida`、`TracerPid`、`ptrace` 字符串定位检测函数
- [ ] 检测在 svc 层 → patch 检测函数 or 换 gadget/zygisk 注入形态
**阶段二：能 attach（spawn 不被踢）**
- [ ] hook `ptrace` 全家（TRACEME/ATTACH 失败化）
- [ ] hook `prctl`（PR_SET_DUMPABLE、PR_SET_NAME）
- [ ] 改写 status 读取的 TracerPid 行（hook read/fgets 缓冲区）
- [ ] 反调试是「子进程占位」型：hook `fork` 返回 0 之外的逻辑或直接杀子进程
**阶段三：能 hook（Java/native 都打得进去）**
- [ ] Java.perform 失败/类找不到 → `enumerateClassLoaders` 切壳的 loader
- [ ] hook 生效但 app 检测到「方法被改」→ 换 stalker 或 patch
- [ ] maps 扫描杀 agent → §2.4 摘链 + §1.4 内存重写
- [ ] 线程名检测 → 魔改版 frida（strongR）或 zygisk-frida
**阶段四：能 dump（稳定运行够久）**
- [ ] 检测循环线程（watchdog）仍在 → 定位 pthread_create 的 start routine，`Stalker.exclude` 或线程级 patch
- [ ] dump 时长任务（脱壳、遍历 dex）先 `Java.scheduleOnMainThread` 避开 ANR 检测
- [ ] 收尾：确认无残留检测点后按「最小 hook 集」收敛脚本，减少被时序检测发现的面

## 参考来源

- 社区《frida自编译以及去特征》（特征清单与自编译流程）
- 博客园 19172251（lief 二进制改串脚本）
- httptoolkit / frida codeshare（hook 生态）
