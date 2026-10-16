# 内核利用与 Fuzzing

> 定位:hook 是「有了 root 之后怎么干活」,本篇是「root 本身从哪来」——利用原语链、页缓存写入原语家族(Dirty Frag/Copy Fail/Fragnesia)、syzkaller 上手、内核/so 里的加密原语识别,以及「什么时候值得下内核」的决策。

## 1. 利用原语链:从内存错误到 root

**通用收口链**(以 GhostLock 类 futex PI UAF 为例,结构在所有内核 LPE 里同构):

```
竞态/UAF(如 rtmutex remove_waiter 的 waiter 悬空)
  → 堆回收+重占(slab 布局,cred_jar/msg_msg/pid 等相邻对象)
  → 任意内核读写(原语化)
  → ① 覆盖目标 task 的 cred:uid/gid/cap_* → 0        ← 最稳
     ② 或全局开关:selinux_enforcing → 0
     ③ 或经典:modprobe_path / core_pattern 重定向
  → 用户态触发(execve SUID 逻辑/写 /proc/.../attr)拿到 root shell
```

**Android 特有的两道额外门**:
1. **SELinux**:光 uid=0 不够,要过的域转换/avc;改 `selinux_enforcing`(全局变量,符号可从 boot.img 提)或直接 `setenforce 0`(root 后);
2. **seccomp-bpf**:app 进程的 syscall 白名单仍在——拿 root 的进程要换域(zygote 派生的域 vs shell 域不同),所以实战多走「内核写 cred + fork 出无 seccomp 的 shell」。
**cred 覆盖细节**(data-only,不碰 RO):`struct cred` 单独 slab(cred_jar),`task_struct->cred/real_cred` 双指针;UAF 场景更常见做法是**利用 cred 分配做堆占位**(cross-cache 之外最可靠的重占对象之一)。现代缓解:CONFIG_STATIC_USERMODEHELPER 让 modprobe_path 路线失效 → cred/selinux 路线地位更高。

## 2. 页缓存写入原语家族:Dirty 系 2025–2026

**统一抽象**(这一代漏洞的共同本质):

> 内核零拷贝路径(splice/sendfile/AF_ALG/XFRM ESP/IPComp/RxRPC)会把**只读文件的页缓存页**钉进一个「内核可写」的 pipeline;若加密/压缩等**原地(in-place)处理**直接写这块共享页,页缓存即被改 = **改文件本身(且不触发写回脏页语义、无审计)** → 覆盖 /etc/passwd、SUID 二进制 → root。**无需竞态,确定性触发**。
家族成员:

| 名字 | CVE | 子系统 | 根因 | 状态 |
|---|---|---|---|---|
| (前身)Dirty Pipe | CVE-2022-0847 | pipe/splice | pipe buffer 的 PIPE_BUF_FLAG_CAN_MERGE 误标脏 | 历史锚点 |
| **Copy Fail** | **CVE-2026-31431** | crypto/**algif_aead**(AF_ALG AEAD) | 错误的就地加密操作,源/目标映射不一致;修复 "Revert to operating out-of-place" | CVSS 7.8,CWE-1288 |
| **Dirty Frag** | **CVE-2026-43284 / 43500** | **xfrm esp4/esp6 + ipcomp4/6 + rxrpc** | 两 bug 链式:页缓存页被钉进 ESP/IPComp/RxRPC 就地加密缓冲 | 发现者 Hyunwoo Kim(@v4bel);**报告期无完整补丁** |
| **Fragnesia** | **CVE-2026-46300** | **XFRM ESP-in-TCP** + skbuff | SKB coalescing 时**丢失 shared-frag 标记** → 共享的文件页 frag 被当作私有页就地加密写 | 修复 commit:"net: skbuff: preserve shared-frag marker during coalescing";有公开 Go PoC |
**Android 上的适用性判断** [推测]:
- GKI 内核源码树包含 esp4/esp6/ipcomp/algif_aead(CONFIG 可载模块),KMI 允许按需 modprobe——但 XFRM/AF_ALG 通常需要 CAP_NET_ADMIN + 相应 SELinux 域,untrusted app 域默认拿不到;
- 因此在 Android 上这些洞的定位是:**adb shell/shell 域、vendor 进程、已半提权进程的进一步 root 手段**,而非 app 直接打;
- Android 特有加成:**dm-verity 的 Merkle 哈希树页同样在页缓存里**——若能页缓存写,理论上可同步污染数据页+hash 树页绕过 verity 完成持久化(无公开 writeup,属推测)。

## 3. syzkaller 上手(Android 可跑)

**是什么**:Google 的内核 fuzzer,用 **syzlang** 声明式描述 syscall 接口(资源类型/参数约束/调用序列),syz-manager 驱动 syz-executor 在目标机上生成调用;配合 KASAN/KCOV 内核,崩溃直接出「KASAN 报告+可复现 C 程序」。
**最小上手**(Linux 起步):

```bash
go get github.com/google/syzkaller/prog/syzgen  # 可选
cd syzkaller && make
# 内核(自编):CONFIG_KCOV=y CONFIG_KASAN=y CONFIG_DEBUG_INFO=y CONFIG_KALLSYMS=y
# cfg: sysz-config 里 target vm/arch, image=磁盘, kernel=vmlinux/bzImage
bin/syz-manager -config=my.cfg
```
- Android 目标:官方文档 `docs/linux/` 下 setup 指南 + Android 专项说明(仓库内 docs);用 Cuttlefish 或真机 root + syz-executor 推到 /data/local/tmp;GKI 允许直接用 AOSP KASAN 调试构建;
- syzlang 样例(理解描述力):

```
binder$bc_transaction(fd fd_binder, cmd const[BINDER_WRITE_READ], ...)
futex$requeue_pi(uaddr ptr[inout futex[pid]], op const[FUTEX_WAIT_REQUEUE_PI], ...)
```

 —— binder、futex PI 全部在 syzkaller 的内置描述里,§1/§2 的洞多数最早由 syzbot 捕获(io_uring_poll 空指针即 syzkaller 捕获 [线索·未定位 syzbot 报告号]);
- 与逆向的接口:拿到一个可疑内核子系统(如厂商私有 binder 扩展)→ 抄 kernel 源码写 50 行 syzlang → 跑一周 → 收 KASAN 报告。

## 4. 内核/so 里的加密原语识别

为什么逆向要认加密:通信加密的密钥/算法常在 native 层,Dirty Frag 家族的利用本质也是「crypto 管线的 in-place 写」——认得出加密,就认得出攻击面。
**静态特征(常量优先,IDA/Ghidra binary search)**:

| 算法 | 特征 | 首字节锚点 |
|---|---|---|
| AES | 256 字节 S-box + 逆 S-box;Rcon 数组;T 表(4×256×4B) | S-box 起始 `63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76` |
| AES(GF(2^8)) | xtime 乘法:左移+`0x1B` 折减 | `0x1B` 立即数 + 循环移位模式 |
| SM4 | 256 字节 S-box | `D6 90 E9 FE CC E1 3D B7 16 B6 14 C2 28 FB 2C 05` |
| ChaCha20/Salsa | 常数 "expand 32-byte k" | ASCII `expa nd 3 2-b yte` |
| RC4 | 256 字节 S 盒初始化(i/j 交换循环) | 无静态常量,看 `for i in 0..255 S[i]=i` |
| MD5/SHA1/SHA256 | 初始向量常量 | SHA256 `67 E6 09 6A ...` |
**ARM64 硬件 AES**:内核 crypto API 与新 so 常用 ARMv8 Crypto Extensions——搜指令 `AESE/AESD/AESMC/AESIMC`(IDA 直接搜指令助记符),出现即 AES,轮密钥在 v 寄存器,配合 `EOR v0.16b` 轮异或;
**内核侧**:XFRM ESP 走 crypto API(`/proc/crypto` 列算法与驱动,如 `aes-arm64-ce`);Dirty Frag 家族的三条管线(esp/ipcomp/rxrpc)全部是「crypto API 作用于可能共享的 frag 页」。
**动态定位(与 frida 篇衔接)**:Cipher 自吐全家桶见 02-frida/java层/加密与自吐.md;native 层挂钩点优先 `EVP_EncryptUpdate`(openssl)/mbedTLS `mbedtls_cipher_update`/自研则找上表常量所在函数。

## 5. 与 Android 逆向的衔接:什么时候下内核

**决策树**:

```
目标 RASP 强度?
├─ 常规(检测 frida-server/简单 maps) → 改名 frida/隐藏(04-对抗攻防 现有篇)够用,别上内核
├─ 强(prologue 全段哈希自检 + svc 直调比对 + 线程扫描 + 反 ptrace)
│    → 上层:内核 uprobe/kprobe trace(07/Android内核与eBPF.md §5)——零用户态痕迹
│    → 断点需求:wxshadow 影子页(07/内核Hook与无痕对抗.md §2.3)——自检结构性失明
└─ 最强(签名 ROM 校验/远程证明/一切用户态全被盯)
     → OS 级 instrumentation:自编/魔改 ROM + APatch(KPM) + hide 栈(ANDROID-MRI 思路,见《内核Hook与无痕对抗.md》§5)
     → 内核 LPE(本篇 §1/§2)作为「从 shell 域拿真 root」的跳板
```

**实战顺序建议**(逆向一个强对抗 app 的完整纵深):
1. 静态:jadx/IDA 摸清 RASP 模块与 native 算法(本篇 §4 特征);
2. 先试 frida 隐藏套餐(成本最低);
3. 被咬住 → root 环境 + bpftrace/uprobe 从内核侧看(不动目标进程);
4. 需要改参/断点 → wxshadow;
5. 需要持久 root/绕环境校验 → 内核 LPE 家族(先看内核版本补丁月,§2 表);
6. 每一步都保留「用户态干净」——这是内核级方案相对 frida 的全部意义。
**一句话**:frida 是便利换暴露;内核是工程量换隐形。下内核的时机 = 「用户态一切痕迹都活不过 RASP 自检」被实锤的那一刻。

## 6. 附录 A:原语落地细节(任意写之后怎么写)

**找 task/cred(ARM64 内核,5.x-6.x 通用思路)**:
- 从 `current`(sp 离 per-cpu 偏移,或 `gs_base`/TPIDR 途径)→ `task_struct`;
- 无 symbol 场景:`init_task` 静态地址(boot.img 提)+ slide → `tasks` 链表遍历按 comm/pid 匹配目标;
- `task_struct->cred/real_cred`(指针)→ `struct cred`:`usage/uid/gid/suid/sgid/euid/egid/fsuid/fsgid` 连续 u32 → 全清 0 + `cap_inheritable/permitted/effective/bset/ambient` 全 `0xFF...`(CAP_FULL);
- 校验:写完 `getuid` 返回 0 即成;再 `setenforce 0`(或内核直写 selinux_enforcing)。
**用户态 helper 路线在 Android 的真实可用性**:
- `modprobe_path`:CONFIG_STATIC_USERMODEHELPER=y(GKI 开)时无效;且 Android 上 modprobe 触发面少;
- `core_pattern` pipe 语法(`|/data/local/tmp/x`)在高版本要求 **fs.suid_dumpable** 且 core dump 触发条件苛刻——优先 cred 路线。
**稳定性口诀**:UAF 重占选 cred_jar 而非 msg_msg(Android 无 SysV msg 域);越界写优先覆盖相邻 struct 的长度/指针字段做二次原语;一切写完 `msleep` 让 rcu 安静再触发。

## 7. 附录 B:syzkaller×Android 详细路径与情报源

**目标选择**:
- Cuttlefish(AOSP 虚拟设备)最优:可加自定义内核参数、跑 KASAN 构建、崩溃自动复位;
- 真机:Pixel 系 + AOSP userdebug + 自编 GKI(KASAN/KCOV/DEBUG_INFO),root 后推 syz-executor;
- 关注面优先级:厂商私有驱动(相机/传感器/TEE,不在 GKI、无社区覆盖)> binder/futex 等通用面(已有 syzbot 长期覆盖,增量难)。
**syzbot 情报利用**(不 fuzz 也要会查): 按子系统(binder/android/locking)过滤 open bug——等于免费的 0day 候选清单;每个 bug 附 repro C 和 kernel commit 链,可直接判断目标内核是否在修复前。
**补丁情报源**(打洞前对表):
- Android 安全公告(每月): (ASPL 对应内核补丁集);
- android-common 分支 commit 流: (安全修复按 `UPSTREAM:/` 标签合入);
- NVD/KEV + 各发行版 advisory(§2 家族三洞的 RedHat/Sysdig 页即此类)。

## 8. 附录 C:内核 crypto API 与 Dirty 系的因果关系

- 内核加密栈:`crypto API`(算法注册,如 `aes-arm64-ce`)← `af_alg`(用户态 socket 接口:algif_aead/algif_hash…)← 零拷贝路径(splice 进 `MSG_SPLICE_PAGES`);
- 正常规则:加密必须 **out-of-place**(输入页只读,输出另页)——因为输入可能是**文件页缓存页**(splice 钉进来的);
- Copy Fail 根因即 algif_aead 某路径退化为 in-place,加密结果直接写穿只读页缓存(RedHat: "Revert to operating out-of-place");
- Fragnesia 则是 SKB 合并时丢了 `shared-frag` 标记,让 ESP-in-TCP 的 in-place 加密误以为 frag 是私有页(修复:preserve shared-frag marker);
- 逆向视角:任何「crypto API + 用户可控 buffer 钉页」的内核新路径都是潜在家族成员;审计口诀——**找 `sg_set_page` 指向 page cache 页后又被同一 SG 用作输出的代码**。

## 9. 附录 D:工具与 PoC 清单(本篇涉及)

| 工具/仓库 | 用途 | 状态 |
|---|---|---|
| syzkaller | 内核 fuzzer(syzlang/KASAN/KCOV) | 可用 |
| syzbot | 公开 bug 库,免费洞候选清单 | 长期在线 |
| KernelPatch(bmax121) | 内核 patch/hook/符号提取,APatch 引擎 | 可用 |
| Fragnesia Go PoC | Fragnesia(CVE-2026-46300)Go 提权 PoC | 可用 |
| vmlinux-to-elf | stripped 内核 → 带(部分)符号 ELF | 社区标准 |
| magiskboot | boot.img 解包/重打包 | 社区标准 |
| kernel.org 文档树 | rt-mutex-design、kgdb 等深读 | 路径以站内搜索为准 |
| Android 安全公告 | 每月 ASPL 对表,判断目标内核洞窗口 | 可用 |
**利用研究入手顺序建议**:复现一个老洞(Dirty Pipe,概念最简单)→ 读 §2 家族三家 writeup(Sysdig/Mondoo/Picus)→ 拿 syzbot 的 binder/locking open bug 找没修的 → 有能力再追 6.12 上的 futex PI 复现(GhostLock 的 IonStack 栈还有兄弟洞的公开推断)。

## 10. 待核清单

- io_uring_poll 空指针的具体 syzbot 报告号;
- dm-verity Merkle 树页缓存污染可行性 [推测];
- ANDROID-MRI 量化数据(97.6%/52.4%);
- VoidLink 仓库实现细节(README 缺失)。
