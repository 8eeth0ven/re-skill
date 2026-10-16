# CTF Writeup 方法论(知识库 · CTF writeup 1001414)

> 对应目录树:CTF writeup [1001414] 共 23 节点。按 ExploitMe → Pwn(用户态/内核态/环境)→ Web → Reverse → Crypto → misc → CrackMe 提炼各题型套路;特色赛制(KCTF 攻防赛)与历史赛事(KCTF [1001027] 树)一并收束。

> 边界:Pwn 的漏洞**原理详解**(堆/GOT/沙箱逃逸逐题级)与二进制漏洞区重合,归 06-二进制漏洞;本文只给**方法论与索引**。

---

## §1 CTF 解题通用心法

1. **先分类再动手**:file/checksec/查壳 → 五大类(Pwn/Reverse/Web/Crypto/misc)分流。
2. **逆向题先跑后看**:先观察行为(输入输出/反调试弹窗),再进 IDA;字符串和常量表是半成品线索。
3. **Pwn 题先看保护**:`checksec`(NX/PIE/Canary/RELRO)直接决定利用路线(§3)。
4. **赛后复盘 > 拿分**:语料帖文化是"writeup 即学习材料",精华区大量赛后复盘帖(西湖论剑/CTF 复盘,见姊妹篇 IoT 文)。

官方入口:
- KCTF 平台 ctf.kanxue.com(攻防赛赛季页含官方 WriteUp)
- 历年题集 Evil0ctal/Kanxue-CTF-Challenge

---

## §2 ExploitMe(社区传统艺能) [1001011]

社区系 CTF 的前身:**主办方放一个漏洞程序,谁先写出 exploit 谁赢**。2007/2008 Exploit Me 挑战赛(赛题+答题分析全文收录)是 Windows 溢出时代的教科书:
- 套路 = 栈溢出/堆溢出 → 抢救 SEH/VEH → 绕过 SafeSEH/DEP(当年主力是 ROP 雏形 ret2libc)。
- 对今天的价值:**读老 writeup 学"无 metasploit 手工利用"的完整推理链**,与现代 Windows 用户态利用(§3.2)一脉相承。

## §3 Pwn [1001012]

### 3.0 环境与前置 [1001765]

- 系统:Ubuntu 各版本 Docker 一容器一题(glibc 版本决定堆行为,2.23/2.27/2.31/2.35 必备)。
- 工具:pwntools(脚本化 IO)+ gdb(gef/pwndbg)+ one_gadget + ROPgadget/Ropper + LibcSearcher/glibc-all-in-one;IDA/Ghidra 静态。
- 命令速记:`checksec ./pwn; file ./pwn; seccomp-tools dump ./pwn`(沙箱检测,orw/seccomp 规则直接改打法)。

### 3.1 Linux 用户态利用 [1001687]

索引总入口:CTF『Pwn』版块精选帖分类索引(栈溢出/ret2libc/ret2csu/retdlresolve/SROP/堆/格式化字符串全收录;**本文方法论骨架来源**)。入门:从0开始CTF-PWN(二)栈溢出。

#### 3.1.1 栈溢出 [1001695]

```
checksec → 无NX:ret2shellcode;有NX:ret2libc
         → 有Canary:泄露canary(格式化串/输出函数)再回填
         → PIE:先泄露返回地址低12位同页性质或放弃栈上定址
         → partial overwrite 是 PIE/ASLR 万金油(改低1-2字节)
```
(决策树 ASCII 自绘)
进阶套路(索引帖收录):ret2csu(64 位缺 gadget)、retdlresolve(无 libc 时伪造 Elf64_Rel 解析 system)、SROP(sigreturn 帧伪造,时钟中断级上下文恢复)。

#### 3.1.2 堆利用 [1001696]

主线 = glibc 堆攻击史:
- **unlink**(2.23 前经典):伪造 fd/bk 满足 `FD->bk==P && BK->fd==P`。
- **fastbin attack**:fd 改写 → 任意分配;fastbin dup 0x7f 骗 size 检查。
- **House of 系列**(Orange/Force/Lore/Atum...):top chunk 改写/house of orange 触发 `_IO_list_all` → FSOP。
- **tcache**(2.27+):tcache poisoning 一次写即任意地址分配;2.29+ 加 key 双重释放检查,绕法=先 free 两次前改 key。
- **高版本**:2.34+ 移除 `__free_hook/__malloc_hook` → 转 exit_funcs/_IO_FILE vtable/ld 链打 `_rtld_global`。
- 大侧写:**house of kiwi**(早期 glibc 2.34,改 `_IO_file_jumps` vtable 指针触发;高版本已被 vtable 校验废掉,方法论仍是 Emma 前置)、**house of emma**(FSOP 变体,劫持 stderr 并把 vtable 偏移到合法 `_IO_cookie_jumps` 区过 `__libc_IO_vtables` 范围检查,覆写 `__pointer_chk_guard` 指针混淆 key,经 Kiwi 式 `__malloc_assert` 触发 cookie 回调拿 system);同族衍生 house of apple 1/2、house of cat、house of bnana。外部正本:evilpan IO_FILE 技巧、roderickchan House of 全家桶总结、how2heap。

#### 3.1.3 格式化字符串 [1001699]

- 三步: `%p` 探偏移 → `%n` 写(`%hhn` 单字节分段写)→ 大数用 `$` 定位+宽度填充。
- 无 bin 泄露时 `fmt` 是万能读:key 位置直接 `%12$p`;多轮交互用 one_gadget 或栈上写 ROP。
- 相关树:格式化字符串原理详解归 06-二进制漏洞 `1000985`。

#### 3.1.4 靶场平台 Write Up [1001700]

- **pwnable.kr** [1001697]:pwnable.kr 之 ascii 解题思路分享(fd/collision/asm 之外的思路型题);全关卡外部参考 veritas501 writeup。
- **WarGame XCTF** [1001698]:XCTF 攻防世界 pwn 区(知识库树专设节点);本地精华语料确证站内 writeup:XCTF攻防世界 level2、经典整数溢出 XCTF int_overflow、XCTF的app3题目、XCTF mobile新手区解题记录(mobile 侧);2017 Wifi万能钥匙 CTF 第 4/5 题 writeup 群同属站内赛题正本。
- 其他靶场:DVRF(路由器 pwn,互链 [iot/固件仿真.md](iot/固件仿真.md))、BUUCTF 复现环境。

### 3.2 Windows 用户态利用 [1001689]

- 体系:SEH 利用 → SafeSEH/SEHOP 绕过 → DEP(ROP)+ ASLR(info leak 先行)→ CFG/VirtualAlloc 保护面。
- 树内专帖稀薄(精华区主流在 06-二进制漏洞 `Exploit 编写系列` [1000990] 与 `Windows漏洞利用开发` [1001435]);本文记边界:方法论=栈/堆/shellcode 三板斧不换,换的是保护机制清单。
- 浏览器/内核分发:Edge/Chrome renderer 漏洞归 06 区浏览器漏洞 [1001439]。

### 3.3 Linux 内核态利用 [1001691]

- 前置:QEMU+busybox 自建内核调试环境(`-s -S` + gdb vmlinux);`/proc/kallsyms` 提符号(需 kptr_restrict=0)。
- 套路清单:整数溢出/UAF/slub 双取 → `commit_creds(prepare_kernel_cred(0))` → KPTI 下 `swapgs_restore_regs_and_return_to_usermode` 返回;modprobe_path 覆写是 5.x 后省事路线;msg_msg/pipe_buffer 是 5.9-6.x 常用原语(外部体系,树内详解归 06 区 `Linux Kernel Exploit 学习` [1001433])。
- 容器逃逸场景(cgroup/overlayfs CVE-2021-3493 等)互链 03-Linux平台 `其他平台.md` §3 容器。

---

## §4 Web [1001262]

- 题面:源码审计型(给了代码)/黑盒型(只有站)。
- 套路优先级:**弱逻辑(越权/重置密码/条件竞争)→ 注入(SQL/NoSQL/SSTI)→ 反序列化(Java/PHP 链)→ SSRF/文件上传**——与 WEB安全 区 [1000965] 的漏洞矩阵一一对应,细节互链 05-WEB安全(本文不复述)。
- 知识库树内 Web 子节点为叶子(无子级帖群展开),方法论以 KCTF 历年 Web 题 + CTF训练营-Web篇(线上课程)为主。

## §5 Reverse [1001415]

- 套路链:查壳(IDA/PEiD/exeinfo)→ 脱壳(壳清单归 01-Windows安全 解密篇)→ 算法还原(常是魔改 TEA/AES/RC4:**先比对标准算法常数表**,TEA 的 delta 0x9E3779B9、AES S-box 一眼假)→ 写 keygen 或 patch。
- VM/自定义指令集题:字节码→opcode 分发 switch/跳表还原指令语义,unicorn 模拟执行加速。
- 社区特色浓度:Reverse 与 CrackMe(§8)高度重合,KCTF 攻防赛主力题种。

## §6 Crypto [1001417]

- 真题分布:古典(古典密码+编码)→ 对称(AES/DES 模式误用:ECB 拼接、CBC 位翻转、Padding Oracle)→ 非对称(RSA 小指数/共模/Wiener/related message、ECDLP 弱曲线)→ LLL 格(背包/已知高位)。
- 工具:SageMath(格/椭圆曲线必装)、yafu/factordb(分解)、RsaCtfTool。
- 算法原理详解互链 01-Windows安全 `解密篇/加密算法 [1000486]`(MD5/SHA/RSA/ElGamal/ECC/DES/AES/TEA 各算法理论帖全在彼处)。

## §7 misc [1001419]

- 杆法:文件类型(exploit 010 Editor 模板)→ 隐写(stegsolve/steghide/zsteg/频域)→ 流量(wireshark/usb 键盘鼠标流量还原本)→ 取证(volatility 内存)→ 奇技(零宽字符,Kanxue-CTF-Challenge 题集就收录零宽隐写题)。
- 硬件型 misc(BLECTF/射频)互链 [无线硬件/BLE与Zigbee.md](无线硬件/BLE与Zigbee.md) / [无线硬件/SDR与无线.md](无线硬件/SDR与无线.md)。

## §8 CrackMe 与 KCTF [1001499]

### 8.1 CrackMe 传统

社区起家文化:破解练习小程序(序列号/keyfile/时间限制)。树内数万字教程归 01-Windows安全 `解密篇`(实例分析按 2000-2024 逐年收录)——**CTF writeup 树的 CrackMe 节点是彼处的 CTF 化延伸**。

### 8.2 KCTF 攻防赛制(独有)

```
防守方(出题):提交题目+漏洞程序     攻击方(解题):限时攻破拿 flag
        └────────── 同一赛季双向计分,题目即攻击面 ──────────┘
```
(赛制 ASCII 自绘,对齐官方页描述)
- 历史:CrackMe 攻防大赛 → KCTF(题目涵盖 Windows/Android/iOS/Pwn/**智能设备**——故 KCTF 是本区姊妹篇所有面的汇合点)。
- 历史赛季树(KCTF [1001027]):金山杯2007、ExploitMe 2007/2008、腾讯 2008/2010、奇虎 2008、2011 ExploitMe、2015MSC、2017 TSRC 秋季赛(九题)、2017 Wifi万能钥匙年中赛(十五题)。
- 近年代表 writeup:2024 KCTF 大赛第十题试探 WriteUP(shellcode+华容道搜索);各题官方 wp 见赛季页(§1 入口)。
- IoT 向赛题复盘:西湖论剑2024 IOT赛后复盘及mqtt rce详解、仿真openwrt二次开发固件的通用思路(NepCTF2024)、mqtt协议pwn入门(ciscn2025 final)——**CTF 已成为 IoT 新攻击面的首发场**,故本方法论与 [iot/](iot/) 各篇互为表里。

## §9 一页总结

| 题型 | 第一步 | 决定性工具 |
|------|--------|-----------|
| Pwn | checksec+seccomp | pwntools/gdb |
| Reverse | 查壳+常量表比对 | IDA/unicorn |
| Web | 审逻辑不看功能 | burp |
| Crypto | 判数学结构 | sage |
| misc | file/strings/binwalk | stegsolve/010 |
| CrackMe/KCTF | 跑起来观察 | x64dbg |
