# CTF体系(KCTF 赛制 + 年度题目技术点 + CTF 逆向/PWN 方法论)

> 本地文章引用格式:`[精华N-<tid>] 标题`
> 互链:堆/栈利用原理 → `堆利用与防护.md`;漏洞类型 → `漏洞类型与利用.md`;CTF 逆向工具 → `../01-Windows安全/`;Android 题逆向 → `../02-Android安全/`

## 1. KCTF 赛制

### 1.1 两阶段攻防(官方规则要点)

- **第一阶段·防守**:防守方按规则制作题目上线靶场;**按"被破解时间"排名**——撑得越久排名越高,无人破解则前列
- **第二阶段·进攻**:攻击方(战队)对全部题目发起破解,**按破解题目数与总用时排名**(官方页面见 pizzatql/Nu1L/tekkens 等队成绩单)
- 平台:KCTF 线上靶场(常年可复现历年题)
- 题目形态:PWN(Linux 用户态/内核/VM)、逆向(CrackMe/VM 保护/反混淆)、Android、算法题;近年每季 8-10 题,春秋两季+年度赛
- 历史:KCTF 前身是 2017 年 TSRC 秋季 CTF(第二/三题 writeup 数十篇,当时还是纯 CrackMe 逆向为主),后演进为 KCTF 攻防对抗制(约 2019 第三届起 PWN 比重上升)

### 1.2 题风演变

- 2017:CrackMe 为主(反调试/多解/VM 壳),单题 writeup 众包式多帖
- 2020:Android 逆向入场(伪装类名/init_array 解密/JNI 动态注册)
- 2021-2022:PWN 成主力——BROP、格式化字符串 GOT、堆 IO_FILE、tcache;VM/LLVM PASS/lua 等新奇面出现( LLVM PASS PWN、 lua pwn)
- 出题人视角:DAS9月月赛PWN题出题心路、DAS10月PWN出题&&CVE-2023-40930(把自发现 CVE 直接出成题的范式)

## 2. 年度题目技术点表

### 2.1 本地 writeup 逐题提炼(2017-2022)

| 届/题 | 题名 | 类型 | 核心技术 | 关键解法 |
|---|---|---|---|---|
| 2017 秋 Q2 | Fpc 露出的花儿 | 逆向 | 有 PWN 影子的 CrackMe | 多帖众包拆解 等 10+ 帖|
| 2017 秋 Q3 | crackMe | 逆向 | 反调试/多解 | 实战过反调试|
| KCTF(经典) | 前世今生 | PWN | 堆上格式化字符串 | isatty 无关漏洞;栈上残留 libc 用 %21$p 泄露;**栈跳板链**(0x...dec0→def0→df20)两级 %n 实现任意写;one_gadget `execve("/bin/sh",rsp+0x70,environ)`|
| KCTF(经典) | KCTF 题(Android) | 逆向 | 类名伪装+native 层 | MainActivity 校验为假;真逻辑在 `AppCompiatActivity`(混淆近名类);so 无 eq 符号→**init_array 字符串解密**→JNI_OnLoad 动态注册→RC4(去-改-加-) + **换表 Base64**(自定义 64 字符集);UUID 形 key|
| 2022 春 Q5 | GetPwn3 | PWN | 格式化字符串+GOT | 用户名+1 校验("rxraclhm");ftp 语义题:put_file 存 name/content、get_file `printf(content)`格式串漏洞、dir→show_dir 调 puts(name);块名 `;/bin/sh;`配合**改 puts@GOT 为 system**→dir 触发 system("/bin/sh");无 libc 文件→多函数偏移比对定版本|
| 2022 春 Q6 | BROP | PWN | 盲 ROP | 见 `堆利用与防护.md`§8.3:低字节爆破→stop gadget→pop 链→dump ELF→SROP getshell;作者踩坑两条:别瞎猜 gadget、泄露了就用确定的|
| NKCTF 2023 | babyHeap | PWN | off-by-one+tcache | 见 `堆利用与防护.md`§2.2|

### 2.2 本地配套赛题库(同期各赛,技术点可迁移 KCTF)

| 赛/题 | 类型 | 核心技术 |
|---|---|---|
| 0ctf2018 heapstorm2 | PWN | unsorted+chunk shrink|
| LCTF2017 2ez4u | PWN | largebin attack|
| Seccon2016 Tinypad | PWN | House of Einherjar|
| ACTF2019 message | PWN | fastbin double free→__free_hook|
| LCTF2016 pwn200 | PWN | House of Spirit|
| BCTF2018 Atum | PWN | tcache 机制对抗|
| 2020祥云杯 garden | PWN | botcake(glibc2.31)|
| 2022 强网杯 House of cat | PWN | 高版本 IO(cat 手法)|
| ciscn2022 半决赛 | Kernel | msg_msg 越界读+pipe_buffer 任意写(1 解题)|
| BlackHat2023 Houseofminho | PWN | 0 解题新 IO 手法|
| 0ctf2020 chromium_rce | 浏览器 | V8+沙箱|
| GoogleCTF2018 justintime | 浏览器 | V8 入门|
| starctf2019 oob | 浏览器 | V8 oob.diff 模板|
| 2023 CISCN 西南/华中 | PWN | 赛题实战|
| pwnable.tw/kr | PWN | 刷题平台入门|

### 2.3 2023/2024 KCTF 概览

- 2023 第七届:年度赛延续攻防制,题面覆盖 PWN(glibc2.35+ 时代 IO/hook 移除后手法)、VM 逆向、Android;各题 writeup 以"第 N 题"系列帖发布于 CTF 对抗版块
- 2024:防守方规则帖;线上靶场可复盘

### 2.4 2017 TSRC 秋季赛:writeup 众包现象

早期保留了单题 10-40 篇 writeup 的盛况(第二题 Fpc、第三题 crackMe):
- 同题多解是常态:"实战过反调试、多解分析"、"真正的粉丝根本不用调试"(纯静态流)
- **对学习者的价值**:一题读三五个不同思路的 writeup,比刷十道题更能打开视野——KCTF 时代依然适用(官方每题赛后汇总攻方 WP)
- 防守方题风:当年已是"PWN 影子的 CrackMe",为后来 PWN 主体化埋线

## 3. CTF 方法论

### 3.0 通用解题流(经验汇总)

```
拿题 → file/checksec(或 apk/so 体检) → 跑一遍录行为 → IDA/Ghidra 静态定位入口
  ├─ PWN:菜单/输入面梳理 → 漏洞点(溢出/格式串/UAF) → leak → 原语 → getshell(注意 seccomp→ORW)
  └─ RE:找校验函数 → 反调试/混淆对抗 → 算法还原(常为 rc4/base64 变体/自定义 VM) → 写 keygen
```

- 拿不准先看 `checksec`+libc 版本定时代(2.23/2.27/2.31/2.35 手法档位,见 `堆利用与防护.md`)
- 远程与本地行为差异(isatty/缓冲)别当防护

### 3.1 逆向方向

- **花指令**:《由易到难全面解析CTF中的花指令》(Dua0g)——原理=**打乱反编译器的线性反编译**(IDA 线性扫描被 jmp 嵌入垃圾字节骗过);分类讲简单/进阶(自定义花指令);**栈指针平衡**是构造要点;附自动化去花脚本编写(unicorn/patch)
- **算法还原**:《黑客精神:算法还原》:《Nep CTF password(rc4+换表 base64)》(与 §2.1 Android 题同款套路)、《enbase64》:`LitCTF enbase64`
- **反混淆**:《3W班试题 AntiOllvm 去混淆》(OLLVM 控制流平坦化还原)
- **移动题**:《细品sec2023安卓赛题》:《smali修改+log动态插桩》:《MobileCTF easy系列》:AliCrackme 系列;工具链 unidbg/frida → `../02-Android安全/`
- **取证**:`CTF取证类题目指南`;密码学:`CTF密码学方向指南`
- **调试环境**:ret-sync(x64dbg+IDA 联调);GDA 移动端 ;docker 靶场 

### 3.2 PWN 方向

- **体系学习主线**(公认路径):蒸米 ROP 系列 → ctf-wiki → pwnable.kr/tw → 各赛题。本地配套:《从0开始CTF-PWN(四)ROP绕过栈保护与GOT劫持》、`从某新生赛入门PWN`
- **堆体系**:`深入理解Pwn_Heap及相关例题`——**按 glibc 2.23/2.27/2.31/2.35/2.37 主流版本分档**整理手法与例题,IO_FILE 另立专题;工具 pwncli/PwnGdb
- **内核**:`基础rop提权`起步 → msg_msg/pipe_buffer→ CVE 复现(`漏洞类型与利用.md`§3)
- **异构**:《ARM & AArch64 架构下的 Pwn》(winmt)——交叉编译工具链、无符号 libc 处理、ARM gadget/栈布局差异
- **新面**:LLVM PASS、lua、ptrace 注入、angr 符号执行、VDSO
- **版本定位**:无 libc 文件时泄露多函数末 12 位比对; 复刻靶机环境
- **出题视角**(打比赛的最佳反哺):出题人心路=考点设计+防非预期解;DAS EASYBOX 把路由器三件套漏洞(目录穿越读 canary/命令注入/栈溢出)合成一题
- **AWD**:《pwntools+seccomp 通防工具》:`AWD_pwn_patch记录`
- **脚本化/团队流**: 环境复刻、 pwndbg+tmux、 angr;题库化训练:CTFHub 系( ret2dl_resolve、 FastBin、 UnsortedBin、 LargeBin|Storm、 ret2VDSO——五篇正好构成堆+栈进阶路线图)

### 3.3 训练资源

- 平台:KCTF 靶场、pwnable.kr/tw、CTFHub、BUUCTF
- writeup 密度最高的赛:ciscn/DASCTF/NKCTF/强网杯/0ctf/LCTF/HITCON(见 §2.2 表)

## 4. 互链

- 堆/tcache/house of/FSOP/ROP 原理 → `堆利用与防护.md`
- V8/内核/文档型/Fuzz → `漏洞类型与利用.md`
- Android CTF 题(样本对抗/frida/unidbg) → `../02-Android安全/`
- 逆向工具(IDA/x64dbg/GDA) → `../01-Windows安全/`
- 算法题(密码学/base64 变体) → 本篇 §3.1
