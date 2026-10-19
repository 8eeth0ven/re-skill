# 打穿短表:PoC 复用与 N-day 打法(PoC-in-GitHub 蒸馏)

> 主索引见 `../打穿短表-CVE.md`;本文承接选靶后的「参考已武器化洞」环节。弹药源:nomi-sec/PoC-in-GitHub(按 CVE 号聚合 GitHub PoC 仓库,1999-2026 年度卷,每 CVE 一份 json=GitHub 搜索结果)。2026-10 全量筛 2023-2026 逆向相关 873 CVE/1403 仓,逐仓核验深挖后蒸馏;纯 Web/CMS/逻辑面不管。用法:**打新面前先查同面已有 PoC 当模板;跟进新补丁时按 §1.3 找绕过;报告复现环境按 §3 抄标准件**。

## 0. 弹药源用法与真假鉴别

| 步 | 做法 | 要点 |
| --- | --- | --- |
| 拉 | `git clone --depth 1`(走代理),每年一目录/每 CVE 一 json(repo 名+描述+链接) | 2026 卷 2518 个 CVE json,全库 1.1 万+ |
| 筛 | 按 repo 名+描述正则分桶(iot-firmware/linux-kernel/binary-pwn/browser-v8/windows-kernel/camera-nas-emb/virtualization/android/apple-xnu/ics),排除词过滤纯 Web(SQL/XSS/CMS/反序列化) | 命中只代表「相关」,真假要逐仓看文件树 |
| 验 | readme + 文件树判真:有 exploit 源码/固件分析/触发脚本才算;信息页/新闻转载/检测器降档 | 检测器/checker 型仓库=部署量大信号,选靶优先级上提 |

**假 PoC 六条(收编前强制关卡,实测实锤过)**:①CVE 归属与厂商 advisory 不符(先查 NVD);②PoC 不符协议二进制格式(明文冒充 SSH 包);③伪科学量化参数;④同 CVE 短时间 10+ 同质仓库(灌水农场,FreeFloat FTP 是常客);⑤平台错乱(Unix 洞谈 Windows SYSTEM);⑥编造编译开关/版本号。

## 1. 定位五路(高星真 PoC 的洞源全部可考:审计>fuzz,fuzz 只做 crash triage)

| 路径 | 怎么做 | 代表 |
| --- | --- | --- |
| 1.1 fix-commit 考古+官方回归测试 | 开源引擎(V8/WebKit/Firefox)修 bug 必附 regression test=官方 PoC;checkout 修复 commit 的**父提交**自建漏洞树(比下历史二进制可靠,避免 BuildConfig 漂移);架构相关 bug 要源码树交叉编译 | V8/WebKit 1day 圈绝对主流;XNU 用 opensource.apple.com tag 区间二分 |
| 1.2 patch-diff 反推 | 开源:git bisect 找引入 commit,引入+修复双留档;闭源 Windows:两个 build Ghidra 对照,**同一模式补了 N 个函数=可利用面地图**;高通:CodeLinaro commit+bulletin;Android:cs.android.com 行级锚链 | MikroTik www 多 build 比对 guard 出现→反推触发+版本映射表 |
| 1.3 补丁只补一半(跟进新补丁的检查盲区) | 上版补丁查字段没查**乘积**(VMXNET3 TSO 32 位 imul 截断);只 pin 依赖没改逻辑(Next.js pin sharp,解码器版本没动——**查实际解码器版本,别查顶层框架版本**);黑名单字符绕过重打 | 每次 VMSA/MSRC/月度 bulletin 后 72h 内对着 patch 找绕过=最高性价比 1-day→n-day |
| 1.4 新合入大重构=审计窗口 | 新数据结构合入(maple tree)、**防御性代码**(class 存在性检查/防崩溃兜底=新攻击面)、类型符号变更重构(size_t→signed 引入回归) | release note 出 rewrite/new parser 同理(开源.md 已有行) |
| 1.5 披露→自补利用 | oss-security/lore 邮件、ITW 公告只给根因不给利用;根因复用选靶:**同根因模式面反复出洞**(nftables genmask 3 年 4+ CVE、page-cache 家族代际传承),盯已出过同根因的面远胜裸扫 | io_uring OOB 披露→自写利用;Android ITW→补丁 diff 复现 |

## 2. 利用原语时代特征(data-only 抗缓解是主流答案:不碰代码指针)

| 原语 | 做什么 | 代表/注意 |
| --- | --- | --- |
| cross-cache→page-cache 收尾链 | slab UAF→跨缓存攻击升 page UAF→覆写只读文件(SUID/libc/配置),SMEP/KPTI/CET/KASLR 全 N/A;当代内核 LPE 事实标准 | nftables 1086/AF_ALG CopyFail/CPU-timer 竞态/DirtyClone 全走此路;硬约束 INIT_ON_ALLOC(Ubuntu 6.5+) |
| 双原语配对 | 先泄后写:大 capture 溢出+小 capture 泄未初始化堆;整数溢出+编译期校验绕过 | ASLR 靠信息泄露破,不硬绕 |
| 解释器/指针复用 | Onigmo VM 复用解释器自身指针存活于 ASLR;**non-PIE 目标选择**(node 官方构建);deopt 混淆(externref↔i64)出非压缩 64 位指针直穿 V8 cage | CET/CFI/MTE 时代没人硬绕,全部换道 data-only 或逻辑洞 |
| Android 三段式 | framework 逻辑洞进 system_server→**借高权 SELinux 域**(neverallow 反查:哪个域能过内核洞的门槛)→内核 data-only 1day 收尾 | 逻辑链 100% 成功率免绕全缓解;持久化用签名历史注入(穿越 OTA) |
| KASLR 泄露源 | seq_operations 回收读回/socket ops 指针/子系统自带 dump API/physmap 直读/MSR 0xC0000082(Windows 最稳单点)/CPU 侧信道兜底 | 泄露证明五件套:窗口无关+跨沙箱穿透+无需 caps+可远程触发+读到敏感数据 |
| 1day 跨厂商移植 | per-device offset 表(kallsyms+ikheaders+RELA 自校验);kmalloc 几何按发行版分型;STATIC_USERMODEHELPER 封 modprobe 时降级 direct cred patch | GhostLock 4.19 移植 checklist 是范本;boot.img 离线抽符号免 root |

## 3. 环境工程标准件(可信 PoC 的共性,复现报告照抄)

- **双版本对照**:漏洞树(fix^)+修复树(fix)同参数编译,PoC 前者崩后者干净=判据;d8 常用 `--allow-natives-syntax --expose-wasm`,反馈塑形 flag 视 bug 定(`--homomorphic-ic` 类);jsc 先关并发(`--useConcurrentJIT=false --useConcurrentGC=false`)
- **镜像/版本钉死**:docker 镜像 sha256 digest 钉死;版本矩阵三档表(affected/tested/fixed)+内存需求+成功率写明;「补丁只 pin 依赖仍可打」的反例也进矩阵
- **内核靶场**:kernelCTF LTS 实例(QEMU+官方 config)当免费验证场;自带 initramfs+config+run.sh 快照;KASAN lab+漏洞/修复双内核差分;Windows 逃逸 PoC 用 QEMU TCG 当可销毁环境
- **竞态**:外层无限重试环;双旋钮调参+可观测日志信号(dmesg oracle 的 `Unexpected outstanding_txns` 类特定串=踩到漏洞路径)迭代
- **触发条件放大器**:`bcdedit /set debug on` 让网卡变 kdnic.sys 放大 RSC 合包;网络适配器 Interrupt Moderation=Extreme;fastboot 命令本身=漏洞探测器(OKAY=可利用)
- **诚实声明纪律**:flag-free 评审标准(无 natives-syntax/零硬编码地址/附命中率);「写原语 works/完整链仅某版本」分档声明;局限清单(CONFIG_LIST_HARDENED 断 post-free 写=退化 DoS 类)——**这种能力边界声明直接抄进报告模板**
- **交付结构模板**:basic_poc→full_poc→sandbox_emulator 三级递进;diagnose/crash/leak/analyze 分目录;漏洞配置文件+Dockerfile 随仓

## 4. 十桶热点速查(选靶=攻击面密度×无特权可达×生态承接)

| 桶 | 热点 | 一句话打法 |
| --- | --- | --- |
| linux-kernel(168) | io_uring>nf_tables 事务/引用计数>page-cache 家族>老协议(DECnet/SCTP/vsock/kTLS 零 fuzz)>futex/binder | `unshare -rUn` 后 nftables 即无特权入口;44% 是当年新洞,武器化窗口极短 |
| iot-firmware(243) | Cisco 28>Ivanti 26>Fortinet 23>TP-Link 21>F5 19;形态:注入 58>鉴权绕过 28>未授权 26>溢出 19 | **1/4 是后认证才算**:升链三路=配 auth-bypass/默认凭证/WAN 面 |
| binary-pwn(146) | nginx 两遍求值>Windows 服务>Apple 驱动>内核>语言运行时原生层(PHP/CPython/jq/OCaml) | 解释器/JIT 中间码越界=新一代高级语言堆溢出 |
| browser-v8(96) | 真引擎类约 46%(V8 19/WebKit 13/Blink 13/Firefox 11);fullchain 仅 3 个且集中在两个作者系 | in-cage ARW 只是半程,出口三选一:wasm RWX 残留/SBX bypass 配链/deopt 非压缩指针 |
| windows-kernel(58) | **BYOVD 41%**且矿区从杀软转向反作弊(Wellbia/GameDriver)+OEM 预装;MS 自带 CLFS/AFD/http.sys 续产;打印栈已冷 | 句柄铸造(ObOpenObjectByPointer KernelMode)=独立于物理读写的第三类原语 |
| camera-nas-emb(68) | ONVIF 8899 无认证 GetProfiles→GetStreamUri 吐硬编码 RTSP 凭据;打印机地址簿=内网凭据金矿(改 SMB 目标→Responder 抓 NTLMv2 中继进域) | 硬编码凭据×未授权读接口=zero-click 升链 |
| virtualization(23) | guest→host 一半在设备模拟后端(SCSI/virtio/VGA/9pfs/共享目录);VMware appliance 管理面 30%(Thrift RPC/固定密钥/flag 注入);KVM shadow MMU 新热区 | guest 内伪造设备描述符+直敲 MMIO 比走 guest 驱动协议栈短 |
| android(21) | framework 逻辑提权 7>内核 5>高通驱动+bootchain 6;binder 直接内存破坏反而稀缺 | binder trigger 用 QEMU/cuttlefish 即可复现,不需完整 AOSP build |
| apple-xnu(11) | kext 面比 XNU 核心软(无 PAC 硬化一致性、更新慢);macOS 沙箱逃逸固定套路=找松散 XPC 服务 | 三版本逐字节对照确认漏洞形态同构;dyld shared cache slide(syscall 536)是独立面 |
| ics-scada(19) | 实际入口全是 HMI/中间件 Web 层,无一例现场协议利用;现场协议只做未授权读写检查(Modbus 功能码 5/15 写只读线圈) | 工控「加密模块」打密钥同源性(厂商工具与设备同源密钥) |

## 5. 已同步进各短表的新枪

固件.md(+5 行):配置密文往返/QEMU-user 挂原厂 so 当加密 oracle;同型号 patch-diff 反推;私有协议认证段审计(TDDP 模式);DHCP Option 66 网络侧供给;云管理面双路径。开源.md(+3 行):两遍求值/二次解析;防御性代码=新攻击面;重构回归(类型符号变更)。Windows.md(+2 行):syscall info class 差异审计;对象管理器命名空间抢注。浏览器与V8.md(+2 行):commit 考古+regression test 主路径;V8 sandbox 后时代出口三选一。通用与收口.md(+1 行):根因复用选靶。

原始深挖材料(逐仓逐 CVE 细节,含 168 kernel CVE 模式表/243 固件 CVE 厂商分布):本地 `/tmp/poc-radar/深挖-*.md` 六篇(会话产物,择要并库后可清)。
