# 打穿短表 · Windows(驱动/内核/提权)

> 总索引见 `../打穿短表-CVE.md`(够 CVE 判据=安全策略违反+可利用证明+影响面);环境与双机内核调试先搭 `../平台/01-Windows安全/win-vuln/工具链搭建.md`;九个内核入口横评见 `../平台/01-Windows安全/win-vuln/内核攻击面定位.md` §1。表上没有的面照样挖,本表只是高产枪。

| 认什么 | 打哪 | 出什么算成 | 假点 |
| --- | --- | --- | --- |
| 签名 .sys(甚至 WHQL)暴露 `\Device\` 但 `IoCreateDeviceSecure` 未设 SDDL → 设备 DACL 缺失 | 枚举面按 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` §1(命名空间/ACL/SDDL/Access 位联动);WinObj 或 access mask 核实 Everyone 可开 | 普通用户可开设备+至少一个坏 IOCTL=完整提权面 | 设备 ACL 只允许 SYSTEM/Admin;设备能开但 IOCTL 全走校验路径 |
| IOCTL 处理里 METHOD_NEITHER 的 `Type3InputBuffer/UserBuffer` 裸用未 Probe(或只 Probe 一次后循环外用) | checklist 按 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` §3.1;CTL_CODE 拆码定性先行(§2.2/§2.3 四种 Method 语义表);用户态传内核地址直写 | 用户态可控指针→内核任意读写(能稳定写才算,BSOD 只是下限) | 全套 Probe+try/except 包裹;METHOD_BUFFERED 且长度全查 |
| `ProbeForRead` 校验后又重新读用户地址/长度(double-fetch 竞态) | 双线程竞态:一线程改缓冲/长度,一线程触发 IOCTL;WinDbg `!analyze` 对比两次读值;定位手法同 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` §3 竞态条目 | 竞态窗口稳定命中(10+ 次触发同崩点) | 校验在内核副本上做(无窗口);窗口太小不可稳定复现 |
| 输出缓冲长度错:输出长度取自用户 InputBuffer 内字段未钳制,或对 `SystemBuffer` 按声明长度越界写 | handler 里追 OutputBufferLength 来源(`Irp->IoStatus.Information` vs 用户字段);Method 语义对照 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` §2.3;构造「超小实际 buffer+超大声明长度」 | 内核池越界写(输出路径的溢出常被漏审) | 长度直取 Irp 字段且有最小值检查;输出走安全拷贝函数 |
| 池溢出原语到手,选重占目标(Win10+ 池隔离后老打法失效) | 按池后端选喷射原语:池演进与当前稳态可用面见 `../平台/01-Windows安全/win-vuln/内核池与CVE模式库.md` §1/§2;溢出→相邻对象按目标分类选型见 §3.1 | 稳定改相邻对象字段(拿类型混淆/改链表)而非一次崩 | 目标对象在 Secure Pool(动态 KDP);Win11 池隔离+延迟复用打散邻接 |
| UAF 窗口到手,选占坑对象(与被释放对象同池同大小的可控分配) | 池风水+占坑原语选型同 `../平台/01-Windows安全/win-vuln/内核池与CVE模式库.md` §2/§3;对象生命周期分析先做 | UAF 变可控类型混淆(如窗口对象被攻击者数据重占) | 窗口太小占不进;引用计数保护实际有效(别只看 free 调用不看 ref) |
| win32k 用户回调再入面:UserModeCallback 期间锁/对象状态被破坏(经典 UAF 总发动机) | 面构成、tagWND 生命周期、定位法全在 `../平台/01-Windows安全/win-vuln/内核攻击面定位.md` §2;messaging API 压测再入路径 | 再入触发 UAF/锁失效且可控 | 回调路径已去 xxx 化迁移 win32kbase;需要罕见窗口状态才进回调 |
| ALPC 端口面:消息处理类型混淆/取消例程竞态/空指针 | 枚举与历史模式、fuzz 工具按 `../平台/01-Windows安全/win-vuln/内核攻击面定位.md` §3;对高消息速率端口发畸形序列 | 内核破坏带可控字段(纯 BSOD 评级低,进一步原语化才算高) | 只蓝屏不可控;端口要求特定权限才能连 |
| 打印池 spoolsv(SYSTEM 进程):驱动加载路径/POINTANDPRINT/spool 目录 ACL | 审 AddPrinterDriver 加载 DLL 路径、spool 目录与假脱机文件 ACL、RPC over TCP 面;对 spoolsv 的无鉴权 RPC 调用逐个枚举 | 普通用户加载任意 DLL 进 SYSTEM 进程,或假脱机越权写 | PointAndPrint 已被收紧;RPC over TCP 关闭;加载路径有签名校验(注明系统版本) |
| 服务提权:未引号服务路径含空格、或服务二进制/配置目录弱 ACL | `sc qc` 全量枚举未引号路径;icacls 查服务 exe 与配置可写性;手工复写验证(别只信扫描器) | 重启/服务重启时以 SYSTEM 执行攻击者 DLL/exe | 路径无空格;目录 ACL 正确;服务 disabled 且无法拉起。注:第三方软件此面多不给 CVE,走厂商 PSIRT |
| 计划任务与注册表执行单元:`\System32\Tasks` 任务文件、RunOnce/IFEO 键的 ACL | schtasks /query /v 交叉任务文件 ACL;低权可改高权执行单元(Image Path 指向可写位置)即面 | 低权改高权执行单元(提权) | 任务文件/键 ACL 只允许 SYSTEM;此面多属配置缺陷,MSRC 常不收,如实走厂商 |
| COM/DCOM 劫持:HKCU CLSID 覆盖 HKLM(InprocServer32 指攻击者 DLL)+ 高权 COM 消费者 | 枚举高权进程加载的 CLSID→查 HKCU 可写覆盖点;DCOM 激活权限(RunAs/Launching)核对 | 高权进程加载攻击者 DLL(提权) | CLSID 查找链不含 HKCU;消费者在 AppContainer。微软多数当纵深防御不给号,默认配置可打才报 |
| 字体解析面:DirectWrite/umfd 的 OTF/TTF/woff2 表解析(历史高产) | 解析函数边界逐表审;fuzz 走 `../平台/01-Windows安全/win-vuln/工具链搭建.md` 静态+WinAFL 对 dwrite.dll 覆盖引导 | 解析面内存破坏(PageHeap 下可控偏移) | 需管理员装字体才触发(Win10 后用户字体区影响降);畸形表静默拒收 |
| 第三方杀软/反作弊/外设自研驱动(BYOVD 名单之外的新签名驱动) | 全套走 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` checklist;重点补一刀:自研进程保护驱动的内核回调注册面(对象/进程回调里信任用户数据),面定位见 `../平台/01-Windows安全/win-vuln/内核攻击面定位.md` §4 | 签名驱动自身的新内核洞(厂商 PSIRT 高收) | 把已知 BYOVD 名单内驱动当新洞;洞需管理员手动装驱动才可达(用户态装不上=面减) |
| EDR 绕过面(卸载保护/驱动停用/unmapping/句柄剥离)——先判 CVE 边界 | 边界:绕过**导致的其他洞**(如绕驱动保护后的进程写入)那个洞算;纯绕检测/绕遏制不构成边界违反 | 不产 CVE,产出只是攻击能力——止损行,别在这类面写报告 | 把绕检测当洞报(必退);在非 CVE 面耗掉整周产出 |
| LPE 链组合:信息泄露(KASLR 绕)+写原语拼完整提权 | 原语构造与组合按 `../平台/01-Windows安全/win-vuln/内核池与CVE模式库.md` §3(泄露选型→token/PreviousMode 写);链每步可复现再串 | end-to-end 拿 SYSTEM shell(PoC 完整度决定报告档位) | 只有崩溃没有稳定原语;依赖不可控堆布局(报告里写清成功率) |
| 日志与遥测缺失面(攻击后无 ETW/事件可查) | 不当洞挖:这是产品反馈不是安全边界违反;最多转 hardening 建议 | 不走 CVE——止损行 | 在这类「发现」上写长报告浪费时间 |
| 手里只有 crash dump(用户报来/WER 抓的),先定根因再决定投入 | 符号服务器+`!analyze -v` 起步:环境按 `../平台/01-Windows安全/win-vuln/工具链搭建.md` §1;三方驱动无符号时 Ghidra 符号与类型恢复见 `../平台/01-Windows安全/win-vuln/PE逆向与符号分析.md` §2.3 | 崩溃点定位到具体驱动函数+根因假设(转白盒审的入口) | dump 里三方驱动全混淆;栈被破坏时 `!analyze` 结论不可尽信 |
| HVCI(内存完整性)默认开着,数据驱动攻击(改可执行页)被拦 | 利用链设计避开代码执行:改函数指针/对象/令牌数据;选靶前先查目标机 HVCI/CFG 状态并写进复现环境 | 在 HVCI on 的默认配置下仍成立的提权(影响面=全部默认用户) | 利用只在 HVCI off 可行(影响面缩水,报告必须注明否则被退) |
| .sys 加壳/混淆/无符号,静态进不去 | 判型+工作流按 `../平台/01-Windows安全/win-vuln/PE逆向与符号分析.md` §1.2/§2(Ghidra headless+审计脚本批量化);IOCTL 分发 switch 特征定位 handler 见 `../平台/01-Windows安全/win-vuln/驱动IOCTL审计.md` §2.5 | handler 全套反编译到手 | 运行时解密全加密(VMP 类):先动态 dump 内存镜像再回静态;别对壳硬啃 |
| 洞定位后按根因分类,反查同驱动/同厂商 SDK 其他驱动的同模式调用 | 根因方法与案例对照 `../平台/11-漏洞根因学/内核漏洞根因案例.md`(案例总表+逐案根因拆解);手法映射 `../平台/11-漏洞根因学/根因手法映射表.md` | 一个根因模式在多驱动复现=批量 CVE(补丁不全=新报) | 不同根因硬凑并报;厂商 SDK 老版本 EOL(仍可报,标明) |
| 报送 MSRC:流程与拿号率 | 渠道判定+报告模板全按 `../漏洞披露与CVE申请.md` §1/§4;内核洞必须带 PoC+受影响版本+复现环境;同根因预期并号 | 编号+赏金(内核 LPE 高档;纯 DoS 低档或不收) | 没有 PoC 只给崩溃描述;重复报已修洞;抢公开时间线违反披露条款 |
| 影响面计算(版本矩阵):报告硬要求 | 对多版本 ntoskrnl/驱动做特征函数 diff 判版本下界上界,工作产物挂 `../平台/01-Windows安全/win-vuln/PE逆向与符号分析.md` §1.4 漏洞假设清单模板;默认配置状态(HVCI/CFG/功能开关)写清 | 精确到 build 的受影响区间+配置前提 | 只写「Win10 及以上」;把已修 build 算进去被 triage 退回 |
| syscall info class 差异审计:NtQuerySystemInformation/NtQueryInformationProcess 新增 class | 做 class×检查矩阵:新 class 与老 class 共享内部函数但老检查不覆盖新分支(补丁 diff 盯「加了一个 case」的提交);任意**自增**也是完整原语(挑计数器/高位字段做 increment-escalation);此类 syscall 多数不在渲染器沙箱拦截表=浏览器沙箱逃逸直达 | 用户态触发的内核任意写/自增(附沙箱可达性证明) | 新 class 有独立完整检查;自增目标无安全语义 |
| 对象管理器命名空间抢注:低权抢注 `\RPC Control\<安全组件专属名>`/Named Pipe | 在 EDR/杀软用户态组件初始化前抢注其对象名(计划任务最高优先级+ARSO 自动重启登录保证先跑),组件启动即崩=整机防护失效;一个原理×全 EDR 厂商名单=横向批量 CVE | 安全组件拒绝服务致防护失效(厂商侧确认影响) | 对象名已有 DACL 保护;组件有重名恢复逻辑;微软侧多数无解——报厂商侧才有 CVE 面 |
