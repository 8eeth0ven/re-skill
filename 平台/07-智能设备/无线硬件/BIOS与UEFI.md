# BIOS 与 UEFI


## 1. 启动链与 Secure Boot

```
CPU 复位 → SEC(临时RAM初始化) → PEI(内存初始化) → DXE(驱动环境,漏洞密集)
→ BDS(启动设备选择) → UEFI 应用(如 Boot Manager) → OS Loader → 内核
Secure Boot:固件 db 白名单证书 → 验 shim → 验 grub/bootmgr → 链式验签
攻击面:DXE 驱动漏洞 / dbx 撤销滞后 / shim 变体 / SMM(DXE 之上,更高权)
```

- 浅析安全启动(Secure Boot)(产品视角:限制消费者读写/调试,保护商业机密)
- UEFI下的HOOK与回调(UEFI 环境先于 OS,Hook/Event 回调面)
- BIOS Rootkit/UEFI bootkit(LoJax 类):树内归 Windows安全 编程篇 BIOS Rootkit 节,本文只记边界不重复。
- Hyper-V+UEFI 调试(windbg+uefi,虚拟化侧)。
- SMM/LoJax 国内专帖(老卷存正主帖群):
  - SMM Rootkit初步-读写SMRAM(rootkit.com SMM PS/2 键盘记录器起步,VPC/VMware I440BX 上读写 SMRAM,D_LCK 未锁前提)
  - 深入SMRAM:SMM重载(译自 CanSecWest 2009)
  - SMM 溢出资料
  - 检测CVE-2017-5721 SMM 提权漏洞
  - LoJax(UEFI bootkit 实案)仍归 Windows安全 BIOS Rootkit 节。

## 实战案例补充

### 跟踪主机启动过程中的CSME/Bios信息
作者:hyjxiaobia

Intel DCI + System Debugger 抓开机全程 CSME/BIOS/PMC 日志(Intel 官方定位 Hangup/花屏类启动问题的标准动作):

- 硬件两条路:DCI-USB2/USB3 调试线(仅格蠹 GDK7 打开了此调试能力)或 DCI OOB"小蓝盒"CCA(约 $390,仅对 Intel Partner 销售);TigerLake 实测用 CCA 完成 Trace。
- 流程:Target/Host 建 DCI 连接 → ISS 里 Tools-"System Debugger NDA"-Trace System Perspective → Create a project 建 Trace 工程 → 加载 ME Trace Hub Decode file → Trace Capture 窗口 Start → 重启目标机抓取 → Message Viewer 按关键字(CSME/BIOS)过滤 → Export Trace Session 导出(交 Intel 分析)。
- 关键坑:Decode file 必须按平台 ME 主版本号下载(TigerLake=ME15,KabyLake/GDK7=ME12),不加载则消息全显 Unknown。
- 大坑:GDK7 BIOS 里 "DCI debug" 设置改错 → USB 调试永久失效,Load Default 救不回;且 DCI-USB3 线可能抓不全 CSME 消息,完整抓取靠 OOB/CCA。
- Decode file 与 ME spec 正常仅 Partner 可得;网上泄露的 33G Intel 机密文档含 Skylake/KabyLake 相关资料可自搜补齐。

### 解密OEM Bios导出给Windows的接口
作者:hyjxiaobia

还原 OEM BIOS 对 Windows 暴露的隐藏 WMI 设置接口(仅 OEM 自家 App/Driver 可调,对用户透明;疑似渗透新入口):

- 原理:BIOS↔Windows 走 WMI 靠 MOF(编译后 BMF)描述接口;主流做法是把 MOF 以 Buffer 资源嵌入 ACPI 命名空间(注册表 WmiAcpi\MofImagePath 方式在 ThinkPad/某 OEM 上均未见)。
- 绕 OEM 封锁:Windows 下联想驱动挡 ACPI 内存读取(RW 无效)→ U 盘进 Ubuntu:
```
acpidump > acpi.out          # dump 全部 ACPI 表
acpixtract -a acpi.out       # 转二进制 .dat(含 AML 机器码)
iasl -d *.dat                # AML 反编译成 .dsl(ASL 源码)
```
- 在 ASL 里定位嵌入式 MOF:位于 PNP0C14 设备 `_WDG` 对象附近,形如 `Name (WQxy, Buffer (0xnnnn){...}`;铁特征是 Buffer 开头 4 字节魔术字 `FOMB`(0x46 0x4F 0x4D 0x42)。
- ASL 字节流转二进制 BMF(没有就伪造一个):notepad++ 列编辑剥掉 ASL 注释/格式 → 写成 C 语言 unsigned char 数组打印 → IDA 加载后 Edit-Export data(raw bytes)导出即 .bmf。
- 生成接口测试脚本与自查编译:
```
mofcomp -B:demowmi.bmf demowmi.mof   # MOF 描述文件编译成 BMF 资源
wmimofck -tdemowmi.vbs demowmi.bmf   # 由 BMF 生成 WMI 接口测试脚本
```
- 验证执行:管理员跑 WMICodeCreator.exe,Namespace 选 root\WMI,枚举/调用解出的类(T460P 实测:Lenovo_PreloadLanguage/Lenovo_SetPreloadLanguage/Lenovo_PlatformSetting/Lenovo_SetPlatformSetting 等);同 OEM 同系列接口基本通用。

### CR3无法被MmMapIoSpace映射原理和绕过代码
作者:学技术打豆豆

Win10 1909:驱动 `MmMapIoSpace` 映射别的进程 CR3 物理页失败的原因与绕过:

- 原理链(windbg 逆向结论):
  1. 看页帧数据库,不同进程 CR3 对应 MMPFN 的 PteAddress 是同一个特殊值;
  2. 该值源自 `MmCreateProcessAddressSpace` → `MiInitializePfnForOtherProcess`;
  3. `MmMapIoSpace` → `MiFillSystemPTES` 中判定:PteAddress(如 0xffff89c4e2713898,页对齐后 0xffff89c4e2713000)落在系统 PTE 区域内 → 判非普通物理页,拒绝映射。
- 绕过 = 临时替换 MMPFN.PteAddress 再映射:
```
1. ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'Mcr3') 申请替身页
2. 从 MmGetVirtualForPhysical 函数体内取基址,免导出符号:
   PTE_BASE     = *(PUINT64)(fn + 0x22)
   MmPfnDatabase= *(PUINT64)(fn + 0x10)  // 再 & ~0xF 对齐
3. Index = physAddr >> 0xC                    // 目标物理页 PFN 号
   OldPteAddress = *(PUINT64)(Index*0x30 + PfnBase + 8)   // MMPFN+8=PteAddress,0x30=MMPFN 大小(1909 实测)
4. *(PUINT64)(Index*0x30 + PfnBase + 8) = ((UINT64)Mem & 0xFFFFFFFFFFFF) >> 0xC) * 8 + PteBase  // 换成替身页的 PTE
   → MmMapIoSpace(Py, 0x1000, FALSE) 即成功
```
- 旧值保存后可恢复也可不恢复(实测未发现问题);偏移(0x22/0x10/0x30/+8)强版本相关,换版本需重逆。
