# BIOS and UEFI


## 1. The Boot Chain and Secure Boot

```
CPU 复位 → SEC(临时RAM初始化) → PEI(内存初始化) → DXE(驱动环境,漏洞密集)
→ BDS(启动设备选择) → UEFI 应用(如 Boot Manager) → OS Loader → 内核
Secure Boot:固件 db 白名单证书 → 验 shim → 验 grub/bootmgr → 链式验签
攻击面:DXE 驱动漏洞 / dbx 撤销滞后 / shim 变体 / SMM(DXE 之上,更高权)
```

- "A brief analysis of Secure Boot" (the product perspective: restricting consumer read/write/debug to protect trade secrets)
- "HOOKs and callbacks under UEFI" (the UEFI environment precedes the OS; the Hook/Event callback surface)
- BIOS Rootkit/UEFI bootkit (LoJax-class): in-tree it belongs to the BIOS Rootkit node of the 01-windows programming chapter; this article records only the boundary, no repetition.
- Hyper-V + UEFI debugging (windbg + uefi; the virtualization side).
- SMM/LoJax domestic threads (old volumes preserving the canonical threads):
  - "SMM Rootkit first steps — reading and writing SMRAM" (starting from the rootkit.com SMM PS/2 keylogger; reading/writing SMRAM on the VPC/VMware I440BX, premised on D_LCK being unlocked)
  - "Deep into SMRAM: SMM reloading" (translated from CanSecWest 2009)
  - "SMM overflow material"
  - "Detecting CVE-2017-5721, an SMM privilege-escalation vulnerability"
  - LoJax (a real UEFI bootkit case) still belongs to the 01-windows BIOS Rootkit node.

## Supplementary Field Cases

### Tracking CSME/BIOS Information Through the Host Boot Process
Author: hyjxiaobia

Intel DCI + System Debugger to capture CSME/BIOS/PMC logs across the whole boot (Intel's standard move for triaging hangup/graphic-glitch boot problems):

- Two hardware paths: a DCI-USB2/USB3 debug cable (only the 格蠹 GDK7 ships with this debug capability enabled) or the DCI OOB "little blue box" CCA (about $390, sold to Intel Partners only); on TigerLake, the trace was completed with a CCA in practice.
- Flow: establish the DCI connection between target/host → in ISS, Tools-"System Debugger NDA"-Trace System Perspective → Create a project to build the trace project → load the ME Trace Hub decode file → Start in the Trace Capture window → reboot the target and capture → filter the Message Viewer by keyword (CSME/BIOS) → Export Trace Session to export (hand it to Intel for analysis).
- Key pitfall: the decode file must be downloaded per the platform's ME major version (TigerLake = ME15, KabyLake/GDK7 = ME12); without loading it, every message shows Unknown.
- Big pitfall: set "DCI debug" wrongly in the GDK7 BIOS → USB debugging dies permanently, and Load Default cannot bring it back; also, a DCI-USB3 cable may not capture all CSME messages — complete capture relies on OOB/CCA.
- The decode files and ME specs are normally Partner-only; the leaked 33G of Intel confidential documents include Skylake/KabyLake material you can hunt down yourself to fill the gaps.

### Decrypting the Interface an OEM BIOS Exposes to Windows
Author: hyjxiaobia

Recovering the hidden WMI settings interface that an OEM BIOS exposes to Windows (callable only by the OEM's own app/driver, invisible to the user; a suspected new pentest entry):

- Principle: BIOS↔Windows talks WMI, described by MOF (compiled into BMF); the mainstream approach embeds the MOF into the ACPI namespace as a Buffer resource (the registry WmiAcpi\MofImagePath approach was seen on neither a ThinkPad nor another OEM).
- Beating the OEM lockdown: on Windows, the Lenovo driver blocks ACPI memory reads (RW is useless) → boot Ubuntu from a USB stick:
```
acpidump > acpi.out          # dump 全部 ACPI 表
acpixtract -a acpi.out       # 转二进制 .dat(含 AML 机器码)
iasl -d *.dat                # AML 反编译成 .dsl(ASL 源码)
```
- Locating the embedded MOF in the ASL: near the `_WDG` object of the PNP0C14 device, shaped like `Name (WQxy, Buffer (0xnnnn){...}`; the iron signature is the 4-byte magic `FOMB` (0x46 0x4F 0x4D 0x42) at the start of the Buffer.
- Turning the ASL byte stream into a binary BMF (forge one if there is none): strip the ASL comments/formatting with notepad++ column editing → write it out as a C unsigned char array and print it → load it in IDA and Edit-Export data (raw bytes) to produce the .bmf.
- Generate the interface test script and self-check the compilation:
```
mofcomp -B:demowmi.bmf demowmi.mof   # MOF 描述文件编译成 BMF 资源
wmimofck -tdemowmi.vbs demowmi.bmf   # 由 BMF 生成 WMI 接口测试脚本
```
- Verification run: run WMICodeCreator.exe as administrator, pick Namespace root\WMI, and enumerate/call the recovered classes (measured on a T460P: Lenovo_PreloadLanguage/Lenovo_SetPreloadLanguage/Lenovo_PlatformSetting/Lenovo_SetPlatformSetting etc.); the interface is basically uniform across one OEM's series.

### Why CR3 Cannot Be Mapped by MmMapIoSpace, and the Bypass Code
Author: 学技术打豆豆

Win10 1909: why a driver's `MmMapIoSpace` fails to map another process's CR3 physical page, and the bypass:

- The principle chain (windbg reverse-engineering conclusions):
  1. Look at the page-frame database: the MMPFN PteAddress for different processes' CR3s is one and the same special value;
  2. That value originates in `MmCreateProcessAddressSpace` → `MiInitializePfnForOtherProcess`;
  3. In `MmMapIoSpace` → `MiFillSystemPTES` the check: the PteAddress (e.g. 0xffff89c4e2713898, page-aligned 0xffff89c4e2713000) falls inside the system PTE region → judged a non-ordinary physical page, and the mapping is refused.
- The bypass = temporarily swap in a stand-in MMPFN.PteAddress, then map:
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
- The old value can be restored or left as is (nothing observed to break in testing); the offsets (0x22/0x10/0x30/+8) are strongly version-dependent — re-reverse them on a new version.
