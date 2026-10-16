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
