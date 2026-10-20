# LEGACY ARCHIVE · Kernel/Mobile/Algorithms/Protocols (the Old Era)

> **LEGACY — reduced use**: the knowledge in this area is outdated; open it only when analyzing legacy samples / doing historical research / old-system forensics; do not reach for it first on contemporary tasks.
> Criteria: valid only on 9x-XP / tied to dead tools / the target service or version is dead with no migration value.

## (Migrated by source file; entries preserved verbatim)

---

## Drivers & Kernel Cases (from [../01-windows-re/drivers-kernel-cases.md](../01-windows-re/drivers-kernel-cases.md))

### Driver Anti-Debug — Hitting SoftICE's Dead Spot (orig: 驱动反调试----点softice死穴)
Author: 天易love
- SoftICE hooks the keyboard interrupt, saving the port-60 scan code at the handler's start (without saving it, the keyboard dies). Driver side: `MmMapIoSpace(0xFEC00000,0x14)` maps the IOAPIC; write 0x12 to IOREGSEL (0x00) selecting IOREDTBL[1] (IRQ1), read back the keyboard vector from IOWIN (0x10); `sidt` reads the IDT for the ISR; an ISR head of `push imm32` (0x68) means SoftICE is present — rewrite the spot where it saves the scan code (patch point = push-immediate + 0x3D) into garbage instructions (`83 C0 00 8B C0`) so the keyboard dies and SoftICE can't keep debugging; restore on unload.

### The Real Solution to Driver-Injected User Threads Notifying csrss Across Sessions (orig: 驱动注入用户线程之跨session通知csrss之真正解决)
Author: mlgbwoai
- On XP/2003, ZwCreateThread injection doesn't notify csrss → creating further threads inside the DLL fails. R3's CreateRemoteThread = `build stack + context + NtCreateThread (suspended) + BasepNotifyCsrOfThread (LPC to \Windows\ApiPort) + Resume`; a kernel imitation would ExEnumHandleTable by LpcPortObjectType+ConnectionPort to find the target process's ApiPort handle and send the LPC, but **across sessions (2003 runs one csrss per session) the reply goes to the relay process**.
- The real fix: inject a small code stub into **the target session's csrss itself**, just two calls: `CsrCreateRemoteThread(ThreadHandle,ClientId)` (exported by csrsrv.dll; auto-creates the associated CSR_THREAD) + `NtTerminateThread(GetCurrentThread(),0)` (the exit code tells the driver it's done); R0 side: ZwCreateThread (target, suspended) → inject csrss → wait for its thread → resume the target. Vista+ ZwCreateThreadEx has cross-session notification built in — the problem no longer exists.
> Same approach: the full driver↔app communication spectrum (one each of APC/event/pipe/two-way confirmation; "Communication Between Drivers and Applications" etc., 8 posts — see the original corpus)

### A Brief Discussion of Ring3 Entering Ring0 Without a Driver Under NT (orig: 浅谈NT下Ring3无驱进入Ring0的方法)
Author: hopy
- The 2K/XP physical-memory hole: (1) GetSecurityInfo/SetEntriesInAcl/SetSecurityInfo changes the `\Device\PhysicalMemory` DACL (administrator is read-only by default) for write access; (2) `sgdt` is unprivileged — take the GDT's virtual base (0x80000000-0xA0000000 maps physical 0 directly; `vaddr & 0x1FFFF000`); (3) construct a call gate {OffsetL/H, Selector=8, DPL=3, Type=0xC, DCount=1} planted into a free GDT slot (descriptors with the P bit clear); (4) `call fword ptr [FarAddr]` enters Ring0, the gate's hand-built stack frame, `retf 4` returns with an argument. **Pitfall**: inside VMware, sgdt returns garbage (hardcode 80036000h). Modern systems have tightened this.
> Same approach: "Using SEH Tricks to Enter Ring0" and the other old-system trick group (see the original corpus)

---

## Keygens & Algorithm Cases (from [../06-crypto/keygen-algorithm-cases.md](../06-crypto/keygen-algorithm-cases.md))

### The UNFOXALL 2.1 Keygen (orig: UNFOXALL 2.1注册机)
Author: 伪装者[BCG]
- Reads unfoxall.ini to extract the user string; an 18-byte fixed table (GBK personal names, the literal table bytes `豫能信息穆鹏义周辉`) participates in the XOR + ROTATE rotate macros; the keygen simply rewrites the ini file.
> Same approach: winhex 9.4 (signature-string locating + the 751E→EB22 patch); Pinyin Jiajia 2.0 (the registry BookID looking up a 16-byte subtraction table, uncertain bytes filled 0x2F) and the other per-software crack essays around 2000 (see the original corpus)

### The Security Guard Keygen (masm6.0) (orig: 安全卫士注册机(masm6.0))
Author: funyliang
- The whole-masm-source era form: the BlowFish_En/Init/Fun trio + the classic LCG (`imul edx,08088405h; inc edx; mul edx`) + floating-point constant tables participating — the algorithm mixes BlowFish with fixed-point multiply-add.
> Same approach: the pure-masm dialog-shell keygen and similar case collections (see the original corpus)

---

## Protocol Reversing Cases (from [../05-network-proto/protocol-reversing-cases.md](../05-network-proto/protocol-reversing-cases.md))

### The DLL for Capturing AMF Packets from Adobe AIR Desktop Programs (orig: Adobe AIR桌面程序抓取AMF封包的DLL)
Author: Dormi
- Desktop flash apps have no browser debugger → hook **two send/receive points inside Adobe AIR.dll** (the source leaves signature comments, portable across versions); export `Mount_Packet(pwd, lpSend_Handler, lpRecv_Handler)` to register callbacks whose arguments = the AMF binary's address + length, parsed into readable structures per the AMF byte tables (e.g. the LoL lobby client).

### Live Display of Sent/Received Packets / Intercepting and Modifying IE's Packets (orig: 实时显示数据包发送和接受/截取修改ie浏览器的数据包)
Author: in-volume tool posts
- Capturing and editing IE traffic at the ring3 SPI/LSP or BHO layer (the contemporaneous practice in vols 8/13); "building a packet generator" (vol.14) = self-assembled Ethernet/IP/TCP headers + checksum, sent directly. Modern equivalents: mitmproxy/frida hooks; the pseudo-header checksum and link-layer header handling details still have reference value.
