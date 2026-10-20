# LEGACY ARCHIVE · Old Tools and Old Platforms Era

> **LEGACY — reduced use**: the knowledge in this area is outdated; open it only when analyzing legacy samples / doing historical research / maintaining inherited environments; do not reach for it first on contemporary tasks.
> Criteria: dead tools (TRW/SoftICE/W32Dasm/Immunity…) / valid only on 9x-XP / dead targets.

## TRW2000 / SoftICE Old-Tool-Unique Techniques (from the original "VI." of 01-windows-re/debuggers-tools-cases.md)

### Nine SoftICE Tricks (orig: SoftICE 技巧九则)
Author: sharksing
- INIT string over 128 chars: write two `INIT=` lines in winice.dat; macros go directly into winice.dat (the graphical config tool eats the quotes and breaks macros).
- `.` returns to the current execution line, `.n` to source line n; Ctrl+L cleans window debris; under the Universal Video Driver, cmd→Alt+Enter fullscreen→Ctrl+D toggles fullscreen without rebooting.
- Underscore dynamic conditions: `bpx eip if eax==_eax` (break when eax equals the current value again), `bpx MessageBoxA if pid==_pid` (current process only); modifiers `bpx.t` (current thread only)/`.p` (current process only).
- `bpint 3 do "bc bpindex"` — a one-shot breakpoint that deletes itself after hitting, defeating int3 anti-debug; `G addr` replaces BPX/BPM (anti-debug breakpoint-clearing is useless against the one-shot G).

### The SoftICE Macro Collection (orig: SoftICE 宏定义集)
Author: 十夜
- Samples: `MACRO sname="s 0 l FFFFFFFF 'Tennight.C'"` (whole-memory search), `argdlg="D esp->c; p ret"` (GetDlgItemTextA arguments), `argwin="D esp->8; p ret"` (GetWindowTextA), `argreg="D ESP->14"`, `reg="bpx RegQueryValueExA IF *(ESP->8)=='%1' DO \"argreg\""`.
- The skeleton: "break on the API → `D esp->offset` to view arguments → `p ret` to return"; the x64dbg-era equivalents = breakpoint commands + expressions.

### SoftICE Breaking at the First Instruction (the Shell-Entry Three Moves) (orig: SoftICE 断在第一条指令(壳程序入口三板斧))
Author: ljttt
(1) ProcDump sets the entry section characteristics to E000020 (executable), then breaks at the EP directly (ineffective against Asprotect); (2) EP minus one (Asprotect happens to leave one spare byte), write 0xCC with HIEW, `I3HERE ON`, then Load breaks at the entry (turn it OFF when done); (3) originates from the DOS4GW-era int3-at-entry method.

### TRW2000 Small Tips + VB Symbol Debugging (orig: TRW2000 小经验 + VB 符号调试)
Author: 令猪冲 / 小楼
- TRW: `bc` can replace `bc*`; VB programs need no pre-placed msvbvm6x.dll — after browse&load, `bpx __vbastrcmp` works directly; `ver blue` is easy on the eyes.
- VB symbols: `dbg2map.exe msvbvm60.dbg` → `msym.exe *.map` produces .sym — drop it in the TRW directory for auto-load (toggle with the `sym` command); you can set breakpoints directly on the VB P-Code mnemonics that exdec decompiles out (the mnemonic names are Microsoft's).

### VMware and SoftICE Network Remote Debugging (orig: VMware 与 SoftICE 网络远程调试)
Author: 小四
- When the display driver won't install, go network-remote: leave exactly one NIC in the VM; install the UND generic NIC driver (UNDSetup.exe; the physical NIC "disappearing" is normal — pick None to restore); Initialization writes `net start <local IP> mask=... gateway=...; net allow <host IP> auto password=xxx;X;`.
- Display issues: in the .vmx add `svga.autodetect="FALSE"`+maxWidth/maxHeight/vramSize; pre-load user32.dll/mfc42.dll via the symbol loader's Exports or bpx by name won't work.

### Modifying SoftICE to Dodge Detection (2000/XP) (orig: 修改 SoftICE 躲检测(2000/XP))
Author: anonymous
- Edit three files (after editing, fix the checksum with LordPE or startup fails): NTICE.SYS — `"GFu*f"→"XFu*f"` (dodging magic-string detection), `\NTICE→\XTICE`, `Bchkd→Xchkd` (dodging the BoundsChecker backdoor), `\Driver\NTice` changed in sync, `Kernel32!UnhandledExceptionFilter→user32!MessageBoxExW` (dodging some int3 checks; the price is Faults On stops working); SIWVID.SYS and NMTRANS.DLL (`\\.\NTICE→\\.\XTICE`) changed in sync.
- Dodging INT1 detection: the IDT instruction shows the IDTBase; at +0D change EE to 8E (automate via the boot command `eb 8003F40D 8E`).

### SoftICE Internals (the Command-Table Structure) (orig: SoftICE Internals(命令表结构))
Author: anonymous
- ComHandlerAddrTable (below the 'A General Protection Violation...' string) holds all command-handler addresses; UserCommandRepository holds `{char Com[n]; char Index;}` double-null-terminated; FindCommand() does string→index — a reference for building your own debugger's command interpreter, and also the patch point for adding commands to SoftICE.

## Old Tools and Peripheral Tools (from the original "VIII." of 01-windows-re/debuggers-tools-cases.md)

### W32Dasm Disassembly Enhancement (Shell Section-Attribute Repair) (orig: W32Dasm 反汇编功能增强(壳程序节属性修复))
Author: anonymous
- After ASProtect, .TEXT Characteristics got changed (C0000040; normal is 60000020) and W32Dasm refuses to disassemble; SoftICE `BPX READFILE` traces the flag-checking loop that reads the file (bd/be to skip loops), and patching the code that saves/compares section attributes fixes it — a model of the old-tool "compatibility patch" style of modification.

### Removing ImmunityDebugger's Ad Restrictions + JIT (orig: 去除 ImmunityDebugger 广告限制+JIT)
Author: anonymous
- Five steps (OD+IDA+Immunity 1.85): (1) break ShellExecuteExA, walk back, nop the IE-opening call; (2) zero the ad string's first byte; (3) nop InsertMenuA (the &Jobs menu)/_beginthread/SetTimer; (4) global-search the purple 0x808000 and change it to 0xC0C0C0; (5) open up the built-in "AeDebug" registry-write branch (sprintf `"\"%s\" %s -AEDEBUG %ld %ld"`) to restore JIT.

## Worms and Lateral Propagation (from the original "II." of 01-windows-re/malware-evasion-cases.md)

### A Simple Analysis and Unpacking Notes on the New Variant of the "Sexy Photo Album" Worm "Worm/MSN.SendPhoto.ab" (orig: 性感相册蠕虫病毒"Worm/MSN.SendPhoto.ab"新变种的简单分析和脱壳资料)
Author: coderui
- An MSN social-engineering worm: sends contacts a "sexy photo album" archive containing an infected EXE; the full unpacking process is attached (a sample of the era's analysis-bulletin style).
