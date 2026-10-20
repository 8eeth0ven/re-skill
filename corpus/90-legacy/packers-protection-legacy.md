# LEGACY ARCHIVE · Packers & Protection (the Old Era)

> **LEGACY — reduced use**: the knowledge in this area is outdated; open it only when analyzing legacy samples / doing historical research / old-software forensics; do not reach for it first on contemporary tasks.
> Criteria: dead tools / valid only on 9x-XP / dead targets.

## (Migrated preserving the original section structure; entries verbatim:)

## 2. Anti-Anti-Debugging and Tool Confrontation (from 01-windows-re/protection-anti-debug-cases.md)

### Exploiting the StrongOD Bug for Anti-Debugging (Kill BadPE Bug) (orig: 利用StrongOD漏洞反调试(Kill BadPE Bug))
Author: 半斤八兩
- The sample (the AntiArp trojan) uses a malformed PE aimed squarely at StrongOD 0.4.5's `!*Kill BadPE Bug` option: on load it reports C0000142 STATUS_DLL_INIT_FAILED and the body never executes — pure "shoot-the-plugin" anti-debugging.
- Locating: two ODs (parent debugging child) by elimination — rename the plugin directory to pin StrongOD, toggle features one by one to pin Kill BadPE; in the child OD's IAT area, StrongOD is visible hooking `ContinueDebugEvent` (the jmp at 0x4AEFBE) — the malformed PE's data flow crashes inside that hook. Countermeasure: turn the option off or switch plugins; lesson: the tools of confrontation get targeted too — when troubleshooting, suspect the plugin before the system.
