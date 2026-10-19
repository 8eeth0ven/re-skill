# Western corpus · Debugger craft (x64dbg / IDA / Ghidra official sources)

> Positioning: maintainer-side insights and modern (IDA 8/9, x64dbg current) craft our Chinese corpus lacks. Sourced from the x64dbg lead dev's blog + official docs, Hex-Rays official blog/docs, Ghidra community references, and Microsoft TTD docs. Deduped against 01-windows-re/debuggers-tools-cases.md (OD plugin dev, OllyScript, IDA plugin/script basics, sig batch, IDAPython cheat sheet all skipped as covered).

## I. x64dbg breakpoint and tracing engine (official docs)

### Conditional Breakpoint engine semantics (src: help.x64dbg.com)
Author: x64dbg docs
- On every hit, in order: set `$breakpointexceptionaddress`; increment hit counter and expose `$breakpointcounter`; evaluate break condition (default 1); if fast resume is on and condition==0, resume immediately skipping plugin callbacks AND GUI updates (this is the speed lever for logging bps); evaluate log condition (default 1), then command condition; break condition==1 prints standard log (suppressed if bp is *silent*), runs plugin callbacks; command text executes with `$breakpointcondition` writable — overwrite it inside the command to control whether the debuggee actually pauses.
- An invalid expression counts as true (always break/log/run). All literals are hex by default; decimal needs a leading dot (`.123`).
- Recipes: never-pause logging bp = break condition `0`; `EAX==1 && ECX==1`; first-arg check `arg.get(0)==1`; `mem.valid(EAX)`; third hit `$breakpointcounter==3`; thread filter `tid()==1C0`; `strstr(utf16(ECX), "foo")`.
- Never put `run` (or any state-changing command) in bp command text — unstable. Drive pause via break/command condition instead.
- Conditional bp can only fire where the bp sits; if you don't know where the condition becomes true, use conditional tracing instead.

### Expression functions worth building on (src: help.x64dbg.com)
Author: x64dbg docs
```
strings: utf8/utf16/ansi(addr[,count]) -> str; strstr/stristr/streq/strieq/strlen; .strict variants fail instead of ""
sel:     dis.sel()/disasm.sel(), dump.sel(), stack.sel()   -- anchor scripts to current GUI selection
mod:     mod.party(addr) 0=user/1=system, mod.base/size/entry/hash, mod.rva, mod.offset(file off!),
         mod.fromname("ntdll.dll"), mod.isexport(addr)      -- module-aware bp conditions
proc:    peb(), teb(), tid(), kusd() (KUSER_SHARED_DATA 0x7FFE0000)
mem:     mem.valid/base/size/iscode(addr), mem.decodepointer(ptr)
dis:     dis.iscall/iscond/isret/ismem/isnop, dis.branchdest/brtrue/brfalse, dis.next/prev,
         dis.mnemonic(cip)->str, dis.text(rip)->str, dis.match(addr,"regex")  e.g. dis.match(rip,"test.+, 0x1")
trace:   tr.enabled(addr), tr.hitcount(addr)  -- fold coverage state into conditions
read:    byte/word/dword/qword/ptr(addr) (0 on bad addr)
anti-aad: isdebuggerfocused() / isdebuggeefocused() for timing-sensitive logging windows
```
- `utf8(rax)` returns a string, not a number — cannot be a numeric condition; use `strstr()` to coerce.
- Plugins can register more via `_plugin_registerexprfunction(ex)` and format functions via `_plugin_registerformatfunction` — extend the condition language instead of forking scripts.

### Variables: user/system/readonly + reserved (src: help.x64dbg.com)
Author: x64dbg docs
- Three classes: USER (`var`/`mov` created, unrestricted), SYSTEM (read/write, not deletable), READONLY. Set with `mov myvar, 1234`, `$myvar = 1234`, or `myvar = 1234`; C-style ops work (`myvar += 0x10`, `|=`, `++`, `--`).
- Reserved: `$res`/`$result` + `$resN` (command results), `$pid`, `$hp`/`$hProcess`, `$lastalloc`, and the bp-interaction trio `$breakpointcondition` (writable — controls pause from inside bp command), `$breakpointcounter` (hit count, set before condition eval), `$breakpointlogcondition`.
- Script pattern: seed `mov hits, 0` at session start, `hits++` inside a never-pause log breakpoint's command text, break condition `$breakpointcounter==N && <state>` — accumulators for state-machine unpacking.

### Log formatting mini-language (src: help.x64dbg.com)
Author: x64dbg docs
- Syntax `{type:expression}`; escape literal braces as `{{`/`}}`. Types: `d` signed, `u` unsigned, `p` zero-padded pointer, `x` hex (default), `a` address-with-symbol (`00401010 <module.EntryPoint>`), `i` instruction text, `f`/`F` float from memory or XMM/YMM/ZMM lanes (`{f:YMM7[7]}`).
- Complex: `{mem;size@addr}` hex dump, `{utf16[;len]@addr}`, `{winerror@code}` / `{ntstatus@code}` (name + FormatMessage text — ErrLookup inline), `{modname@addr}`, `{label@addr}`, `{comment@addr}`, `{bswap;4@rax}`.
- Practical: `password: {utf16@4*ecx+0x402000}`; full-instruction trace log `{p:cip} {i:cip}`; quote the whole format string in `log "{mem;8@rax}"` so `;` is not eaten as a command separator.

### Conditional tracing and trace coverage (src: help.x64dbg.com)
Author: x64dbg docs
- Trace loop mirrors bps but break condition defaults to 0 (never stop) — pure recording runs need no condition. Command text can rewrite `$tracecondition` to stop mid-trace; command condition defaults to the break condition.
- Coverage-driven tracing (`TraceIntoBeyondTraceCoverage` etc.) stops when leaving already-covered code — first run maps the module, second run with coverage beyond record explores only new territory; fold `tr.hitcount(addr)` into the condition for full manual control.
- Trace Over never pauses inside stepped-over calls even if the condition is true there, and skips logging for them — faster but lossy; want the data, use Trace Into.
- `TraceSetLogFile` (or GUI) redirects the formatted trace log to a file for offline grep.
- Coverage updates on every step/pause event, including manual ones — interactive exploration and scripted tracing accumulate into the same coverage bitmap.

### Trace file format spec for external tooling (src: help.x64dbg.com)
Author: x64dbg docs
- `TRAC` magic, 4-byte length + JSON header, then binary blocks. Block type 0 = one executed instruction: `{type, nRegChanges, nMemAccesses, flags|opcodeSize, optional ThreadId, Opcode[], RegChangePosition[] (delta-encoded vs REGDUMP index), RegChangeNewData[], MemAccessFlags/Address/OldData/NewData[]}`.
- Relative register indexing (index[i] = index[i-1] + 1 + delta[i]) compresses well and lets REGDUMP grow without widening the byte counter. Full register snapshots at trace start and every 512 instructions (`RegisterChanges` = 172 on x64 / 216 on x86) make the file randomly accessible.
- Memory flag bit0 = unchanged, so NewData entry omitted; reader disassembles the opcode to know true access type. `cip` in the snapshot gives the instruction address.
- Use: write your own coverage/differential tooling over `.trace` files instead of re-running the debuggee.

### Plugin model: exports instead of registration calls (src: help.x64dbg.com)
Author: x64dbg docs
```
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT*);  // required
extern "C" __declspec(dllexport) bool plugstop();                  // unregister everything here
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*);// menus + GUI after init ok
// optional: plain exports named CBINITDEBUG/CBSTOPDEBUG/CBEXCEPTION/CBDEBUGEVENT/CBMENUENTRY...
//           auto-registered as callbacks; CBALLEVENTS gets everything. No underscore in names.
```
- Only export callbacks you actually use. Same job via `_plugin_registercallback` if you prefer runtime registration.
- Rich bridge surface for plugin features: `Dbg*` (DbgMemRead/DbgGetRegDump/DbgCmdExec/DbgGetBpList/DbgValFromString), `Gui*` (GuiReferenceInitialize/SetCellContent to build result tables, GuiGetLineWindow for input, GuiExecuteOnGuiThread for thread safety), `_plugin_logprintf`, `_plugin_startscript`, `_plugin_registercommand`.
- Trace callback `CB_TRACEEXECUTE` fires per traced instruction — plugin-side trace filters/coverage tools hook here.

### Breakpoint control as commands, incl. DLL breakpoints (src: help.x64dbg.com)
Author: x64dbg docs
- Every bp property is scriptable: `SetBPX/bp` (+Options), `SetHardwareBreakpoint` (r/w/x + slot), `SetMemoryBPX`/`SetMemoryRangeBPX` (page-guard style on address ranges), and the whole conditional layer per bp type: `SetBreakpointCondition/-Log/-LogCondition/-Command/-CommandCondition/-FastResume/-Silent/-Singleshoot/-Name`, with `Get/ResetBreakpointHitCount` per type — mirror of the GUI bp dialog, so breakpoint farms are buildable from .x64dbg scripts.
- DLL load/unload breakpoints are first-class "Librarian" commands: `LibrarianSetBreakpoint dllname` + Enable/Disable/Remove — this is the mechanism behind "break on DLL load" (as used in the Enigma/FreeArc workflow below); combines with `SetBreakpointCommand` to auto-run dump/trace commands the moment a module lands.
- `bpgoto` (jump to bp), `bplist`; exception breakpoints get their own family (`SetExceptionBPX`) — auto-pause on specific first-chance codes without the exceptions settings dialog.
- Analysis-adjacent: `traceexecute` (feed an address list to coverage), `virtualmod` (map a raw file as a module so bps/labels apply to non-loaded images), `symload/symdownload` (PDB fetch).

## II. Anti-anti-debug from the debugger-dev side

### TitanHide: kernel-mode hiding driver (src: mrexodia.re)
Author: mrexodia (x64dbg lead)
- Threat model split: user-mode-patchable checks (IsDebuggerPresent, NtGlobalFlag — just edit the PEB) are NOT handled; TitanHide only covers what needs kernel hooks (NtClose-based invalid-handle traps, debug-object queries), where user-mode hookers like ScyllaHide can themselves be detected.
- x64 SSDT location without exports: pattern-scan `KeAddSystemServiceTable` for `cmp qword ptr [...], 0` whose immediate encodes the SSDT RVA (XP x64 – 8.1; variant pattern for Win10 TP). Does NOT disable PatchGuard — the user boots with debug mode (bcdedit /debug on) so PG never loads.
- x64 SSDT entries are relative offsets, so a naked pointer won't fit: `FindCaveAddress` drops into compiler padding near the target and plants `mov rax, NewFunc; push rax; ret`.
- No hardcoded syscall indexes per OS: parse the on-disk ntdll, read the `mov eax, IDX; syscall` stub of each export, derive the SSDT index at runtime. Hooking is then one call: `SSDT::Hook("NtQueryInformationProcess", HookNtQueryInformationProcess)`.
> Same approach: our corpus' VT-based Ddvp / ReloadKernel entries cover custom debug engines; the novel part here is the version-proof SSDT discovery + per-OS index derivation recipe.

### Field report: unpacking Enigma under TitanHide (src: mrexodia.re)
Author: mrexodia
- Empirical tool state (2017): TitanHide debugged Enigma x64 fine while "ScyllaHide has issues" — first thing to swap when a packer beats usermode hiding.
- Loader-chain technique: x64dbg DLL breakpoint on `unarc.dll` (bp on module load), then break on `FreeArcExtract`; locate callback `cbArcExtract` by first-parameter xref; password string ("Arc password: ...") read straight out of the check. Companion compressor DLLs (facompress, CLS-MSC, CLS-srep) copied next to a standalone unarc.exe to detonate extraction safely outside the dropper.
- Enigma OEP at +$3059C had stolen bytes: the original prologue lives inside the protector stub. Recovery trick — compile a Hello World in the *same* toolchain/packer-free target language (here AutoIt), paste the ~17 stolen bytes over its entry, rerun to observe semantics, then transplant.
- Nested AutoIt stages: Exe2Aut-decompile, patch bogus header `00000000001C0004` into the 7z magic `377ABCAF271C0004`, extract with the hardcoded password; the SCRIPT resource from the unpacked Enigma binary was dropped into a fresh Hello-World AutoIt 32-bit host and decompiled again.
- Process-tree following: DbgChild plugin auto-attaches x64dbg to every child process — dropper chains (setup.tmp → DSETUP.exe → fake svchost) stay observable without manual attach races. C2 read from a YouTube video description (download/run/update commands).

## III. x64dbg internals and script bindings

### The debug loop architecture (src: mrexodia.re)
Author: mrexodia
- The loop itself lives in TitanEngine, not x64dbg: `SetCustomHandler()` registers per-event handlers; STATUS_SINGLE_STEP (stepping) and STATUS_BREAKPOINT (software bps) are special-cased; threads/modules/bps bookkept around them. Handlers run inside `WaitForDebugEvent/ContinueDebugEvent` — the loop blocks until the handler returns.
- Three-thread model: GUI main thread spawns a Command Thread (waits for a command, dispatches to its handler, waits again); `InitDebug` on the command thread spawns the Debug Thread running the debug loop. GUI never blocks on the debuggee.
- Pause = the Debug Thread parking inside a custom handler on a lock (`lock()/unlock()/wait()`) until the GUI releases it. Shared global state (breakpoints, comments, bookmarks) guarded by CriticalSectionLocker.
- Read this before writing plugins that touch debugger state — knowing which thread your callback runs on (inside the loop, blocking) explains why heavy plugin work freezes stepping.

### Script API and language bindings (src: mrexodia.re)
Author: mrexodia
- Design goal: one script API so anyone can bind a favorite language and ship it as a plugin (AngelScript prototype in the testplugin repo). Surface: debug control (run/step/stop/pause), register get/set, mem read/write, find/write patterns, module info, GUI selection get/set.
- Script-side step-out sample reads the spirit of the API: `Register::GetCIP()`, loop `Debug::StepOver()` until `byte at CIP == 0xC3` — everything an OllyScript had, but callable from a real language.
- Alternative pattern: script DLLs exporting a single `StartScript` — any language that can produce a native DLL works, enabling even commercial closed-source unpacker scripts as drop-ins.

### MenuBuilder: lazy predicate menus (src: mrexodia.re)
Author: mrexodia
- x64dbg's Qt context menus are built by a recursive lazy builder: every QAction/QMenu/sub-MenuBuilder registers with an `std::function<bool(QMenu*)>`; at popup time the tree is evaluated and an item only lands in the live menu if its predicate passes (e.g. "follow in dump" only when `DbgMemIsValidReadPtr(selection)`).
- Kills the classic Qt boilerplate explosion (per-action member pointer, slot, connect, refreshShortcutsSlot); `makeAction(text, slot-or-lambda)` + `makeShortcutAction(icon,text,slot,id)` do the rest; `build(&menu); menu.exec(pos)`.
- Pattern to steal for plugin/researcher GUIs: interpret a menu spec per-context instead of maintaining a static tree with enabled flags.

## IV. IDA 8/9-era workflow

### Built-in Microcode Viewer (IDA 9.2) (src: hex-rays.com/blog)
Author: Hex-Rays (Rolf Rolles)
- Ship-in-tool viewer for the decompiler IR at any maturity level, synced with disassembly and pseudocode. Structure: `mba_t` (function) → `mblock_t` (blocks) → `minsn_t` (instructions, up to 3 `mop_t` operands); operands can be outputs of other minstructions, so the IR nests; as it matures, instructions die and survivors grow complex.
- This is the layer where `optinsn_t`/`optblock_t` optimization rules catch compiler or obfuscator patterns the stock passes miss; your modifications still benefit from later built-in passes.
- Hard rule for microcode plugin work: call `verify()` on the `mba_t` after editing; use SDK's verify.cpp to decode `interr` numbers when you corrupt it.
- Lineage to mine further: community predecessors lucid (Gaasedalen), genmc (patoi). Our corpus' ctree-plugin entry covers ctree; this adds the microcode layer below it.

### IDA + WinDbg Time Travel Debugging (IDA 9.1+) (src: docs.hex-rays.com)
Author: Hex-Rays docs
- IDA loads a TTD `.run` trace like a crash dump, but execution can be "continued" both directions: Continue backwards, Step into/over backwards, Run to cursor backwards (toolbar/Debugger menu). It is navigation over a recorded instruction log — no register writes, no behavior changes.
- Setup gotcha: only standalone WinDbg (the AppX) has TTD; Debugging Tools for Windows cannot load traces. Windows blocks executing from the AppX folder, so copy its `amd64` dir out (`Get-AppxPackage Microsoft.WinDbg | select InstallLocation`, or unzip the `.msixbundle` via the `.appinstaller` MainBundle Uri), then point `DBGTOOLS` in ida.cfg at the copy containing dbgeng.dll. Updated dbgeng.dll required.
- In-session commands: `!positions`, `!tt`, and `dx` data-model queries (memory reads/writes to an address) work from IDA's command line too. Backward stepping does not work with source-level debugging.

### Debugger register subview + unwind-based call stacks (IDA 9.2) (src: hex-rays.com/blog)
Author: Hex-Rays (Arnaud Diederen)
- New Registers subview auto-dereferences pointer-looking values and follows chains recursively; memory kinds (code/stack/heap/readonly) color-coded; deref depth configurable (default 5, 0 = off) — a poor-man's structure walker during dynamic analysis.
- x64 PE call stacks rebuilt from unwind metadata in exception records, mirroring `RtlVirtualUnwind` without depending on Windows: fixes bogus top frames after control transfers (demo: cmd.exe → RtlValidSid via RegOpenKeyEx → RtlOpenCurrentUser).
- Call stack addresses now point at the call instruction in the caller, not the return slot after it — stops the off-by-one when mapping frames back onto the disassembly.

### idalib: headless IDA as a library (src: hex-rays.com/blog)
Author: Hex-Rays
- IDA 9.x ships idalib (Python and Rust bindings) for driver-less headless analysis; four showcase tools define the patterns: Rhabdomancer (Rust) scans for risky-API calls and ranks for audit triage; Haruspex (Rust) decompiles every function to per-function files feeding Semgrep/weggli; Augur correlates strings with surrounding pseudocode for IOC-to-code mapping; headless-ida (Python) batch-processes directories with your existing IDAPython scripts — replacing the old `idat -A -S` batching with an in-process API.
- headless-ida-mcp-server turns IDA into a remote analysis backend (rename, inspect, manage regions across many IDBs).
- Licensing: embedding into products/SaaS/private multi-user servers needs an OEM license; personal pipeline automation on a normal license is fine.

### Golang decompilation via tuple types (IDA 9.2) (src: hex-rays.com/blog)
Author: Hex-Rays
- New tuple type in the type system models Go multi-return: members scattered across registers (rax, rbx, rcx...) and stack slots; two tuples are "equal" when offsets/sizes/types match (names/alignment ignored).
- Kills the classic Go-analysis pain set: cryptic oversized argument lists, false "potentially uninitialized" stack vars, missing return-value mapping, broken string lengths. Members show as `_r0`, `_r1` (std-lib name recovery not yet) — map them against Go's ABI internal docs.
- Fewer hand-edited prototypes means function prototypes survive call chains. Test target suggestion: Flare-On 11 Challenge 2 Go binary, 9.1 vs 9.2 diff.

### FLIRT Manager + maintained signature packs (IDA 9.0) (src: hex-rays.com/blog)
Author: Hex-Rays
- FLIRT Manager lists signatures and applies them tentatively in bulk (multi-select replaces double-clicking each); with idalib configured, thousands of signatures apply near-instantly during analysis.
- Signature packs are now Hex-Rays-maintained downloads, refreshed when upstream toolchains change: Golang 1.10.0–1.23 (win/lin/darwin, x86/x64/ARM/ARM64), Rust 1.77–1.81 (GCC/LLVM/MSVC across three OSes), MSVC WinSDK 10/11 + ATL/MFC/CTL, Ubuntu/Debian libc/OpenSSL/zlib/curl/SDL down to s390x/MIPS/PPC64.
- Workflow shift vs our corpus' sigmake batch: stop curating your own .sig for common toolchains — pull the maintained pack and reserve custom FLIRT (makesig on already-reversed functions) for in-house/statically-linked code only.

### Open-source SDK + hcli/Plugin Manager (IDA 9.2+) (src: hex-rays.com/blog)
Author: Hex-Rays
- SDK lives on Hex-Rays' GitHub (all platforms, IDA Free included); IDAPython and the C++ SDK are now one repo — no separate SDK download mismatch. CI/CD for plugin builds got materially easier.
- Companion infra: hcli (license/install/plugin management CLI, `hcli mcp install` hooks MCP clients), the Plugin Manager inside IDA, plugins.hex-rays.com directory, and the "claim ownership of your plugin" push so renamed/stolen plugin builds can be told apart on user machines.

### Official Hex-Rays IDA MCP server (src: hex-rays.com/blog)
Author: Hex-Rays
- Free, open-source MCP server letting agents (Claude Code, Codex, Copilot CLI, any stdio MCP client) drive IDA Pro/Home/Classroom/OEM. "Code Mode" design: deliberately few tools — Database (open/close/save IDBs), IDAPython (read/write/update + evaluate logic via Python), Reference (search API docs) — instead of dozens of granular endpoints; ~20% token reduction vs granular-tool MCPs on their internal malware benchmark. All the decompile/xref/rename power routes through IDAPython execution.
- Multi-agent via ida-nexus: many agents share many IDBs concurrently, live alongside a human in the GUI; headless mode on idalib enables fully autonomous pipelines (e.g. agent extracts and analyzes a dropper's second stage).
- Install: with `uv` present, `uvx ida-hcli mcp install` (or `hcli mcp install`); one-command setups exist for Claude Code, Codex, Copilot CLI, Pi; any stdio MCP client works (LM Studio and similar).
- Security stance: IDA's Python is not isolated from the system — sandbox/VM the whole harness; opt-in only. Works fully local for air-gapped use; open-weight models (DeepSeek, Kimi, GLM, Qwen) reportedly approach frontier performance on RE tasks.

## V. Ghidra scripting gems

### Decompiler API: three levels of control (src: GhidraSnippets, CC0)
Author: HackOvert
```
# 1) flat one-liner (quick look):
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
fdapi = FlatDecompilerAPI(FlatProgramAPI(getState().getCurrentProgram()))
print(fdapi.decompile(fpapi.getFunction('main')))
# 2) full control (options, timeout, monitor):
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface(); ifc.setOptions(DecompileOptions()); ifc.openProgram(currentProgram)
res = ifc.decompileFunction(func, 60, monitor)   # timeout seconds, TaskMonitor
print(res.getDecompiledFunction().getC())
# 3) high-level: high_func = res.getHighFunction(); op = high_func.getPcodeOps(addr).next()
```
- Lookup discipline: `getFunctionAt` matches entry points only — for an address inside a function use `getFunctionContaining`; `getGlobalFunctions(name)` returns a list (names repeat).
- Function/xref walk: `fm = currentProgram.getFunctionManager(); for f in fm.getFunctions(True):` then `getReferencesTo(f.getEntryPoint())`.

### PCode for call arguments + slices + emulation (src: GhidraSnippets)
Author: HackOvert
- Argument recovery without reading the disassembly by hand: decompile → `getHighFunction()` → `getPcodeOps(target).next().getInputs()` yields varnodes for the call target plus each argument — the reliable way to script "what got passed here" (register/stack/spilled handled by the high-level pcode).
- Data-flow tracing: `DecompilerUtils.getBackwardSlice(varnode)` / `getForwardSlice` — from a leaked-pointer varnode, walk back to its producers for deobfuscation stories.
- `EmulatorHelper`: set registers/memory, single-step, read state — in-process string deobfuscation without leaving Ghidra.
- Pattern: rename-by-registration — walk xrefs to a registration/dispatch function, decompile each caller, extract string + function args from CALL pcode ops, `setName()` both; scales to hundreds of handlers.
- API discovery trick: interactive Python (Window → Python) with `help(currentProgram)` and tab-completion; bundled Java scripts are reference implementations of the same API.

### Headless + script-project workflow (src: SentinelOne labs guide)
Author: SentinelOne
- Script project: GhidraDev (Eclipse) from the Ghidra Extensions zip + PyDev; open bundled scripts through Ghidra's Script Manager "edit in Eclipse" button to get the Jython interpreter wired; script metadata comments drive Script Manager category/menupath/toolbar icon.
- Batch: `analyzeHeadless <proj> <name> -import <bin> -preScript x.py -postScript y.py` (postScripts run after analysis; -process for already-imported programs). This is the Ghidra counterpart of IDA's `idat -A -S` batching in our corpus — cross-useful for the same jobs.
- `askBytes()`/`askFile()` style popups make scripts interactive inside the GUI but block headless runs — guard them or fork GUI/headless variants.
- Memory blocks via `currentProgram.getMemory().getBlocks()`; code units `listing.getCodeUnits(func.getBody(), True)`; basic blocks `BasicBlockModel(currentProgram).getCodeBlocksContaining(body, monitor)`; five comment types (EOL, PRE, POST, PLATE, REPEATABLE) via `codeUnit.getComment(i)`.

## VI. WinDbg TTD craft (Microsoft + Mandiant)

### TTD object model: LINQ over the trace (src: learn.microsoft.com)
Author: Microsoft
- TTD extensions hang data off `@$curprocess.TTD` (Lifetime, Threads, Events, SetPosition, Prev/NextMemoryAccess) and `@$cursession.TTD` (Calls, Memory, MemoryForPositionRange, Data.Heap, Utility, Analyzers, Bookmarks, Checkers). Query with `dx`, grids with `dx -g`, depth with `-r2`.
```
dx -r2 @$cursession.TTD.Calls("kernelbase!GetLastError").OrderBy(c => c.TimeStart)
dx -g @$cursession.TTD.Calls("kernelbase!GetLastError").Where(x => x.ReturnValue != 0)
   .GroupBy(x => x.ReturnValue).Select(x => new { Err = x.First().ReturnValue, N = x.Count() })
   .OrderByDescending(p => p.N)                          # error histogram over the whole run
dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception").Select(e => e.Exception)
dx @$curprocess.TTD.Events.Where(t => t.Type == "ModuleLoaded").Where(t => t.Module.Name.Contains("ntdll"))
dx @$cursession.TTD.Memory(&@$teb->LastErrorValue, &@$teb->LastErrorValue+4, "r")     # r/w/e/c mask
   .Where(m => m.TimeStart < @$dialog).OrderBy(m => m.TimeStart).Last().TimeEnd.SeekTo()
```
- Store query results: `dx @$var = <expr>` then `dx -g @$var`. Jumping: `!tt 9:0` or `SetPosition()`.
- Troubleshooting: "UnknownOrMissingSymbols" = no symbols (public symbols give name + 4 default u64 params, private give real params); empty Calls results — check `x` for case, jump past the DLL load first, inlined calls invisible, wildcards too broad.

### TTD against a process-hollowing dropper (src: Mandiant blog)
Author: MTI (Josh Hsu)
- Record with standalone `ttd.exe sample.exe` (not tttracer, not the UI): yields `.run` (trace), `.idx` (~2x trace size, built on first open), `.out` (log). Use `-children` or the child process is untraced and its memory invisible. TTD is not a sandbox — malware runs for real.
- Navigation: backward mirrors of everything — `g-`, `g-u`, `t-`, `p-`; positions are `MajorSeq:StepCount`.
- Triage as queries, not stepping: `TTD.Calls("kernel32!CreateProcess*")` → CREATE_SUSPENDED(0x4) on InstallUtil.exe, handle 0x104; `TTD.Calls("kernel32!WriteProcessMemory*")` → four writes to handle 0x104 at 0x400000/0x402000/0x43e000/0x440000 = classic PE load (header/.text/.rsrc/.reloc).
- Carve the payload from trace memory: `!dh 0x9810af0` (COR20 dir → .NET), `.writemem headers.bin 0x9810af0 L0x200` + per-section dumps, reassemble, dnSpy → AgentTesla config.
- Caveats: on x86 the data model merges pairs of 32-bit stack args into one u64 — read args off the stack (`dd /c1 esp+4 L0A`, `da poi(esp+4)`) for accuracy; filtering calls by main-module ReturnAddress is unreliable for .NET (JIT code lives outside the image). P/Invoke is the pivot: obfuscated managed code still shows its Win32 calls.

### .NET crash triage without SOS hand-holding (src: mrexodia.re)
Author: mrexodia
- JIT-attach WinDbg to a crashing managed app and just run `!analyze -v`: it auto-detects managed code (MANAGED_CODE/MANAGED_ENGINE_MODULE/MANAGED_ANALYSIS_PROVIDER fields), loads SOS internally, decodes `e0434352` → HRESULT 0x80131509 → bucket CLR_EXCEPTION_System.InvalidOperationException, prints the exception message, a resolved managed STACK_TEXT across NGEN images, plus MethodDesc/MethodTable/mdToken per frame.
- `STACK_COMMAND` reveals the underlying invocation (`!sos.pe <addr>`) — copy that pattern when you need the same output without the full analyze pass. No .load sos / mscordacwks version dance needed in modern WinDbg.

### WinAPI "optional" that is not (src: mrexodia.re)
Author: mrexodia
- `DeviceIoControl` with `lpOverlapped=NULL` crashes on Win7 unless `lpBytesReturned` is also non-NULL — worked fine on 8.1. Lesson scaled to our tooling: MSDN "optional" parameters are conditional; read the Remarks before trusting a signature. Bit a kernel-bridge helper talking to TitanHide.

## VII. Adjacent workflows from the same sources

### Firmware extraction before disassembly (src: mrexodia.re)
Author: mrexodia
- Consumer-keyboard update chain: the vendor's upgrade EXE carries the image as RCDATA resource — pull it with CFF Explorer (resource view), the blob is a small loader with the real firmware as an appended overlay, metadata at the tail.
- Chip ID from strings in the tail ("SN32F24x" → SONiX SN32F248, ARM Cortex-M0); vendor's datasheet + ISP Tool then validate/parse the image (this generation ships unencrypted — earlier ones needed a decryption pass first).
- Methodology transfer: for any peripheral firmware, hunt the updater's resources and overlays before touching hardware dumps; then build a known-good reference firmware with the matching toolchain for diffing (the author's stated next step, done in Ghidra in parts 2–3 of the series).

### CyberChef embedded in IDA (src: hex-rays.com/blog)
Author: Willi Ballenthin (plugin spotlight)
- Open-source plugin embedding CyberChef's data-transformation engine inside IDA — decode/deobfuscate byte ranges in the disassembly with the full CyberChef recipe stack (chains of from-hex/xor/decode operations) without round-tripping to a browser.
- Fits the same slot as our corpus' "dump to file → external decode → patch back" loops, but stays on the IDA side; useful for config decoders and string deobfuscation during static triage.

## VIII. Gap notes vs the Chinese corpus

- We have OD conditional logging breakpoints (OllyRecord) but no x64dbg engine semantics: fast resume, `$breakpointcondition` write-back, silent flag, hex-default literals (`.123` for decimal) — the pause/log/command matrix in section I is the modern replacement for OD Shift+F4 habits.
- We have VT/debug-engine plugins (Ddvp, ReloadKernel) but no version-proof SSDT discovery recipe (KeAddSystemServiceTable pattern + ntdll stub index parse) — borrow for any kernel-bridge tooling, not just hiding.
- We have IDA ctree-plugin craft; the built-in Microcode Viewer (9.2) plus `verify()` discipline is the missing observability layer for writing optinsn_t rules on obfuscated code.
- We batch IDA via `idat -A -S`; idalib (in-process, Rust/Python bindings) and Ghidra `analyzeHeadless` are the two headless counterparts for the same directory-sweep jobs — one pipeline can span all three.
- TTD (`.run` traces, dx LINQ over Calls/Memory/Events) has no Chinese-corpus counterpart at all — the hollowing workflow (query, don't step; carve PE with writemem) is the template, and IDA 9.1+ can replay the same traces.
- Trace-side tooling: x64dbg's documented `.trace` binary format plus the `LibrarianSetBreakpoint` command families enable scripted coverage diffing and auto-dump-on-DLL-load, jobs our OD-era scripts did through the GUI.

## Sources

- mrexodia blog (redirects to mrexodia.github.io): TitanHide; Analyzing torrent repack malware; Script API; x64_dbg from top to bottom 1; Dynamic menu builder; Look Out!; Dot Net callstack from WinDbg; Analyzing keyboard firmware part 1
- help.x64dbg.com / x64dbg docs GitHub (x64dbg/docs): ConditionalBreakpoint.md, ConditionalTracing.md, Expression-functions.md, Formatting.md, Variables.md, developers/tracefile.md, developers/plugins/basics.md, commands/ tree (breakpoint-control, conditional-breakpoint-control, analysis)
- hex-rays.com/blog: Spying on Decompiler Internals (microcode viewer); IDA Debugger: New Register Subview; IDA 9.1 (TTD); 4 Powerful Applications of IDALib; Stop Guessing and Start GOing (Golang tuples); FLIRT Manager; Open-Sourcing the IDA SDK; Hex-Rays IDA MCP Server
- docs.hex-rays.com: WinDbg TTD integration page
- learn.microsoft.com: Time Travel Debugging — object model, overview, walkthrough
- Mandiant/MTI blog: An Introduction to Time Travel Debugging using a .NET process (hollowing)
- Ghidra: HackOvert/GhidraSnippets (CC0), SentinelOne labs Ghidra scripting guide, ghidra.re GhidraScript javadoc
