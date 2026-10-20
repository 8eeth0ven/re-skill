# Internals (Part 4: System Internals 1000140 + the Windows System Programming Series 1000908)

> Positioning: the Windows system-mechanism foundation that reverse engineering needs — how processes/threads are born, how memory is managed, where handles and objects live, how messages flow, and how files and the registry are stored. This is the knowledge main line of the knowledge base's "Internals" part, and the foothold of every confrontation technique in the later Protection and Reconstruction chapters.

## 1. The Full Process-Creation Chain (Node 1000176, the Core of This Part)

### 1.1 Why Reverse Engineers Must Understand the Process-Creation Chain

Three reasons: ① packers and anti-debugging frequently hook/detect this chain (e.g., hooking NtCreateProcessEx to stop debuggers from attaching to child processes; dual-process protection relies on it for mutual guarding); ② injection, unpacking, and dumping all require pinpointing "when is the process actually running"; ③ the Internals part of *Encryption & Decryption* treats this chain as the outline of Windows mechanics.

### 1.2 The User-Mode Chain (kernel32 → ntdll)

```
CreateProcessW / CreateProcessA          (kernel32, thin wrapper)
        │
        ▼
CreateProcessInternalW                   (kernel32 does the real work)
  1. Parse lpApplicationName / lpCommandLine (image path search order)
  2. Open the exe, read the DOS header/NT header, validate the subsystem
     (DOS/OS2/POSIX images → take the VDM/POSIX branch)
  3. Build RTL_USER_PROCESS_PARAMETERS
     (command line, environment block, current directory, window station/desktop, handle inheritance table)
        │
        ▼
ntdll!NtCreateUserProcess                (since Vista, one system call creates process+thread)
  XP/2003 old chain: NtCreateProcessEx + NtCreateThread (two calls)
        │  syscall / KiFastSystemCall
        ▼
nt!NtCreateUserProcess (kernel mode)
```

Essentials:
- After Vista, CreateProcessInternalW mainly goes through `NtCreateUserProcess`, merging the creation of the process and its initial thread into one system call, with arguments passed via `RTL_USER_PROCESS_PARAMETERS` + `PS_CREATE_INFO`/`PS_ATTRIBUTE_LIST` (in reverse engineering you see it in the ntdll export table in its undocumented form).
- In the XP era it was the two steps `NtCreateProcessEx` (create the EPROCESS) → `NtCreateThread` (create the initial ETHREAD); many older posts (from the 3rd-edition era of *Encryption & Decryption*) explain along this old chain — mind the OS version when reading them.
- On 32-bit, entering the kernel goes through `KiFastSystemCall` (mov edx,esp / sysenter), with the syscall number taken from `KeServiceDescriptorTable` (see §4.4); after Win10 user mode uses the `syscall` instruction directly.

### 1.3 Kernel Mode (What NtCreateUserProcess Does)

```
nt!NtCreateUserProcess
 ├─ Open the image file → IoCreateFile/parse the Section
 ├─ MmCreatePeb                    ← build the PEB, write in the parameters
 ├─ PspCreateProcess               ← build the EPROCESS/KPROCESS
 │    ├─ Object manager ObCreateObject(EPROCESS)
 │    ├─ Initial process handle table ObjectTable
 │    ├─ Address space MmCreateAddressSpace (CR3/page tables)
 │    └─ Map ntdll + image Section
 ├─ PspCreateThread                ← build the ETHREAD/KTHREAD + user stack + TEB
 └─ Notify CSRSS (the Windows subsystem, ALPC port CsrPortProcessId)
```

### 1.4 User-Mode Startup of the Initial Thread (the Segment Reverse Engineers Care About Most)

The kernel queues a user-mode APC into the new thread; the first time it gets scheduled it starts running at ring3 from `ntdll!LdrInitializeThunk`:

```
LdrInitializeThunk
  └─ LdrpInitializeProcess
       ├─ Initialize PEB->LoaderData (PEB_LDR_DATA)
       ├─ Load ntdll→kernel32→… in dependency order (inserted into the three chains one by one via InLoadOrderModuleList:
       │   InLoadOrder / InMemoryOrder / InInitializationOrder)
       ├─ Static import resolution: walk the Import Table, fill the IAT
       ├─ TLS callbacks → DLL_PROCESS_ATTACH (in order)
       └─ Jump to the OEP (Entry Point)
```

Reverse-engineering touchpoints:
- **Breakpoint timing**: when attaching, often just `bp ntdll!LdrpInitializeProcess`, or break on `LdrLoadDll` to see which DLLs the packer pulls in.
- **TLS callbacks execute before the OEP** — packers and anti-debugging love putting checks in the TLS callback, commonly around `01005000`; when hunting the OEP while unpacking, don't stare only at the entry.
- The implementation point of **dual-process protection** is exactly this chain: after the parent CreateProcess'es the child, they OpenProcess+ReadProcessMemory each other to validate.
- Old-post main-line references: "Overall Flow Analysis of the CreateProcess Function", "Analysis of NtCreateProcessEx", "The Communication Flow Between Process Creation and csrss", "Hooking Native API to Control Process Creation", "Intercepting Process Creation", "A Simple Implementation of Registry Modification and Process-Creation Monitoring under WinXP", "PsSetCreateProcessNotifyRoutine".

## 2. Threads and Synchronization (Node: Structures of Processes and Threads 1000173)

### 2.1 The Three-Layer Structure

| Layer | Structure | Key fields (reverse-engineering view) |
|---|---|---|
| User mode | TEB | fs:[0] (x86)/gs:[0] (x64) self-reference; ExceptionList (SEH chain head), StackBase/StackLimit, PEB pointer, ClientId (UniqueProcess/UniqueThread) |
| Executive | ETHREAD | StartAddress, Cid, CrossThreadFlags, ThreadsProcess pointing back to EPROCESS |
| Kernel | KTHREAD | scheduling priority, kernel stack base, WaitBlock (which dispatcher object it waits on) |

- `_EPROCESS` keys: `UniqueProcessId`, `ActiveProcessLinks` (walking the process list, the battlefield of hidden processes — details belong to the Programming chapter/binary-vulnerability area), `ObjectTable`, `PEB` (at a high user-mode address; view `_PEB` in WinDbg with `!peb`).
- User-stack/kernel-stack switching: on kernel entry the CPU switches TSS/`KTHREAD.KernelStack` automatically — the basis of SSDT hooks and kernel-stack backtrace analysis.

### 2.2 Synchronization Objects and Reverse Applications

- Critical section `CRITICAL_SECTION` (user-mode spin + kernel wait hybrid; deadlock analysis looks at LockCount/OwningThread); when a multi-threaded packer decompresses, x64dbg must freeze the other threads first before setting breakpoints.
- Mutex/Semaphore/Event: the `WaitForSingleObject` family, kernel dispatcher objects.
- **Named mutex anti-multi-instance**: software starts with `CreateMutex(NULL,TRUE,"MyApp")` + `GetLastError==ERROR_ALREADY_EXISTS` popping "program already running" — the patch point is the decision jump; conversely, dual-launching a game means killing exactly this check.
- Deadlock/race reversing: two threads contending over the same global validation variable; running only one thread during unpacking deadlocks — precisely the problem "multi-threaded debugging" (Debugging 1001374) solves.

## 3. Memory Management (Nodes 1000911/1000912)

### 3.1 The Full VirtualAlloc Chain

```
VirtualAlloc/VirtualAllocEx   (kernel32)
   │
   ▼
ntdll!NtAllocateVirtualMemory  (syscall)
   │
   ▼
nt!NtAllocateVirtualMemory
   ├─ Find a free VA range (from Zone/top-down)
   ├─ Create/merge VAD nodes (the process's VAD tree, describing "which VA range, what attributes, backed by which Section/pagefile")
   └─ Return the base address (physical pages not yet allocated!)
        │
        ▼ first access to the page → #PF page fault
nt!MmAccessFault → materialize the physical page per the VAD description (demand paging)
```

Essentials:
- VirtualAlloc's MEM_COMMIT only commits without touching; physical pages are granted only on the first access fault. **Some pages of an unpacking dump being sparse** is related to this.
- `VirtualProtect`→`NtProtectVirtualMemory`: the shell makes .text writable → decrypts → flips it back to executable; a breakpoint on `NtProtectVirtualMemory` catches the shell's self-decryption rhythm.
- The VAD tree is the core of memory forensics: even with the PEB unlinked, the VAD still records all the process's mappings (the key to anti-hiding).

### 3.2 Heaps

- Default heap: `GetProcessHeap`, i.e., PEB->ProcessHeap; `HeapCreate` for private heaps.
- RtlAllocateHeap: backend free lists/lookaside lists; Vista+ defaults to LFH (Low Fragmentation Heap).
- Reverse-engineering value: PEB->ProcessHeap's Flags/ForceFlags heap markers get modified by debuggers → an anti-debugging detection point (see Protection §1.1); when dumping strings U-decrypted on the heap, wait for decryption to finish.

### 3.3 Memory Layout (x86 User Space)

```
0x7FFFFFFF ┌──────────────┐
           │ 0x7FFDF000 TEB │ ← fs:[0] points here
           │ 0x7FFDB000 PEB? (XP location; drifts across versions)
           │ KUSER_SHARED_DATA 0x7FFE0000 (read-only system area)
           │ system mappings like ntdll.dll / kernel32.dll
           │ ↓ dynamic DLLs/heaps/stacks
           │ the process's exe image
0x00010000 └──────────────┘ (below 64KB reserved, NULL-pointer protection)
```
x64: user space up to 0x00007FF_FFFFFFFF; TEB/PEB fetched via gs:[0x30]/gs:[0x60].

### 3.4 Memory-Mapped Files (Node 1000912)

- Chain: `CreateFile`→`CreateFileMapping` (kernel Section object)→`MapViewOfFile`→`NtMapViewOfSection`, mapping a file/pagefile-backed region into VA.
- Uses: analyzing big files without reading them whole, inter-process shared memory (the IPC first choice, §9.2), and the loader itself maps PEs via Sections.
- Reverse applications: multi-process packers share decryption keys via shared sections; writing to the mapping writes the file (except under copy-on-write).

## 4. Handles and Object Management, Core Data Structures (Node 1000164)

### 4.1 Objects and Handles

```
What the user gets: HANDLE = (handle-table index << 4) | attribute bits
   │
   ▼ look up EPROCESS->ObjectTable (multi-level handle table, up to three levels on x86, similar to page tables)
OBJECT_HEADER → OBJECT_TYPE (Process/File/Key/Section/Mutant…)
   → object body (EPROCESS / FILE_OBJECT / …)
```

- Common attribute bits: 0x1 inheritance flag (PROCESS_FLAG…); the low bits take effect during DuplicateHandle/handle passing.
- Reverse-engineering meaning: a debugger attach is essentially obtaining a PROCESS_ALL_ACCESS handle; `CloseHandle` with an invalid handle raises an exception — used as anti-debugging (see Protection); handle right downgrade (removing PROCESS_VM_READ) is a counter-dump measure.
- Object directories `\??`, `\BaseNamedObjects` (where named mutexes/semaphores live; viewable with WinObj).

### 4.2 TEB (Node 1000168)

On x86, `mov eax, fs:[0x18]` yields the TEB self-reference, then other fields; `fs:[0x30]` is the PEB. Key offsets (minor version drift): `+0x00 ExceptionList`, `+0x18 Self`, `+0x30 ProcessEnvironmentBlock`. When the debugger switches thread context, the TEB switches with it — multi-threaded anti-debugging paints flags into different threads' TEBs.

### 4.3 PEB (Node 1000169)

```c
PEB (x86 offsets): +0x02 BeingDebugged   // the source of IsDebuggerPresent (same offset on x64)
     +0x0C Ldr → PEB_LDR_DATA // the three module chains (the proper way to find kernel32; x64 +0x18)
     +0x18 ProcessHeap        // its Flags/ForceFlags get modified by LFH (x64 +0x30)
     +0x68 NtGlobalFlag       // set to FLG_HEAP_* when started by a debugger (x64 +0xBC)
```
The PEB is user-mode writable — hence anti-debugging inspects the PEB, and anti-anti-debugging writes it back (the ScyllaHide principle, expanded in the Protection chapter).

### 4.4 SSDT (Node 1000066→1000166)

- `KeServiceDescriptorTable` → the service function table; `ntdll.dll`'s syscall numbers enter the kernel through this table; Win32K has a separate `KeServiceDescriptorTableShadow` (GUI services).
- Reverse-engineering meaning: the system call is the inescapable final layer — every shell eventually calls VirtualAlloc/WriteProcess/Protect; hooking at the SSDT layer sees everything; conversely SSDT hooks are also a kernel-layer anti-debugging means. Note: the knowledge base appendix has the Windows System Call Table (node 1001141).

### 4.5 GDT/Protected Mode (Nodes 1000167/1000162)

- Segment registers are basically flat under Windows (fs/gs special); the GDT holds the TSS/segment descriptors; VT-related detection (e.g., sidt reading the IDT base to probe for a hypervisor) belongs to Anti-VM in the Protection chapter.
- Paging: CR3→PDT→PT→PFN, 2MB/4MB large pages; `MmGetPhysicalAddress` and physical-memory searches (the principle behind game trainers).

### 4.6 The API Secret Archive (Node 1000175)

Community-organized material on undocumented/under-documented APIs (NT-layer function prototypes, undocumented structures); consult it when doing tool-grade patches, mini debuggers, or API self-implementation. Modern equivalents: symbol libraries (winternl.h, the phnt headers). (Content varies with OS version; verify before use.)

### 4.7 NTFS / HIVE / Cache Structures (Nodes 1000170/1000171/1000172)

- **NTFS**: the MFT master file table, 1KB per record, attribute streams (0x10 STANDARD_INFORMATION, 0x30 FILE_NAME, 0x80 DATA); resident/non-resident. Appendix 5 also covers the NTFS format (1001143). The foundation of forensics and "file masquerading/data hiding" analysis.
- **HIVE**: the registry's on-disk format, `CM_KEY_NODE`/`CM_KEY_VALUE`, the root-key files (SYSTEM, SOFTWARE… in the config directory); registry readers/password-extraction tools parse the HIVE directly. The five registry trees HKLM/HKCU/HKCR/HKU/HKCC; the RegOpenKeyEx→NtOpenKey chain; autostart (Run keys/services) is the first stop of security triage.
- **Cache structures**: the Cache Manager's lazy write, system cache views; in memory forensics, the "file changed in cache but not yet flushed" window.

## 5. The Message Mechanism (the Skeleton of Windows GUI)

```
Hardware input → the system Raw Input Thread (RIT) → the thread message queue (attached to the thread that created the window)
                                          │
   GetMessage/PeekMessage ← ──────────────┘
        │ TranslateMessage (keyboard virtual key → the character message WM_CHAR)
        ▼ DispatchMessage → USER32 finds the WndProc of the hwnd
        ▼
   window procedure switch(msg){ WM_COMMAND / WM_TIMER / … }
```

- Every thread that creates a window has its own queue; `PostMessage` is async enqueueing, `SendMessage` is cross-thread synchronous (the receiver must enter GetMessage to return) — deadlocks and "message breakpoints" both stem from this.
- **Reverse applications**:
  - Blowing up warning/NAG windows: set message breakpoints on `WM_CLOSE`/button `WM_COMMAND` to locate the handling logic;
  - Spy++ / message hooks (SetWindowsHookEx WH_CALLWNDPROC) to capture communications;
  - Network-validation clients often put logic in WM_TIMER; breaking on WndProc beats breaking on APIs.
- The message loop is the theoretical basis of "adding buttons/menus" in secondary development (§9.5, the Reconstruction chapter).

## 6. File System and Registry API Chains (Commonly Used Breakpoint Layers in Reverse Engineering)

### 6.1 Files

```
CreateFileW → ntdll!NtCreateFile → the I/O manager builds an IRP (MJ_CREATE) → the FSD (ntfs.sys)
            → cache manager/volume manager → disk
```
- CD-check/keyfile protections all land on this chain: the `CreateFile`+`SetFilePointer`+`ReadFile` sequence; break on NtReadFile and grab the buffer.
- File-system filter drivers (minifilters) hook the IRP path — the principle of file-monitoring tools and host protection (details belong to driver development in the Programming chapter).

### 6.2 Registry

- The configuration manager parses the HIVE into a memory tree; `NtQueryValueKey` returns structures like KEY_VALUE_BASIC_INFORMATION.
- The serial-protection "registry comparison method" (Unpacking node 1000201): diff snapshots before/after a run to locate persistence keys.

### 6.3 DLL Basics and the Loader (Node 1000916)

- Load order (static imports): see §1.4; dynamic: `LoadLibrary`→`LdrLoadDll`; unloading and reference counting.
- DLL_THREAD_ATTACH/DETACH: multi-threaded packers use thread attach for anti-debugging (checks inside thread callbacks).
- **DLL search order** (the basis of hijacking, expanded in Reconstruction §4): application directory → system directory → Windows directory → current directory → PATH; KnownDLLs are mapped directly without searching.

## 7. Structured Exception Handling SEH (Nodes 1000163/1000915)

### 7.1 The x86 SEH Chain

```
An exception occurs (e.g., #UD/#PF)
  → kernel KiUserExceptionDispatcher (back to user mode)
  → RtlDispatchException:
      ① VEH first (AddVectoredExceptionHandler, XP+)
      ② Walk every EXCEPTION_REGISTRATION_RECORD on the fs:[0] chain
         (node->handler(ExceptionRecord, EstablisherFrame, ContextRecord))
      ③ Nobody handles it → default handler (UEF / UnhandledExceptionFilter)
```

- Each on-stack node is 8 bytes: `[next][handler]`; the compiler places `__except_handler4` (with a scope table, cookie-validated).
- **Reverse touchpoints**: ① exception-based anti-debugging (deliberately trigger an exception; if the debugger seizes it, it exposes itself, Protection §1.4); ② OEP capture (shells jump via SEH); ③ malicious code hides its real flow in the SEH chain.

### 7.2 x64 Table-Driven Unwinding

x64 SEH is decoupled from the stack: `.pdata` (RUNTIME_FUNCTION: function extent) + `.xdata` (UNWIND_INFO), `RtlAddFunctionTable`; on exception, unwinding restores per the tables. Reverse-engineering impact: you can no longer stuff nodes onto the fs:[0] chain to forge handlers like on x86, and anti-debugging techniques morph accordingly (switching to VEH).

## 8. Interrupts and System Calls (Node 1000161)

- The interrupt vector table IDT: 0x2E was the XP-era system-call gate (int 2Eh), later replaced by sysenter/syscall; the debugger's single step uses 0x1, breakpoints 0x3.
- IDT/GDT/debug registers are all ring0 resources — the "Ring0 privilege" node (1000180) covers how to get from ring3 to ring0 (driver loading, physical-memory exploits); privilege-escalation exploitation itself belongs to the binary-vulnerability area and is not expanded here.
- WoW64 (1001482): 32-bit processes are forwarded via wow64cpu to the 64-bit ntdll, with two sets of syscall-number mappings — one source of behavioral differences when unpacking old programs on new systems.

## 9. The Windows System Programming Series (Node 1000908, Nine Chapters Merged)

### 9.1 Process Management (1000909)
The CreateProcess family/CreateToolhelp32Snapshot enumeration/ExitProcess termination; job objects controlling child processes. Reverse counterparts: process monitoring, anti-multi-instance, parent-child mutual guarding.

### 9.2 Inter-Process Communication (1000910)
The full spectrum: anonymous pipes (parent-child), named pipes (cross-machine), mailslots (one-way broadcast), shared memory (§3.4 + semaphore synchronization), the clipboard, `WM_COPYDATA` (SendMessage carrying data, cross-process read-only), RPC/COM. Reverse counterparts: client-validator (local validation service) — capture WM_COPYDATA/named-pipe traffic and you capture the registration traffic.

### 9.3 System Services (1000913)
SCM: OpenSCManager/CreateService/StartService; the service entry ServiceMain + the control dispatcher. Reverse counterparts: protection drivers/anti-piracy services autostart as SERVICEs; removal means stopping the service and changing the startup entry.

### 9.4 Asynchronous I/O and Completion Ports (1000914)
OVERLAPPED overlapped IO → IOCP (GetQueuedCompletionStatus); the skeleton of high-performance network-validation servers and game servers; a reference thread model when doing packet analysis.

### 9.5 DLL Injection and API Hooking (1000917)
- The three injection forms: remote thread CreateRemoteThread+LoadLibrary, Windows hooks (WH_CBT/WH_GETMESSAGE cross-process), APC injection.
- API hooking: IAT hooks (patching import-table entries) and inline hooks (patching the 5-byte function head) — the system-mechanism layer ends here; engineering details belong to the Programming chapter's Hook nodes (1000837).

## 10. Representative Posts and Search Index

- A First Look at the Windows Debugging Infrastructure (including process/debug-object mechanisms)
- Learning Windows-Platform Anti-Debugging Techniques (crossing with PEB/system mechanisms)
- Knowledge Base · Patch Technology Directory (system mechanisms such as memory access)
- Principles and Use of Debug Registers DR0-DR7

On-site search expressions:
- `process creation NtCreateUserProcess` / `CreateProcess source analysis` → see §1 (the five R3-chain posts)
- `PEB Ldr module chains` / `SSDT parsing` (SSDT posts see Programming §4) / `VAD memory management`
- the `Windows System Programming` series (nine chapters, reachable directly via knowledge-base nodes 1000908-1000917)
- `SEH exception handling analysis` / `x64 SEH unwinding`
- `NTFS MFT parsing` / `HIVE registry file format`

Related chapters: Protection (this directory), Reconstruction (this directory); Hook/injection/driver details see the Programming chapter (by another author).
