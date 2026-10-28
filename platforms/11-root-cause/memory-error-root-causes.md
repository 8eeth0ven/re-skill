# Memory Error Root Causes (11 — Vulnerability Root-Cause Studies)

> **Division of labor**: exploitation techniques (tcache poisoning/unlink/House of/ROP) → `../06-binary-vuln/heap-exploitation.md`; exploitation patterns for kernel/V8/document-format CVEs → `../06-binary-vuln/vuln-types-exploitation.md`. This document covers only **root causes**: why the buggy code gets written in the first place, why compilers and runtimes fail to stop it, what actually happens at the memory level, and how it escalates into a security incident.
> Uniform template, one per class: **typical code pattern (line by line) → what happens at the memory level (ASCII) → why it isn't caught → escalation chain → historical precedents**.

## 0. Master Overview: Six Error Classes, One Unified Lens

Any memory-safety vulnerability decomposes into a product of three factors; remove any one and it collapses:

1. **Attacker-influenced data** (network packets/files/environment/shared memory/another thread) enters the program;
2. **A boundary the language or runtime does not check** (array length/lifetime/type tag/integer width — the C abstract machine delegates all of them to the programmer);
3. **Once the error happens, control cannot be reclaimed** (the out-of-bounds bytes have no owner; interpretation rights belong to "whoever reads them next").

| Class | Erroneous action | One-line root cause | Primary primitive |
|------|-----------------|--------------------|-------------------|
| Stack overflow | Out-of-bounds write into a stack frame | Arrays decay into raw pointers; bounds information is discarded at compile time | Overwrite return address / local flags |
| Heap overflow / OOB | Out-of-bounds write into a heap chunk | Allocator metadata and user data are interleaved; free trusts an already-poisoned "map" | Corrupt size/fd/bk/next |
| UAF | Dereference after free | free cannot enumerate aliases; lifetimes are a manual convention | Reuse of the object slot → fake object |
| Double free | Freeing the same pointer twice | Detection is designed to be O(1) and only catches the most trivial shapes | Same address, two owners → overlap |
| TOCTOU / race | The object gets swapped between check and use | The two steps are not atomic; the trust boundary is drawn in the wrong place | Swap data / swap privileges |
| Type confusion / integer | A bit pattern gets reinterpreted under the wrong type | Casts are zero-cost and unchecked; integer conversions are silent | Negative offsets / small allocations / fake objects |

Take any memory CVE: first classify it into one of these six rows, then ask where factor 1 enters, which boundary in factor 2 is unchecked, and in factor 3 who reads the poisoned bytes first — the root-cause report writes itself.

---

## 1. Stack Overflow / Buffer Overflow

### 1.1 Typical Code Pattern

```c
void handle_packet(char *in, size_t len) {   // [A] len comes from a network packet header and is attacker-controlled
    char name[64];                           // [A] Fixed-size stack buffer; the boundary exists only in source code
    unsigned long auth = 0;                  // [B] Authorization flag located immediately above the buffer
    memcpy(name, in, len);                   // [C] Copies len bytes; machine code does not associate len with 64
    if (check_token(name)) auth = 1;         // [D] A common layout allows the out-of-bounds write to change auth first
    if (auth) grant_admin();                 // [E] An overflow with 64<len<=72 can grant administrator access
}
```

Line-by-line breakdown:
- **[A]** In C, `name` in an expression decays to `&name[0]` (a raw pointer). `sizeof(name)==64` holds only while compiling this one line; once it is passed to another function, that information evaporates completely.
- **[C]** The semantics of `memcpy` are "move n bytes one at a time"; it neither knows nor asks how large the destination is. `len` is a runtime value — there is no runtime comparison against `64` unless the programmer writes `if (len > sizeof(name)) return;` by hand.
- **[B][E]** Even if the attacker cannot reach the return address, the flags, pointers, and handles sitting in the same stack frame next to the buffer get smashed first — **the first victim of an overflow is usually not ret, but "the control datum closest to the buffer"**.

### 1.2 What Happens at the Memory Level

x86-64 stack frame (grows toward lower addresses; an overflowing write climbs toward higher addresses):

```
High addresses
+---------------------------+
| Caller stack frame          |
+---------------------------+
| Return address (ret addr)   | ← Final target: ret pops it into RIP
+---------------------------+
| saved rbp                  | ← leave restores the caller frame from it
+---------------------------+
| auth (8B)                  | ← Reached by a 64–72 byte overflow: the write changes authorization
+---------------------------+
| (possible alignment padding)|
+---------------------------+
|  name[56..63]              |
|  name[0..55]     |        |
+---------------------------+ ← rsp points here
Low addresses: memcpy writes upward from name[0]; len>64 overwrites auth→saved rbp→ret byte by byte
```

The sole action of the `ret` instruction: pop the top 8 bytes of the stack into RIP. **A stack overflow = placing your own bytes at that position = directly choosing the address of the next instruction executed.**

### 1.3 Why It Isn't Caught

- **At the C standard level**: out-of-bounds access is undefined behavior (UB). The compiler not only fails to stop it — it is entitled to **assume it never happens** (e.g., optimizing on "auth is definitely 0/1" and deleting dead branches you believed were protective). UB means "the compiler owes you nothing from here on".
- **The compiler trade-off**: runtime bounds checking means one extra compare + branch per array access (double-digit percentage losses for array-dense code); 1970s–80s hardware could not afford it, and it later calcified into ABI and ecosystem path dependency. `_FORTIFY_SOURCE`'s `__memcpy_chk` only catches cases where **the destination size is derivable at compile time and the overflowing value is a constant** — it is blind to any network-supplied `len`.
- **The canary is only partially effective**:
  - It protects only the return path, not `auth`/function pointers/handles in the same frame — [E] in 1.1 passes with 72 bytes while the canary stays untouched;
  - The canary value lives in TLS (`fs:0x28`); **information-leak-class bugs (format strings, out-of-bounds reads) can read it out and write it back**, so the canary is transparent to an attacker who reads first and writes later;
  - Byte-by-byte brute force: in fork-style servers (nginx/apache prefork), a crashed child is re-forked by the parent with the canary unchanged; on Linux the canary's first byte is always `\x00` (to prevent leaks via string-function truncation), so only 7 bytes need brute-forcing, each guess costing one connection. A subthread's stack overflow can in turn overwrite that thread's own `stack_guard` (covered in 06 §6).

### 1.4 Escalation Chain

```
Out-of-bounds write (length difference not controlled)
 → Overwrite auth/function pointer/handle (data-only impact can require few bytes)
 → Overwrite return address (control flow)
 → With NX: ROP/ret2libc (code reuse, 06 §8)
 → Without output: blind BROP discovery (06 §8.3)
Security impact: remote RCE / local privilege escalation / authentication bypass
```

Note that the first stop of the escalation chain is routinely overlooked: **you do not need to hijack control flow — flipping a 0 to non-0 is already a security incident** (flip is_admin, flip a balance, flip an ACL bit). Data-plane attacks generate no crash logs and are stealthier than control-plane ones.

### 1.5 Precedents

- **CVE-2015-0235 (GHOST)**: glibc's `__nss_hostname_digits_dots` overflows a stack buffer while processing an overlong hostname; the entire `gethostbyname()` family was affected. Fixed in glibc back in 2013, but **statically linked legacy programs froze the poisoned code inside their binaries** — the canonical case of a root-cause fix failing to propagate.
- **CVE-2017-11882 (Equation Editor)**: EQNEDT32.EXE overflows via `strncpy` while parsing a formula font name; the component had been unmaintained since 2000 and the binary **has no canary and no ASLR** — the full modern mitigation suite absent, letting one CVE live on from the excavation to today. The RCE technique belongs to 06.
- Prehistory: the 1988 Morris worm spread via a stack overflow in `fingerd`'s `gets()` plus the sendmail DEBUG command as a second entrance — `gets` does not even take a length parameter; it is the living fossil of this entire class.

---

## 2. Heap Overflow and Out-of-Bounds Access

### 2.1 Typical Code Patterns

Pattern one: an off-by-one boundary slip (off-by-one / off-by-null):

```c
char buf[256];
ssize_t n = read(fd, buf, sizeof(buf));  // [A] Reads at most 256 bytes, n∈[0,256]
buf[n] = '\0';                           // [B] n==256 writes buf[256]: exactly one extra null byte
```

Pattern two: a length field decoupled from the application buffer:

```c
struct msg {
    uint16_t declared;         // [C] Body length declared by the packet
    char body[512];
};
memcpy(m->body, pkt + 2, m->declared);   // [D] Copies the declared length, which may exceed 512
```

- **[B]** The single null byte lands on **the lowest byte of the next chunk's size field**, exactly clearing the `PREV_INUSE` bit — see 2.2.
- **[D]** The parser plague: the length is what the attacker claims, the capacity is a fact about the program, and the two share no runtime binding point. Declaring `declared` as 0xFFFF punches straight through.
- Common to both patterns: **the overflow distance can be as small as 1 byte — even just one null byte flipping bits to zero**.

### 2.2 What Happens at the Memory Level

ptmalloc chunks sit adjacent (structural detail belongs to `../06-binary-vuln/heap-exploitation.md` §1.2; here we only look at "where the overflow lands"):

```
       chunk A (overflow source)         chunk B (victim)
      +--------------------+        +--------------------+
      | prev_size          |        | prev_size          | ← The overflow from the end of A user data first reaches here
      +--------------------+        +--------------------+
      | size = 0x91 (P=1)  |        | size = 0x91 (P=1)  | ← Additional bytes change the low byte of B size
      +--------------------+        +--------------------+
  A ->| 0x88 bytes user data|--overflow-->| B user data (fd/bk/ |
      |                    |            | next/key reuse)    |
      +--------------------+        +--------------------+
```

- **One extra null byte written** (off-by-null): clears B's `PREV_INUSE`; on the next `free(B)` the allocator reads back `prev_size` to find "the previous free chunk" and merge — `prev_size` is equally within overflow reach, **so the attacker has effectively forged B's memory**. The root of House of Einherjar / poison null byte (technique detail in 06 §4.2).
- **One extra ordinary byte** (off-by-one): rewrites the low byte of B's size (0x91→0xf1 and the like); after B is freed it enters a bin under the tampered size, and **the next allocation swallows the chunk behind B** — two pointers aimed at the same region = the universal intermediate state (06 §5 chunk extend).
- **A full out-of-bounds write** (pattern two): fd/bk/tcache next/key are all in range — direct "pointer surgery" on allocator data structures.

### 2.3 Why It Isn't Caught: The Design Trade-Off of Interleaving Metadata with Data

- **Why the malloc header sits in front of user data**: the 1979 dlmalloc choice — an inline header lets `free(ptr)` locate the chunk and its neighbors in O(1) from `ptr-16`, and boundary tags let adjacent free chunks merge bidirectionally to fight fragmentation. A separated design (metadata in dedicated pages / indirection tables) costs an extra memory indirection, worse locality, plus fragmentation management for the metadata itself. **A correct engineering decision for performance and fragmentation — at the price that any user-area out-of-bounds write necessarily hits metadata first**.
- **The allocator's checking philosophy**: the free/malloc paths perform only "self-consistency" checks (unlink's `FD->bk==P && BK->fd==P`, fastbin's size match) — **what is checked is "this map is internally consistent", not "this map has not been swapped"**. An attacker who forges a logically self-consistent fake map passes every check. 2.29/2.30 gradually added linked-list integrity checks — narrowing the definition of "self-consistent" — but the design is unchanged.
- **Heap allocation bounds and array bounds share the same origin**: malloc only promises "here is your block" and knows nothing about how, or how much, you use inside it — the raw-pointer problem of 1.1 replays verbatim on the heap.

### 2.4 Escalation Chain

```
Out-of-bounds write (as small as 1 byte/1 null byte)
 → Corrupt allocator metadata (size/P bit/fd/bk/next/key)
 → Allocator follows forged metadata: unlink double write / arbitrary tcache allocation / overlapping chunks after consolidation
   (techniques: 06 §2–§4; tcache poisoning → 06 §2.2; unlink → 06 §3.1)
 → Arbitrary write / controlled-address allocation
 → Targets: function pointers/GOT/vtables/kernel objects
Security impact: RCE / kernel privilege escalation / container escape
```

Out-of-bounds **reads** share the same root cause (nobody validates the boundary); only the primitive changes, to information leak: leak the canary/heap addresses/libc base to pave the way for the write direction — a write+read combination is the norm of a complete exploit chain.

### 2.5 Precedents

- **CVE-2021-22555 (Google in-house 0day)**: one spot in the netfilter iptables compatibility layer (a compat-conversion memset zeroing alignment padding) writes **4 out-of-bounds zero bytes** — a seemingly weak primitive, escalated into heap metadata corruption → msg_msg forgery → kernel LPE + container escape (Google's blog was originally titled "Turning \x00\x00 into 10000$") — the textbook proof that "minimal OOB write ≠ minimal impact" (case-by-case detail in [kernel-vuln-root-cause-cases.md](kernel-vuln-root-cause-cases.md) §2).
- **CVE-2021-3156 sudo "Baron Samedit"**: while parsing the `-s` argument, sudo mishandles `\` escaping and copies an unboundedly concatenated string into a fixed-size heap buffer — the mass-produced version of pattern two in 2.1; preinstalled, therefore instant root.
- **CVE-2014-0160 Heartbleed**: the precedent for OOB **reads** — the heartbeat reply length is taken from an attacker-claimed field in the request without being checked against the actual data, so `memcpy` reads process memory out of bounds (private keys/session tickets); no write primitive whatsoever is needed to constitute a top-tier incident.

---

## 3. UAF (Use After Free)

### 3.1 Typical Code Patterns

Userspace service (alias not cleared):

```c
struct conn *c = table_lookup(id);     // [A] The global table holds a reference to c
pthread_mutex_lock(&c->lock);          // [B] Lock through c
...
conn_destroy(c);                       // [C] Frees c but forgets to remove it from the table
...
struct conn *c2 = table_lookup(id);    // [D] Lookup still returns the dangling pointer
c2->handle(pkt);                       // [E] The new occupant of that memory handles the call
```

Kernel refcount style:

```c
obj = obj_get(id);     // [F] refcnt++
...
obj_put(obj);          // [G] if (--refcnt == 0) kfree(obj)
// Failure F': a raw pointer is used without get; another CPU drops the final put and frees it while it remains in use
// Failure G': an error path performs an extra put, or exit omits a put (the corresponding leak case)
```

- The essence of **[C][D]**: the free operation only returns memory, **it does not hunt down references**. `c` sits in a table, on a list, in a thread-local cache, in a closure — free knows about none of them.
- **[E]** is the moment of incident: the function pointer/vtable pointer is read out of **already-reused memory**; interpretation rights belong to the new contents.

### 3.2 What Happens at the Memory Level

```
After free(c), before reuse:
      Object memory
      +---------------------+
      | fd / next (allocator)| ← Free state: tcache/fastbin list pointers occupy the first 16 bytes
      | key                 |
      +---------------------+
      | old fields and vptr  | ← Beyond allocator metadata, stale object contents remain

After a spray reclaims the region (attacker mallocs the same size):
      +---------------------+
      | attacker data       | ← Payload/forged object aligned with the former type layout
      +---------------------+
The vptr read by c2->handle(pkt) points to the attacker-controlled forged vtable
```

Kernel-side primitives: the freed object slot gets occupied by sprayable objects such as `msg_msg`/`pipe_buffer`/`sk_buff`/`tty_struct` (the object→primitive table in 06 `../06-binary-vuln/vuln-types-exploitation.md` §3.1). Browser/Office side: HTML+JS heap spraying fills predictable addresses (the origin of the IE-era 0x0c0c0c0c).

### 3.3 Why It Isn't Caught

- **Why free doesn't clear pointers (C's philosophy)**: free receives **a copy of the pointer's value**; at the language level it cannot enumerate "every variable pointing at this memory" — alias analysis is undecidable in general, let alone at runtime. Clearing the one that was passed in leaves every other dangling pointer intact, and even manufactures the illusion of "already cleaned up". Zeroing would also cost cache-line pollution and extra instructions, while C's founding principle is "no abstraction you don't pay for".
- **Lifetime is a convention, not a type**: which code holds which reference for how long is scattered across thousands of get/put pairs, lock-hold intervals, and callback register/unregister sites. The language has no way to express "this pointer lives until line N", so the compiler has nothing to check against.
- **The production cost of detection tooling**: ASan quarantines freed memory and poisons it, reliably catching UAF — at several times the memory and roughly 2x slowdown, so it can only live during the test phase; paths the CI never fed still ship to production.

### 3.4 The Kernel's Three Lifetime-Management Mechanisms and Their Failure Modes

| Mechanism | Contract | Typical failure |
|-----------|----------|-----------------|
| Refcounting | get before use, put when done, free at zero | missing get (raw pointer across kfree), extra put (double free on error paths), counter overflow wraparound, **put ordered wrongly against the last dereference** |
| Locks | the object cannot disappear while the lock is held | the freeing path drops the lock before free while another CPU has just grabbed the old pointer inside the lock; **calling callbacks / copy_from_user while holding the lock**, with object state mutated inside the callback or a page fault |
| RCU | lock-free traversal on the read side; the write side reclaims only after a grace period | missing synchronize_rcu or wrong call_rcu ordering; the read side carrying the pointer **out of the RCU critical section and continuing to use it**; combined with premature frees on other paths |

When all three mechanisms govern the same object (common: refcount + spinlock + RCU traversal), the combinatorial complexity of the contracts exceeds the programmer's mental model — CVE-2019-2215 (Binder) is epoll's wait_queue falling out of sync with the binder_thread's lifetime.

### 3.5 The Three Fates of a Dangling Pointer: Why the "Non-Crashing UAF" Is the Most Dangerous

1. **Crash**: after the free, the memory is overwritten by allocator list pointers; the dereference lands on an invalid address → SIGSEGV. Looks like an incident but is really **free fuzzing** — QA and crash-reporting systems fish it out; most such UAFs don't survive the test phase.
2. **Silent corruption**: the memory is reused by a same-size, different-type object whose fields "happen to" fit; reads and writes stay in bounds — the data is quietly wrong, the symptom is an occasional logic glitch routed to the ticket queue rather than the security channel. **In forensics it reads as a "mystical bug"; nobody suspects a vulnerability.**
3. **Exploited**: the attacker sprays with precise size/content to seize the slot; the new object's contents are fully controlled — the UAF upgrades into type confusion or an arbitrary function-pointer call.

Category 3 is constructed deliberately by the attacker; category 1 is intercepted for free; **category 2 neither crashes nor reports, lurks in production indefinitely, and can be upgraded into category 3 at any moment** — it is the hardest UAF risk to price. To triage a UAF's severity, first ask "does it crash": the non-crashing ones are the deadly ones.

### 3.6 Escalation Chain and Precedents

```
A reachable reference remains after free → that reference is dereferenced again
 → Crash caught by QA / silent data corruption / type confusion after reclamation
 → Forged object / vptr or function-pointer hijack → RCE or kernel privilege escalation
Techniques: UAF against tcache (06 §2.2), introductory CTF pwnable_hacknote
```

- **CVE-2012-1889 "Baolei" (MSXML UAF)**: one of the most popular web drive-by vulnerabilities of its year; a textbook UAF + heap-spray RCE; the local corpus holds several analyses of the same IE UAF family.
- **CVE-2014-3153**: an ownership-management error for plist nodes on the Linux futex `requeue_pi` path → a controlled kernel write; towelroot's one-click root swept Android that year.
- **CVE-2023-32233**: a UAF in nftables anonymous-set batch deletion, seized with nft objects for production-grade LPE; the same family includes the kernel cases collected in 06 §3.2.

---

## 4. Double Free / Reentrancy

### 4.1 Typical Code Patterns

```c
if (ptr) {           // [A] Rejects NULL only; it does not prevent repeated frees
    free(ptr);       // [B] free does not modify ptr, which remains non-NULL and retains its address
    ...              // [C] Error-handling/early-return/longjmp path
    free(ptr);       // [D] The same pointer value reaches free a second time
}
```

Error-path version (the hardest form to audit):

```c
int load(void) {
    p = malloc(n);
    if (parse_hdr() < 0) return cleanup();   // cleanup: free(p) ...
    ...
}
// Caller: if (load() < 0) free(p); ← two release sites each assume the other has not released it
```

- **[A]** `if (ptr)` as double-free protection is a negative optimization: it implies the author believed free nulls the pointer. C's free does not (same reasoning as 3.3).
- **[C]** longjmp/exceptions/C++ destruction order can all route control flow around the mental "already freed" marker — a double free is essentially **two owners claiming the right to free**.
- **Reentrancy (broad sense)**: a signal handler/callback invoked mid-destruction re-enters a half-dead object — the same memory simultaneously used by two flows of control under different lifetime assumptions.

### 4.2 What Happens at the Memory Level

```
First free: p enters tcache[idx]
      tcache[idx]: p → x → y
                       p.next = x

Second free (not detected):
      tcache[idx]: p → p → x → y     ← Cycle: p.next points to itself
      malloc #1 removes p (the new head is again p)
      malloc #2 removes p again     ← Two owners receive the same address: overlap
```

The fastbin era is isomorphic: the `A→B→A` sandwich (06 §3.2). `_int_free`'s check for fastbins is a single `old == p` (a double free is reported only when the list head equals this very chunk) — **it checks only for an immediate repeat, not the whole chain**; A→B→A with one chunk in between passes. Why so lax: **checking the full chain turns free from O(1) into O(n)**, a price the allocator refuses to pay on the hot path.

### 4.3 Why the tcache Key Can Be Bypassed

Since glibc 2.29, `tcache_entry` carries a `key` field: on free it stores `e->key = tcache` (pointing at this thread's per-thread structure); on freeing the same chunk again, if `e->key == tcache`, the chain is walked to confirm it is really in it → abort("double free detected in tcache 2").

Bypasses (root-cause view):

1. **The key lives on the heap, in the same domain as user data** — any UAF write / heap overflow can zero `e->key` (or write any value ≠ tcache), short-circuiting the first step of the detection condition. **Using one heap-write bug to disarm another heap bug's detection is the basic rhythm of this cat-and-mouse game**: the detection itself has no independent trust base.
2. Two different threads have different tcache pointers, so cross-thread frees don't trigger the same-key comparison (conditions apply, but it happens in reality).
3. Once the tcache holds 7 entries, the second copy of a double free goes straight down the fastbin/unsorted path, bypassing the tcache detection logic (the root of House of Botcake, 06 §4.5).

2.32's Safe-Linking encrypts only the `next` pointer and does not change the key's writability (see §7).

### 4.4 Escalation Chain and Precedents

```
Double free → duplicate ownership/self-looping list
 → Two malloc calls return the same memory (chunk overlap)
 → Use owner A to modify owner B pointer fields → arbitrary write/controlled allocation (06 §2.2/§3.2)
 → Targets: hooks/vtables/function pointers
```

- **CVE-2019-11932**: a double free in WhatsApp's DDGifSlurp while parsing GIFs; receiving a malicious GIF triggers a media-library RCE — the benchmark for "interactionless double free" on mobile.
- **CVE-2014-1767**: a double-free/UAF in Windows afd.sys; the local corpus has a full analysis and exploitation write-up; classic in-the-wild exploitation on the eve of XP's end-of-support.
- **CVE-2022-2588**: a double free on the kernel cls_route deletion path, combined with an nft chain into a stable LPE — a familiar pattern in recent kernel CTF and real-world work.
- The local corpus also holds a dedicated post on the application-level analysis of the SPL double-list double free.

---

## 5. Race Conditions (TOCTOU)

### 5.1 Typical Code Patterns

Userspace file version (TOCTOU in its literal form):

```c
if (access("/etc/target", W_OK) == 0) {   // [A] Check: is access allowed now?
    fd = open("/etc/target", O_WRONLY);   // [B] Use: a separate syscall leaves a race window
    write(fd, buf, n);                     // /etc/target may already have been replaced with a symbolic link
}
```

Kernel double-fetch (reading the same user memory twice):

```c
copy_from_user(&len, uarg, sizeof(len));     // [C] First fetch: validation
if (len > MAX_LEN) return -EINVAL;
...                                          // [D] Window: a user thread modifies the page referenced by uarg
copy_from_user(&len2, uarg, sizeof(len2));   // [E] Second fetch: execution uses changed content
process(data, len2);                         // [F] Uses unvalidated len2
```

CPU reordering version (publication without barriers):

```c
data = 42;                // [G] Ordinary write
ready = 1;                // [H] Compiler/CPU can reorder before [G]; the peer sees ready before initialized data
// Correct: smp_store_release(&ready, 1) paired with smp_load_acquire on the peer
```

Kernel callback-under-lock version:

```c
mutex_lock(&dev->lock);
dev->ops->callback(dev);   // [I] Callback may acquire the same lock (deadlock, the less exploitable case)
mutex_unlock(&dev->lock);  // It may retain a raw dev reference after dropping the lock (the more dangerous case)
```

### 5.2 What Happens at the Timeline Level

```
Thread A (checker)                  Thread B (attacker)
─────────────────────────────      ─────────────────────────────
check(object O): read-only permission ✓
                                    swap(object O, malicious object O')
use(object O): write under the read-only assumption
  → The write reaches O': the authorization model was replaced
```

Double-fetch is the same picture, except that "thread B's write" lands between the kernel's two `copy_from_user` calls, **and the page being written lives in user address space — the kernel has no control over it whatsoever**.

### 5.3 Why It Isn't Caught

- **Check and use are inherently two instructions/two calls**; the language offers no "the world stands still between these two steps" primitive unless the programmer explicitly locks or snapshots. **Single-threaded thinking writing multi-threaded code**: the author's mental "program state diagram" has no second timeline.
- **The double-fetch trust boundary is drawn wrong**: the kernel cannot lock user memory (user pages may fault, may be swapped out; waiting under a lock would deadlock the system), so it can only "copy — validate — copy again". But the second copy still fetches **data inside the attacker's domain** — swapping "the validated copy" for "a fresh read of the original" opens the window. The correct pattern: copy once, then validate and use **the same copy** (snapshot semantics).
- **CPU reordering is physical reality**: compiler visibility optimizations plus ARM/POWER weak memory models mean store order is not guaranteed to propagate in order. Code perfectly correct under single-thread semantics is observed in a different order by other threads. Memory barriers are a performance compromise — **one missing barrier is one data-race window**, and "where barriers are needed" depends on the programmer's grasp of the entire concurrency protocol.
- **Static analysis can't catch it**: it would need to enumerate all thread interleavings, and the state space explodes combinatorially with synchronization points; dynamic detection (TSan) costs 5–15x, is only usable during testing, and race triggering is itself probabilistic — **not hitting it in tests ≠ it doesn't exist**.

### 5.4 Escalation Chain and Precedents

```
A race window exists → attacker changes data/object/permissions inside it
 → Invalidated checks (unvalidated input is used) or object substitution (often triggers UAF)
 → Broken authorization model/kernel-write primitive → privilege escalation/sandbox escape
```

- **CVE-2016-5195 Dirty COW**: a race between copy-on-write and the write-permission check yields a "write into a read-only mapping" primitive, usable against suid binaries/`/etc/passwd`; introduced in 2007, fixed only in 2016 — **a nine-year window**.
- **CVE-2019-2215**: a lifetime race between Binder's and epoll's wait_queues → kernel UAF; exploited in the wild by NSO in real attacks; Project Zero did the retrospective.
- **Double-fetch precedents**: the local corpus has dedicated posts and CTF problems (a recurring kernel-pwn problem type; grep `../../data/精华全量索引.md` for Double Fetch).

---

## 6. Type Confusion and Integer Problems

### 6.1 Typical Code Patterns

**Pattern one: the silent C cast (bit-pattern reinterpretation)**

```c
struct base    { int kind; };
struct derived { int kind; void (*fn)(void); long secret; };

struct base *b = get_from_table(id);     // [A] The table stores base*
((struct derived *)b)->fn();             // [B] Compiler reads b+8 as a function pointer based on the cast
                                          // Neither kind nor actual layout is checked: one cast, zero checks
```

**Pattern two: types self-certified by magic numbers/offsets (the chronic disease of homegrown OOP)**

```c
if (hdr->tag == 0xCAFEBABE) {            // [C] The tag is in attacker-writable memory
    obj = (java_obj *)hdr;
    obj->vtable->invoke(obj);            // [D] A forgeable tag makes the type discriminator forgeable
}
```

The object systems of kernels/browsers/COM/packers are all hand-rolled "pseudo type systems" built on top of C: **the type tag sits in the same row as the object, and the tag itself is data**. A parser taking one wrong state-machine branch interprets object A's bytes as type B — V8/IE/kernel type confusions are all this family (local precedents: CVE-2017-11893 execution-flow-induced type confusion, Edge Chakra JIT type confusion).

**Pattern three: sign extension (0xffffffff → -1 → 0xffffffffffffffff)**

```c
int len = get_len();                    // [E] Signed 32-bit value; attacker supplies 0xFFFFFFFF
if (len > 1024) return -1;              // [F] Signed comparison: -1 < 1024, so it passes
memcpy(dst, src, len);                  // [G] memcpy third argument is size_t (unsigned 64-bit)
                                          // (size_t)(int)-1 sign-extends to 2^64-1
                                          // The length check and copy use different numeric semantics
```

**Pattern four: truncation (int → uint16_t size field)**

```c
int total = width * height * 4;          // [H] Compute the total size using int
uint16_t alloc_size = total;             // [I] Truncation: 65536+8 → 8
char *buf = malloc(alloc_size);          // [J] Allocate 8 bytes
memcpy(buf, src, total);                 // [K] Copy 65544 bytes → heap overflow
```

**Pattern five: multiplication wraparound bypassing length checks (small alloc, big write)**

```c
size_t n = count * sizeof(struct item);  // [L] With count=2^61 on 64-bit, multiplication wraps to 0
buf = malloc(n);                          // [M] malloc(0) can return a small allocation
memcpy(buf, src, count * sizeof(struct item));  // [N] Intended large copy based on the pre-wrap amount; check the actual expression semantics
// Correct: if (count > SIZE_MAX / sizeof(struct item)) return; — omitting this check permits overflow
```

### 6.2 What Happens at the Bit/Memory Level

```
Sign extension (pattern three):
  int      0xFFFFFFFF        =  -1
    ↓ (size_t) sign extension
  size_t   0xFFFFFFFFFFFFFFFF =  18446744073709551615
  [F] Semantics during the check      [G] Semantics during use
  ────────────────              ────────────────────────
  -1 ── small, accepted                2^64-1 ── huge, unbounded copy

Truncation (pattern four):
  0x00010008 (65544) --low 16 bits--> 0x0008 (8)
  Allocate with truncated bits, write with the full value → the difference is out of bounds
```

### 6.3 Why It Isn't Caught

- **The cast is the very definition of the C abstract machine**: a type conversion = reinterpreting the bit pattern as the target type, at zero runtime cost with zero runtime checks. Checked conversions like `dynamic_cast` are a C++ runtime facility restricted to polymorphic classes — kernels, protocol parsers, and object systems are precisely all non-polymorphic C structs.
- **Integer rules are silent**: signed↔unsigned conversions, integer promotion (types narrower than int are promoted to int before arithmetic), width truncation — none of them warn. `-Wsign-conversion`/`-Wconversion` are not in `-Wall`, and once enabled they drown in false positives — **a historical decision that traded "safe" for "quiet"**.
- **Checks and uses live in two different type worldviews** (pattern three is the exemplar): `len` is an int during the comparison and becomes size_t entering memcpy — **one variable, two semantics**. Unless every implicit conversion is annotated during review, these bugs are extremely hard to spot by eye. The local corpus has several dedicated posts (integer overflow study notes / integer overflow and array OOB / integer overflow).
- **Homegrown type-system tags have no trust base**: if the tag lives in attacker-writable memory (user pages, heap chunks, network packets), the type verdict is self-certification — pattern two is essentially "handing the ID badge to the attacker".

### 6.4 Escalation Chain and Precedents

```
Sign extension → huge/negative lengths → unbounded copy (returns to §1/§2 overflow cases)
Truncation/multiplication wrap → small allocation with a large write → heap overflow (§2)
Negative offset (int in 64-bit base arithmetic) → OOB read/write before the base
Type confusion (forgeable type system) → forged object → arbitrary function-pointer call/misinterpreted fields
```

- **CVE-2002-0392 (historical landmark)**: an integer overflow in Apache's chunked-encoding chunk-size computation → heap overflow → remote code execution, at its peak affecting one third of the world's web servers — a landmark that established integer overflow as a standalone root-cause category.
- **CVE-2021-21224 (V8 TurboFan, collected in 06 §2.4)**: a faulty type inference let the code after the `Object.is` branch keep operating on the narrow type; truncation to int32 → out-of-bounds indexing → fake objects. Same family: CVE-2021-38001 (06 §2.5).
- **CVE-2017-11893**: the scripting engine's execution flow taking a wrong branch invalidated the object-type assumptions → type-confusion RCE.

---

## 7. The Nature of Mitigations: Why Each Layer Blocks Only One Class

All mitigations answer the same question: **the bug has already been written — can we break the chain before it turns into an incident?** The answer is always "break one link, ignore the others":

| Mitigation | What it blocks | What it cannot block (root cause) |
|-----------|----------------|-----------------------------------|
| NX/DEP | Data pages non-executable; injected shellcode dies instantly | The code was already executable — ROP/JOP treat "rearranged legitimate instructions" as the payload; **it governs "data becoming instructions", not "instructions being rearranged"** |
| ASLR/PIE | Fixed-address payloads stop working | **A single information leak zeroes it out** (any leaked pointer computes the base); partial overwrites still hit the low bits on the same page; non-PIE legacy modules serve as trampolines |
| Stack Canary | Any linear stack overflow must touch the canary before reaching ret | Information leaks read the canary directly; fork-style deployments allow byte-wise brute force (§1.3); **the heap, non-protected data in the same frame, and non-overflow bug classes (format strings/UAF) are entirely out of scope** |
| RELRO | Full RELRO turns the GOT read-only | Under Partial RELRO the GOT stays writable; attack surfaces such as function pointers/vtables/IO structures remain (newer versions pivot to FSOP, 06 §7) |
| CFI (incl. kCFI/CET-IBT) | Indirect call/jump targets must be inside a precomputed set | **It governs forward control flow only, not data flow**: data-only attacks alter lengths/permissions/list pointers and gain privileges without hijacking a single branch; granularity is proportional to overhead, and industrial deployments are mostly coarse-grained |
| MTE (ARMv8.5) | A 4-bit tag per 16-byte granule, tagged pointers, mismatched access faults — **runtime bounds checking, in hardware** | 16-byte granularity (intra-granule overflows unreported); uninstrumented libraries unchecked; async mode only counts, doesn't intercept; ~5% overhead keeps servers in wait-and-see — **a compromise of coverage vs. cost** |
| PAC (ARMv8.3) | Return addresses/function pointers signed; ROP chains fail to link | A leaked key defeats it (PACMAN-style speculative side channels); reuse of "already-signed gadgets"; unprotected pointers remain bare |
| Safe-Linking (glibc 2.32) | The tcache next is stored XORed with `storage address>>12`; blindly writing next is no longer directly usable | The key is just the heap address's high bits — **once a heap info leak happens (already common), it decrypts**; 2.32's alignment check only demands 16-byte alignment; **the landing spots for poisoned allocations in the part-RELRO era (GOT and other writable targets) are all still there**; the tcache key remains plaintext and clearable (§4.3) |

### 7.1 Summary: Mitigation Raises Cost; It Does Not Eliminate Root Causes

- Each mitigation layer raises the cost of one exploitation path by an order of magnitude, and the attacker switches to a path **that layer doesn't cover**: NX→ROP, canary→leak, read-only GOT→FSOP, encrypted tcache→leak the heap first. **The history of offense and defense is the alternating growth of the mitigation matrix and the bypass matrix** (06 §6's checksec table is the exploitation-side view of it).
- All mitigations share one blind spot: **data-plane attacks**. Without hijacking any control flow — just set `auth=1`, tweak a length field, flip a permission bit — every mitigation except MTE (partially) stays silent.
- **The root cause is never touched**: ① the absence of memory-safe languages — arrays/pointers carry no bounds or lifetime, casts and integer conversions have no runtime semantics; ② wrong trust-boundary assumptions — the validated data and the executed data are not the same copy (double-fetch), type tags sit in attacker-writable domains, user-supplied length fields are used directly as capacities. Language-level elimination (e.g., Rust's borrow checker turning the root causes of §1/§2/§3/§4 into compile errors) proves this is not a law of physics but an engineering choice; yet legacy code, FFI boundaries, and performance-sensitive paths (kernel/allocator/JIT) make "rewrite it all" infeasible for the foreseeable future — **which is why root-cause research will long remain security's foundational homework**.

---

## 8. Precedent Index Table (20 Landmark CVEs)

| # | CVE | Root-cause class | One-line root cause | Exploitation primitive | Notes |
|---|-----|------------------|---------------------|------------------------|-------|
| 1 | CVE-2015-0235 | Stack overflow | glibc `__nss_hostname_digits_dots` copies an overlong hostname into a fixed stack buffer | Stack write → control flow | Static linking defeated fix propagation |
| 2 | CVE-2017-11882 | Stack overflow | Equation Editor parses a font name with an overflowing `strncpy`; component abandoned for 17 years | Stack write → ROP → document RCE | No canary, no ASLR |
| 3 | CVE-2010-3333 | Stack overflow | MSCOMCTL ActiveX stack overflow | Stack write → Office RCE | APT regular |
| 4 | CVE-2021-22555 | Heap OOB write | netfilter iptables compat layer memsets alignment zeros 4 bytes out of bounds | Minimal write → msg_msg forgery → LPE + container escape | Google 0day |
| 5 | CVE-2021-3156 | Heap overflow | sudo argument-escaping copies unboundedly into a fixed heap buffer (Baron Samedit) | Heap overflow → arbitrary write → root | Enormous preinstalled base |
| 6 | CVE-2019-0708 | Heap overflow | RDP termdd channel pre-auth heap overflow (BlueKeep) | Heap write → pre-auth RCE | Worm-class |
| 7 | CVE-2020-0796 | Heap OOB write | SMBv3 compression/decompression missing a length check (SMBGhost) | Heap write → pre-auth RCE/LPE | — |
| 8 | CVE-2014-0160 | Heap OOB read | OpenSSL heartbeat length taken from an attacker-claimed field (Heartbleed) | OOB read → private key leak | — |
| 9 | CVE-2012-1889 | UAF | MSXML object freed then reused by an event (Baolei) | UAF + heap spray → drive-by RCE | Original write-up in local corpus |
| 10 | CVE-2014-3153 | UAF (kernel) | futex requeue_pi plist node ownership error (towelroot) | Controlled kernel write → root | — |
| 11 | CVE-2023-32233 | UAF (kernel) | nftables anonymous set batch-delete use | nft object reclaim → LPE | — |
| 12 | CVE-2021-1732 | UAF (kernel) | win32kfull window-object lifetime error | UAF → LPE, exploited in the wild | — |
| 13 | CVE-2019-11932 | Double free | WhatsApp GIF decoder double free | Double free → interactionless RCE | — |
| 14 | CVE-2014-1767 | Double free/UAF (kernel) | afd.sys DIO context freed twice | UAF write → LPE | Original write-up in local corpus |
| 15 | CVE-2022-2588 | Double free (kernel) | cls_route deletion path double free | Double free + nft chain → LPE | — |
| 16 | CVE-2016-5195 | Race | Race between COW teardown and the write-permission check (Dirty COW) | Read-only page write primitive → patch suid | Original write-up in local corpus |
| 17 | CVE-2019-2215 | Race → UAF | Binder thread cleanup out of sync with the epoll wait_queue | Kernel UAF → LPE, NSO in-the-wild | — |
| 18 | CVE-2002-0392 | Integer overflow | Apache chunked size computation wraps | Heap overflow → remote RCE | Historical landmark |
| 19 | CVE-2021-21224 | Type confusion (integer) | V8 TurboFan type-inference error → truncation | Fake objects → in-sandbox RCE | Cross-linked 06 §2.4 |
| 20 | CVE-2021-4034 | Boundary/trust assumption | pkexec mishandles argc==0; argv/env reads/writes go OOB (PwnKit) | OOB pointer write → .so injection → root | — |

How to read this table: compare precedents horizontally within a root-cause class — stack overflow cases cluster around "legacy component + static linking + abandonment"; heap OOB around "parsers trusting external lengths"; UAF/double-free around "kernel object lifetimes"; races around "two subsystems sharing an object while managing lifetimes separately"; integer/type around "checks and uses living under two different semantics". **The root-cause class transfers better than the CVE number** — new bugs change costumes, not classes.

## 9. Cross-Links and Gaps

- All exploitation techniques (tcache/unlink/House of/ROP/SROP/FSOP) → `../06-binary-vuln/heap-exploitation.md`
- Pattern catalog and fuzz-based hunting for kernel/V8/document-format CVEs → `../06-binary-vuln/vuln-types-exploitation.md`
- Not yet covered, to be added: how JIT compiler optimization mis-lowerings generate type confusion (expandable section, → `userspace-runtime-root-causes.md` §1); lifecycle semantics of the Windows object manager/handle table; smart-pointer use_count races (a C++-specific double-free surface); measured MTE/PAC bypass cases.
- Corpus entry point: `../../data/精华全量索引.md` — grep for "UAF/条件竞争/类型混淆/整数溢出/double free/缓冲区溢出" to reach the original write-ups behind each section's precedents.
