# Kernel Vulnerability Root-Cause Case Library (Linux + Windows)

> Positioning: **root cause and fix, case by case** — where the vulnerable code sits, which assumption gets broken, why it becomes a privilege-escalation primitive, and how upstream fixed it.
> Exploitation primitive chains (heap spray/reclaim/ROP finale) are not repeated here → cross-link `~/.zcode/skills/re/techniques/07-kernel/kernel-exploit-fuzzing.md` §1; the CVE name overview → `../06-binary-vuln/vuln-types-exploitation.md` §3.
> Uniform case template: **background → vulnerable code → the broken assumption → trigger conditions and race window → primitive-ization → fix diff**.

---

## 0. Case Master Table

| # | CVE | Subsystem | One-line root cause | Root-cause pattern (§8) | Primitive |
|---|-----|-----------|---------------------|--------------------------|-----------|
| 1 | CVE-2022-0847 DirtyPipe | pipe/splice | pipe_buffer.flags left uninitialized; the zero-copy path inherits a stale CAN_MERGE | Stale flag residue | Cross-privilege page-cache write |
| 2 | CVE-2021-22555 | netfilter compat | the alignment-padding memset offset isn't counted into the allocation size | OOB zeroing | OOB write of zeros → msg_msg UAF |
| 3 | CVE-2022-2588 | cls_route | replacing a filter with `fold->handle==0` skips the unlink before freeing | Wrong unlink condition | UAF → DirtyCred SC→RC |
| 4 | unix_gc race (fix 47d8ac011fe1) | af_unix | GC traversal concurrent with connect(); inflight count wrong | Lifetime/refcount | UAF |
| 5 | CVE-2019-2215 | binder | BINDER_THREAD_EXIT frees the embedded waitqueue; epoll never deregistered | Cross-subsystem lock-domain assumption | UAF → iovec reclaim |
| 6 | CVE-2020-0423 | binder | the proc->files pointer-liveness assumption broken by vma_close | Refcount imbalance | double free |
| 7 | CVE-2014-3153 | futex PI | requeue_pi's two assumptions (user values trusted + uaddr1≠uaddr2) → a stale rt_waiter left on the kernel stack | Kernel-stack residue | Arbitrary write (value uncontrolled) |
| 8 | CVE-2024-26229 + CVE-2023-36036 | Windows cldflt.sys | Reparse Point data validation missing a total-length constraint / premature object release | Wrong validation scope + UAF | Kernel pool OOB write |
| 9 | CVE-2022-0995 | watch_queue | allocation-loop and write-loop bound constants disagree | Inconsistent two-loop bounds | OOB bit write of zeros |
| 10 | CVE-2016-5195 DirtyCOW | mm/gup | the COW failure path still lets FOLL_WRITE through | Failure path not rolled back | Read-only mapping write |

Note: CVE-2021-4145 is actually a QEMU bug (fix 66fed30c9cd1), **not** af_unix GC — a common transcription error when copying DirtyCred case numbers; the real af_unix GC race is §3.3.

---

## 1. DirtyPipe (CVE-2022-0847): A Zero-Copy Optimization Awakens a Five-Year-Dormant Uninitialized Flag

### 1.1 Background: Pipes and Page-Cache References in splice

A pipe is a kernel IPC primitive: internally a ring array of `pipe_buffer`, each buffer holding a `struct page *page` + `offset/len/flags`. To avoid a userspace round-trip, `splice()` hangs **file page-cache pages** directly into the pipe (refcount +1, no copy). This is the shared foundation of the "zero-copy" family (sendfile/AF_ALG/XFRM in-place encryption included).

### 1.2 Vulnerable Code (fs/pipe.c, Linux 5.13)

```c
// fs/pipe.c:400 pipe_write()
if (chars && !was_empty) {
    unsigned int mask = pipe->ring_size - 1;
    struct pipe_buffer *buf = &pipe->bufs[(head - 1) & mask];
    int offset = buf->offset + buf->len;

    if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
        offset + chars <= PAGE_SIZE) {      // 只查"能不能装下",没查"这页是谁的"
        ret = pipe_buf_confirm(pipe, buf);
        ...
        ret = copy_page_from_iter(buf->page, offset, chars, from);
        buf->len += ret;
```

The key is elsewhere: when `copy_page_to_iter_pipe()` (the splice-into-pipe path) constructs a new pipe_buffer, it **assigns only page/offset/len/ops and never writes flags**. flags retains the stale value of the ring's previously freed buffer.

### 1.3 The Broken Assumption (One-Line Root Cause)

**"A freshly assigned pipe_buffer.flags is clean"** — the developer assumed a reused buffer struct in the ring gets fully initialized; in fact flags is polluted by the previous buffer's leftover `PIPE_BUF_FLAG_CAN_MERGE`, so the "append to the current page" fast path swaps its target from an anonymous pipe page to **a read-only file's page-cache page**.

Timeline (why it only exploded in 5.8):
- v4.9 commit `241699cd72a8`: introduced the uninitialized flags — "at the time none of the flag bits mattered";
- v5.8 commit `f6dd975583bd` "pipe: merge anon_pipe_buf*_ops": changed the "mergeable" test from an ops-pointer comparison to a **per-buffer flag** — the patch itself introduced no bug, it just turned the stale flag into a security switch (PoC comment verbatim: The commit did not introduce the bug, it just provided an easy way to exploit it).
- This is the textbook of "harmless defect × later feature = vulnerability": **a flag's semantics were upgraded by a later commit, but nobody went back to audit all the assignment sites**.

### 1.4 Trigger Conditions and Race Window

**No race; deterministic trigger** — which is also why it is nicer to use than DirtyCOW. Steps (Max Kellermann PoC):
1. `pipe(p)` creates the pipe;
2. `write()` fills the entire pipe → all ring entries get flags=PIPE_BUF_FLAG_CAN_MERGE;
3. `read()` drains it → the pipe_buffers are freed but the flags remain;
4. `splice(fd, &offset-1, p[1], NULL, 1, 0)` hangs the page containing the byte just before the target offset into the pipe (flags uninitialized, CAN_MERGE still set);
5. `write(p[1], data, n)` → `copy_page_from_iter()` writes directly into the **page-cache page**.

Limitations: the target file must be readable; the offset must not sit at a page boundary (you must splice 1 byte first to take a page reference); the write cannot cross a page; the file cannot grow. The origin story is itself a root-cause lesson: Max found it while debugging CRC corruption in server logs (a two-process writer/splicer experiment, BBBB overwriting AAAA).

### 1.5 Primitive-ization: A Page-Cache Write ≠ an Ordinary Arbitrary Write

What gets written is the page cache; what is bypassed is not memory protection but the **file permission model**:
- /etc/passwd opened O_RDONLY, SUID binaries, read-only mounts (CD-ROM), btrfs read-only snapshots, immutable files — all valid targets; writing the pipe performs no permission check whatsoever;
- The overwritten page is not marked dirty and is not necessarily written back to disk → vanishes on reboot, so you can **leave no trace**;
- Standard playbook: overwrite `root:x:` with `root:::` in `/etc/passwd` to blank the password field, then `su root` (a one-line bash script); or overwrite a SUID program; inside a container, overwrite files in the host-mounted read-only layer to escape.
- Reproduction record: a 5.13 kernel + the above PoC succeeds out of the box, no environment pitfalls.

### 1.6 Fix Diff

```diff
// commit 9d2231c5d74e13b2a0546fee6737ee4446017903
// copy_page_to_iter_pipe() 中给新 pipe_buffer 补上 flags 初始化
  buf->page = page;
  buf->offset = 0;
  buf->len = PAGE_SIZE;
+ buf->flags = 0;          // 新挂进来的页缓存引用,一律不可合并
```

Fix philosophy: **patch the source of dirty state, not the check logic** — pipe_write's merge fast path isn't wrong; what was wrong was letting an external page enter carrying a stale flag. Shipped simultaneously in 5.16.11/5.15.25/5.10.102. Successor lineage (Dirty Frag/Copy Fail/Fragnesia, the 2025–2026 same-family in-place page-cache writes) → `~/.zcode/skills/re/techniques/07-kernel/kernel-exploit-fuzzing.md` §2.

---

## 2. CVE-2021-22555: Two Bytes of Zeros, a Fifteen-Year Veteran

### 2.1 Background: netfilter's 32-bit compat Layer

When a 64-bit kernel runs 32-bit userspace programs, setsockopt(IPT_SO_SET_REPLACE) takes the compat path: the kernel converts iptables rules from the 32-bit compact format into the 64-bit native format **in place** (struct pointers grow from 4 to 8 bytes, entry sizes change, requiring relocation + alignment padding). This bug has been along since v2.6.19-rc1.

### 2.2 Vulnerable Code (net/netfilter/x_tables.c)

```c
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
                                unsigned int *size)
{
    const struct xt_target *target = t->u.kernel.target;
    int pad, off = xt_compat_target_offset(target);
    ...
    t = *dstptr;                                   // 转换后的目标位置(用户可控相对偏移)
    memcpy(t, ct, sizeof(*ct));
    ...
    pad = XT_ALIGN(target->targetsize) - target->targetsize;  // 8 字节对齐差
    if (pad > 0)
        memset(t->data + target->targetsize, 0, pad);         // ★ 越界点
}
```
(The isomorphic `xt_compat_match_from_user` has the same disease.)

### 2.3 The Broken Assumption

**"The padding region from t->data + targetsize to +pad lies inside the allocation"** — when allocating `xt_table_info` (kvmalloc, GFP_KERNEL_ACCOUNT, kmalloc-512 and up), the size **never counts the pad**, so the alignment-zeroing memset writes 2–4 bytes past the allocation boundary. The attacker uses `char pad[0x108 + PRIMARY_SIZE - 0x200 - 0x2]` to pick a custom entry length, controlling which kmalloc-4096/2048 bucket the vulnerable chunk lands in and precisely aligning the neighboring object; `data.target.u.user.revision` selects the NFLOG target so that targetsize=4 (not 8-aligned, pad>0).

Writing only `\x00`, only 2 bytes — why is that valuable? Because writing zeros is **truncation**: clearing the low 2 bytes of a neighboring object's pointer, `0xffff91a49cb7f000 → 0xffff91a49cb70000`, lands exactly back in the controllable heap region (writing 4 bytes would produce the invalid `0xffff91a400000000` — exploiters specifically want only 2 bytes).

### 2.4 Trigger Conditions and Race Window

No race. CAP_NET_ADMIN is obtainable inside a user namespace (after `unshare -unr`, setsockopt triggers it directly) — this is where its "container-escape regular" status comes from.

### 2.5 Primitive-ization: Write-Zeros → UAF → Arbitrary Read/Write (the Textbook Chain)

Line-by-line reconstruction of the public exploit skeleton:
1. **Heap layout**: msgget×4096 queues; msgsnd pairs a primary (4096B, kmalloc-4k) + a secondary (1024B, kmalloc-1k), tagging the primaries at 1024-byte intervals;
2. **Trigger**: IPT_SO_SET_REPLACE makes xt_table_info land in the hole; the memset zero-truncates a neighboring primary's mlist.next (which points at a secondary) → with some probability two primaries now point at **the same secondary** (1-1024/65536);
3. **Identification**: msgrcv(MSG_COPY) reads the tags and diffs to locate the fake/real queues;
4. **UAF**: msgrcv from the real queue frees the shared secondary; the fake queue still holds a dangling reference;
5. **SMAP bypass**: socketpair sk_buffs spray 1024B forged msg_msg to reclaim; enlarge m_ts to OOB-read and leak mlist.next → self-locating;
6. **KASLR/SMEP**: after the second free of the sk_buff UAF, spray pipe_buffer (kmalloc-1k) to reclaim, with ops pointing at .data's anon_pipe_buf_ops; reading the sk_buff leaks it → kernel base;
7. **Finale**: a fake pipe_buf_operations whose release points at a stack-pivot gadget; ROP `commit_creds(prepare_kernel_cred(NULL))` + `switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)` → setns out of the container, host root shell.
Local reproduction pitfall: with CONFIG_SECURITY=y, `security_msg_msg_alloc()` adds a non-null security pointer to msg_msg; the forged struct fails validation, so it must be turned off.

### 2.6 Fix

fix commit `b29c457a6511` ("netfilter: x_tables: fix compat sysctl mismatch causing OOB writes", v5.13-rc4): the compat conversion now **computes offsets explicitly**; the landing point of the padding zeroing must be inside the allocation boundary, no longer assumed from "the struct's natural layout". In one sentence: **alignment padding is data too — account for it at allocation time**.

---

## 3. The DirtyCred Route: When UAF Meets Credential Objects

### 3.1 Background: Why UAF Exploitation Needs "Reclaim"

The classic UAF follow-up is spraying same-size victim structs to reclaim the slot. But modern mitigations (SLAB_FREELIST_RANDOM/HARDENED, uncontrollable contents) make "precise forgery" ever harder. DirtyCred (CCS 2022) flips the idea: **don't forge data — move a privileged credential object into the freed memory** —
- **SC (same-cache cross-type)**: the victim object and the target credential object share one slab cache; free the victim, then immediately have the kernel allocate a file/cred struct into it; subsequent accesses to the victim actually operate on the privileged credential;
- **RC (re-alloc in cache)**: let the page holding the victim be reused across caches, reallocated as a credential.
Effect: an unprivileged process's ordinary `struct file` for an opened file is layout-identical to a privileged process's `struct file` — after the reclaim you "steal" a **real, kernel-trusted credential**, not fake data; likewise you can swap another process's cred in. No information leak required; naturally immune to the traditional KASLR/SMEP/CFI playbook.

### 3.2 CVE-2022-2588: A List Node Lost to a One-Line Conditional

**Background**: cls_route is an old traffic classifier; route4_change() handles filter add/delete/replace.

**Vulnerable code** (net/sched/cls_route.c, before the fix):
```c
    rcu_assign_pointer(f->next, f1);
    rcu_assign_pointer(*fp, f);

    if (fold && fold->handle && f->handle != fold->handle) {   // ★
        th = to_hash(fold->handle);
        h = from_hash(fold->handle >> 16);
        b = rtnl_dereference(head->table[th]);
        ... /* 从哈希表摘除旧 filter fold */
    }
    ...
    /* 随后 fold 被 kfree */
```

**The broken assumption**: **"the to-be-freed old filter can always be found by handle and unlinked from the hash table"** — when the old filter's handle is 0, the condition short-circuits, the unlink is skipped, but kfree runs anyway → the hash table holds a permanently dangling pointer; the next traversal is a UAF.

**Trigger**: netlink TC commands — first insert a filter with handle=0, then issue another change request to replace it (the replacement path's new handle ≠ 0). Reachable with CAP_NET_ADMIN in a userns (a container-facing surface again). No race; deterministic.

**Primitive-ization**: the UAF object is a route4_filter (an ordinary kmalloc/slab object) — the DirtyCred paper uses CVE-2022-2588 to demonstrate SC→RC: after the free, occupy the slot with controllable generic objects (spray) to gain a "controlled free", then swap a `struct file` (opened read-only on /etc/passwd vs. opened on a privileged file) or a `struct cred` into the same memory, upgrading "unauthorized file write" into "process credential replacement". The accompanying generic tricks are the same family as §2's msg_msg/sk_buff → cross-link the techniques library wiki §1.

**Fix diff** (commit `9ad36309e2719a884f946678e0296be10f0bb4c1` "net_sched: cls_route: remove from list when handle is 0", 2022-08):
```diff
-    if (fold && fold->handle && f->handle != fold->handle) {
+    if (fold) {
```
A one-line fix whose meaning is: "**if there is an old node, it must be unlinked** — whether unlinking is needed depends on whether the object is on a list, not on its business-field value (the handle is only a lookup aid)". The commit message adds: the bug predates the RCU conversion (1109c00547fc) and was masked back then because old filters were reused. Audit lesson: **conditionals coupling data-structure membership with business fields are a high-incidence zone for unlink/free-class bugs**.

### 3.3 The af_unix Garbage-Collector Race: Why the GC Forgets References

**Background**: after AF_UNIX domain sockets pass fds around via SCM_RIGHTS, a cycle means the refcount never returns to zero; the kernel runs the `unix_gc()` graph traversal periodically to reclaim "inflight orphans".

**Root cause** (fix commit `47d8ac011fe1c9251070e1bd64cb10b48193ec51` "af_unix: Fix garbage collector racing against connect()", 2024-04): the GC's mark phase races with `connect()` — connect happens to hang a new reference onto the inflight count just after the GC has already declared "this socket has no external references, dead" → the GC frees per the old snapshot while the new referent receives a dangling pointer. **Broken assumption: "the graph during GC traversal is the graph at reclaim time"**, with no lock in between that would bar topology changes.

**Fix**: make connect mutually exclusive with the GC (establish synchronization between the inflight-count mutation points and the GC); the GC re-confirms before freeing. The same problem has recurred historically (multiple rounds of fixes in 2013, 2021, 2024) — **every edge where the garbage collector shares state with the "normal path" is an audit point**, the same pattern as binder's lock-domain issue (§4).

### 3.4 CVE-Number Clarification

DirtyCred cases are often transcribed as "CVE-2021-4145 (unix_gc)" — verified: **CVE-2021-4145 is a QEMU block-mirror null-pointer dereference** (fix 66fed30c9cd1), unrelated to the kernel. The recent representative unix_gc race is the 2024 fix in §3.3; for the DirtyCred paper's public kernel demonstrations, go with CVE-2022-2588/CVE-2021-22555 and the like.

---

## 4. Binder UAF: The Cross-Subsystem Fight Over "Who Cleans Up"

### 4.1 CVE-2019-2215: epoll Slips on binder's Waitqueue

**Background**: the binder driver creates a `binder_thread` per ioctl thread (kmalloc-512) with an embedded `wait_queue_head_t wait`. `binder_poll()` returns this embedded waitqueue to poll/epoll — epoll_ctl(ADD) hangs an epitem's wait_queue entry on it.

**Vulnerable code** (drivers/android/binder.c, before the fix):
```c
static void binder_free_thread(struct binder_thread *thread)
{
    ...
    kfree(thread);          // ★ thread->wait 随之消失,但没人通知 epoll
}
```
Call chain: `ioctl(BINDER_THREAD_EXIT)` → `binder_thread_release` → `binder_thread_dec_tmpref` → `binder_free_thread` → kfree. Working backward from P0's KASAN report: the crash is in process-exit `ep_free → ep_remove_wait_queue → remove_wait_queue` doing `spin_lock_irqsave(&wq_head->lock)` on the already-freed waitqueue_head.

**The broken assumption**: **"the waitqueue's lifetime covers all registrants"** — binder assumed poll registrations are transient and never expected epoll to hang a wait_queue entry on its embedded waitqueue **long-term**; no `ep_poll_callback`-level deregistration happens before the kfree. This is a **cross-subsystem protocol mismatch**: both subsystems are individually "correct"; their composition produces a UAF.

**Trigger sequence** (fully reachable from userspace):
```c
epoll_fd = epoll_create(1000);
epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event);  // ① 挂监听
ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);             // ② kfree(thread+wait)
exit(0);                                                // ③ ep_free 踩悬空 waitqueue
```
No race, deterministic crash (exploitation requires reclaim takeover). Exploited in the wild since 2017 (P0: reported 2019-11; many OEM kernels never merged the 2018 fix).

**Primitive-ization** (r0Cat's line-by-line walkthrough post):
1. **Placeholder object: writev's iovec array** (readv/writev copies the whole iovec array into the kernel): a single iovec is 16B (base + length), the array length is adjustable → full coverage of the 512B kmalloc-512; `iov_base` is a pointer the kernel will actually read from → you get a "kernel moves data per your pointer" primitive;
2. **The key alignment**: the offset of iovs[iov_idx] relative to the array head = the offset of `wait` within binder_thread → modifying the iovec modifies the waitqueue;
3. **Spinlock bypass**: mmap a fixed address `0x100000000` (low 4 bytes zero) as dummy_page; once the dangling waitqueue_head's lock field is occupied, its low bits are all zero → the spinlock "looks" unlocked;
4. **Timing**: set the pipe capacity to 1 page; the writev's first iovec (reading dummy_page) fills the pipe and blocks on the second iovec (base pre-filled with 0xdeadbeef) — **the blocked writev already holds the kernel-side iovec copy**; trigger the UAF path at this moment to rewrite iov_base; once unblocked, the kernel reads per the new pointer → information leak; then switch to readv to write in reverse → arbitrary read/write (the ARM64 "near-universal" iovec method, standard in the later CVE-2019-2215 exploitation family).

**Fix** (three-layer evolution):
```c
// android-common f5cb779ba163 (2018-01) "ANDROID: binder: remove waitqueue when thread exits."
//   → BINDER_THREAD_EXIT 时 wake_up_poll(&thread->wait, EPOLLHUP | POLLFREE)
//     POLLFREE 语义:ep_poll_callback 收到后自行把 epitem 摘出 waitqueue
// android-common 5eeb2ca02a2f (2018-02) "binder: synchronize_rcu() when using POLLFREE."
//   → 补 RCU 宽限期,防止 callback 还在跑就 kfree
// torvalds/linux a880b28a71e3 (2021-12) "binder: use wake_up_pollfree()"
//   → 上游统一改用 wake_up_pollfree()(POLLFREE 忘调会 WARN)
```
Fix philosophy: **whoever owns the waitqueue is responsible for broadcasting "I'm dying"**; and the first fix (adding POLLFREE only) still left an RCU window, closed by a follow-up — "a fix that opens a new window" is itself a pattern (see §8 pattern 8).

### 4.2 CVE-2020-0423: The proc->files Pointer-Liveness Assumption

**Background**: in binder ioctls, after `binder_get_thread`, finding a free slot for a new fd goes through `task_get_unused_fd_flags → __alloc_fd(files)`.

**Root cause**: `proc->files` points at the creating process's `files_struct`, but that struct is cleaned up by `binder_vma_close` (process exit / munmap of the binder mapping); **holding only a binder_proc reference does not pin the files_struct** — when vma close runs concurrent with an ioctl, `__alloc_fd` dereferences a stale `files` → UAF + double free (the fight between `binder_release_work` and `binder_dec_node` over the same binder_work is the other face).

**Fix** (android commit `7f3dc0088b98` "binder: fix proc->files use-after-free"): guard the cleanup and use of proc->files with a mutex ("protect proc->files with a mutex to prevent cleanup while in use") — **a borrowed pointer must have an explicit mutual-exclusion boundary, not a prayer that the other side outlives you**. For the exploitation side (KSMA to bypass KASLR/CFI, Android 8–11) see the local post (cross-link `../06-binary-vuln/vuln-types-exploitation.md` §3.2).

---

## 5. futex PI (CVE-2014-3153): The Ghost rt_waiter on the Kernel Stack

### 5.1 Background: PI Futexes and Requeue

futex is the kernel accelerator for userspace locks; PI (priority inheritance) futexes use rt_mutex to prevent priority inversion. `futex_wait_requeue_pi(uaddr1,uaddr2)`: a thread first sleeps on uaddr1, then gets batch-moved by `futex_requeue` to wait on uaddr2's rt_mutex. Towelroot (CVE-2014-3153) owned the entire Android 4.4 family.

### 5.2 The Bug: Two Bugs Composing into One Abnormal Flow

**relock bug**: futex_lock_pi_atomic grabs the lock with `cmpxchg(uaddr, 0, newval)` — treating "uaddr's value is 0 = unowned". But uaddr lives in **userspace memory**: one write of `*uaddr = 0` and the kernel believes the lock was legitimately released. Side effect: none of the cleanup an unlock should do (waking blocked waiters, tearing down pi_state) **happens at all**.
**Broken assumption**: the kernel treats a user-memory value as the authoritative source of lock state, and user memory can fake "unlocked" at any moment.

**requeue bug**: the requeue path allows `futex(uaddr2, FUTEX_CMP_REQUEUE_PI, ..., uaddr2)` — i.e., uaddr1==uaddr2 ("requeueing" the waiters of uaddr2 onto uaddr2). Nobody checked for this self-referential call.
**Broken assumption**: the design assumed uaddr1/uaddr2 are two distinct locks; the self-call smuggles "kernel-mode wakeup" out as "an ordinary userspace wakeup".

**Composition** (four trigger steps):
1. The main thread `futex_lock_pi(&uaddr2)` locks uaddr2;
2. Thread 2 calls `futex_wait_requeue_pi(&uaddr1,&uaddr2)` → uaddr2 is locked → enters rt_mutex waiting, **and the on-stack local `rt_waiter` gets linked into the rt_mutex's waiter list**;
3. relock bug: userspace does `*uaddr2=0`;
4. requeue bug: `futex(uaddr2,...,uaddr2)` → uaddr2 "unlocked" → the ordinary wakeup path returns to userspace — **the stack frame is reclaimed while rt_waiter is still on the kernel list**.

Root cause in one line: **"a stack temporary is always unlinked from global structures before the function returns"** — an early-exit path skipped the cleanup.

### 5.3 Primitive-ization: From Stack Residue to cred

Three steps:
1. **Stack memory sharing**: the stale rt_waiter's stack address gets reused by locals of subsequent syscalls — pick `__sys_sendmmsg`: its userspace-passed mmsghdr array lands at the same stack depth; the attacker uses msg_iov contents to **rewrite the on-stack rt_waiter/plist node from userspace** (function A's local address == function B's local address; the post demonstrates it with a 32-bit example);
2. **Arbitrary address write (value uncontrolled)**: mmap a fake plist node in userspace and point rt_waiter's list at it; when the kernel lock wakeup inserts into the list by prio, the prev pointer at target address A gets written as "the new node's kernel address" — where you write is controllable, what you write is not;
3. **Uncontrolled value → controlled**: on old kernels (3.4), `thread_info` sits at a fixed location atop the stack (`sp & ~0x1fff`) containing `addr_limit` (the userspace access ceiling): by rotating multiple threads, write "an address higher than the target thread's stack" into its addr_limit, and that thread can write kernel memory directly from userspace → thread_info→task_struct→**cred fields zeroed/maxed out** (credbuf's full field list: uid/gid/cap_*/security sid).

### 5.4 Fix

Introduced by commit `52400ba` (PI futex); the fix family (v3.14/stable trees): **`54a2178` "futex: Prevent requeue_pi on same futex"** (reject uaddr==uaddr2 at the entry) + `13fbca4`/`b3eaa9f`/`e9c243a` (per-branch companions, including mandatory owner-tid clearing on unlock paths). Fix philosophy: **validate the invariant at the entry (the two locks must differ) and guarantee symmetric cleanup on every exit path** — rather than patching one link of the exploitation chain.

---

## 6. Windows Side: The cldflt.sys Cloud-File Driver Family (Pool Overflow + UAF)

### 6.1 Background: Cloud Files / Placeholders

cldflt.sys (Windows Cloud Files Mini Filter Driver) powers the **placeholder** mechanism for cloud files such as OneDrive: locally, a file is just reparse-point metadata; the real content is hydrated on demand. The filter driver runs in the SYSTEM context; userspace talks to it via `CfExecute`/FSCTL, and the input is the file's own Reparse Point data — **kernel parsing input fully controlled by the attacker**.

### 6.2 CVE-2023-36036: HsmpRpCommitNoLock's Out-of-Bounds memmove

**Call chain** (restored with IDA in the post):
```
HsmFltPreFILE_SYSTEM_CONTROL → HsmFltProcessHSMControl → HsmFltProcessUpdatePlaceholder
  → HsmiOpUpdatePlaceholderDirectory → HsmpRpCommitNoLock
      → HsmpRpReadBuffer → HsmpRpiDecompressBuffer   // 解压 Reparse Point
```

**The bug**: in HsmpRpCommitNoLock's do-while loop:
```c
dst = ExAllocatePoolWithTag(..., 0x4000, ...);          // 固定 0x4000
len = ElementInfos[10].Length;                          // 来自解压后的 reparse 数据
memmove(dst, src /* 解压后 ElementInfos[10] 数据 */, len);  // ★ len 无上界校验
```
Fix diff (bindiff in the post): add a `> 0x4000` check on `*(_WORD *)(a1 + 10)` inside `HsmpRpiDecompressBuffer` — **truncate at the decompression exit, not at the consumption point**.

**Why validation didn't stop it**: upstream `HsmpRpValidateBuffer` does validate the HSM_DATA structure, but a bypass exists: after the first-layer validation passes, if `ElementInfos[1].Data & 0x10` it **returns directly (treated as passed)**; and the vulnerable consumption reads `ElementInfos[10]` — **the validated elements and the consumed elements are not the same batch**.

**Attack surface**: a Reparse Point with `IO_REPARSE_TAG_CLOUD_3(0x9000301A)`; craft ElementInfos[0]/[1] to pass validation with ElementInfos[10].Length>0x4000, CRC32 the data and compress it with RtlCompressBuffer into FileData; any ordinary user can `SetReparsePoint` on a file in a writable directory (DeviceIoControl FSCTL_SET_REPARSE_POINT) to reach a kernel pool OOB write — the classic Windows LPE finale (pool overflow → adjacent object → token theft; cross-link `../06-binary-vuln/vuln-types-exploitation.md` §4 HEVD series).

**The broken assumption**: "a post-decompression Length never exceeds the decompression destination buffer" — the output length of a **variable-size transform** such as compression/decompression must be re-checked against the destination capacity before writing, not trusted from the element structure declared by the input.

### 6.3 CVE-2024-26229: A UAF in the Same Driver (Exploited in the Wild)

**Fact card** (verified against NVD/MSRC/ZDI/PoC repos; function-level public detail not released):
- Official title "Windows **Cloud Files Mini Filter Driver** Elevation of Privilege Vulnerability", CWE class UAF; the NVD summary at one point mislabeled it "Windows **CSC Service**" (client-side caching / offline files neighbors the cloud-files feature and the two are often conflated — this is the correction to the "CSC EoP" name);
- CVSS 7.8, fixed on the 2024-04 patch Tuesday (KB5036892/93/96/99), ZDI-24 series report; Kaspersky's Q2'2024 report confirms **in-the-wild exploitation**;
- Public PoC (michredteam/PoC-26229) idea: **symlink the protected file to an attacker-controlled object and abuse SYSTEM-context file operations / improper permission handling** for elevation;
- Fix: closed-source binary patch; the community located it via bindiff (diffing old vs. new cldflt.sys), method as in §6.2.
Learning path: master cldflt's attack surface through 36036 (the local post publishes the full root cause + patch diff) → self-study 26229 and later CVEs the same way.

---

## 7. Two Quick Cases (Rounding Out Pattern Coverage)

### 7.1 CVE-2022-0995: watch_queue's Two Loops, Inconsistent Bounds

`watch_queue_set_filter()` (kernel/watch_queue.c) loops twice:
```c
// 第一遍:数数(决定分配多大)
if (tf[i].type >= sizeof(wfilter->type_filter) * 8) continue;   // 边界 A
nr_filter++;
...
wfilter = kzalloc(struct_size(wfilter, filters, nr_filter), ...);  // 按 A 分配
// 第二遍:写入
if (tf[i].type >= sizeof(wfilter->type_filter) * BITS_PER_LONG) continue;  // 边界 B(更宽!)
q->type = tf[i].type; ...
__set_bit(q->type, wfilter->type_filter);                        // ★ type 落在 B 内即写
```
With sizeof=16, A=128 and B=1024: the allocation counts "type<128" while the write pass admits "type<1024" → `__set_bit` sets bits out of bounds on the `type_filter` bitmap (writing 0x30a goes OOB by 20 bytes). The exploitation is the exact same shape as CVE-2021-22555 (OOB followed by the msg_msg chain; the post says outright it "creates the same situation as the CVE-2021-22555 write-up"). Fix: the `WATCH_TYPE__NR` constant unifies both bounds (+ bitmap_free added on the free path).
**Pattern**: the same constraint expressed with different expressions at the "counting" and "using" sites — **a constant inconsistency is by itself sufficient for a bug**; when reviewing code, diff the two loops first.

### 7.2 CVE-2016-5195 DirtyCOW: The Failure Path That Doesn't Roll Back

`get_user_pages(FOLL_WRITE)` meets COW: writing a private mapping after fork requires breaking the page and copying; `madvice(MADV_DONTNEED)` racing repeatedly invalidates the PTE so `follow_page_mask` fails to get the page → the `faultin_page` retry path **drops the "writable" requirement along the way**, obtains a direct reference to the read-only mapping, and writes to it. The local post patched a read-only file under `/system/bin` in 7–8 minutes on Android 4.4/kernel 3.4. Fix (the 3.2+ series, commit 4ceb5db9757a family): on COW failure, explicitly re-check `VM_FAULT_WRITE`; if FOLL_WRITE is unsatisfied, fail the call — don't let it through. **Pattern: the permission semantics of the error-recovery path must be symmetric with the main path**. The two principle posts are cross-linked in another dedicated local write-up.

---

## 8. The Kernel Vulnerability Root-Cause Pattern Table (Core Deliverable)

> Per pattern: identification cues / code smells / how to audit. Patterns often compose (e.g., the DirtyCred case is "wrong unlink condition" producing the UAF, then stacking the "reclaim" mitigation blind spot).

| # | Pattern | Identification cues | Code smell | Audit method | Case in this doc |
|---|---------|---------------------|------------|--------------|------------------|
| 1 | **Stale/uninitialized flags** | "harmless defect × new semantics"; explodes after an optimization turns an implicit test into an explicit flag | struct-reuse points (ring arrays/slab) assigning only some fields; a new flag without rescanning all construction sites | For each flag, enumerate "who sets / who clears / who consumes"; asymmetry among the three is a candidate; focus on merge/copy fast paths | DirtyPipe (§1) |
| 2 | **OOB zeroing / miscounted alignment padding** | memset/memcpy target = pointer + field offset, length = alignment delta | `memset(p + size, 0, XT_ALIGN(x)-x)`; the allocation excludes pad; pointer arithmetic mixing struct*/char* | For every memset, ask: which allocation does the target range live in? Was this pad counted at allocation time? Sweep all compat/alignment paths | CVE-2021-22555 (§2) |
| 3 | **Wrong unlink/deregister condition** | the condition for freeing an object ≠ the condition for removing it from its container | `if (obj && obj->field && ...) { remove(obj); } kfree(obj)` — the unlink carries business-field conditions, the free doesn't | Wherever a conditional unlink precedes kfree, counterexample each one: if the condition is false, is the object still on the list? A "value-range" test instead of an "existence" test is an alarm | CVE-2022-2588 (§3.2) |
| 4 | **Cross-subsystem lifetime mismatch** | subsystem A hands an embedded registrable structure to B for long-term list hanging; the kfree side doesn't know the registrant | poll/fops->poll returning an embedded waitqueue; notify_chain; callbacks registered but never unregistered; **no documented contract for "who cleans up"** | For every embedded waitqueue/list_head/callback, ask: can outsiders hold it long-term? Does the free path broadcast deregistration (POLLFREE-style)? If not, it's a UAF | CVE-2019-2215 (§4.1) |
| 5 | **Borrowed pointer without mutual exclusion** | struct A stores a raw pointer to struct B; B's release is triggered by a third event (vma_close/GC/timer) | `proc->files`-style cross-object raw pointers; no lock/refcount pinning during the borrow | Draw the "pointer-target graph + release-trigger graph" and overlay them; any edge crossing a release point is a candidate; for GC/RCU, question every traversal edge against concurrent mutation points | CVE-2020-0423 (§4.2), unix_gc (§3.3) |
| 6 | **Missing entry invariant** | the user can combine legal APIs into out-of-design states (self-referential parameters / the same lock passed twice) | syscall entries not validating uaddr1≠uaddr2, new==old, idx≠idx2 | Enumerate parameter equivalence/self-reference/degenerate cases for equivalence-class testing; add "same resource passed twice" to the fuzz dictionary | CVE-2014-3153 (§5) |
| 7 | **Early-exit path skipping cleanup** | error/shortcut returns skip unlinking on-stack/on-list objects | a local plist/list_head already linked into a global before a goto out; a trylock fast path returning without undo | For every "local variable linked into a global structure", find all return points and verify each one unlinks; label-ize cleanup into a single exit | CVE-2014-3153 (§5) |
| 8 | **Failure path not rolling back permissions/state** | after a racing failure and retry, the previous state bits/permission requirements are lost | a faultin retry not restating FOLL_WRITE; a half-committed transaction returning an error | On every -E path, ask: what did the entry path escalate? Did the exit path restore it? | DirtyCOW (§7.2) |
| 9 | **Inconsistent two-loop/two-read bounds** | the counting pass and the writing pass use different constants; the validated fields and the consumed fields differ | the same constraint in two expressions (×8 vs ×BITS_PER_LONG); validate checks Elements[0..n], consumption uses Elements[m] | diff the condition expressions of the two loops; diff the fields covered by the validator against the fields actually read | CVE-2022-0995 (§7.1), CVE-2023-36036 (§6.2) |
| 10 | **Variable-length transform output unchecked** | post-compression/decompression/deserialization length written without comparing against destination capacity | memmove/copy lengths taken from post-transform data fields; fixed-size pools fed variable lengths | For every fixed-capacity allocation (the 0x4000 kind), trace all writers' length sources; require "validate once more before writing" | CVE-2023-36036 (§6.2) |
| 11 | **Refcount imbalance** | get/put asymmetry; dec in the wrong lock domain; missing RCU grace period | put inside a callback, get outside a lock; callbacks still in flight after kfree (missing synchronize_rcu) | Pair-audit every refcount field (who +1/-1, under which lock); after a fix, still look for the new window (the POLLFREE patch itself needed a patch) | §4.1 fix chain, unix_gc (§3.3) |
| 12 | **double-fetch (TOCTOU)** | user memory re-read after validation; the user can change it between the reads | copy_from_user twice from the same source; size validated, then a re-read value used for the copy | grep for copy_from_user hitting the same uaddr multiple times; switch to memdup_user for a single snapshot | the classic family; the cases in this library are all single-fetch — always check when auditing IOCTL/netlink handlers |

**The common funnel**: patterns 1/2/9/10 yield the "raw memory error" → patterns 3/4/5/11 yield "UAF/dangling pointer" → patterns 6/7/8 yield "logic-state corruption"; afterwards everything runs the techniques library wiki §1 primitive-ization chain (reclaim → arbitrary read/write → cred/modprobe_path/selinux_enforcing). When auditing a new kernel surface (CVE 0day white-box): first grep out candidate points per the smells above, then construct counterexamples pattern by pattern per each "audit method".

---

## 9. Not Covered / To Be Deepened

- **The io_uring family** (CVE-2021-41073 / the IORING_OP leak family): no dedicated post in the local digest corpus (the feature only entered the kernel after corpus v5.1); waiting on new corpus material or online sources
- **CVE-2024-26229 function-level root cause**: closed-source; requires self-sourced pre/post-patch cldflt.sys bindiff (method per §6.2)
- **The DirtyCred paper's full CVE evaluation table** (10 cases): the PDF needs downloading and close reading
- **NTFS CVE-2021-31956 / the CLFS family** (Windows side): multiple local posts; enough volume for a standalone article, reserved as the next piece of the 11-root-cause series
