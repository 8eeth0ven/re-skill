# Userspace Runtime Root Causes: Why Interpreters / JIT / Deserialization / Managed Runtimes Are Vulnerability Incubators

> Division of labor: the sister piece [injection-logic-root-causes.md](injection-logic-root-causes.md) covers "how data crosses the interpreter boundary and becomes syntax"; [06-binary-vuln/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) and [heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) cover **techniques and exploit chains**; this piece covers only **root causes** — why the runtime layer itself (rather than any specific function) systematically produces bugs, and why each class of fix only buys time.

## 0. One-Sentence Overview

> **A runtime is a machine for "interpreting byte streams into behavior": the interpreter interprets bytes as instructions, the JIT interprets hot paths into machine code, the deserializer interprets bytes into object graphs, the GC interprets reachability into life and death. Every one of these interpretations rests on "the input's shape matches the assumptions" — the common root of the vulnerability incubator is that, for performance, these assumptions get frozen into compile-time decisions while validation is deferred, deleted, or simply never synchronized with execution.**

Three leitmotifs run through the whole text:
1. **The assumption leitmotif** (§1, §2): type feedback/type tags are "guesses"; optimization/gadgets execute per the "guess";
2. **The interleaving leitmotif** (§1.4, §3): object headers, heap chunk headers, class names inside serialization streams — metadata and user data share storage and share trust; polluting the data lets you impersonate metadata;
3. **The boundary leitmotif** (§4, §5): at every crossing between the managed world and the native world (JNI, write barriers, bytecode loading), pointers are unchecked and lifetimes are governed by two layers.

---

## 1. Why JIT Compilers Produce Bugs (V8 Focus)

### 1.1 The TurboFan Pipeline and the Deopt Assumption

V8 executes in two tiers: `Parser→AST→Ignition interpreter` generates bytecode and runs it while background threads collect **type feedback**; once a function gets hot, TurboFan optimizes the bytecode into machine code based on that feedback. Pipeline:

```
BytecodeGraphBuilder   字节码 → sea-of-nodes 图
InliningPhase          函数内联展开
TyperPhase             遍历全图,给每个节点标注类型/Range
TypedLoweringPhase     按 Typer 结果把 JS 节点降为 Simplified 节点(删检查从这里开始)
LoadEliminationPhase   消除"冗余"Load
EscapeAnalysisPhase    逃逸分析
SimplifiedLoweringPhase 表示选择(int32/float64/tagged)+ 最终降级
GenericLoweringPhase   剩余 JS 运算降为 Runtime/Builtin/IC 调用
```

Only two mechanisms actually provide safety: **CheckXxx nodes at the entries** (CheckBounds/CheckMaps/CheckNumber…) and **runtime deopt** — the `wrong map` bail out in `--trace-deopt` is it. The safety of the entire system rides on one assumption:

```
编译期假设 = 运行期事实
反馈说参数恒为 int32 → 砍掉类型检查,加法直接编译成 add 指令
运行时发现类型变了  → deopt 回解释器,恢复完整检查
```

If the optimized code, upon meeting an illegal input, **fails to deopt correctly, or never scheduled a deopt at all**, that code gets used wrongly. The deopt safety net itself fails in three ways, each mapping to a class of real precedents:

1. **Missing check**: a CheckXxx that should have been inserted wasn't (§1.3B's restriction error skipped the check entirely);
2. **Wrong predicate**: the check is there, but the basis of its verdict (the Typer Range) is wrong — the check "correctly" lets a bad value through (§1.3A/B are all this);
3. **Misplaced window**: the check passed, but between check and use a re-entrancy (getter/Proxy/GC) mutated the object state (§1.3C).

Hence the first formula for deriving JIT bugs:

> **Bug = the compile-time inferred type/range ≠ the runtime value, with the discrepancy landing exactly on a dimension covered by a deleted check.**

Note the directionality: a wrong inference isn't necessarily a bug (it may just compute wrong numbers); only "wrong along a checked dimension" (index range, Map, sign, length) escalates into memory corruption. This explains why JIT bug PoCs often "just look like a wrong return value" — unlike traditional overflows, **V8 optimization bugs are rooted in the logic layer V8's own engineers designed; a debugger will not show you "how it overflowed"** — you need `--trace-turbo` to find the first node that went wrong.

### 1.2 The Map/Shape Mechanism: Why ICs Are Fast, and Why Type Confusion Equals Map Deception

V8 gives every object a hidden class **Map** (i.e., its shape): it describes "which properties this object has, at which offsets, of which types". Two mechanisms layer on top:

1. **Inline caches (IC)**: after `foo(obj){ return obj.x }` gets hot, the IC slot remembers the `(Map→offset)` pair; the next hit on the same Map skips the whole prototype-chain lookup and does `*(obj+offset)` directly.
2. **Megamorphic degradation**: once one call site has seen >4 Maps, it gives up caching and takes the slow path (the monomorphic/polymorphic/megamorphic state machine).

Fast, because **one Map comparison replaces one full lookup**; dangerous, because **after the comparison the engine unconditionally trusts the offset semantics**:

```
// IC handler 伪代码(本质)
if (obj->map == cached_map)          // 唯一的检查
    return load(obj, cached_offset); // 之后零校验
```

Issue 1203122 (LoadSuperIC type confusion) is precisely this check being misplaced: in a super property access, the IC hit validates the Map of `lookup_start_object`, while the value-fetch offset applies to a differently laid-out object — `B.__proto__` is rewritable from the JS layer, decoupling `receiver`'s memory layout from `lookup_start_object`'s. The author's own words are clearest: **offset +10 in object A is a number, offset +10 in object B is an object address; expect A but actually get B, and the pointer at B+10 is returned as a number (info leak); the other way around, a number gets returned as an object pointer (fake object)**. Hence:

> **Type confusion = Map deception: make the engine believe the memory is laid out as A while it is actually B. The offset isn't wrong — what's wrong is the premise of "which layout".**

### 1.3 Three Classes of Typical Root Causes (Each with Simplified IR)

#### A. Bounds-Check-Elimination Errors (the CVE-2021-30632 Class)

CheckBounds is the gatekeeper of array accesses. Once Typer computes a Range for the index node and `Range ⊆ [0, length)`, TypedLowering/SimplifiedLowering will outright **delete the check node**. Using the GoogleCTF2018 JIT problem (DuplicateAdditionReducer) to demonstrate the canonical shape of this class:

```
源码层:  double_array[t + 1 + 1]
Typer :  CheckBounds(index: Range(2,3), length=4)   → 判定恒安全 → 删除检查
TypedLowering: (t+1)+1 被重写为 t+2                   ← 未重算 Range!
运行期: t = MAX_SAFE_INTEGER+1 时,(t+1)+1 ≠ t+2
        (IEEE754:9007199254740991+1 = ...992,再+1 仍是 ...992;
         而一次 +2 会得到不同的最近可表示数)
结果 :  索引实际为 4/5,检查已不存在 → OOB 读写
```

Root cause in one line: **the check was based on "the old expression's Range"; a later pass rewrote the expression without owning the responsibility of recomputing every affected safety predicate**. The more optimization passes (TurboFan has 30+), the larger the combinatorial space of "rewrite–check desynchronization". CVE-2021-30632 belongs to the same class: StoreStoreElimination judged a store carrying a **Map-migration side effect** as a redundant store and deleted it — what was deleted was not just "the write" but "the shape change" itself; later code writes the old Map's array per the new Map's layout (elements-kind mismatch), a direct OOB write. Local CTF precedent: starctf2019 oob (an artificially added builtin OOB; the practice target for exactly this exploitation template).

#### B. Typer Type-Inference Errors (Arithmetic Simplification Picks the Wrong Sign)

The range analysis itself computes wrong — no need to even fool the check. Two precedents:

**CVE-2021-21224 (issue 1195777)**:

```
源码:  let x = -1; if (b) x = 0xFFFFFFFF;
       return -1 < Math.max(0, x, -1);
Phi 节点 Range(-1, 4294967295)
SimplifiedLowering: Float64 → ChangeFloat64ToInt64 → TruncateInt64ToInt32
    4294967295 (0xFFFFFFFF) 截断成 int32 = -1
比较被选为 Int32LessThan:-1 < -1 → false(正确语义应为 unsigned: 4294967295 > -1 → true)
```

Root cause: 0xFFFFFFFF is **Unsigned32** under JS semantics, but the truncation node interprets it as signed — **truncation and comparison (signedness) are two dimensions out of sync**. The exploit amplifies it in one line: `new Array(Math.sign(0 - Math.max(0,x,-1)))`; Typer believes the length is always 0 (a dead array), so `arr.shift()` is optimized into "decrement the length field directly", writing 0xFFFFFFFE; at runtime Math.sign returns 1, the array lives, and you get **an array of length 0xFFFFFFFF**.

**CVE-2020-16040 (issue 1150649)** — deeper down the same leitmotif: SimplifiedLowering's three phases (`Propagate→Retype→Lower`) communicate via `restriction_type`:

```
Propagate: SpeculativeSafeIntegerAdd 被标记 truncate-to-word32
           → VisitBinop(..., kWord32, Type::Signed32())  // restriction = Signed32
Retype   : feedback_type = Intersect(静态 Range(0, 0x80000000), Signed32)
                                = Range(0, 0x7fffffff)      // 上界被"交集"砍掉
Lower    : NumberLessThan 看到 Range(0,0x7fffffff) ⊆ Unsigned32
           → 选择 Uint32LessThan(无符号比较)
运行期  : y=0x7fffffff, (y+1)|0 = -0x80000000,按无符号比 0x80000000 < 0 = false
```

The patch comment confesses the root cause itself: *"Using Signed32 as restriction type amounts to promising there won't be signed overflow. This is incompatible with relying on a Word32 truncation in order to skip the overflow check."* — **promising no overflow on one hand while relying on truncation to skip the overflow check on the other**: two mutually contradictory assumptions. This is the form "optimization and checks out of sync" takes inside the type system: for one and the same value, the truncation dimension thinks it is a word32, the range dimension thinks it is non-negative, and the comparison dimension picks unsigned.

#### C. Map/Lifetime Races (Feedback Racing Object State)

The third class is not in arithmetic but in **timing**: feedback collection, Map migration, and GC object movement interleave with the execution of optimized code. First look at Map migration itself: storing a double into a `PACKED_SMI_ELEMENTS` array in V8 does not patch the value in place — it **re-lays-out the entire array's elements** (rebuild the backing store + swap the Map); property additions also walk the transition tree to a new Map. Any window of "validate the Map first, then read/write per the old layout" is a landing spot for type confusion — in CVE-2021-30632, the deleted store was precisely the migration store; after the deletion, optimized code writes the **old-layout** array with **new-layout** semantics.

Issue 1307610 is the cleanest specimen — a GC bug rather than a JIT bug, but the root cause is the same family, expanded in §4: one `SKIP_WRITE_BARRIER` object write decoupled the GC's reachability graph from the real reference graph, leaving `re.lastIndex` a dangling pointer. The JIT-side isomorphic precedent: a callback (side effect) changes an array's elements kind / prototype chain while optimized code treats "check Map" and "use offset" as indivisible — any time the engine re-enters JS between the two (a getter, a Proxy, valueOf), each re-entrancy is a layout-mutation opportunity. CVE-2021-37975 (a V8 GC-related UAF, exploited in the wild) and CVE-2024-0517 (a 2024 in-the-wild OOB write) both sit on this "optimization assumptions racing object state" line.

### 1.4 Object Forgery: Why OOB Immediately Becomes Arbitrary Read/Write

The JS engine object model: **a reference is a pointer; the engine decides how to interpret the bytes after the pointer by its Map — and checks nothing beyond that**. A JSArray in memory is four slots:

```
[ map | properties | elements | length ]   // 16B(指针压缩后)
   ↑ 类型解释权        ↑ 数据指针      ↑ 引擎读它做隐式边界
```

So once an OOB read/write is in hand, the upgrade path is **deterministic** and needs no new bug:

1. **Rewrite a neighboring array's length field** → the relative read/write expands to the entire heap page;
2. **addrof / fakeobj primitives**: the template from the CVE-2021-38001 analysis post — flip an array's Map back and forth between "object-array Map" and "double-array Map":
   ```js
   function addressOf(o){   // 期待对象数组:存的是指针
       setMap(evil, obj_array_map);  evil[0] = o;
       setMap(evil, double_array_map);          // 同一块内存按 double 读
       return ftoi(evil[0]); }                  // 指针 ← 当数字读出
   function fakeobj(addr){ // 反向:数字被当指针
       setMap(evil, double_array_map); evil[0] = itof(addr);
       setMap(evil, obj_array_map);
       return evil[0]; }                        // 引擎把它当对象用
   ```
   Expecting layout A while given B = addrof; expecting B while given A = fakeobj — exactly the two directions of the §1.2 sentence.
3. **Pointer compression helps skip the leak**: V8 reserves a 4GB cage and references store only the low 32 bits; with a fixed object-creation order → **the low-32-bit addresses of built-in Maps are constant within the same V8 build** (the map of `var array=[1.1]` is still 0x08203af9 after a restart). An attacker debugs once offline and hardcodes every Map address; ASLR's high 32 bits are eaten by the cage.
4. **fakeobj → forge an entire JSArray** (map pointing at the real Map value, elements pointing anywhere) → **arbitrary read/write**; then read `WasmInstance+0x68` for the RWX page and write shellcode (the full exploit is in the CVE-2021-38001 analysis post).

In one sentence: **the object model = unchecked pointers, so there is no moat between "can write the heap" and "arbitrary read/write/execution"; heap-layout determinism (pointer compression + fixed allocation order) erases the last bit of randomness too**. The V8 sandbox (turning object pointers into table handles) only builds that moat between "arbitrary read/write → arbitrary code execution"; the first half (OOB → arbitrary heap read/write) remains unsolved, because it is the object model itself.

---

## 2. Why Deserialization = Code Execution

### 2.1 Root Cause: The Protocol Carries Type Information → the Byte Stream Is a Construction Instruction Set

Plain data protocols (JSON without @type) transfer "values"; serialization protocols transfer "**instructions to instantiate types**" — that is the essential difference:

```
Java 序列化流: AC ED 00 05 ... [类描述符(全限定名+字段表+ serialVersionUID)] [字段值]...
               └── 反序列化端: 按描述符 Class.forName → newInstance → 反射逐字段赋值
               └── Serializable 类还有自定义入口: readObject() —— 对象自己写的恢复逻辑
```

So the equation holds: **the inbound byte stream = specifying "which classes to instantiate + which fields to feed"**. This is not an implementation bug; it is the protocol's design goal (faithfully reconstruct the object graph); the security boundary can only be retrofitted (allowlists/blocklists/look-ahead). The definition of a gadget follows from this: **a class on the classpath that happens to combine "controllable fields + concatenatable behavior in a lifecycle method"; chain several such classes head-to-tail into a call chain**.

The "type tag → execution" paths of three ecosystems side by side (three entrances of one root cause):

```
Java 原生流 : 类描述符(全限定名) → Class.forName → newInstance → readObject(自定义入口)
Fastjson    : {"@type":"类名"}    → autoType 反射 → setter/getter 链
pickle      : REDUCE opcode       → 协议级指令   → 直接 callable(*args)
              ↑ 三者都是"输入指定 callable + 参数",差别只在协议语法糖
```

### 2.2 The CC1 Chain: A Code-Level Root-Cause Dissection

The Commons Collections 1 study notes dissect the chain down to method level — perfect for watching "how data becomes calls":

```
入口(反序列化端自动触发,无需攻击者调用任何方法):
  AnnotationInvocationHandler.readObject()
    → memberValues.entrySet() 遍历 → memberValue.setValue( mismatchProxy )
      → AbstractInputCheckedMapDecorator.setValue()        // TransformedMap 的父类
        → checkSetValue(value)
          → valueTransformer.transform(value)              // valueTransformer 是字段!
            → ChainedTransformer.transform(): for (i) object = transformers[i].transform(object)
                ① ConstantTransformer(Runtime.class)        // 无视输入,固定返回 Runtime.class
                ② InvokerTransformer("getMethod",…).transform(①) // 反射: getMethod("getRuntime")
                ③ InvokerTransformer("invoke",…).transform(②)   // 反射: invoke(null) → Runtime 实例
                ④ InvokerTransformer("exec",…).transform(③)     // 反射: exec("calc")
```

Look at the root cause, not the chain: **every link is "legitimate code written by library authors"** — InvokerTransformer's transform is precisely a public "configurable reflective call" API; calling setValue inside AnnotationInvocationHandler.readObject is normal recovery logic. The bug lives in no single line; it lives in **deserialization handing the right to "choose these classes, configure these fields" to the remote end**. This also explains the methodology of chain hunting: from a dangerous sink's `transform()`, Find Usages backward, specifically hunting callers with **different method names**, all the way to some class's `readObject()` — essentially a reachability search over the classpath.

### 2.3 Why Java/PHP/.NET Are Heavy, and How Language Built-ins Amplify

- **Java is heavy from its "reflection culture"**: frameworks do DI/ORM/serialization via reflection, meaning **any class that stores "method names/class names" as fields is a potential gadget** (InvokerTransformer, TemplatesImpl's bytecode field, JNDI lookup's url field); multiply by hundreds of jars on the classpath — the attack surface = the transitive closure of the whole dependency graph.
- **PHP**: the magic methods `__wakeup/__destruct/__toString/__call` are language-level hooks; destructors fire right after deserialization; the `phar://` stream turns file functions into deserialization entrances too ([05-web/code-audit.md](../05-web/code-audit.md) §3).
- **.NET**: ViewState is itself an encrypted deserialization payload; a leaked machineKey / a default empty key = directly delivering object graphs generated by ysoserial.net; the historical Exchange/SharePoint mega-holes (the ProxyLogon series) are all "deserialization + SSRF" combos.
- **Python**: the pickle protocol has a `REDUCE` opcode outright — **the execution operator is a protocol instruction**; `__reduce__` returning `(os.system, ("cmd",))` is RCE, no gadget hunting needed.

**Fastjson's one-line root cause** (the "Java JSON deserialization woes" series + the 05-region §4.3 cross-link): `{"@type":"ClassName"}` in JSON lets **the remote end directly pick the class for reflective instantiation**, then strings behavior along the setter/getter chain (autoType); it proves that "deserialization vulnerabilities" require no binary protocol — **any design of "type name carried in data + reflection by name" is an isomorphic deserialization surface**. The difference between CC1 and Fastjson is only the entrance semantics (the native Java stream vs a JSON field); the shared root cause is one and the same: **the type tag is supplied by the input, and the runtime trusts it unconditionally** — perfectly isomorphic to §1.2's "Map deception", with the Map replaced by a class name.

**The fix hierarchy** (why blocklists die): a blocklist blocks known classes → every new jar contributes new gadgets (a death spiral); allowlists / SerCheck-style look-ahead (scan the class names in the stream before deciding to parse) is structural mitigation; the only radical cure is: **keep the "class choice" out of the data** — which loops back to the leitmotif of [injection-logic-root-causes.md](injection-logic-root-causes.md) §1: data must not acquire syntactic standing.

---

## 3. Why Heap Managers Are Exploitable

### 3.1 Security Was Never in the Design Goals

malloc's three design goals: throughput (O(1) allocation), low fragmentation, low metadata overhead. **Security has always been a bolt-on** — every check in glibc (`unlink`'s `FD->bk == P`, tcache's key, Safe-Linking) is a patch added after being bitten, not a design constraint. This decides the asymmetry of the game: the allocator must be correct forever; the attacker needs to find only one writable metadata field.

The heap chunk's memory layout is the root cause itself:

```
chunk 头: [ prev_size | size | fd | bk | ... ]   ← 分配器赖以工作的元数据
用户区:   [ attacker 可完全控制的数据 ....... ]   ← 紧贴着元数据
```

**Metadata and user data share the heap and share trust**: any overflow/off-by-one/UAF lands first on the neighbor's metadata. DWORD SHOOT: after the old-style unlink check passes, it executes `FD->bk = BK; BK->fd = FD` — **the allocator places "the write address of a pointer field" inside a pointer that can itself be tampered with**; one overflow equals one "write arbitrary address ← semi-controlled value" primitive. Modern checks sealed this road, but the pattern didn't change — it just moved to tcache.

### 3.2 The LIFO of tcache/fastbin: The Exploiter's Blessing

glibc 2.26 introduced tcache (structure and CTF problem analysis posts):

```c
typedef struct tcache_entry {
    struct tcache_entry *next;   // 指向下一个空闲 chunk 的用户区
    void *key;                   // 2.29+: double-free 检测
} tcache_entry;
// 每 thread 64 条单链(按 size class),每链最多 7 个
// free: 命中尺寸 → 头插;tcache 满 → 走 fastbin/unsorted
// malloc: 优先 tcache → 头弹
```

Why LIFO is the "blessing":
1. **The allocation order is fully predictable**: the chunk you freed last is the one your next malloc gets — **heap feng shui becomes deterministic engineering**; the spray-then-free order is the layout;
2. **The next pointer lies in the first word of the user area** — a UAF/overflow changes one word, and the next malloc returns "the address you designate" as a chunk (tcache poisoning → allocation at an arbitrary address → forged structs such as `__free_hook`/IO_FILE; see the Off-by-one + Tcache Attack, fastbin attack, and IO_FILE chain posts);
3. **fastbin/tcache had near-zero validation early on** (2.26's tcache: no size check, no double-free check) — the fast path cut every verification for throughput, and cut exactly along the attack path.

### 3.3 What Entropy Safe-Linking Actually Adds

Since glibc 2.32, `next` is no longer stored in plaintext: `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`. It defends against "forging a pointer just by reading the residual value on the heap" — the XOR key is **the chunk's own address high bits (the page address)**. So its premise is: **forging next now requires knowing the target chunk's heap address first** (one in-heap info leak). Note that it does not, and cannot, defend against an adversary who already holds in-heap arbitrary read/write — the entropy is only the 12-bit page offset, and the key comes from the victim itself. This is the fate of "bolted-on security": hardening strength ≤ the compatibility cost it is willing to pay.

### 3.4 The Essential Wrap-Up

> **The allocator must trust metadata to work (size, fd/next, bin indexes), while the metadata is interleaved with user data in the same writable memory.** So "heap bugs" were never malloc's bug — they are the inevitable corollary of this layout: the moment user data can step one byte out of bounds, it upgrades into "impersonating the allocator's control data". Contrasted with §1.4: V8 trusts Maps, glibc trusts chunk headers — **two runtimes, one leitmotif: control flow/interpretation rights decided by header fields living on the same level as the data**. The technique genealogy (the house-of series, FSOP) is detailed in [06-binary-vuln/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) and not repeated here.

---

## 4. Why Managed Memory Is Still Unsafe

### 4.1 The GC's Job Description: Collect Only; Boundaries and Types Are Someone Else's Job

"Managed" creates an illusion of safety. The GC's contract is one line: **unreachable objects will be reclaimed**. It does not handle: array bounds, type correctness, cross-boundary pointer semantics. So managed-memory bugs all grow outside the GC's contract:

- **An array OOB in Java is an exception, not corruption**: HotSpot keeps bounds checks even under JIT (or eliminates them only with proof); an OOB → `ArrayIndexOutOfBoundsException`, memory safety intact. This also explains why HotSpot JIT bugs are far rarer than V8's: the bytecode is **statically typed + entry-verified + has no Map/shape-style "layout decided at runtime"**, so the type facts optimizations rely on are language-level invariants; V8 is the exact opposite on all three counts (dynamic types, no verifier, migratable Maps) — **a JIT's safety ceiling is set by the safety invariants of the language it optimizes, not by the JIT's own engineering quality**. **The real escape hatch is the native boundary**: JNI functions, `sun.misc.Unsafe`, DirectByteBuffer off-heap memory, the manual world of `malloc` — checking responsibility is handed back to C code, and all the C code receives is a "trust me" raw pointer. JNI type-confusion precedent (common knowledge): native code expects a `jintArray` but receives a `jdoubleArray`; the JNI layer doesn't check types, the element widths differ by 2x, instant OOB.
- **The GC's own correctness is the new attack surface**: Issue 1307610's root-cause chain —
  ```
  RegExpUtils::SetLastIndex():
      NewNumberFromInt64(last_index)          // > SMI 上限 → 分配 HeapNumber(new space)
      JSRegExp::cast(recv).set_last_index(v, SKIP_WRITE_BARRIER)
                                             // ↑ BUG:old→new 引用未记录 write barrier
  后续:regexp 对象进 old space;minor GC(scavenge)移动/回收 new space 的 HeapNumber
       —— GC 的 remembered set 里没有这条边 → 不会更新 re.lastIndex → 悬垂指针
  利用:UAF 后用浮点数组回填原地址,内容 = [map|properties|elements|length] 十六字节
       (低 32 位地址因指针压缩+固定分配顺序而可预知,§1.4)
       再引用 re.lastIndex → 引擎按 map 解释为 JSArray → 任意读写
  ```
  The patch is one line: `SKIP_WRITE_BARRIER` → `UPDATE_WRITE_BARRIER`. **The GC-bug template: decouple the "reachability graph" from the "real reference graph" (a missed barrier / weak refs / finalizer timing), and the GC frees a still-living object for you** — the cause of the UAF shifts from "forgot to free" to "the GC's graph was polluted"; CVE-2021-37975 is the same family.
- **Heap-layout determinism backfires**: generational GC/compaction makes object addresses "predictable" (rerun the same script, the object's compressed address is unchanged), saving the attacker even the leak.

### 4.2 ART/Dalvik: Why dex Can Be Dumped

An Android packer's encryption exists only in the **file state**; to execute code, the `ClassLoader` (and `dex2oat`) must obtain the **plaintext dex** (in memory / a private mmap). The trust boundary is the loader: everything after loading (the plaintext dex, Class objects, oat artifacts) is attacker-readable — so the root cause of frida dexDump/FART-style unpacking is **architectural: interpreted execution requires a plaintext instruction stream in process memory**; countermeasures can only raise the cost of timing and locating (reflective call sites, per-function decryption, VMP), never abolish it. For the dex/oat/vdex formats and the compilation chain, see [02-android/file-formats.md](../02-android/file-formats.md) and [compiler-and-system.md](../02-android/compiler-and-system.md); the full unpacking toolkit is in `techniques/`.

### 4.3 eval/Dynamic Typing: The Runtime's Built-in Injection Surface

Dynamic typing isn't itself a bug, but it **defers type checks to runtime** and makes "string → code" a first-class operation: `eval`/`new Function` (JS), `eval/exec` (Python), `assert` and `$var($var)` (PHP), OGNL/SpEL/MVEL (JVM expression engines). Each is the runtime-layer projection of the interpreter entrances in [injection-logic-root-causes.md](injection-logic-root-causes.md) §1: the place where data acquires syntactic standing shifts from the SQL parser to the language itself. Expression engine + user input = RCE is the repeatedly validated pattern of the Java ecosystem ([05-web/code-audit.md](../05-web/code-audit.md) §4). Same essence as §2: **every boundary where "input can specify what executes" is a variant of deserialization/injection**.

---

## 5. Interpreters and Bytecode: Why a Modified Opcode Table Is Mere Obfuscation

### 5.1 Bytecode Is the Interpreter's Machine Code

Bytecode injection = delivering a forged instruction stream to the interpreter. The interpreter's trust model for bytecode decides the risk:
- **JVM**: accepts **externally submitted** bytecode (class files), so it must have a bytecode verifier (StackMapTable type checking) — the only mainstream runtime that takes "validating the instruction stream" seriously;
- **V8/LuaJIT/in-game embedded Lua**: bytecode should only ever be generated by the home compiler; the runtime **barely validates** (register indexes, constant-pool indexes, operand-type legality are all trusted). Fine in normal times; but once an attacker gains a memory primitive over "write the constant pool / feedback vectors / bytecode buffer" (after §1.4), **forging bytecode is easier than forging machine code**: no DEP/CFI to get past — the interpreter itself is a legitimate "arbitrary dispatch loop".
- The V8 bytecode disassembly/decompilation field guide proves the bytecode layer can be statically recovered — poor readability is not a security property; the LuaJIT reversing/injected-file post shows LuaJIT allowing bytecode to be loaded directly from a string, an injection surface even further forward than V8's (exposed at the language layer). LuaJIT's exact mechanism: `loadstring(s)` / `loadfile` don't distinguish "source" from "bytecode" — a string starting with `\x1bLJ` (or Lua 5.1's `\x1bLua`) is **decoded directly as bytecode, skipping the compiler**, and the interpreter trusts everything in it: the constant pool, jump targets, register indexes. When games and IoT put business logic into Lua, they hand "instruction-stream generation rights" to anyone who can write that string: change one constant-pool entry = change one function-pointer-sized value; after an opcode-table mod the tools go blind, but an attacker with differential analysis rebuilds it anyway (§5.2).

### 5.2 A Modified Opcode Table = Shipping the Key with the Lock

Rearranging the opcode table (common in VMP/hardened Lua/private VMs) is only **changing the alphabet**:
1. The interpreter necessarily contains the full `dispatch_table[opcode] → handler` mapping — **the key (the mapping table) ships with the binary**;
2. The attacker doesn't need to break it, only **rebuild it differentially**: find the handler for each semantic instruction (signature matching / trace comparison); the typical workload drops from "infeasible" to "tedious";
3. Precedent: DEX static patching based on Smali just-in-time compilation bypasses **signature checks** — the opcode/instruction layer was never the verification layer; VMP handler-identification methods are in [01-windows/protection.md](../01-windows/protection.md).

> **Obfuscation changes the "cost of reading", not the "trust model"**. The only real boundaries are: verification (verify), isolation (sandbox), unforgeability (HSM/TEE). Any design claiming "security through a proprietary bytecode format" has booked it under the wrong account in the obfuscation-vs-security ledger.

---

## 6. Runtime Root-Cause Pattern Summary Table

| # | Pattern | One-line root cause | Precedents |
|---|---------|---------------------|------------|
| 1 | **Trusting the input's type assumptions** | the runtime interprets memory per "the shape the input claims / the feedback hints at", without re-validation | CVE-2021-21224 truncation picking the wrong sign; CVE-2020-16040 restriction-intersection error; Fastjson @type reflective instantiation; the CC1 gadget chain |
| 2 | **Optimization and checks out of sync** | checks deleted/selected per the old state; execution runs per the new state | GCTF2018 JIT: rewriting the expression without recomputing the CheckBounds Range; CVE-2020-16040: promising no overflow vs truncation skipping the overflow check; CVE-2021-30632: deleting the store deletes the Map-migration side effect with it; the starctf2019 oob template |
| 3 | **Metadata interleaved with data** | interpretation rights decided by header fields on the same level as user data; writable data = impersonatable metadata | tcache poisoning (next in the user area); fastbin attack; unlink/DWORD SHOOT; V8 map forgery addrof/fakeobj |
| 4 | **Cross-boundary pointers unchecked** | at the handover between two worlds, one side's guarantees are not re-verified by the other | LoadSuperIC: validates lookup_start_object's Map, fetches per receiver; JNI type confusion (jintArray↔jdoubleArray, common-knowledge precedent); SKIP_WRITE_BARRIER missing the cross-generational edge |
| 5 | **Lifetimes managed across layers** | the object's life/death decided by layer A (GC/loader), the reference held by layer B; the two graphs can decouple | Issue 1307610 GC dangling lastIndex; CVE-2021-37975 GC UAF in the wild; dex packing: encrypted at the file layer, plaintext at the memory layer, trust boundary at the loader (§4.2); CVE-2023-4762 type confusion in the wild |

The five patterns combine pairwise orthogonally into the complete generative grammar of runtime bugs: pattern 1×3 = the common base of V8 type confusion and heap attacks; pattern 2×5 = the GC/JIT race family; pattern 1×4 = the deserialization and expression-injection family. Fix correspondence: allowlists/parameterization dismantle pattern 1; invariant reconstruction with "checks and transforms in the same pass" dismantles pattern 2; metadata isolation (V8 sandbox/handle tables, heap-metadata validation) dismantles pattern 3; explicit typed exchange at boundaries dismantles pattern 4; single ownership dismantles pattern 5 — **every radical cure rewrites "implicit trust" into "explicit verification"**, which converges with the three leitmotifs of [injection-logic-root-causes.md](injection-logic-root-causes.md) §7 at a higher level.

## 7. Cross-Links

| Destination | Content |
|-------------|---------|
| [injection-logic-root-causes.md](injection-logic-root-causes.md) | Sister piece: interpreter boundaries/timing/mental models (data → syntax) |
| [memory-error-root-causes.md](memory-error-root-causes.md) | Sister piece: the master overview of memory-class root causes (stack/heap/UAF/races) |
| [kernel-vuln-root-cause-cases.md](kernel-vuln-root-cause-cases.md) | Sister piece: kernel case-by-case root causes and fix diffs |
| [06-binary-vuln/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) | V8 six-CVE pattern table, sandbox escapes, kernel comparison (technique layer) |
| [06-binary-vuln/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) | tcache evolution / 13 house-of forms / FSOP / mitigation bypasses (technique layer) |
| [05-web/code-audit.md](../05-web/code-audit.md) | CC1/Fastjson/Shiro evolution line, gadget originals (entrance surface) |
| [02-android/compiler-and-system.md](../02-android/compiler-and-system.md) · [file-formats.md](../02-android/file-formats.md) | ART/JIT/dex-oat formats (the format side of the dump root cause) |
| [01-windows/protection.md](../01-windows/protection.md) | VMP/junk code/opcode-obfuscation countermeasures (the technique side of §5) |
| `techniques/` | frida/unpacking/dex dump full chain |
