# OLLVM 原理与 Pass 源码

> 定位:混淆器**生成侧**源码级拆解——fla/split/bcf/跳转加密/字符串加密各 Pass 在 LLVM IR 层怎么写出来,及自写混淆 Pass 的完整套路;与 `去混淆实战.md`(逆向还原侧)互补:读懂数据结构与关键指令序列,去混淆识别器可按生成规则反推。

## 1. 混淆器总览与构建

### ollvm快速学习
作者:七少月

llvm-4.0.1 官方源码 vs ollvm(llvm-4.0 分支)BeyondCompare 对比(取消比较时间戳、仅文件模式),差异集中:`include/llvm/Transforms/obfuscation/` 6 个头——5 个对应编译参数 `fla`(控制流平展)/`sub`(指令替换)/`bcf`/`split`/`aesSeed`,`Utils.h` 是功能箱;`lib/Transforms/obfuscation/` 为 cpp 实现;注册靠 `lib/Transforms/CMakeLists.txt`+`LLVMBuild.txt` 加构建、`IPO/LLVMBuild.txt`+`PassManagerBuilder.cpp` 完成。

**Pass 注册链**(自写 Pass 铺路):`PassManagerBuilder.cpp` 导入头 → 加 cl::opt flag → 全局 `aesSeed` 初始化(`cryptoutils->prng_seed()`)→ `createSplit/createFlattening/createBogus/createSubstitution` 塞进管线 → 工厂函数在同名 .h 声明。**bcf 调用链**:`struct BogusControlFlow : public Pass`(ModulePass)→ `runOnModule` → `bogus(f)` → `addBogusFlow(BB1, BB2)` 核心;`CryptoUtils` 提供 `get_bytes/scramble32` 随机原语。

**phi 消除**:真实汇编无 phi,处理前用 `reg2mem` 打成 load/store:`b=phi(a1,a2)` → 两个前驱各 `store 值->slot`,使用处 `b=load slot`。**行业视角**:ollvm 需源码(二进制加固需自研反汇编引擎抽指令转虚拟指令);**只有 LLVMIR 时没有虚拟化,只有混淆**。

### Windows10 Android Studio3.6.1 安装使用 ollvm8.0(浓缩为命令节)
作者:天河霜雪

源码 GitHub `heroims/obfuscator` llvm-8.0 分支,CMake 生成 VS2019 工程编译 20-40 分钟;产物 `Release/bin/` clang.exe 等替换 NDK `toolchains/llvm/prebuilt/windows-x86_64/bin/` 同名文件(NDK 20.1),缺头从 NDK `sysroot/usr/include` 拷 `__stddef_max_align_t.h/float.h/stdarg.h/stddef.h`;`build.gradle` 启用混淆:`cppFlags "-mllvm -sub -mllvm -bcf -mllvm -fla"`。

## 2. 控制流平坦化 Pass 源码(Flattening)

### ollvm源码分析 - Pass之Flattening
作者:freakish

函数粒度 `FunctionPass`;`toObfuscate(flag, tmp, "fla")` 查 `__attribute__((annotate(("fla"))))` 或 `-mllvm -fla`,通过后 `flatten()`:

**① 种子 + ② 消除源 switch / 首块处理**:
```cpp
char scrambling_key[16];
llvm::cryptoutils->get_bytes(scrambling_key, 16);
createLowerSwitchPass()->runOnFunction(*f);   // 已有 switch 消成 if/else,统一按分发块处理
// 收集全部 BB 进 origBB;移出首块;首块终结符条件跳转或后继>1 时 splitBasicBlock(i,"first") 再分割
```

**③ 搭骨架**(CFG:首块写 state 初值 → loopEntry(load+switch)→ 各 case 块 ↔ loopEnd ← swDefault):
```cpp
switchVar = new AllocaInst(Int32Ty, 0, "switchVar", insert);
new StoreInst(ConstantInt::get(Int32Ty, cryptoutils->scramble32(0, key)), switchVar, insert);  // state 初值
load = new LoadInst(switchVar, "switchVar", loopEntry);    // loopEntry 内 load state
insert->moveBefore(loopEntry);  BranchInst::Create(loopEntry, insert);   // 首块→loopEntry
BranchInst::Create(loopEntry, loopEnd);  BranchInst::Create(loopEnd, swDefault);
switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);  switchI->setCondition(load);
```

**④ 填块进 switch**(case 值全过 `scramble32`——同一 so 不同函数 case 值无规律的原因;`i->moveBefore(loopEnd)` 仅视觉搬入无逻辑):
```cpp
for (遍历 origBB) {   // numCase = ConstantInt::get(condTy, scramble32(getNumCases(), key))
  switchI->addCase(numCase, i);
}
```

**⑤ 块尾改写**(按后继数三种):0 后继(返回块)不动;1 后继删终结符,查后继 case 值 `new StoreInst(numCase, load->getPointerOperand(), i)` + `br loopEnd`(写新 state 回 loopEnd 再分发);2 后继(条件跳转)用 `SelectInst` 折成 state 选择:
```cpp
ConstantInt *numCaseTrue  = switchI->findCaseDest(term->getSuccessor(0));
ConstantInt *numCaseFalse = switchI->findCaseDest(term->getSuccessor(1));
// 任一 NULL(后继是 default)时回退 scramble32(getNumCases()-1)
SelectInst *sel = SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "", term);
new StoreInst(sel, load->getPointerOperand(), i);  BranchInst::Create(loopEnd, i);
```
`findCaseDest(succ)` 在 switch 里反查后继块 case 值;真假两路 → `sel = cond ? caseTrue : caseFalse` 一次写入。

**IDA F5 最终形态**:
```c
int state = 0x123456;
while (true) switch (state) {
  case 0x654321: /*真实逻辑B*/ state=0x...; continue;   case 0x123456: /*真实逻辑A*/ state=0x...; continue; }
```

## 3. 基本块切分(SplitBasicBlocks)

### ollvm源码分析 - Pass之SplitBaiscBlocks
作者:freakish

Function 粒度 `FunctionPass`;`runOnFunction` 校验 `-mllvm -split_num=x` 区间 **(1,10]**,`toObfuscate(..., "split")` 后 `split()`:
```cpp
void SplitBasicBlock::split(Function *f) {
  std::vector<BasicBlock *> origBB;               // 收集全部 BB(省略有效性检查)
  for (遍历 origBB) {
    std::vector<int> test;
    for (unsigned i = 1; i < curr->size(); ++i) test.push_back(i);  // 生成 1..n-1
    if (test.size() != 1) { shuffle(test); std::sort(test.begin(), test.begin()+splitN); }
    BasicBlock::iterator it = curr->begin();  BasicBlock *toSplit = curr;  int last = 0;
    for (int i = 0; i < splitN; ++i) {
      for (int j = 0; j < test[i]-last; ++j) ++it;   last = test[i];       // 推进到切割点
      if (toSplit->size() >= 2) toSplit = toSplit->splitBasicBlock(it, name + ".split");  // 连切
    }
  }
}
```
**切割点算法**:n 条指令生成 `[1,n)` → 洗牌 → 只排前 splitN 个 → 这几个即切割位置(如 `[2,4,5]` 切成 4 段)。

**迭代器陷阱**:循环里复用的 `it` 不失效——`splitBasicBlock` 内部把 it 更新为**新块(后半段)的 begin()**,下轮 `++it` 以新块为基准。

`BasicBlock::splitBasicBlock` 本体语义(官方):切割点前指令留原块,剩余含终结符 splice 入新块(插原块后),原块尾补无条件跳转;并修正后继块 PHI 的 incoming block 从 this→New,否则语义破坏。PHI=SSA 约束产物:`a=1; if(v<10) a=2; b=a` → SSA 下 `b=PHI(a1,a2)`,按控制流到达路径取版本。

**效果**:每块切成 x+1 块,无条件跳转串联 `entry→entry.split→...`;**split 的意义是给 fla 供货**——块越碎,平坦化后 case 越多越随机。

## 4. 指令膨胀与花指令(自写壳/x86 生成侧)

### 自写保护壳交流——指令的膨胀和花指令的插入
作者:Wszzy

自写保护壳 = PE 处理/混淆虚拟化/保护;混淆引擎三件套:
1. **代码块拆分**:以跳转指令为界拆代码块,打属性标签(`JCC`/`NULL`/`End`);
2. **全局地址管理器**:混淆时不知下一区块膨胀后多大,须由管理器动态分配块地址并串起来(去重定位、按加载基址 0x401000 分块),配简易重定位;
3. **混淆过程 = 拆分 + 地址管理 + 指令膨胀 + 花指令**。

**指令膨胀(等价替换)**,`push 0x123456` → 离线算 `imm=(0x123456+0x111111)^0x22222`,运行时还原:
```asm
push eax;  mov eax, imm;  xor eax, 0x22222;  sub eax, 0x111111   ; 逆运算还原出 0x123456
push eax;  mov eax, dword ptr [esp+0x4]
```

**花指令插入**(`_flower_code` 全局开关按 %100 概率,asmjit 实现,三模式随机):
```cpp
void CodeObfuscationEngine::_insert_flower_code(asmjit::X86Assembler *&_a) {
  if (_insert_junk_code_number % 100 > _flower_code) return;
  switch (rand() % 3) {  // case 0/1: jmp 过 1 字节假 E8/E9 —— Label l=newLabel; jmp(l); db(0xE8/0xE9); bind(l)
  case 2: Label l = _a->newLabel(); int addr = rand()%0x66+0x5;    // call 跳过 0x74+rand 字节再平衡栈
          _a->call(l); _a->db(0x74); _a->db(addr); _a->bind(l); _a->add(esp, 4); break;
  }
}
```
模式 0/1 的「jmp 过单字节 E8/E9」正是逆向侧最常见「短跳过垃圾字节」花指令 pattern 的生成源;模式 2 用 call+add esp,4 制造假调用。

## 5. 逻辑运算等价推导(VMP 万用门 / OLLVM sub)

### 备忘录:一些逻辑运算的公式推导(VMP、OLLVM)
作者:天水姜伯约

原文"nand"实为 **nor**:`Nor(a,b)=~a&~b`(按原文公式形态沿用)。

**VMP 万用门**(一个门拼出全部逻辑):
```
Not(a)   = Nor(a, a)
Or(a,b)  = Nor(Nor(a,b), Nor(a,b))
And(a,b) = Nor(Nor(a,a), Nor(b,b))
Xor(a,b) = ~(a&b) | ~(~a&~b) = Nor(And(a,b), Nor(a,b)) = Nor(Nor(Nor(a,a),Nor(b,b)), Nor(a,b))
```
逆向价值:VMP handler 流里只见同一种双目运算反复自组合时,按万用门公式逆向展开即得真实逻辑。**算术恒等式**(EFLAGS 推导未严格证明,备查):`-a = ~a+1`;`a-b = ~(~a+b)`。

**OLLVM sub 三组等价式**:
```
a = b & c  →  a = (b ^ ~c) & b     [b^~c=(~b&~c)|(b&c),与 b 相与仍得 b&c]
a = b | c  →  a = (b & c) | (b ^ c)
a = a ^ b  →  a = (~a & b) | (a & ~b)   [定义式]
```
识别:碰上 `(x^~y)&x`、`(x&y)|(x^y)`、`(~x&y)|(x&~y)` 三种 IR/汇编形态直接折叠回 and/or/xor(d810 内置同款规则)。

## 6. 跳转加密(indirect branch)

### 对目前开源OLLVM的跳转加密混淆学习笔记
作者:wx_tuancc

**Hikari indirectBr**:条件 BR 生成 `[2 x i8*]` BrTable 存 2 个目标 label 符号,替换成 `gep(BrTable, zext(cmp结果))` 取 label 后 `indirectbr`;非条件 BR 用 GlobalTable 存所有目标 label,`gep(GlobalTable, index)`+`indirectbr`。x86 形态:非条件 `mov eax,[TableN]; jmp eax`;条件 `mov eax,[TableX+ecx*8]; jmp eax`。**弱点**:label 明文存表,直接读表即知真假目标。

**Goron indirectBr**(同框架两处强化):BrTable 存 `gep(label)+随机数` 偏移,运行时读出用 Key 解密——表中无明文地址;解密 Key **拆两半**(一半 store 进函数局部变量,另一半以常数参与 sub,跳转前汇合):
```asm
mov  [esp+n], key1
mov  ebx, [esp+n]
...FunctionCode
mov  eax, [TableX+ecx*8]
mov  edx, key2
sub  edx, ebx          ; key2-key1 = 真实解密偏移
add  eax, edx
jmp  eax
```
逆向侧手法:BR 前回溯 key1 的 store 槽位与 key2 常数,一次减法批量求出跳转表真值(见 `去混淆实战.md` §4 指令栈回溯)。

## 7. 字符串加密(三篇合一节)

### 对目前开源OLLVM的字符串加密混淆学习笔记
作者:wx_tuancc

**IR 先修**:字符串常量/字符数组都是 `ConstantDataSequential(CDS)`;匿名字面量 `@.str = private unnamed_addr constant`,具名 `@name = global/internal constant`,空串 `[1 x i8] zeroinitializer`。**常量表达式退化**:把 load/store/call 内嵌 gep/bitcast 提成独立指令(`getAsInstruction+setOperand` / `replaceUsesOfWith`),之后对 GV 的引用只剩「指令直接引用全局 CDS」或「经 CA/CS/i8* 间接引用」两种。

**Armariris**:遍历 CDS GV,按名 `.str`/`.str.` 判定(过滤 `llvm.metadata`/`__objc_methname`);`getRawDataValues().data()` 取原数据加密建新 GV,`replaceAllUsesWith` 替换;`appendToGlobalCtors` 建 ctor 统一解密,删原 GV。可加密所有 ANSI/UNICODE 常量;**不能加密字符串数组**(数组符号名不以 .str 开头)。

**Yag00**:`isString`(i8 数组)/`isCString`(i8+null) 过滤取数,加密建 `.encstr` 新 GV;再遍历指令改引用——`CallInst/InvokeInst`:参数 `dyn_cast<ConstantExpr>` 过滤 CE、GEP 型,`getPointerOperand()->getName()` 命中加密 GV 则 `setArgOperand` 换新 Alloc;`LoadInst`:`getPointerOperand()`→GV→CE→GEP 名称过滤,`replaceAllUsesWith`。解密生成:`AllocaInst` 缓冲 + `GEP(alloc,idx)`/`GEP(数组,idx)` 取密文 + Load + `CreateXor` + Store。可加密 const 数组;**不能**:非 const 数组、UNICODE(isString 只认 i8)、char 局部变量引用(IR 是 store GEP)、结构体内字符串、字符串数组读取引用(load(GEP) 而非 load(GV))。

**Hikari**(最复杂):遍历 Function 生成解密状态 GV(encstatus);BB→Inst→Operand,`dyn_cast<GlobalVariable>` 入 Globals/Usrs 表(`dyn_cast<User>` 递归展开间接引用)。Globals 过滤 `llvm.metadata`/objc;`NSConstantString_tag`(OC 串)取第 2 成员入 rawStrings;CDS 入 rawStrings;`ConstantArray` 遍历 Operands 把 GV 再入 Globals。rawStrings 按 getInt8/16/32/64Ty 生成 key 表与密文表(GV2Keys、old2new);objCStrings 用 `ConstantExpr::getInBoundsGetElementPtr` 造加密 ConstantStruct 入 old2new;`replaceUsesOfWith` 全量替换+删旧 GV。**解密块插入**(Function 入口三板斧):EntryBlock(A) 分割出 PrecedingBlock(C),中间插 StringDecryptionBB(B):Load(GEP)→Xor→Store 解密循环 + `CreateBr(C)`;A 中 `CreateLoad` 原子读 encstatus + `CreateICmpEQ` 条件分支「已解密→C / 未解密→B」;C 中 `CreateStore` 原子写状态(防重入)。可加密 const 与非 const 数组;**不能**:全局 char/wchar 变量引用的常量、结构体变量内字符串。

| 方案 | 定位方式 | 解密时机 | 数组 | UNICODE | 结构体内 |
|---|---|---|---|---|---|
| Armariris | 名称 .str 前缀 | ctor | × | ✓ | × |
| Yag00 | isString/isCString | 引用处前 | 仅const | × | × |
| Hikari | 遍历Operand+类型过滤 | Function入口+状态位 | ✓(含非const) | 部分 | × |

### 对目前开源OLLVM的字符串加密混淆总结
作者:wx_tuancc

设计空间三维:**加密范围 × 解密时机 × 解密存储位置**;范围=指令直接引用 CDS 或经 CA/CS/i8* 间接引用。时机:① **ctor** 兼容最好、覆盖几乎全部 CDS,但运行后全程明文 DUMP 即得,强度最低;② **Function 入口**只处理本函数引用、不管重复引用顺序,缺点进函数即全明文;③ **Instruction 前**执行到才解,性能最优范围最小,但要处理同函数对同一 CDS 的重复引用。

存储:① **段上**:任何时机 DUMP 进程内存都能拿执行过的明文;入口/指令前解密到段上还有解密状态与多线程重入问题(要加锁——开源方案均未处理);② **栈上**:用完即被覆盖,DUMP 整个进程也未必拿到明文,天然免疫多线程,**综合最优**;代价:解密串不能当常量用(不能做返回值/赋给全局或堆变量)、加密范围受限、高负载反复解密有性能损耗。

结论:段上解密与 ctor 时机无实际意义;「用后再加密」重入+性能问题严重不如栈上;可行方案收敛到 **Function 入口或 Instruction 前解密 + 栈上存储,放弃间接引用 CDS**。**VMProtect 参照**:`VMProtectDecryptString(str)` 包常量只覆盖指令直接引用 CDS(定义处不能调函数)= Instruction 前解密;实测解密串存**堆**(同一字符串只申请解密一次、后续直接返回指针),最大保护又无性能损耗,但堆申请用 IR 实现麻烦。

### 使用ollvm自定义简单的字符串加密
作者:misskings

**自写 Pass 四步**:① C++ 先实现加密算法并验证;② `clang -emit-llvm -S main.cpp -o main.ll` 生成参考 IR;③ Pass 按参考 IR 用 C++ API 造指令;④ 按参考 IR 造解密函数。

**算法**(迭代异或,末次取反再异或,kstr_size 控制轮数):
```cpp
int randkey = 11;                 // 演示固定,实战每字节 cryptoutils->get_uint8_t()
int enclen = randkey + kstr_size;
for (i in len) for (y = randkey; y < enclen; y++)
    enc[i] = (y==randkey) ? str[i]^y : (y==enclen-1) ? enc[i]^(~y) : enc[i]^y;
// 解密:y 从 enclen-1 降到 randkey,y==enclen-1 时先 ^~y,其余 ^y
```

**Pass 骨架**(kstr 名注册,toObfuscate 走 annotate/kstr flag):
```cpp
struct KStringEncode : public FunctionPass {
  static char ID;  bool flag;
  bool runOnFunction(Function &F) {
    if (!(KStringSize > 0 && KStringSize <= 0x20)) { /* 报错返回 */ }
    if (toObfuscate(flag, &F, "kstr")) { kstr(F); return true; }
    return false; }   void kstr(Function &func);
};
// (省略:ID 初始化 / RegisterPass 注册 / createKStringEncode 工厂——与 ollvm 内置 pass 同套路)
```

**字符串定位**:字符串在 IR 里是指令 operand(`@.str = private unnamed_addr constant [15 x i8] c"hello world!!!\00"`);三重遍历 Function→BasicBlock→Instruction→operands(),`stripPointerCasts()` 后 `contains(".str")` 过滤;取内容:
```cpp
std::string ConvertOpToString(Value* op) {
  GlobalVariable* gv = dyn_cast<GlobalVariable>(op);   if (!gv) return "";
  ConstantDataSequential* cds = dyn_cast<ConstantDataSequential>(gv->getInitializer());
  if (!cds) return "";   return cds->getRawDataValues();
}
```

**解密 IR 生成**(定位处逐条造指令,`insertBefore/insertAfter` 控序;缓冲 = `[N x i8]` alloca + bitcast i8* + 结果 alloca):
```cpp
for (i in strdata) {
  element = GetElementPtrInst::CreateInBounds(bitInst, i_const);          // &buf[i]
  for (y = enclen-1; y >= randkey; y--) {  // y 常数 alloca+store 再 load 回来
    // y==enclen-1: CreateNot(~y)→CreateXor(enc_const,notOp)→store eor_res
    // else: load 上轮 eor_res→CreateXor(prev,eor_load)→store;y==randkey 记尾锚点
  }
  new StoreInst(load(eor_res), element);   // 最终明文写入 buf[i]
}  // 结尾:val->replaceAllUsesWith(bitInst) 改指解密缓冲;eraseFromParent() 删明文 GV
```

**作用域坑**:同一字面串两处使用(两处 `printf("hello")`)在汇编层合并为一个字符串,使用处解密时另一分支可能访问不到 bitcast(不在同作用域)。**解法:记录函数第一条指令 `begin_ins`,全部解密指令统一插函数最开头**;遍历中改指令流要先缓存 `begin_ins` 再动 IR。

## 8. fla 在 ARM 上的落地产物与真实块/控制块判据

### 细说arm反类ollvm混淆-基本思想
作者:my1988

thumb+fla 实测,运行模型:`[真实块]→[控制块(0..n个)]→[下一个真实块]→...`。真实块做完原逻辑后 `MOV R0,#imm` 写分发寄存器;控制块只按 R0 `CMP+B.EQ/B.NE` 链式比较(可经多个中转块)落到下一真实块——正是 §2 Flattening `store state→loopEnd→switch` 的 ARM lowered 形态(state 落 R0/局部变量,switch 落成 CMP 链)。

**关键判据(可静态识别)**:
1. **控制块特征**:极短、只有寄存器操作、无内存操作、尾 `cmp+跳转`;不同厂商细节有别,反混淆程序用多态/适配器隔离;识别出的控制块可直接清零(修复后不执行,免干扰 IDA);
2. **真实块特征**:输入与分发控制块**数据流不相交**(真实块输入是 var_20 等局部变量,与控制块读写的 R0 等分发寄存器无交集)——判真实/控制块的硬标准;
3. 控制块只起「决定下一个真实块」的分发作用:知道真实块前后关系后直接 B/BNE 连起来跳过全部控制块,程序依然正确。

**前后关系确定**(静态太慢,走 trace):① IDA 动态:每指令下断点改属性 `BPT_TRACE`(不停下只触发回调),回调记录地址+寄存器现场,产出逐指令 trace(`0x0001CA34: ADD R5,SP,#0X208 ;(SP=0x100FF248)` 形态);② 模拟执行 unidbg/AndroidNativeEmu 系(补 syscall+JNI),无视反调试。从 trace 提后继:真实块 A 定位到 trace 位置 n,从 n+1 起遇控制块跳过,第一个真实块 B 的首指令即 A 的后继;双后继块靠多组输入 trace 分别覆盖两路径。**局限**:未覆盖分支丢失(还原的是被执行逻辑,非 100%),但天然滤掉 bcf 虚假块;**通用性**:不限 ollvm,适用一切「真实块+分发控制块」类 fla 混淆(实测多款视频 app 与加固 so),区别仅控制块识别微调。**patch 注意**:真实块尾不能盲 patch——尾部 `BL` 等有逻辑意义的调用指令不能覆盖,需逐类分析可覆盖性。
