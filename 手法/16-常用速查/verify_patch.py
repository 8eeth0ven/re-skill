#!/usr/bin/env python3
# 补丁字节自验:capstone 反汇编校验 + unicorn 模拟执行演示「原函数返 0 → 补丁后返 1」
# 运行: tools-env/.venv/bin/python cve-hunter/verify_patch.py
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_32, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_X0
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP

# (名称, capstone架构, capstone模式, hex字节, 期望反汇编包含的助记)
PATTERNS = [
    ("arm64 NOP",              CS_ARCH_ARM64, 0, "1f2003d5", ["nop"]),
    ("arm64 返回1",             CS_ARCH_ARM64, 0, "200080 52c0035fd6".replace(" ", ""), ["mov\tw0, #1", "ret"]),
    ("arm64 返回0",             CS_ARCH_ARM64, 0, "00008052c0035fd6", ["mov\tw0, #0", "ret"]),
    ("arm NOP(mov r0,r0)",     CS_ARCH_ARM, CS_MODE_ARM, "00 00 a0 e1".replace(" ", ""), ["mov\tr0, r0"]),
    ("arm 返回1",               CS_ARCH_ARM, CS_MODE_ARM, "0100a0e31eff2fe1", ["mov\tr0, #1", "bx\tlr"]),
    ("thumb NOP",              CS_ARCH_ARM, CS_MODE_THUMB, "00bf", ["nop"]),
    ("thumb 返回1",             CS_ARCH_ARM, CS_MODE_THUMB, "0120 7047".replace(" ", ""), ["movs\tr0, #1", "bx\tlr"]),
    ("x86 NOP",                CS_ARCH_X86, CS_MODE_32, "90", ["nop"]),
    ("x86 返回1",               CS_ARCH_X86, CS_MODE_32, "b801000000c3", ["mov\teax, 1", "ret"]),
    ("x86 返回0(xor+ret)",     CS_ARCH_X86, CS_MODE_32, "31c0c3", ["xor\teax, eax", "ret"]),
    ("x86_64 NOP",             CS_ARCH_X86, CS_MODE_64, "90", ["nop"]),
    ("x86_64 返回1",            CS_ARCH_X86, CS_MODE_64, "b801000000c3", ["mov\teax, 1", "ret"]),
]


def disasm_check():
    ok = 0
    for name, arch, mode, hx, expect in PATTERNS:
        code = bytes.fromhex(hx)
        md = Cs(arch, mode)
        text = "; ".join(f"{i.mnemonic}\t{i.op_str}" for i in md.disasm(code, 0))
        good = all(e in text for e in expect)
        ok += good
        flag = "PASS" if good else "FAIL"
        print(f"[{flag}] {name}: {hx} -> {text or '(反汇编为空)'}")
    return ok


def unicorn_demo():
    """arm64: 原函数 mov w0,#0; ret(校验失败返0) → 补丁为 mov w0,#1; ret 后返 1
    注意 ret 跳 x30,必须先给 LR 设合法返回哨兵地址,否则 FETCH_UNMAPPED"""
    res = {}
    for label, hx in (("原函数", "00008052c0035fd6"), ("补丁后", "20008052c0035fd6")):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_map(0x2000, 0x1000)
        uc.mem_write(0x1000, bytes.fromhex(hx))
        uc.reg_write(UC_ARM64_REG_LR, 0x2000)
        uc.emu_start(0x1000, 0x2000)
        res[label] = uc.reg_read(UC_ARM64_REG_X0)
    print(f"[unicorn/arm64] {list(res)}  (原函数 x0={res['原函数']}, 补丁后 x0={res['补丁后']})")
    return res


def x86_demo():
    """x86 32 位: ret 弹栈跳转,须把返回哨兵 0x2000 压在栈上(esp 指向它)"""
    import struct
    res = {}
    for label, hx in (("原函数", "31c0c3"), ("补丁后", "b801000000c3")):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x1000, 0x4000)
        uc.mem_write(0x1000, bytes.fromhex(hx))
        uc.mem_write(0x3000, struct.pack("<I", 0x2000))
        uc.reg_write(UC_X86_REG_ESP, 0x3000)
        uc.emu_start(0x1000, 0x2000)
        res[label] = uc.reg_read(UC_X86_REG_EAX)
    print(f"[unicorn/x86] {list(res)}  (原函数 eax={res['原函数']}, 补丁后 eax={res['补丁后']})")
    return res


if __name__ == "__main__":
    n = disasm_check()
    a = unicorn_demo()
    x = x86_demo()
    print(f"\n结论: 反汇编 {n}/{len(PATTERNS)} PASS;arm64 原返0/补丁返1={'正确' if a['原函数']==0 and a['补丁后']==1 else '异常'};x86 同理={'正确' if x['原函数']==0 and x['补丁后']==1 else '异常'}")
