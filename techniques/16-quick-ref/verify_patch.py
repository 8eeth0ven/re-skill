#!/usr/bin/env python3
# Patch-byte self-check: capstone disassembly verification + unicorn emulated demo of "original returns 0 -> patched returns 1"
# Run: tools-env/.venv/bin/python techniques/16-quick-ref/verify_patch.py
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_32, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_X0
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP

# (name, capstone arch, capstone mode, hex bytes, expected mnemonics contained in the disassembly)
PATTERNS = [
    ("arm64 NOP",              CS_ARCH_ARM64, 0, "1f2003d5", ["nop"]),
    ("arm64 return1",             CS_ARCH_ARM64, 0, "200080 52c0035fd6".replace(" ", ""), ["mov\tw0, #1", "ret"]),
    ("arm64 return0",             CS_ARCH_ARM64, 0, "00008052c0035fd6", ["mov\tw0, #0", "ret"]),
    ("arm NOP(mov r0,r0)",     CS_ARCH_ARM, CS_MODE_ARM, "00 00 a0 e1".replace(" ", ""), ["mov\tr0, r0"]),
    ("arm return1",               CS_ARCH_ARM, CS_MODE_ARM, "0100a0e31eff2fe1", ["mov\tr0, #1", "bx\tlr"]),
    ("thumb NOP",              CS_ARCH_ARM, CS_MODE_THUMB, "00bf", ["nop"]),
    ("thumb return1",             CS_ARCH_ARM, CS_MODE_THUMB, "0120 7047".replace(" ", ""), ["movs\tr0, #1", "bx\tlr"]),
    ("x86 NOP",                CS_ARCH_X86, CS_MODE_32, "90", ["nop"]),
    ("x86 return1",               CS_ARCH_X86, CS_MODE_32, "b801000000c3", ["mov\teax, 1", "ret"]),
    ("x86 return0(xor+ret)",     CS_ARCH_X86, CS_MODE_32, "31c0c3", ["xor\teax, eax", "ret"]),
    ("x86_64 NOP",             CS_ARCH_X86, CS_MODE_64, "90", ["nop"]),
    ("x86_64 return1",            CS_ARCH_X86, CS_MODE_64, "b801000000c3", ["mov\teax, 1", "ret"]),
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
        print(f"[{flag}] {name}: {hx} -> {text or '(empty disassembly)'}")
    return ok


def unicorn_demo():
    """arm64: original mov w0,#0; ret (check failed returns 0) -> after patching to mov w0,#1; ret it returns 1
    Note that ret jumps to x30, so LR must first be set to a valid return sentinel, otherwise FETCH_UNMAPPED"""
    res = {}
    for label, hx in (("原函数", "00008052c0035fd6"), ("补丁后", "20008052c0035fd6")):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_map(0x2000, 0x1000)
        uc.mem_write(0x1000, bytes.fromhex(hx))
        uc.reg_write(UC_ARM64_REG_LR, 0x2000)
        uc.emu_start(0x1000, 0x2000)
        res[label] = uc.reg_read(UC_ARM64_REG_X0)
    print(f"[unicorn/arm64] original / patched  (original x0={res['原函数']}, patched x0={res['补丁后']})")
    return res


def x86_demo():
    """x86 32-bit: ret pops the stack to jump, so the return sentinel 0x2000 must be pushed on the stack (esp pointing at it)"""
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
    print(f"[unicorn/x86] original / patched  (original eax={res['原函数']}, patched eax={res['补丁后']})")
    return res


if __name__ == "__main__":
    n = disasm_check()
    a = unicorn_demo()
    x = x86_demo()
    print(f"\nResult: disassembly {n}/{len(PATTERNS)} PASS;arm64 original returns0/patched returns1={'correct' if a['原函数']==0 and a['补丁后']==1 else 'unexpected'};x86 same check={'correct' if x['原函数']==0 and x['补丁后']==1 else 'unexpected'}")

    success = n == len(PATTERNS) and a["原函数"] == 0 and a["补丁后"] == 1 and x["原函数"] == 0 and x["补丁后"] == 1
    raise SystemExit(0 if success else 1)
