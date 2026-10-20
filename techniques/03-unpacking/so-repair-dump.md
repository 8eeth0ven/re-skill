# so repair dump

> Covers: parsing the soinfo struct (offset table), solist traversal, the full dumpSoFromSoInfo code, offset-drift hints such as 0x7a40, and post-dump so repair essentials (segment write-back / symbol tables).

## 1. Background

After an encrypted/hardened so finishes decrypting and relocating in memory, a blind dump taken straight off `module.base` + `module.size` yields a "memory-state" file: no notion of file offsets, misaligned segments, and possibly wiped symbol tables. The right way is to obtain the so's phdr/dynamic/strtab/symtab/rela table addresses through linker's **soinfo** struct, then write each segment back onto the file layout per the program headers' `p_offset`, restoring a so that IDA can analyze normally.

Two routes to obtain the soinfo:
1. **solist traversal** (this doc): take the list head from linker64's `__dl__ZL6solist` symbol and walk it to find the target so's soinfo.
2. **call_constructors interception** (the init_array hook in `../02-frida/native-hook-cheatsheet.md`): at onEnter, `args[0]` is exactly the soinfo pointer.

## 2. Parsing the soinfo struct (offset table)

Key soinfo field offsets for the 64-bit linker (matching roughly the Android 9 linker64; for other versions see the drift notes in section 5):

| Offset | Field | Meaning |
|------|------|------|
| 0 | phdr | program header table pointer |
| 16 | base | so load base |
| 24 | size | occupied size |
| 32 | dynamic | dynamic section pointer |
| 40 | _next | where the next soinfo in the list lives (the pointer storage) |
| 56 | strtab | dynamic string table |
| 64 | symtab | dynamic symbol table |
| 104 | plt_rela | PLT relocation table (.rela.plt) |
| 112 | plt_rela_count | PLT relocation count |
| 120 | rela | data relocation table (.rela.dyn, used by R_AARCH64_GLOB_DAT) |
| 128 | rela_count | data relocation count |
| 152 | init_array | init function array |
| 160 | init_array_count | init count |
| 168 | fini_array | fini function array |
| 176 | fini_array_count | fini count |
| 184 | init_func | init function |
| 192 | fini_func | fini function |
| 208 | link_map_head.l_addr | link_map start |
| 216 | link_map_head.l_name | so name pointer |
| 248 | load_bias | load bias (needed to compute real addresses) |
| 432 | realpath | full path as a std::string |

### 2.1 parseSoInfo: parse a soinfo pointer into an object

```javascript
function parseSoInfo(soinfo_addr) {
    return {
        soinfo_addr: soinfo_addr,
        phdr: soinfo_addr.add(0).readPointer(),
        base: soinfo_addr.add(16).readPointer(),
        size: soinfo_addr.add(24).readULong(),
        dynamic: soinfo_addr.add(32).readPointer(),
        _next: soinfo_addr.add(40),
        strtab: soinfo_addr.add(56).readPointer(),
        symtab: soinfo_addr.add(64).readPointer(),
        plt_rela: soinfo_addr.add(104).readPointer(),
        plt_rela_count: soinfo_addr.add(112).readULong(),
        rela: soinfo_addr.add(120).readPointer(),
        rela_count: soinfo_addr.add(128).readULong(),
        init_array: soinfo_addr.add(152).readPointer(),
        init_array_count: soinfo_addr.add(160).readULong(),
        fini_array: soinfo_addr.add(168).readPointer(),
        fini_array_count: soinfo_addr.add(176).readULong(),
        init_func: soinfo_addr.add(184).readPointer(),
        fini_func: soinfo_addr.add(192).readPointer(),
        link_map_head: {
            l_addr: soinfo_addr.add(208),
            l_name: soinfo_addr.add(216).readPointer()
        },
        load_bias: soinfo_addr.add(248).readPointer(),

        getStrtabSize: function () {
            // 通过ELF头部和动态段获取字符串表大小
            let currentDyn = this.dynamic;
            while (true) {
                const d_tag = Number(currentDyn.readULong());
                // DT_NULL (0) 标记动态段结束
                if (d_tag === 0) break;

                // DT_STRSZ (10) 包含字符串表大小
                if (d_tag === 10) {
                    const strSize = currentDyn.add(8).readULong();
                    console.log(`从动态段获取到字符串表大小: ${strSize}`);
                    return strSize;
                }

                // 移动到下一个动态段条目 (Elf64_Dyn 结构体大小为16字节)
                currentDyn = currentDyn.add(16);
            }
            return 4096;  // 默认假设至少有4KB的字符串表

        },
        next: function () {
            return parseSoInfo(this._next.readPointer())
        },

        // 一般都是空的
        getSoname: function () {
            return this.link_map_head.l_name.readUtf8String()
        },

        // 获取std::string的字符串内容
        // 一般都有值，可能有问题，有问题std::string，但是我还是实现了，因为爱情
        getRealpath: function () {
            const realpath_addr = soinfo_addr.add(432);
            return readStdString(realpath_addr);
        }
    };
}
```

### 2.2 parseElf64_Rela: a relocation entry (0x18 bytes)

```javascript
// 0x18大小
function parseElf64_Rela(rela_addr) {
    return {
        r_offset: rela_addr.readULong(),
        r_info: rela_addr.add(8).readULong(),
        r_addend: rela_addr.add(16).readLong()
    };
}
```

### 2.3 parseElf64_Sym: a symbol entry (0x18 bytes)

```javascript
// 0x18大小
function parseElf64_Sym(sym_addr) {
    return {
        st_name: sym_addr.readU32(),
        st_info: sym_addr.add(4).readU8(),
        st_other: sym_addr.add(5).readU8(),
        st_shndx: sym_addr.add(6).readU16(),
        st_value: sym_addr.add(8).readPointer(),
        st_size: sym_addr.add(16).readULong(),

        // 辅助方法：获取符号类型
        getType: function () {
            return this.st_info & 0xf; // ELF32_ST_TYPE(i) ((i)&0xf)
        },

        // 辅助方法：获取符号绑定属性
        getBind: function () {
            return this.st_info >> 4; // ELF32_ST_BIND(i) ((i)>>4)
        }
    };
}
```

### 2.4 readStdString: read a std::string inside soinfo

```javascript
function readStdString(str_addr) {
    // 小字符串优化情况 - 通常在23字节内的字符串直接存储在对象中
    try {
        // 长字符串情况 - 第一个8字节是指向实际字符串的指针
        const str_ptr = str_addr.readPointer();
        return str_ptr.readUtf8String();
    } catch {
        console.log(str_addr.sub(15).readUtf8String())
        return str_addr.sub(15).readUtf8String();
    }
}
```

## 3. solist traversal

### 3.1 getSoInfoHead: take the list head from linker64

```javascript
function getSoInfoHead() {
    const module = Process.findModuleByName("linker64");
    const symbols = module.enumerateSymbols();
    let soInfoHead = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        if (symbol.name.indexOf("__dl__ZL6solist") !== -1) {
            soInfoHead = symbol.address;
            break;
        }
    }
    if (!soInfoHead) {
        throw new Error("linker解析错误")
    }
    return soInfoHead.readPointer();
}
```

### 3.2 readLinkMap: read the link_map struct

```javascript
function readLinkMap(linkMapAddr) {
    // 读取link_map结构体
    const l_addr = linkMapAddr.readPointer();   // ElfW(Addr) l_addr
    const l_name_ptr = linkMapAddr.add(Process.pointerSize).readPointer();  // char* l_name
    const l_ld = linkMapAddr.add(Process.pointerSize * 2).readPointer();  // ElfW(Dyn)* l_ld
    const l_next = linkMapAddr.add(Process.pointerSize * 3).readPointer();  // struct link_map* l_next
    const l_prev = linkMapAddr.add(Process.pointerSize * 4).readPointer();  // struct link_map* l_prev

    // 读取l_name指向的字符串
    let l_name = "";
    if (!l_name_ptr.isNull()) {
        l_name = l_name_ptr.readUtf8String();
    }

    return {
        l_addr: l_addr,
        l_name: l_name,
        l_ld: l_ld,
        l_next: l_next,
        l_prev: l_prev
    };
}
```

### 3.3 getSoInfo: walk the solist by so name to find the soinfo

```javascript
function getSoInfo(so_name) {
    let soInfo = parseSoInfo(getSoInfoHead())
    while (true) {
        let realPath;
        realPath = soInfo.getSoname()
        if (realPath && realPath.indexOf(so_name) !== -1) {
            console.log(realPath)
            return soInfo
        }
        try {
            soInfo = soInfo.next()
        } catch (e) {
            break
        }
    }
}
```

With this function you can directly print a so's key layout info (base, init sections, rela, plt, string table, symbol table); a complete example is `getPltAddr` in `../02-frida/advanced/gothook.md`.

## 4. The full dumpSoFromSoInfo code

Reconstructing an SO file from soinfo: write the in-memory segments back to their correct file offsets per the program headers, then patch in the dynamic section, symbol table, string table, and relocation tables.

```javascript
// 从soInfo重构SO文件
function dumpSoFromSoInfo(soInfo, outputPath) {
    // 获取内存映射信息，查找目标SO的所有段
    const soBase = soInfo.base;
    const soSize = soInfo.size;

    console.log(`开始导出SO: 基址=${soBase}, 大小=${soSize}`);

    // 创建文件句柄
    const file = new File(outputPath, "wb");
    if (file === null) {
        throw new Error(`无法创建输出文件: ${outputPath}`);
    }

    // 遍历所有段并写入文件
    try {
        // 读取完整ELF头
        const elfHeader = Memory.readByteArray(soBase, 64);  // ELF头通常为64字节
        file.write(elfHeader);
        console.log("已写入ELF头");

        // 获取程序头表信息
        const phdr = soInfo.phdr;
        const e_phnum = soBase.add(56).readU16();  // ELF64头部中e_phnum的偏移量为56
        const e_phentsize = soBase.add(54).readU16();  // ELF64头部中e_phentsize的偏移量为54
        console.log(`程序头表数量: ${e_phnum}, 每个条目大小: ${e_phentsize}`);

        // 读取和写入程序头表
        const phdrSize = e_phnum * e_phentsize;
        const phdrData = Memory.readByteArray(phdr, phdrSize);
        file.write(phdrData);
        console.log("已写入程序头表");

        // 遍历程序头表，获取每个段的信息
        for (let i = 0; i < e_phnum; i++) {
            const phdrEntry = phdr.add(i * e_phentsize);
            const p_type = Number(phdrEntry.readU32());

            // 只处理LOAD类型的段 (p_type = 1)
            if (p_type === 1) {
                const p_offset = phdrEntry.add(8).readU64();
                const p_vaddr = phdrEntry.add(16).readPointer();
                const p_filesz = phdrEntry.add(32).readU64();

                if (p_filesz > 0) {
                    // 计算内存中的实际地址
                    const segmentAddr = soBase.add(p_vaddr.sub(soInfo.load_bias));
                    // 设置文件偏移
                    file.seek(p_offset);

                    // 读取段内容并写入文件
                    try {
                        const segmentData = Memory.readByteArray(segmentAddr, p_filesz);
                        file.write(segmentData);
                        console.log(`已写入段: 偏移=${p_offset}, 地址=${segmentAddr}, 大小=${p_filesz}`);
                    } catch (e) {
                        console.error(`读取段时出错: ${e.message}`);
                    }
                }
            }
        }

        // 写入动态段
        if (!soInfo.dynamic.isNull()) {
            // 找到动态段的文件偏移
            for (let i = 0; i < e_phnum; i++) {
                const phdrEntry = phdr.add(i * e_phentsize);
                const p_type = phdrEntry.readU32();

                // 动态段 (p_type = 2)
                if (p_type === 2) {
                    const p_offset = phdrEntry.add(8).readU64();
                    const p_filesz = phdrEntry.add(32).readU64();

                    // 设置文件偏移
                    file.seek(p_offset);

                    // 读取动态段内容并写入文件
                    const dynamicData = Memory.readByteArray(soInfo.dynamic, p_filesz);
                    file.write(dynamicData);
                    console.log(`已写入动态段: 偏移=${p_offset}, 大小=${p_filesz}`);
                    break;
                }
            }
        }

        // 写入符号表和字符串表
        if (!soInfo.symtab.isNull() && !soInfo.strtab.isNull()) {
            // 计算符号表和字符串表的大小
            // 这里简化处理，实际应该通过动态段的DT_STRSZ和DT_SYMENT等项计算
            // 符号表大小估算（可能不精确）
            let symtabSize = 0;
            let strtabSize = 0;
            // 尝试通过遍历动态段找到符号表大小
            let currentDyn = soInfo.dynamic;
            while (true) {
                const d_tag = Number(currentDyn.readULong());
                if (d_tag === 0) break; // DT_NULL

                // DT_STRSZ (10) 包含字符串表大小
                if (d_tag === 10){
                    strtabSize = currentDyn.add(8).readULong();
                }

                // DT_SYMENT (11) 表示符号表条目大小
                if (d_tag === 11) {
                    const entrySize = currentDyn.add(8).readULong();
                    // 粗略估计符号表总条目数
                    symtabSize = soInfo.rela_count * entrySize;
                }

                currentDyn = currentDyn.add(16); // 移动到下一个动态条目
            }

            // 在文件中找到符号表和字符串表的偏移
            for (let i = 0; i < e_phnum; i++) {
                const phdrEntry = phdr.add(i * e_phentsize);
                const p_type = phdrEntry.readU32();

                if (p_type === 1) { // LOAD类型
                    const p_vaddr = phdrEntry.add(16).readPointer();
                    const p_offset = phdrEntry.add(8).readU64();
                    const p_memsz = phdrEntry.add(40).readU64();

                    // 检查符号表地址是否在这个段内
                    if (soInfo.symtab.compare(soBase.add(p_vaddr.sub(soInfo.load_bias))) >= 0 &&
                        soInfo.symtab.compare(soBase.add(p_vaddr.sub(soInfo.load_bias)).add(p_memsz)) < 0) {

                        const symtabOffset = soInfo.symtab.sub(soBase.add(p_vaddr.sub(soInfo.load_bias))).add(p_offset);
                        file.seek(symtabOffset.toUInt32());
                        const symtabData = soInfo.symtab.readByteArray(symtabSize);
                        file.write(symtabData);
                        console.log(`已写入符号表: 偏移=${symtabOffset}, 大小=${symtabSize}`);
                    }

                    // 检查字符串表地址是否在这个段内
                    if (soInfo.strtab.compare(soBase.add(p_vaddr.sub(soInfo.load_bias))) >= 0 &&
                        soInfo.strtab.compare(soBase.add(p_vaddr.sub(soInfo.load_bias)).add(p_memsz)) < 0) {

                        const strtabOffset = soInfo.strtab.sub(soBase.add(p_vaddr.sub(soInfo.load_bias))).add(p_offset);
                        file.seek(strtabOffset.toUInt32());
                        const strtabData = soInfo.strtab.readByteArray(strtabSize);
                        file.write(strtabData);
                        console.log(`已写入字符串表: 偏移=${strtabOffset}, 大小=${strtabSize}`);
                    }
                }
            }
        }

        // 写入重定位表
        if (!soInfo.rela.isNull() && soInfo.rela_count > 0) {
            const relaSize = soInfo.rela_count * 24; // Elf64_Rela结构体大小为24字节

            // 查找重定位表在文件中的偏移
            for (let i = 0; i < e_phnum; i++) {
                const phdrEntry = phdr.add(i * e_phentsize);
                const p_type = phdrEntry.readU32();

                if (p_type === 1) { // LOAD类型
                    const p_vaddr = phdrEntry.add(16).readPointer();
                    const p_offset = phdrEntry.add(8).readU64();
                    const p_memsz = phdrEntry.add(40).readU64();

                    // 检查重定位表地址是否在这个段内
                    if (soInfo.rela.compare(soBase.add(p_vaddr.sub(soInfo.load_bias))) >= 0 &&
                        soInfo.rela.compare(soBase.add(p_vaddr.sub(soInfo.load_bias)).add(p_memsz)) < 0) {

                        const relaOffset = soInfo.rela.sub(soBase.add(p_vaddr.sub(soInfo.load_bias))).add(p_offset);
                        file.seek(relaOffset.toUInt32());
                        const relaData = soInfo.rela.readByteArray(relaSize);
                        file.write(relaData);
                        console.log(`已写入重定位表(Rela): 偏移=${relaOffset}, 大小=${relaSize}`);
                    }
                }
            }
        }

        // 写入PLT重定位表
        if (!soInfo.plt_rela.isNull() && soInfo.plt_rela_count > 0) {
            const pltRelaSize = soInfo.plt_rela_count * 24; // Elf64_Rela结构体大小为24字节

            // 查找PLT重定位表在文件中的偏移
            for (let i = 0; i < e_phnum; i++) {
                const phdrEntry = phdr.add(i * e_phentsize);
                const p_type = phdrEntry.readU32();

                if (p_type === 1) { // LOAD类型
                    const p_vaddr = phdrEntry.add(16).readPointer();
                    const p_offset = phdrEntry.add(8).readU64();
                    const p_memsz = phdrEntry.add(40).readU64();

                    // 检查PLT重定位表地址是否在这个段内
                    if (soInfo.plt_rela.compare(soBase.add(p_vaddr.sub(soInfo.load_bias))) >= 0 &&
                        soInfo.plt_rela.compare(soBase.add(p_vaddr.sub(soInfo.load_bias)).add(p_memsz)) < 0) {

                        const pltRelaOffset = soInfo.plt_rela.sub(soBase.add(p_vaddr.sub(soInfo.load_bias))).add(p_offset);
                        file.seek(pltRelaOffset.toUInt32());
                        const pltRelaData = soInfo.plt_rela.readByteArray(pltRelaSize);
                        file.write(pltRelaData);
                        console.log(`已写入PLT重定位表: 偏移=${pltRelaOffset}, 大小=${pltRelaSize}`);
                    }
                }
            }
        }

        console.log(`SO文件导出成功: ${outputPath}`);
        return true;
    } catch (e) {
        console.error(`导出SO时出错: ${e.message}, ${e.stack}`);
        return false;
    } finally {
        file.close();
    }
}

// 使用示例
function dumpSo(soInfo, outputPath) {
    return dumpSoFromSoInfo(soInfo, outputPath);
}

// 将函数导出到RPC
rpc.exports = {
    dumpSo
}
```

## 5. Offset-drift notes

soinfo field offsets differ across linker versions; when switching device/system they must be re-verified:

```
// 0x48D438 - 0x4859f8
// 0x7a40
```

- The two addresses (`0x48D438 - 0x4859f8`) are a real address-range example related to symtab/strtab from one engagement; `0x7a40` is the drift value of one soinfo struct relative to the standard offsets on that device.
- In practice: open the target device's `linker64` in IDA first (path `/system/bin/linker64`), locate the `soinfo` struct, and adjust this doc's offset table field by field to the current version; or hook `call_constructors` to grab a soinfo pointer and back-derive each field's actual offset from `getSoname`/`base`.
- On 32-bit it is `linker` instead of `linker64`, the pointer width is 4 bytes, and the offset table is completely different.

## 6. Post-dump so repair essentials

1. **Segment write-back**: the core of dumping is writing memory contents back onto the file layout per the program headers' `p_offset` (already implemented in dumpSoFromSoInfo above); writing `Memory.readByteArray(base, size)` straight to disk is memory-state with misaligned segments.
2. **Symbol/string tables**: packers often wipe or relocate strtab/symtab. The `strtab`/`symtab` pointers in soinfo are the addresses the linker actually uses after relocation — when dumping, trust soinfo over the stale values in the ELF header; when writing into the file, convert them to file offsets within the corresponding LOAD segment.
3. **Relocation tables**: `.rela.plt` (plt_rela) and `.rela.dyn` (rela) must each be written back, otherwise imported functions in IDA are all bare addresses with no names.
4. **ELF header checks**: if IDA cannot open the dump, check the ELF header's `e_shoff`/`e_shnum` first (the runtime loader does not need section headers, and the packer may have zeroed them; without a section table IDA degrades to program-header analysis — you can also rebuild a section table by hand).
5. **load_bias for real addresses**: mind `load_bias` when converting between the soInfo `base` and the program headers' `p_vaddr`; the code above uniformly uses `soBase.add(p_vaddr.sub(soInfo.load_bias))`.

## Related docs

- GOT hooking also uses soinfo (getPltAddr/GotHook/soListRemove): [../02-frida/advanced/gothook.md](../02-frida/advanced/gothook.md)
- Waiting on dynamically loaded so (waitForModule), the call_constructors hook: [../02-frida/native-hook-cheatsheet.md](../02-frida/native-hook-cheatsheet.md)
- dex unpacking: [dex-unpacking.md](dex-unpacking.md)
