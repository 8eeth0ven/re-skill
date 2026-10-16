# so 修复 dump

> 覆盖:soinfo 结构解析(偏移表)、solist 遍历、dumpSoFromSoInfo 完整代码、0x7a40 等偏移差异提示、dump 后 so 修复要点(段回填/符号表)。

## 一、背景

加密/加固的 so 在内存中完成解密与重定位后,直接按 `module.base` + `module.size` 盲 dump 出来的文件是「内存态」的:没有文件偏移概念、段错位、符号表可能被壳抹掉。正确姿势是通过 linker 的 **soinfo** 结构拿到该 so 的 phdr/dynamic/strtab/symtab/rela 表地址,再按程序头的 `p_offset` 把各段回填到文件布局上,还原出一个 IDA 可以正常分析的 so。

获取 soinfo 的两条路:
1. **solist 遍历**(本文):从 linker64 的 `__dl__ZL6solist` 符号拿到链表头,遍历找到目标 so 的 soinfo。
2. **call_constructors 拦截**(`02-frida/native层hook速查.md` 的 init_array hook):onEnter 时 `args[0]` 就是 soinfo 指针。

## 二、soinfo 结构解析(偏移表)

64 位 linker 的 soinfo 关键字段偏移(对应 Android 9 左右的 linker64,其他版本见第五节差异提示):

| 偏移 | 字段 | 含义 |
|------|------|------|
| 0 | phdr | 程序头表指针 |
| 16 | base | so 加载基址 |
| 24 | size | 占用大小 |
| 32 | dynamic | 动态段指针 |
| 40 | _next | 链表下一个 soinfo 的位置(指针存储处) |
| 56 | strtab | 动态字符串表 |
| 64 | symtab | 动态符号表 |
| 104 | plt_rela | PLT 重定位表(.rela.plt) |
| 112 | plt_rela_count | PLT 重定位条数 |
| 120 | rela | 数据重定位表(.rela.dyn,R_AARCH64_GLOB_DAT 用) |
| 128 | rela_count | 数据重定位条数 |
| 152 | init_array | init 函数数组 |
| 160 | init_array_count | init 条数 |
| 168 | fini_array | fini 函数数组 |
| 176 | fini_array_count | fini 条数 |
| 184 | init_func | init 函数 |
| 192 | fini_func | fini 函数 |
| 208 | link_map_head.l_addr | link_map 起始 |
| 216 | link_map_head.l_name | so 名字指针 |
| 248 | load_bias | 加载偏置(算真实地址要用) |
| 432 | realpath | std::string 的完整路径 |

### 2.1 parseSoInfo:把 soinfo 指针解析成对象

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

### 2.2 parseElf64_Rela:重定位条目(0x18 大小)

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

### 2.3 parseElf64_Sym:符号条目(0x18 大小)

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

### 2.4 readStdString:读 soinfo 里的 std::string

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

## 三、solist 遍历

### 3.1 getSoInfoHead:从 linker64 拿链表头

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

### 3.2 readLinkMap:读 link_map 结构体

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

### 3.3 getSoInfo:按 so 名遍历 solist 找 soinfo

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

利用这个函数可以直接打印 so 的关键布局信息(基址、init 段、rela 段、plt 段、字符串表、符号表),完整示例见 `../02-frida/高级/gothook.md` 的 `getPltAddr`。

## 四、dumpSoFromSoInfo 完整代码

从 soinfo 重构 SO 文件:按程序头把内存中的段回填到正确的文件偏移上,再补写动态段、符号表、字符串表、重定位表。

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

## 五、偏移差异提示

不同版本 linker 的 soinfo 字段偏移不一样,换设备/系统必须重新核对:

```
// 0x48D438 - 0x4859f8
// 0x7a40
```

- 两个地址(`0x48D438 - 0x4859f8`)是某次实战中 symtab/strtab 相关的真实地址区间示例;`0x7a40` 是该机型上某 soinfo 结构相对标准偏移的差异值。
- 实操方法:先用 IDA 打开目标机的 `linker64`(路径 `/system/bin/linker64`),定位 `soinfo` 结构体,把本文偏移表逐字段改成当前版本的;或者 hook `call_constructors` 拿到 soinfo 指针后,按 `getSoname`/`base` 反推各字段实际偏移。
- 32 位下用 `linker` 而不是 `linker64`,且指针宽度 4 字节,偏移表完全不同。

## 六、dump 后 so 修复要点

1. **段回填**:dump 的核心是按程序头 `p_offset` 把内存内容写回文件布局(代码在上面的 dumpSoFromSoInfo 里已实现),直接 `Memory.readByteArray(base, size)` 落盘是内存态,段错位。
2. **符号表/字符串表**:壳常把 strtab/symtab 抹掉或搬走。soinfo 里的 `strtab`/`symtab` 指针是 linker 重定位后实际使用的地址,dump 时优先信 soinfo 而不是 ELF 头里的旧值;写入文件时要换算成对应 LOAD 段内的文件偏移。
3. **重定位表**:`.rela.plt`(plt_rela)和 `.rela.dyn`(rela)分别要回填,否则 IDA 里 import 函数全是地址无名字。
4. **ELF 头校验**:dump 后如果 IDA 打不开,先检查 ELF 头的 `e_shoff`/`e_shnum`(运行时 loader 不需要 section header,壳可能清零;没有 section table 时 IDA 会退化按 program header 分析,也可以手工补 section table)。
5. **load_bias 计算真实地址**:soInfo 里 `base` 与程序头 `p_vaddr` 换算时注意 `load_bias`,上面代码统一用 `soBase.add(p_vaddr.sub(soInfo.load_bias))`。

## 相关文档

- GOT hook 也在用 soinfo(getPltAddr/GotHook/soListRemove):[../02-frida/高级/gothook.md](../02-frida/高级/gothook.md)
- so 动态加载等待(waitForModule)、call_constructors hook:[../02-frida/native层hook速查.md](../02-frida/native层hook速查.md)
- dex 脱壳:[dex脱壳.md](dex脱壳.md)
