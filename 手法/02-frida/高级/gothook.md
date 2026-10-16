# frida 高级·GOT hook

> 主题:GOT hook(ELF 解析+soinfo 两路)

## 二、GOT hook

frida 的 Interceptor 是 inline hook,对某些被壳保护的函数下不去手;GOT hook 只改导入表项,不碰代码段。两种实现:纯 js 解析 ELF 找 GOT 项、走 linker 的 soinfo 找。

### 2.1 查找 got 位置的 js 实现(完整 ELF 解析)

什么时候用:拿到一个 so 的内存镜像,想找出某个导入函数的 GOT 表项偏移。

```javascript
function parse_elf_headers(pbuff) {
    // Read e_ident
    let e_ident = pbuff.slice(0, 16);
    let ei_class = e_ident[4];
    let ei_data = e_ident[5];

    // Determine endianness
    let littleEndian = (ei_data === 1);

    // Check ELF class
    if (ei_class !== 2) {
        throw new Error('仅支持 64 位 ELF 文件');
    }

    // Create a DataView
    let dv = new DataView(pbuff.buffer, pbuff.byteOffset, pbuff.byteLength);

    // Read the ELF header fields
    let offset = 16; // Skip e_ident
    let elf_header = {};

    elf_header.e_type = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_machine = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_version = dv.getUint32(offset, littleEndian); offset += 4;
    elf_header.e_entry = dv.getBigUint64(offset, littleEndian); offset += 8;
    elf_header.e_phoff = dv.getBigUint64(offset, littleEndian); offset += 8;
    elf_header.e_shoff = dv.getBigUint64(offset, littleEndian); offset += 8;
    elf_header.e_flags = dv.getUint32(offset, littleEndian); offset += 4;
    elf_header.e_ehsize = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_phentsize = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_phnum = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_shentsize = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_shnum = dv.getUint16(offset, littleEndian); offset += 2;
    elf_header.e_shstrndx = dv.getUint16(offset, littleEndian); offset += 2;

    // Read program headers
    let program_headers = [];
    let e_phoff = Number(elf_header.e_phoff);
    let e_phentsize = elf_header.e_phentsize;
    let e_phnum = elf_header.e_phnum;

    for (let i = 0; i < e_phnum; i++) {
        let phdr_offset = e_phoff + i * e_phentsize;
        let phdr = {};
        let ph_offset = phdr_offset;

        phdr.p_type = dv.getUint32(ph_offset, littleEndian); ph_offset += 4;
        phdr.p_flags = dv.getUint32(ph_offset, littleEndian); ph_offset += 4;
        phdr.p_offset = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;
        phdr.p_vaddr = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;
        phdr.p_paddr = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;
        phdr.p_filesz = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;
        phdr.p_memsz = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;
        phdr.p_align = dv.getBigUint64(ph_offset, littleEndian); ph_offset += 8;

        program_headers.push(phdr);
    }

    return { littleEndian, program_headers };
}

function vaddr_to_offset(program_headers, vaddr) {
    for (let phdr of program_headers) {
        if (phdr.p_type === 1) { // PT_LOAD
            let p_vaddr = Number(phdr.p_vaddr);
            let p_memsz = Number(phdr.p_memsz);
            if (p_vaddr <= vaddr && vaddr < p_vaddr + p_memsz) {
                let p_offset = Number(phdr.p_offset);
                return p_offset + (vaddr - p_vaddr);
            }
        }
    }
    return null;
}

function parse_dynamic_section(pbuff, littleEndian, program_headers) {
    let dynamic_offset = null;
    let dynamic_size = null;

    for (let phdr of program_headers) {
        if (phdr.p_type === 2) { // PT_DYNAMIC
            dynamic_offset = Number(phdr.p_offset);
            dynamic_size = Number(phdr.p_filesz);
            break;
        }
    }
    if (dynamic_offset === null) {
        throw new Error("未找到 PT_DYNAMIC 段");
    }
    let dv = new DataView(pbuff.buffer, pbuff.byteOffset, pbuff.byteLength);
    let dynamic_entries = [];
    let dyn_size = 16; // Each dynamic entry is two 8-byte fields (QQ)
    for (let i = 0; i < dynamic_size; i += dyn_size) {
        let offset = dynamic_offset + i;
        let d_tag = dv.getBigUint64(offset, littleEndian); offset += 8;
        let d_val = dv.getBigUint64(offset, littleEndian); offset += 8;
        dynamic_entries.push({ d_tag, d_val });
        if (d_tag === 0n) { // DT_NULL
            break;
        }
    }
    return dynamic_entries;
}

function extract_dynamic_info(dynamic_entries) {
    let dynsym_addr = null;
    let dynstr_addr = null;
    let rela_plt_addr = null;
    let rela_plt_size = null;
    let dynsym_entsize = null;

    for (let entry of dynamic_entries) {
        let d_tag_num = Number(entry.d_tag);
        switch (d_tag_num) {
            case 6: // DT_SYMTAB
                dynsym_addr = entry.d_val;
                break;
            case 5: // DT_STRTAB
                dynstr_addr = entry.d_val;
                break;
            case 23: // DT_JMPREL
                rela_plt_addr = entry.d_val;
                break;
            case 2: // DT_PLTRELSZ
                rela_plt_size = entry.d_val;
                break;
            case 11: // DT_SYMENT
                dynsym_entsize = entry.d_val;
                break;
            default:
                break;
        }
    }

    return { dynsym_addr, dynstr_addr, rela_plt_addr, rela_plt_size, dynsym_entsize };
}

function parse_dynsym(pbuff, littleEndian, program_headers, dynsym_addr, dynsym_entsize) {
    let dynsym_offset = vaddr_to_offset(program_headers, Number(dynsym_addr));
    if (dynsym_offset === null) {
        throw new Error("无法找到 dynsym 的文件偏移");
    }

    let dynsym_size = 0x1000;
    let end_offset = Math.min(dynsym_offset + dynsym_size, pbuff.byteLength);
    let dynsym_data = pbuff.slice(dynsym_offset, end_offset);
    let dv = new DataView(dynsym_data.buffer, dynsym_data.byteOffset, dynsym_data.byteLength);

    let sym_size = Number(dynsym_entsize);
    if (sym_size === 0) {
        sym_size = 24;
    }

    let dynsym_entries = [];
    for (let i = 0; i < dynsym_data.byteLength; i += sym_size) {
        if (i + sym_size > dynsym_data.byteLength) {
            break;
        }
        let offset = i;

        let st_name = dv.getUint32(offset, littleEndian); offset += 4;
        let st_info = dv.getUint8(offset); offset += 1;
        let st_other = dv.getUint8(offset); offset += 1;
        let st_shndx = dv.getUint16(offset, littleEndian); offset += 2;
        let st_value = dv.getBigUint64(offset, littleEndian); offset += 8;
        let st_size = dv.getBigUint64(offset, littleEndian); offset += 8;

        dynsym_entries.push({
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size
        });
    }

    return dynsym_entries;
}

function parse_dynstr(pbuff, program_headers, dynstr_addr) {
    let dynstr_offset = vaddr_to_offset(program_headers, Number(dynstr_addr));
    if (dynstr_offset === null) {
        throw new Error("无法找到 dynstr 的文件偏移");
    }

    let dynstr_size = 0x1000;
    let end_offset = Math.min(dynstr_offset + dynstr_size, pbuff.byteLength);
    let dynstr_data = pbuff.slice(dynstr_offset, end_offset);

    return dynstr_data;
}

function parse_rela_plt(pbuff, littleEndian, program_headers, rela_plt_addr, rela_plt_size) {
    let rela_plt_offset = vaddr_to_offset(program_headers, Number(rela_plt_addr));
    if (rela_plt_offset === null) {
        throw new Error("无法找到 .rela.plt 的文件偏移");
    }

    let rela_size = 24;
    let rela_entries_count = Number(rela_plt_size) / rela_size;

    let rela_plt_entries = [];
    let dv = new DataView(pbuff.buffer, pbuff.byteOffset, pbuff.byteLength);

    for (let i = 0; i < rela_entries_count; i++) {
        let offset = rela_plt_offset + i * rela_size;
        if (offset + rela_size > pbuff.byteLength) {
            break;
        }

        let r_offset = dv.getBigUint64(offset, littleEndian); offset += 8;
        let r_info = dv.getBigUint64(offset, littleEndian); offset += 8;
        let r_addend = dv.getBigUint64(offset, littleEndian); offset += 8;

        rela_plt_entries.push({
            r_offset,
            r_info,
            r_addend
        });
    }

    return rela_plt_entries;
}

function find_function_got_entry(function_name, dynsym_entries, dynstr_data, rela_plt_entries) {
    let symbol_index = null;

    for (let i = 0; i < dynsym_entries.length; i++) {
        let sym = dynsym_entries[i];
        let st_name = sym.st_name;

        let name = '';
        for (let j = st_name; j < dynstr_data.length; j++) {
            let charCode = dynstr_data[j];
            if (charCode === 0) {
                break;
            }
            name += String.fromCharCode(charCode);
        }
        if (name === function_name) {
            symbol_index = i;
            break;
        }
    }

    if (symbol_index === null) {
        console.log(`未找到函数 ${function_name} 的符号`);
        return null;
    }

    for (let rela of rela_plt_entries) {
        let r_info = rela.r_info;
        let rel_sym = Number(r_info >> 32n);
        if (rel_sym === symbol_index) {
            let got_entry_addr = Number(rela.r_offset);
            console.log(`函数 ${function_name} 的 GOT 表项地址为: 0x${got_entry_addr.toString(16).toUpperCase()}`);
            return got_entry_addr;
        }
    }

    console.log(`未找到函数 ${function_name} 的重定位条目`);
    return null;
}

function find_got_entry(pbuff, function_name) {
    let { littleEndian, program_headers } = parse_elf_headers(pbuff);
    let dynamic_entries = parse_dynamic_section(pbuff, littleEndian, program_headers);

    let { dynsym_addr, dynstr_addr, rela_plt_addr, rela_plt_size, dynsym_entsize } = extract_dynamic_info(dynamic_entries);

    let dynsym_entries = parse_dynsym(pbuff, littleEndian, program_headers, dynsym_addr, dynsym_entsize);
    let dynstr_data = parse_dynstr(pbuff, program_headers, dynstr_addr);
    let rela_plt_entries = parse_rela_plt(pbuff, littleEndian, program_headers, rela_plt_addr, rela_plt_size);

    return find_function_got_entry(function_name, dynsym_entries, dynstr_data, rela_plt_entries);
}
```

用法示例(在 libc.so 内存里找 pthread_create 的 GOT 项偏移;`create_pthread_create` 的完整实现另见 [native层hook速查.md](../native层hook速查.md) 1.8,两处相同,此处不重复):

```javascript
function hook() {
    const module = Process.findModuleByName("libc.so")
    const data = Memory.readByteArray(module.base, module.size)
    const pthread_create_offset = find_got_entry(new Uint8Array(data), "pthread_create")
    console.log(pthread_create_offset)
}


hook();
```

### 2.2 libc GOT 替换 android_dlopen_ext 实战

什么时候用:改 libc 自己 GOT 里的 `android_dlopen_ext` 项,验证 GOT hook 链路通不通(0xc4c98 即上面 find_got_entry 算出来的偏移)。

```javascript
// 0xc4c98
function create_android_dlopen_ext() {
    const android_dlopen_ext_ptr = Module.findExportByName(null, "android_dlopen_ext");
    const android_dlopen_ext = new NativeFunction(
        android_dlopen_ext_ptr,
        'pointer', // 返回类型
        ['pointer', 'int', 'pointer'] // 参数类型
    );
    return new NativeCallback((parg0, parg1, parg2) => {
        console.log("android_dlopen_ext hook成功")
        // 成功的返回值是0
        return android_dlopen_ext(parg0, parg1, parg2)
    }, "pointer", ["pointer", "int", "pointer"])
}

const new_android_dlopen_ext = create_android_dlopen_ext();
console.log(new_android_dlopen_ext)

function hook_dlopen() {
    const module = Process.findModuleByName("libc.so")
    console.log(Module.findExportByName(null, "android_dlopen_ext"));
    const got_address = module.base.add(0xc4c98)
    const android_dlopen_ext = got_address.readPointer()
    console.log(android_dlopen_ext)
    Memory.protect(got_address, 8, "rw-")
    got_address.writePointer(new_android_dlopen_ext)
    Memory.protect(got_address, 8, "r--")
}

function test_load() {
    const module = Process.findModuleByName("libc.so")
    let LoadSharedLibraryPtr = null
    module.enumerateSymbols().forEach(symbol => {
        if (symbol.name.indexOf("_Z17LoadSharedLibraryPKcS0_P14MallocDispatch") !== -1) {
            LoadSharedLibraryPtr = symbol.address
        }
    })
    console.log(LoadSharedLibraryPtr);
    const LoadSharedLibrary = new NativeFunction(
        LoadSharedLibraryPtr,
        'pointer', // 返回类型
        ['pointer', 'pointer', 'pointer'] // 参数类型
    );

    const libraryPath = Memory.allocUtf8String("/system/lib64/libc.so");
    const param2 = ptr(0);
    const param3 = ptr(0);

    const handle = LoadSharedLibrary(libraryPath, param2, param3);
}

hook_dlopen()
test_load()
```

### 2.3 linker soinfo 方案(getPltAddr / GotHook / soListRemove)

走 linker 的 soinfo 拿目标 so 的 plt_rela/symtab/strtab,按符号名定位 GOT 项再改写,不用手撕 ELF。`parseSoInfo` / `getSoInfoHead` / `getSoInfo` 等基础函数的完整实现另见 [../03-脱壳dump/so修复dump.md](../../03-脱壳dump/so修复dump.md)(solist 遍历与 soinfo 偏移表也在该篇)。

getPltAddr:按函数名找 so 里对应 GOT 项地址:

```javascript
function getPltAddr(so_name, funcName) {
    const soInfo = getSoInfo(so_name)
    if (!soInfo) {
        throw new Error("not find soinfo " + so_name)
    }
    // // so地址
    // console.log(soInfo.getRealpath());
    //
    // // init段
    // console.log(soInfo.init_array.sub(soInfo.base));
    //
    // // plt R_AARCH64_GLOB_DAT段，本身全局会用到
    // console.log(soInfo.rela.sub(soInfo.base))
    // console.log(soInfo.rela.sub(soInfo.base).add(soInfo.rela_count * 0x18))
    //
    // // plt R_AARCH64_JUMP_SLOT段，import导入会用到
    // console.log(soInfo.plt_rela.sub(soInfo.base))
    // console.log(soInfo.plt_rela.sub(soInfo.base).add(soInfo.plt_rela_count * 0x18))

    // // 字符串
    // console.log(soInfo.strtab.sub(soInfo.base))

    // // 符号信息
    // console.log(soInfo.symtab.sub(soInfo.base))

    let elf64Rela = null;
    for (let i = 0; i < soInfo.plt_rela_count; i++) {
        // console.log("elf64Rela偏移: " + soInfo.plt_rela.add(i * 0x18).sub(soInfo.base))
        const _elf64Rela = parseElf64_Rela(soInfo.plt_rela.add(i * 0x18));
        // 右移32位，得到的就是第
        const _offset = Number(BigInt(_elf64Rela.r_info) >> 32n)
        const _elf64SymAddr = soInfo.symtab.add(_offset * 0x18)
        // console.log("elf64Sym偏移: " + _elf64SymAddr.sub(soInfo.base))
        const _elf64Sym = parseElf64_Sym(_elf64SymAddr);
        const _funcName = soInfo.strtab.add(_elf64Sym.st_name).readUtf8String()
        if (_funcName.indexOf(funcName) !== -1) {
            elf64Rela = _elf64Rela
            break
        }
    }
    if (!elf64Rela) {
        throw new Error("找不到符号")
    }
    console.log("got hook offset:", elf64Rela.r_offset.toString(16))
    return soInfo.base.add(elf64Rela.r_offset)
}
```

GotHook:改 GOT 项指向新函数:

```javascript
function GotHook(so_name, funcName, newFuncAddr) {
    let gotAddress = getPltAddr(so_name, funcName)
    console.log("gotAddress:", gotAddress)
    // 函数替换
    Memory.protect(gotAddress, 8, "rw-")
    gotAddress.writePointer(newFuncAddr)
    console.log("gotAddress hook after", gotAddress.readPointer())
    Memory.protect(gotAddress, 8, "r--")
}
```

soListRemove:把指定 so 从 solist 摘链(过 so 名单检测;删除注入的 so):

```javascript
function soListRemove(so_name) {
    let soInfo = parseSoInfo(getSoInfoHead())
    while (true) {
        let realPath;
        let _soInfo;
        try {
            _soInfo = soInfo.next()
        } catch (e) {
            break
        }
        realPath = _soInfo.getSoname()
        if (realPath && realPath.indexOf(so_name) !== -1) {
            let __soInfo
            try {
                __soInfo = _soInfo.next()
            } catch (e) {
                __soInfo = {
                    soinfo_addr: ptr(0)
                }
            }
            Memory.protect(soInfo._next, 8, "rw-")
            soInfo._next.writePointer(__soInfo.soinfo_addr)
            Memory.protect(soInfo._next, 8, "r--")
            console.log("soList remove " + so_name)
            break
        }
        soInfo = _soInfo
    }
}

// 删除注入的so

rpc.exports = {
    getSoInfo,
    GotHook
}
```


## 相关文档

- soinfo 基础函数与 dumpSoFromSoInfo 完整代码:[../03-脱壳dump/so修复dump.md](../../03-脱壳dump/so修复dump.md)
- so 修复 dump 归置与动态 so 等待(waitForModule):[so与soinfo操作.md](so与soinfo操作.md)(同目录;solist 摘链 soListRemove 已收录在本篇上文)
