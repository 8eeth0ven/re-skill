# frida advanced · GOT hook

> Topic: GOT hook (two routes: ELF parsing + soinfo)

## 2. GOT hook

frida's Interceptor is an inline hook, which cannot get a grip on some packer-protected functions; a GOT hook only modifies an import-table entry and never touches the code segment. Two implementations: parse the ELF in pure JS to find the GOT entry, or locate it through linker's soinfo.

### 2.1 JS implementation for locating the GOT entry (full ELF parsing)

When to use: you have a so's memory image and want to find the GOT entry offset of some imported function.

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

Usage example (find the GOT entry offset of pthread_create inside libc.so's memory; for the full implementation of `create_pthread_create` see section 1.8 of [native-hook-cheatsheet.md](../native-hook-cheatsheet.md) — identical there, not repeated):

```javascript
function hook() {
    const module = Process.findModuleByName("libc.so")
    const data = Memory.readByteArray(module.base, module.size)
    const pthread_create_offset = find_got_entry(new Uint8Array(data), "pthread_create")
    console.log(pthread_create_offset)
}


hook();
```

### 2.2 Hands-on: replacing android_dlopen_ext via libc's own GOT

When to use: modify the `android_dlopen_ext` entry in libc's own GOT to verify the GOT-hook chain works (0xc4c98 is the offset computed by find_got_entry above).

```javascript
// 0xc4c98
function create_android_dlopen_ext() {
    const android_dlopen_ext_ptr = Module.findExportByName(null, "android_dlopen_ext");
    const android_dlopen_ext = new NativeFunction(
        android_dlopen_ext_ptr,
        'pointer', // Return type
        ['pointer', 'int', 'pointer'] // Argument types
    );
    return new NativeCallback((parg0, parg1, parg2) => {
        console.log("android_dlopen_ext hook成功")
        // A successful call returns 0
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
        'pointer', // Return type
        ['pointer', 'pointer', 'pointer'] // Argument types
    );

    const libraryPath = Memory.allocUtf8String("/system/lib64/libc.so");
    const param2 = ptr(0);
    const param3 = ptr(0);

    const handle = LoadSharedLibrary(libraryPath, param2, param3);
}

hook_dlopen()
test_load()
```

### 2.3 The linker-soinfo route (getPltAddr / GotHook / soListRemove)

Go through linker's soinfo to get the target so's plt_rela/symtab/strtab, locate the GOT entry by symbol name, then rewrite it — no need to hand-shred the ELF. The full implementations of the base functions `parseSoInfo` / `getSoInfoHead` / `getSoInfo` are in [so-repair-dump.md](../../03-unpacking/so-repair-dump.md) (solist traversal and the soinfo offset table are also in that doc).

getPltAddr: find the address of a so's GOT entry by function name:

```javascript
function getPltAddr(so_name, funcName) {
    const soInfo = getSoInfo(so_name)
    if (!soInfo) {
        throw new Error("not find soinfo " + so_name)
    }
    // Shared-object base address
    // console.log(soInfo.getRealpath());
    //
    // Initialization section
    // console.log(soInfo.init_array.sub(soInfo.base));
    //
    // PLT R_AARCH64_GLOB_DAT relocations used by global references
    // console.log(soInfo.rela.sub(soInfo.base))
    // console.log(soInfo.rela.sub(soInfo.base).add(soInfo.rela_count * 0x18))
    //
    // PLT R_AARCH64_JUMP_SLOT relocations used by imported functions
    // console.log(soInfo.plt_rela.sub(soInfo.base))
    // console.log(soInfo.plt_rela.sub(soInfo.base).add(soInfo.plt_rela_count * 0x18))

    // String table
    // console.log(soInfo.strtab.sub(soInfo.base))

    // Symbol information
    // console.log(soInfo.symtab.sub(soInfo.base))

    let elf64Rela = null;
    for (let i = 0; i < soInfo.plt_rela_count; i++) {
        // console.log("elf64Rela offset: " + soInfo.plt_rela.add(i * 0x18).sub(soInfo.base))
        const _elf64Rela = parseElf64_Rela(soInfo.plt_rela.add(i * 0x18));
        // Shift right by 32 bits to obtain the symbol-table index
        const _offset = Number(BigInt(_elf64Rela.r_info) >> 32n)
        const _elf64SymAddr = soInfo.symtab.add(_offset * 0x18)
        // console.log("elf64Sym offset: " + _elf64SymAddr.sub(soInfo.base))
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

GotHook: point the GOT entry at the new function:

```javascript
function GotHook(so_name, funcName, newFuncAddr) {
    let gotAddress = getPltAddr(so_name, funcName)
    console.log("gotAddress:", gotAddress)
    // Replace the function
    Memory.protect(gotAddress, 8, "rw-")
    gotAddress.writePointer(newFuncAddr)
    console.log("gotAddress hook after", gotAddress.readPointer())
    Memory.protect(gotAddress, 8, "r--")
}
```

soListRemove: unlink a given so from the solist (defeats so-list detection; removes injected so):

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

// Unlink the injected shared object

rpc.exports = {
    getSoInfo,
    GotHook
}
```


## Related docs

- soinfo base functions and the full dumpSoFromSoInfo code: [so-repair-dump.md](../../03-unpacking/so-repair-dump.md)
- so repair-dump placement and waiting for dynamic so (waitForModule): [so-soinfo-ops.md](so-soinfo-ops.md) (same directory; the solist-unlinking soListRemove is already included earlier in this doc)
