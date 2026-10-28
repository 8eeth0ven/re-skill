"""Format metadata from LIEF/dnfile and bounded disassembly from Capstone."""
import hashlib
import struct
from pathlib import Path

from ..archive import extract_archive
from ..errors import BudgetExceeded, CapabilityMissing, InvalidInput
from ..models import Asset, ProfileResult
from ..safety import Budget, read_bytes
from ..scope import ScopePolicy


def uleb(data: bytes, offset: int, max_bits: int = 32) -> tuple[int, int]:
    value = 0
    for index in range((max_bits + 6) // 7):
        if offset >= len(data):
            raise InvalidInput("Truncated LEB128 integer")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            if value >= 1 << max_bits:
                raise InvalidInput("LEB128 integer overflow")
            return value, offset
    raise InvalidInput("Overlong LEB128 integer")


def wasm_name(data: bytes, offset: int) -> tuple[str, int]:
    size, offset = uleb(data, offset)
    if size > 16384 or offset + size > len(data):
        raise InvalidInput("Invalid WASM name length")
    try:
        name = data[offset:offset + size].decode("utf-8")
    except UnicodeError as exc:
        raise InvalidInput("Invalid WASM UTF-8 name") from exc
    return name, offset + size


def wasm_limits(data: bytes, offset: int) -> tuple[dict, int]:
    flags, offset = uleb(data, offset)
    if flags not in (0, 1, 2, 3):
        raise InvalidInput("Unsupported WASM limits flags")
    minimum, offset = uleb(data, offset)
    maximum = None
    if flags & 1:
        maximum, offset = uleb(data, offset)
        if maximum < minimum:
            raise InvalidInput("WASM maximum less than minimum")
    return {"minimum": minimum, "maximum": maximum, "shared": bool(flags & 2)}, offset


def wasm(data: bytes) -> dict:
    if data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise InvalidInput("Unsupported or truncated WASM header")
    offset, sections, imports, exports, memories = 8, [], [], [], []
    seen = set()
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = uleb(data, offset)
        end = offset + size
        if section_id > 13 or end > len(data) or len(sections) >= 1000:
            raise InvalidInput("Invalid WASM section boundary/count")
        if section_id and section_id in seen:
            raise InvalidInput("Duplicate WASM section")
        seen.add(section_id)
        section = data[offset:end]
        record = {"id": section_id, "offset": offset, "bytes": size}
        cursor = 0
        if section_id == 0:
            record["name"], cursor = wasm_name(section, cursor)
        elif section_id in (2, 5, 7):
            count, cursor = uleb(section, cursor)
            if count > 10000:
                raise BudgetExceeded("WASM entry count budget exceeded")
            for _ in range(count):
                if section_id == 2:
                    module, cursor = wasm_name(section, cursor)
                    name, cursor = wasm_name(section, cursor)
                    if cursor >= len(section):
                        raise InvalidInput("Truncated WASM import")
                    kind = section[cursor]
                    cursor += 1
                    entry = {"module": module, "name": name, "kind": kind}
                    if kind == 0:
                        entry["type_index"], cursor = uleb(section, cursor)
                    elif kind == 1:
                        if cursor >= len(section):
                            raise InvalidInput("Truncated table import")
                        cursor += 1
                        entry["limits"], cursor = wasm_limits(section, cursor)
                    elif kind == 2:
                        entry["limits"], cursor = wasm_limits(section, cursor)
                    elif kind == 3:
                        if cursor + 2 > len(section):
                            raise InvalidInput("Truncated global import")
                        entry["value_type"], entry["mutable"] = section[cursor], bool(section[cursor + 1])
                        cursor += 2
                    elif kind == 4:
                        if cursor >= len(section):
                            raise InvalidInput("Truncated tag import")
                        cursor += 1
                        entry["type_index"], cursor = uleb(section, cursor)
                    else:
                        raise InvalidInput("Unsupported WASM import kind")
                    imports.append(entry)
                elif section_id == 5:
                    limits, cursor = wasm_limits(section, cursor)
                    memories.append(limits)
                else:
                    name, cursor = wasm_name(section, cursor)
                    if cursor >= len(section):
                        raise InvalidInput("Truncated WASM export")
                    kind = section[cursor]
                    index, cursor = uleb(section, cursor + 1)
                    exports.append({"name": name, "kind": kind, "index": index})
            if cursor != len(section):
                raise InvalidInput("Unexpected bytes in WASM structural section")
        sections.append(record)
        offset = end
    return {"format": "wasm", "version": 1, "sections": sections, "imports": imports, "exports": exports, "memories": memories}


def jvm(data: bytes) -> dict:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise InvalidInput("Invalid JVM class header")
    minor, major, count = struct.unpack_from(">HHH", data, 4)
    if count < 1:
        raise InvalidInput("Invalid JVM constant pool count")
    cursor, index, pool = 10, 1, {0: None}
    widths = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        if cursor >= len(data):
            raise InvalidInput("Truncated JVM constant pool")
        tag = data[cursor]
        cursor += 1
        if tag == 1:
            if cursor + 2 > len(data):
                raise InvalidInput("Truncated UTF8 constant")
            size = struct.unpack_from(">H", data, cursor)[0]
            cursor += 2
            if cursor + size > len(data):
                raise InvalidInput("Truncated constant string")
            pool[index] = {"tag": tag, "value": data[cursor:cursor + size].decode("utf-8", "replace")}
            cursor += size
        elif tag in widths:
            size = widths[tag]
            if cursor + size > len(data):
                raise InvalidInput("Truncated JVM constant")
            pool[index] = {"tag": tag, "value": data[cursor:cursor + size].hex()}
            cursor += size
        else:
            raise InvalidInput("Unknown JVM constant pool tag")
        index += 2 if tag in (5, 6) else 1
    if cursor + 8 > len(data):
        raise InvalidInput("Truncated JVM class declaration")
    flags, this, parent, interface_count = struct.unpack_from(">HHHH", data, cursor)
    cursor += 8

    def class_name(reference):
        entry = pool.get(reference)
        if not entry or entry["tag"] != 7:
            return None
        name = pool.get(int(entry["value"], 16))
        return name["value"] if name and name["tag"] == 1 else None

    def short():
        nonlocal cursor
        if cursor + 2 > len(data):
            raise InvalidInput("Truncated JVM member count/index")
        value = struct.unpack_from(">H", data, cursor)[0]
        cursor += 2
        return value

    def string(reference):
        entry = pool.get(reference)
        if not entry or entry["tag"] != 1:
            raise InvalidInput("JVM member references a non-UTF8 constant")
        return entry["value"]

    def attributes():
        nonlocal cursor
        count = short()
        if count > 10000:
            raise BudgetExceeded("JVM attribute count exceeded")
        records = []
        for _ in range(count):
            name = string(short())
            if cursor + 4 > len(data):
                raise InvalidInput("Truncated JVM attribute length")
            size = struct.unpack_from(">I", data, cursor)[0]
            cursor += 4
            if cursor + size > len(data):
                raise InvalidInput("JVM attribute exceeds class bounds")
            records.append({"name": name, "offset": cursor, "bytes": size})
            cursor += size
        return records

    interfaces = [class_name(short()) for _ in range(interface_count)]
    if any(name is None for name in interfaces):
        raise InvalidInput("JVM interface reference is invalid")
    def members():
        values = []
        for _ in range(short()):
            access, name, descriptor = short(), string(short()), string(short())
            values.append({"name": name, "descriptor": descriptor, "access_flags": access, "attributes": attributes()})
        return values
    fields, methods, class_attributes = members(), members(), attributes()
    if cursor != len(data):
        raise InvalidInput("Unindexed trailing JVM class bytes")
    return {
        "format": "jvm-class", "version": {"major": major, "minor": minor},
        "class": class_name(this), "superclass": class_name(parent), "access_flags": flags,
        "constant_pool_count": count, "interfaces_count": interface_count,
        "interfaces": interfaces, "fields": fields, "methods": methods, "attributes": class_attributes,
        "class_references": [class_name(i) for i, entry in pool.items() if entry and entry["tag"] == 7][:2000],
    }


def _dotnet(path: Path) -> dict | None:
    try:
        import dnfile
        pe = dnfile.dnPE(str(path), fast_load=False)
        if not pe.net:
            pe.close()
            return None
        tables = pe.net.mdtables
        types = [str(row.TypeNamespace) + "." + str(row.TypeName) for row in tables.TypeDef.rows] if tables.TypeDef else []
        assemblies = [str(row.Name) for row in tables.AssemblyRef.rows] if tables.AssemblyRef else []
        result = {"types": types[:2000], "assembly_references": assemblies[:1000], "metadata_version": str(pe.net.metadata.struct.Version)}
        pe.close()
        return result
    except ImportError as exc:
        raise CapabilityMissing("dnfile is required for .NET metadata") from exc
    except Exception as exc:
        raise InvalidInput(f".NET metadata parse failed: {type(exc).__name__}") from exc


def _disassemble(binary, raw: bytes) -> tuple[list[dict], str | None]:
    import capstone as cs
    header = binary.header
    architecture = str(getattr(header, "machine_type", getattr(header, "machine", getattr(header, "cpu_type", "")))).upper()
    config = None
    if any(x in architecture for x in ("X86_64", "AMD64")):
        config = (cs.CS_ARCH_X86, cs.CS_MODE_64)
    elif any(x in architecture for x in ("I386", "I686", "X86")):
        config = (cs.CS_ARCH_X86, cs.CS_MODE_32)
    elif any(x in architecture for x in ("AARCH64", "ARM64")):
        config = (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    elif "ARM" in architecture:
        config = (cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
    elif "MIPS" in architecture:
        endian = cs.CS_MODE_BIG_ENDIAN if "MSB" in str(getattr(header, "identity_data", "")) else cs.CS_MODE_LITTLE_ENDIAN
        config = (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | endian)
    if config is None:
        return [], f"Capstone entry disassembly is not configured for {architecture}"
    entry = int(binary.entrypoint)
    if not entry:
        return [], "No executable entrypoint declared (library or object file)"
    # PE entrypoint may be an RVA; normalize against image base.
    imagebase = int(getattr(binary, "imagebase", 0))
    if imagebase and entry < imagebase:
        entry += imagebase
    try:
        code = bytes(binary.get_content_from_virtual_address(entry, 512))
        decoder = cs.Cs(*config)
        rows = [{"address": hex(i.address), "bytes": i.bytes.hex(), "mnemonic": i.mnemonic, "operands": i.op_str} for i in decoder.disasm(code, entry, count=64)]
        return rows, None if rows else "Entry bytes did not decode under the selected architecture/mode"
    except Exception as exc:
        return [], f"Entry disassembly failed: {type(exc).__name__}"


def native(path: Path, data: bytes) -> tuple[dict, list[str]]:
    try:
        import lief
    except ImportError as exc:
        raise CapabilityMissing("LIEF is required for native format parsing") from exc
    binary = lief.parse(str(path))
    if binary is None:
        raise InvalidInput("LIEF rejected the native binary")
    header = binary.header
    imports = []
    for entry in getattr(binary, "imports", []):
        if len(imports) >= 2000:
            break
        imports.append({"library": str(entry.name), "symbols": [str(x.name) for x in entry.entries][:2000]})
    libraries = [str(x) for x in getattr(binary, "libraries", [])][:2000]
    symbols = [str(s.name) for s in binary.symbols][:5000]
    sections = [{
        "name": str(section.name), "offset": int(section.offset), "bytes": int(section.size),
        "virtual_address": hex(int(section.virtual_address)), "entropy": round(float(section.entropy), 4),
    } for section in list(binary.sections)[:2000]]
    instructions, warning = _disassemble(binary, data)
    result = {
        "format": str(binary.format),
        "architecture": str(getattr(header, "machine_type", getattr(header, "machine", getattr(header, "cpu_type", "unknown")))),
        "entrypoint": hex(int(binary.entrypoint)), "sections": sections, "symbols": symbols,
        "imports": imports, "libraries": libraries, "entry_disassembly": instructions,
        "signature_present": bool(getattr(binary, "has_signatures", False)),
        "encrypted_ranges": [],
    }
    if isinstance(binary, lief.PE.Binary) and bool(getattr(binary, "has_configuration", False)):
        result["load_configuration_present"] = True
    if isinstance(binary, lief.PE.Binary) and bool(getattr(binary, "has_data_directory", False)):
        pass
    if isinstance(binary, lief.PE.Binary):
        # Metadata parsing is only attempted when PE declares a CLR directory.
        try:
            directory = binary.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER)
            if directory and directory.rva:
                result["dotnet"] = _dotnet(path)
        except AttributeError:
            pass
    if isinstance(binary, lief.MachO.Binary):
        result["encrypted_ranges"] = [{"offset": int(c.crypt_offset), "bytes": int(c.crypt_size), "crypt_id": int(c.crypt_id)} for c in binary.commands if hasattr(c, "crypt_id")]
        result["code_signature_present"] = bool(getattr(binary, "has_code_signature", False))
    return result, [warning] if warning else []


def _upx_route(result: ProfileResult, path: Path, output: Path, budget: Budget) -> None:
    """Best-effort static unpack for UPX-indicated PEs; never fatal to the profile."""
    from ..unpackers import upx_indication, upx_unpack

    if not upx_indication(result.analysis):
        return
    try:
        route = upx_unpack(path, output / "unpack-upx", budget)
    except InvalidInput as exc:
        result.check("protected-binary-unpack-upx", "failed", str(exc))
        return
    if route is None:
        result.check("protected-binary-unpack-upx", "skipped", "Set RE_RUN_UPX to a trusted upx executable to enable static unpacking")
        return
    result.analysis["unpack_route"] = route
    if route["status"] == "succeeded":
        result.check("protected-binary-unpack-upx", "succeeded")
        unpacked = route["unpacked"]
        names = ",".join(item["name"] for item in unpacked["sections"][:32])
        result.check(
            "unpacked-binary-structure", "succeeded",
            f"unpacked.bin sections={names} import_libraries={len(unpacked['import_libraries'])} sha256={unpacked['sha256']}",
        )
    else:
        result.check("protected-binary-unpack-upx", "degraded", route.get("error") or f"UPX static unpack reported {route['status']}")


def _looks_like_fat_header(data: bytes) -> bool:
    # CAFEBABE is shared with JVM class files; accept it as a fat Mach-O only when the
    # big-endian archive table describes slices that plausibly fit inside this buffer.
    if len(data) < 8:
        return False
    count = struct.unpack_from(">I", data, 4)[0]
    if not 1 <= count <= 64 or 8 + count * 20 > len(data):
        return False
    return all(
        size and offset >= 8 + count * 20 and offset + size <= len(data) and alignment <= 30 and not offset % (1 << alignment)
        for offset, size, alignment in (struct.unpack_from(">III", data, 16 + index * 20) for index in range(count))
    )


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path is None or path.is_dir():
        raise InvalidInput("Binary profile needs a binary file")
    data = read_bytes(path, budget.limits["max_input_bytes"])
    result = ProfileResult()
    if data.startswith(b"\x00asm"):
        result.analysis = wasm(data)
        result.check("wasm-structure")
        result.limitations.append("WASM structural sections are parsed; function bodies are not validated or executed.")
    elif data.startswith(b"\xca\xfe\xba\xbe") and (asset.format == "jvm" or path.suffix == ".class" or (not _looks_like_fat_header(data) and len(data) >= 8 and 45 <= struct.unpack_from(">H", data, 6)[0] <= 100)):
        result.analysis = jvm(data)
        result.check("jvm-constant-pool-and-class")
        result.limitations.append("JVM class references are indexed; bytecode control flow is not analyzed.")
    elif path.suffix == ".jar":
        inventory = extract_archive(path, output / "jar", budget)
        classes = []
        for item in inventory:
            if item["path"].endswith(".class"):
                classes.append({"path": item["path"], **jvm(read_bytes(output / "jar" / item["path"], 8_388_608))})
                if len(classes) >= 2000:
                    break
        result.analysis = {"format": "jar", "files": inventory, "classes": classes}
        result.check("jar-index-and-class-metadata")
        result.limitations.append("JAR classes are not loaded or executed; reflection and obfuscated bytecode need a JVM provider.")
    else:
        if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            endian = ">" if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
            if len(data) < 8:
                raise InvalidInput("Truncated fat Mach-O header")
            count = struct.unpack_from(endian + "I", data, 4)[0]
            is64 = data[:4] in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
            width = 32 if is64 else 20
            if not 1 <= count <= 64 or 8 + count * width > len(data):
                raise InvalidInput("Invalid fat Mach-O architecture count")
            records, intervals = [], []
            for index in range(count):
                cursor = 8 + index * width
                if is64:
                    cpu, subtype, offset, size, alignment, _ = struct.unpack_from(endian + "IIQQII", data, cursor)
                else:
                    cpu, subtype, offset, size, alignment = struct.unpack_from(endian + "IIIII", data, cursor)
                if not size or offset < 8 + count * width or offset + size > len(data) or alignment > 30 or offset % (1 << alignment):
                    raise InvalidInput("Fat Mach-O slice bounds/alignment invalid")
                intervals.append((offset, offset + size))
                selected = output / f"macho-slice-{index}.bin"
                selected.write_bytes(data[offset:offset + size])
                metadata, warnings = native(selected, data[offset:offset + size])
                records.append({"cpu": cpu, "subtype": subtype, "offset": offset, "bytes": size, **metadata})
                result.limitations.extend(warnings)
            ordered = sorted(intervals)
            if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
                raise InvalidInput("Overlapping fat Mach-O slices")
            # Merge per-slice encryption commands to the top level so protections.annotate sees them.
            merged, seen = [], set()
            for record in records:
                for item in record["encrypted_ranges"]:
                    key = (item["offset"], item["bytes"], item["crypt_id"])
                    if key not in seen:
                        seen.add(key)
                        merged.append(dict(item))
            result.analysis = {"format": "mach-o-fat", "slices": records, "encrypted_ranges": merged}
            result.check("fat-macho-slices-and-native-metadata")
            result.limitations.append("Each architecture slice is parsed separately; only configured architectures receive entry disassembly.")
        else:
            result.analysis, warnings = native(path, data)
            result.check("native-header-sections-imports")
            result.check("entry-disassembly", "degraded" if warnings else "succeeded", "; ".join(warnings))
            result.limitations.extend(warnings)
            from ..providers import radare2
            provider = radare2(path, output, budget)
            if provider:
                result.analysis["native_provider"] = provider
                result.check("radare2-function-and-reference-analysis", "succeeded" if provider["status"] == "succeeded" else "degraded", provider.get("error") or "")
            else:
                result.check("native-provider", "skipped", "Set RE_RUN_R2 to a trusted r2 executable or install it on PATH")
            _upx_route(result, path, output, budget)
    if result.analysis.get("encrypted_ranges") and any(x["crypt_id"] for x in result.analysis["encrypted_ranges"]):
        result.limitations.append("Encrypted Mach-O ranges cannot be statically disassembled until an authorized decrypted image is supplied.")
    runtime = []
    if b"Go build" in data or b"go.buildid" in data or b"\xff Go buildinf:" in data:
        runtime.append("go-build-marker")
    if b"rustc" in data or b"rust_eh_personality" in data or b"/rustc/" in data:
        runtime.append("rust-runtime-marker")
    result.analysis["runtime_markers"] = runtime
    result.analysis["sha256"] = hashlib.sha256(data).hexdigest()
    result.limitations.append("Samples are never executed. Entry disassembly does not recover all functions or defeat packing/obfuscation; use a configured decompiler and isolated runtime for deeper work.")
    return result
