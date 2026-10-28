import hashlib
import plistlib
import struct
import zlib
from pathlib import Path

from ..archive import extract_archive
from ..decompile import apktool, jadx
from ..errors import BudgetExceeded, InvalidInput
from ..intake import iter_tree
from ..models import Asset, ProfileResult
from ..parsing import xml
from ..safety import Budget, read_bytes
from ..scope import ScopePolicy
from .binary import native, uleb


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Lexical smali markers for S1 candidate rules. A class reference in smali is a
# signal to review, never a verified behavior or a confirmed data flow.
SMALI_RULES = (
    ("Landroid/telephony/TelephonyManager;", "android-smali-telephony-identifier",
     "Smali references telephony identifier access (TelephonyManager)"),
    ("Landroid/location/LocationManager;", "android-smali-location-access",
     "Smali references device location access (LocationManager)"),
)
SMALI_MAX_FILES = 2000
SMALI_MAX_FILE_BYTES = 1_048_576
SMALI_MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _smali_reference_scan(tool_dir: Path, result: ProfileResult, budget: Budget) -> None:
    hits: dict[str, tuple[str, str, str]] = {}
    scanned = total_bytes = 0
    for path in sorted(tool_dir.rglob("*.smali")):
        if scanned >= SMALI_MAX_FILES or total_bytes >= SMALI_MAX_TOTAL_BYTES:
            break
        budget.check()
        scanned += 1
        try:
            if path.stat().st_size > SMALI_MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_bytes += len(text)
        for marker, rule, title in SMALI_RULES:
            if marker in text and rule not in hits:
                hits[rule] = (title, marker, path.relative_to(tool_dir.parent).as_posix())
    for rule, (title, marker, location) in hits.items():
        result.candidate(rule, title,
                         f"Lexical scan of apktool smali found a reference to {marker}; call sites were not analyzed.",
                         location=location, severity="medium",
                         impact="A class reference alone does not establish runtime behavior, permission grants or data exfiltration.",
                         remediation="Confirm the API call sites and that manifest permissions and privacy disclosures justify the access.")


def _string_length(data: bytes, cursor: int, utf8: bool) -> tuple[int, int]:
    if utf8:
        if cursor >= len(data):
            raise InvalidInput("Truncated Android string")
        value = data[cursor]
        cursor += 1
        if value & 0x80:
            if cursor >= len(data):
                raise InvalidInput("Truncated Android string length")
            value = ((value & 0x7F) << 8) | data[cursor]
            cursor += 1
    else:
        if cursor + 2 > len(data):
            raise InvalidInput("Truncated Android UTF16 length")
        value = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if value & 0x8000:
            if cursor + 2 > len(data):
                raise InvalidInput("Truncated Android UTF16 length")
            value = ((value & 0x7FFF) << 16) | struct.unpack_from("<H", data, cursor)[0]
            cursor += 2
    return value, cursor


def _string_pool(chunk: bytes) -> list[str]:
    if len(chunk) < 28:
        raise InvalidInput("Truncated Android string pool")
    _, header, _ = struct.unpack_from("<HHI", chunk)
    count, style_count, flags, start, _ = struct.unpack_from("<IIIII", chunk, 8)
    if count > 100000 or header < 28 or header + count * 4 > len(chunk) or start >= len(chunk):
        raise InvalidInput("Invalid Android string pool bounds")
    result = []
    for index in range(count):
        offset = struct.unpack_from("<I", chunk, header + index * 4)[0]
        cursor = start + offset
        if flags & 0x100:
            _, cursor = _string_length(chunk, cursor, True)
            size, cursor = _string_length(chunk, cursor, True)
            multiplier, encoding = 1, "utf-8"
        else:
            size, cursor = _string_length(chunk, cursor, False)
            multiplier, encoding = 2, "utf-16le"
        if size > 65536 or cursor + size * multiplier + multiplier > len(chunk):
            raise InvalidInput("Android string exceeds chunk bounds")
        try:
            result.append(chunk[cursor:cursor + size * multiplier].decode(encoding))
        except UnicodeError as exc:
            raise InvalidInput("Invalid Android string encoding") from exc
    return result


def axml(data: bytes) -> list[dict]:
    if len(data) < 8 or struct.unpack_from("<H", data)[0] != 3:
        raise InvalidInput("Invalid Android binary XML header")
    _, header, size = struct.unpack_from("<HHI", data)
    if header < 8 or size != len(data):
        raise InvalidInput("Invalid Android binary XML size")
    strings, nodes, cursor, depth = [], [], header, 0

    def string(index):
        if index == 0xFFFFFFFF:
            return ""
        if index >= len(strings):
            raise InvalidInput("Android XML string reference out of range")
        return strings[index]

    while cursor < size:
        if cursor + 8 > size:
            raise InvalidInput("Truncated Android XML chunk")
        kind, head_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_size < head_size or head_size < 8 or cursor + chunk_size > size or not chunk_size:
            raise InvalidInput("Invalid Android XML chunk bounds")
        chunk = data[cursor:cursor + chunk_size]
        if kind == 1:
            strings = _string_pool(chunk)
        elif kind == 0x0102:
            if head_size < 16 or len(chunk) < 36:
                raise InvalidInput("Truncated Android start element")
            _, name, attr_start, attr_size, count = struct.unpack_from("<IIHHH", chunk, 16)
            if attr_size < 20 or count > 10000 or 16 + attr_start + count * attr_size > chunk_size:
                raise InvalidInput("Invalid Android attribute bounds")
            attributes = {}
            for index in range(count):
                location = 16 + attr_start + index * attr_size
                ns, attr_name, raw, value_size, _, value_type, value = struct.unpack_from("<IIIHBBI", chunk, location)
                if value_size != 8:
                    raise InvalidInput("Invalid Android typed value")
                namespace = string(ns)
                attribute_name = string(attr_name)
                if namespace and namespace != "http://schemas.android.com/apk/res/android":
                    attribute_name = "{" + namespace + "}" + attribute_name
                if raw != 0xFFFFFFFF:
                    decoded = string(raw)
                elif value_type == 3:
                    decoded = string(value)
                elif value_type == 0x12:
                    decoded = "true" if value else "false"
                elif value_type in (0x10, 0x11):
                    decoded = str(value)
                else:
                    decoded = f"@0x{value:08x}"
                if attribute_name in attributes:
                    raise InvalidInput("Duplicate Android XML attribute")
                attributes[attribute_name] = decoded
            depth += 1
            if depth > 48 or len(nodes) > 50000:
                raise BudgetExceeded("Android XML structure budget exceeded")
            nodes.append({"tag": string(name), "attributes": attributes, "depth": depth})
        elif kind == 0x0103:
            depth -= 1
            if depth < 0:
                raise InvalidInput("Unbalanced Android XML element")
        cursor += chunk_size
    if depth != 0 or not nodes:
        raise InvalidInput("Incomplete Android XML structure")
    return nodes


def protobuf_fields(data: bytes, max_fields: int = 100000) -> list[tuple[int, int, object]]:
    fields, cursor = [], 0
    while cursor < len(data):
        tag, cursor = uleb(data, cursor, 64)
        number, wire = tag >> 3, tag & 7
        if number == 0 or len(fields) >= max_fields:
            raise InvalidInput("Invalid protobuf field/count")
        if wire == 0:
            value, cursor = uleb(data, cursor, 64)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if cursor + size > len(data):
                raise InvalidInput("Truncated protobuf value")
            value = data[cursor:cursor + size]
            cursor += size
        elif wire == 2:
            size, cursor = uleb(data, cursor, 64)
            if size > 16_777_216 or cursor + size > len(data):
                raise InvalidInput("Invalid protobuf length")
            value = data[cursor:cursor + size]
            cursor += size
        else:
            raise InvalidInput("Protobuf groups/invalid wire type are not supported")
        fields.append((number, wire, value))
    return fields


def aab_xml(data: bytes) -> list[dict]:
    nodes = []

    def walk(encoded: bytes, depth: int):
        if depth > 48 or len(nodes) >= 50000:
            raise BudgetExceeded("AAB XML depth/node budget exceeded")
        # aapt Resources.proto: XmlNode.element=1; XmlElement name=3, attributes=4, child=5.
        element = next((value for number, wire, value in protobuf_fields(encoded) if number == 1 and wire == 2), None)
        if element is None:
            return
        fields = protobuf_fields(element)
        name = next((value.decode("utf-8") for number, wire, value in fields if number == 3 and wire == 2), "")
        attributes = {}
        for number, wire, value in fields:
            if number != 4 or wire != 2:
                continue
            attr = protobuf_fields(value)
            key = next((v.decode("utf-8") for n, w, v in attr if n == 2 and w == 2), "")
            namespace = next((v.decode("utf-8") for n, w, v in attr if n == 1 and w == 2), "")
            if namespace and namespace != "http://schemas.android.com/apk/res/android":
                key = "{" + namespace + "}" + key
            text = next((v.decode("utf-8") for n, w, v in attr if n == 3 and w == 2), "")
            if key in attributes:
                raise InvalidInput("Duplicate AAB manifest attribute")
            attributes[key] = text
        nodes.append({"tag": name, "attributes": attributes, "depth": depth})
        for number, wire, value in fields:
            if number == 5 and wire == 2:
                walk(value, depth + 1)

    try:
        walk(data, 1)
    except UnicodeError as exc:
        raise InvalidInput("Invalid AAB XML string") from exc
    if not nodes or nodes[0]["tag"] != "manifest":
        raise InvalidInput("AAB lacks a valid protobuf manifest element")
    return nodes


def manifest_nodes(data: bytes, fmt: str) -> list[dict]:
    if data.lstrip().startswith(b"<"):
        root = xml(data)
        nodes, stack = [], [(root, 1)]
        while stack:
            element, depth = stack.pop()
            nodes.append({"tag": element.tag.rsplit("}", 1)[-1], "attributes": {key[len(ANDROID_NS):] if key.startswith(ANDROID_NS) else key: value for key, value in element.attrib.items()}, "depth": depth})
            stack.extend((child, depth + 1) for child in reversed(list(element)))
        return nodes
    return aab_xml(data) if fmt == "aab" else axml(data)


def dex_metadata(data: bytes) -> dict:
    if len(data) < 112 or not data.startswith(b"dex\n") or data[7] != 0:
        raise InvalidInput("Invalid/unsupported DEX header")
    values = struct.unpack_from("<20I", data, 32)
    file_size, header_size, endian = values[:3]
    if file_size != len(data) or header_size != 112 or endian != 0x12345678:
        raise InvalidInput("DEX file/header size or byte order is invalid")
    strings_count, strings_off = values[6:8]
    types_count, types_off = values[8:10]
    methods_count, methods_off = values[14:16]
    classes_count, classes_off = values[16:18]
    for count, offset, width in ((strings_count, strings_off, 4), (types_count, types_off, 4), (methods_count, methods_off, 8), (classes_count, classes_off, 32)):
        if count > 1000000 or offset + count * width > len(data):
            raise InvalidInput("DEX indexed section exceeds file bounds")
    strings = []
    for index in range(min(strings_count, 20000)):
        position = struct.unpack_from("<I", data, strings_off + index * 4)[0]
        _, position = uleb(data, position)
        end = data.find(b"\x00", position, min(len(data), position + 16385))
        if end == -1:
            raise InvalidInput("Unterminated/oversized DEX string")
        strings.append(data[position:end].decode("utf-8", "replace"))
    class_names = []
    for index in range(min(classes_count, 2000)):
        type_index = struct.unpack_from("<I", data, classes_off + index * 32)[0]
        if type_index >= types_count:
            raise InvalidInput("DEX class type reference out of range")
        string_index = struct.unpack_from("<I", data, types_off + type_index * 4)[0]
        if string_index >= strings_count:
            raise InvalidInput("DEX type string reference out of range")
        class_names.append(strings[string_index] if string_index < len(strings) else f"string-index:{string_index}")
    return {
        "version": data[4:7].decode("ascii", "replace"), "string_count": strings_count,
        "type_count": types_count, "method_count": methods_count, "class_count": classes_count,
        "classes": class_names,
        "endpoints": [s[:2048] for s in strings if s.startswith(("http://", "https://", "ws://", "wss://"))][:1000],
        "signature_valid": hashlib.sha1(data[32:]).digest() == data[12:32],
        "checksum_valid": zlib.adler32(data[12:]) & 0xFFFFFFFF == struct.unpack_from("<I", data, 8)[0],
        "strings_indexed": len(strings),
    }


def android(asset: Asset, path: Path, output: Path, budget: Budget) -> ProfileResult:
    result = ProfileResult()
    if asset.format == "dex":
        result.analysis = {"dex": dex_metadata(read_bytes(path, budget.limits["max_input_bytes"]))}
        result.check("dex-header-and-indexes")
        if not result.analysis["dex"]["checksum_valid"] or not result.analysis["dex"]["signature_valid"]:
            result.check("dex-integrity", "degraded", "DEX signature/checksum mismatch")
        result.limitations.append("DEX structure only; no instruction control-flow or compact-DEX support.")
        return result
    inventory = extract_archive(path, output / "package", budget)
    names = {item["path"] for item in inventory}
    manifest_path = "base/manifest/AndroidManifest.xml" if asset.format == "aab" else "AndroidManifest.xml"
    if manifest_path not in names:
        raise InvalidInput(f"Package missing {manifest_path}")
    nodes = manifest_nodes(read_bytes(output / "package" / manifest_path, 8_388_608), asset.format)
    if nodes[0]["tag"] != "manifest":
        raise InvalidInput("Android manifest root must be manifest")
    app = next((n["attributes"] for n in nodes if n["tag"] == "application"), {})
    sdk = next((n["attributes"] for n in nodes if n["tag"] == "uses-sdk"), {})
    components = [{"type": n["tag"], **n["attributes"]} for n in nodes if n["tag"] in ("activity", "activity-alias", "service", "receiver", "provider")]
    permissions = [n["attributes"].get("name") for n in nodes if n["tag"].startswith("uses-permission")]
    dexes = []
    for name in sorted(names):
        budget.check()
        if name.endswith(".dex"):
            dexes.append({"path": name, **dex_metadata(read_bytes(output / "package" / name, budget.limits["max_input_bytes"]))})
    result.analysis = {
        "format": asset.format, "package": nodes[0]["attributes"].get("package"),
        "version": nodes[0]["attributes"].get("versionName"), "sdk": sdk,
        "application": app, "permissions": permissions, "components": components,
        "dex": dexes, "native_libraries": [name for name in sorted(names) if name.endswith(".so")],
        "files": inventory, "v1_signature_files": [name for name in sorted(names) if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))],
    }
    result.check("package-safe-extraction-and-manifest")
    result.check("dex-indexing", "succeeded" if dexes else "skipped", f"{len(dexes)} DEX files")
    if any(not d["signature_valid"] or not d["checksum_valid"] for d in dexes):
        result.check("dex-integrity", "degraded", "At least one DEX checksum/signature is invalid")
    for key, rule, title in (
        ("debuggable", "android-debuggable", "Application declares debuggable=true"),
        ("usesCleartextTraffic", "android-cleartext", "Application allows cleartext traffic"),
    ):
        if str(app.get(key, "")).lower() == "true":
            result.candidate(rule, title, f"Manifest application attribute {key}=true.", location=manifest_path,
                             remediation="Review production manifest, network security configuration and build type.")
    for component in components:
        if str(component.get("exported", "")).lower() == "true" and not component.get("permission"):
            result.candidate("android-exported-component", "Exported component without declared permission",
                             f"{component['type']} {component.get('name')} declares exported=true; component behavior and caller checks are unknown.",
                             location=manifest_path, remediation="Review intended exported behavior and enforce appropriate caller permissions/authorization.")
    if asset.format == "apk":
        # S1 unpack stage: apktool (resources + smali) first, then jadx (Java
        # sources). Both are skipped honestly when RE_RUN_APKTOOL/RE_RUN_JADX
        # are unset; an empty classes.dex yields a degraded jadx result, which
        # is the honest signal that there was no bytecode to decompile.
        s1: dict = {}
        decode = apktool(path, output, budget)
        if decode:
            s1["apktool"] = decode
            result.check("android-bytecode-decompile-apktool", decode["status"],
                         decode.get("error") or f"{len(decode['sources'])} decoded artifacts")
            if decode["sources"]:
                _smali_reference_scan(output / "apktool", result, budget)
        else:
            result.check("android-bytecode-decompile-apktool", "skipped",
                         "Set RE_RUN_APKTOOL to a trusted apktool jar (run via java -jar) to decode resources and smali")
        decompiled = jadx(path, output, budget)
        if decompiled:
            s1["jadx"] = decompiled
            result.check("android-bytecode-decompile-jadx", decompiled["status"],
                         decompiled.get("error") or f"{len(decompiled['sources'])} java sources")
        else:
            result.check("android-bytecode-decompile-jadx", "skipped",
                         "Set RE_RUN_JADX to a trusted jadx executable or distribution directory to decompile dex to java")
        if s1:
            result.analysis["s1_extraction"] = s1
    result.limitations.extend([
        "Static package structure and DEX references only; native libraries, bytecode control flow and obfuscation require an analysis provider.",
        "APK/AAB signatures are inventoried, not cryptographically verified. Dynamic adb/Frida and emulator testing are not completed by this profile.",
        "Indexed endpoints do not expand the authorized network scope.",
    ])
    return result


def safe_plist(data: bytes) -> dict:
    if len(data) > 8_388_608:
        raise BudgetExceeded("Plist byte budget exceeded")
    if not data.startswith(b"bplist"):
        xml(data)
    try:
        value = plistlib.loads(data)
    except Exception as exc:
        raise InvalidInput(f"Malformed plist: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise InvalidInput("Bundle plist must be an object")
    stack, count = [(value, 0)], 0
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 48:
            raise BudgetExceeded("Plist depth/node budget exceeded")
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)
    return value


def _entitlements(binary_path: Path, metadata: dict) -> dict | None:
    import lief
    binary = lief.parse(str(binary_path))
    signature = getattr(binary, "code_signature", None)
    if signature is None:
        return None
    data = read_bytes(binary_path, 134_217_728)
    offset = int(signature.data_offset)
    length = int(signature.data_size)
    if offset + length > len(data) or length < 12:
        raise InvalidInput("Mach-O code signature exceeds file bounds")
    blob = data[offset:offset + length]
    magic, declared, count = struct.unpack_from(">III", blob)
    if magic != 0xFADE0CC0:
        return None
    if declared > len(blob) or count > 1000 or 12 + count * 8 > declared:
        raise InvalidInput("Invalid code signature superblob")
    for index in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + index * 8)
        if start + 8 > declared:
            raise InvalidInput("Code signature subblob out of bounds")
        kind, size = struct.unpack_from(">II", blob, start)
        if size < 8 or start + size > declared:
            raise InvalidInput("Code signature subblob length invalid")
        if kind == 0xFADE7171:
            return safe_plist(blob[start + 8:start + size])
    return None


def apple(asset: Asset, path: Path, output: Path, budget: Budget) -> ProfileResult:
    if path.is_dir():
        base = path
        inventory = [{"path": p.relative_to(base).as_posix(), "bytes": p.stat().st_size} for p in iter_tree(base, budget)]
        bundles = [base]
    else:
        inventory = extract_archive(path, output / "package", budget)
        base = output / "package"
        bundles = [p.parent for p in base.rglob("Info.plist") if p.parent.suffix == ".app"]
        if not bundles:
            raise InvalidInput("IPA missing .app/Info.plist")
    bundle_records, executable_records, entitlements = [], [], []
    for bundle in bundles[:100]:
        plist_path = bundle / "Info.plist"
        if not plist_path.is_file():
            plist_path = bundle / "Contents" / "Info.plist"
        info = safe_plist(read_bytes(plist_path, 8_388_608))
        bundle_records.append({
            "path": bundle.relative_to(base).as_posix(), "identifier": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"), "executable": info.get("CFBundleExecutable"),
            "minimum_os": info.get("MinimumOSVersion"), "url_types": info.get("CFBundleURLTypes", []),
            "transport_security": info.get("NSAppTransportSecurity", {}),
        })
        name = info.get("CFBundleExecutable")
        if isinstance(name, str) and name and "/" not in name and "\\" not in name and name not in (".", ".."):
            executable = bundle / name
            if not executable.exists():
                executable = bundle / "Contents" / "MacOS" / name
            if executable.is_file():
                metadata, _ = native(executable, read_bytes(executable, budget.limits["max_input_bytes"]))
                executable_records.append({"path": executable.relative_to(base).as_posix(), **metadata})
                parsed = _entitlements(executable, metadata)
                if parsed is not None:
                    entitlements.append({"path": executable.relative_to(base).as_posix(), "values": parsed})
        for entitlement_file in bundle.glob("*.entitlements"):
            entitlements.append({"path": entitlement_file.relative_to(base).as_posix(), "values": safe_plist(read_bytes(entitlement_file, 8_388_608))})
    result = ProfileResult(analysis={"format": asset.format, "bundles": bundle_records, "executables": executable_records, "entitlements": entitlements, "files": inventory})
    result.check("apple-bundle-and-plist")
    result.check("mach-o-metadata", "succeeded" if executable_records else "skipped", f"{len(executable_records)} executables present")
    for bundle in bundle_records:
        if bundle.get("transport_security", {}).get("NSAllowsArbitraryLoads") is True:
            result.candidate("apple-ats-arbitrary-loads", "App Transport Security permits arbitrary loads", "Info.plist declares NSAllowsArbitraryLoads=true.", location=bundle["path"] + "/Info.plist", remediation="Restrict ATS exceptions to required HTTPS endpoints and validate runtime behavior.")
    for entry in entitlements:
        if entry["values"].get("get-task-allow") is True:
            result.candidate("apple-debug-entitlement", "Debug task entitlement enabled", "get-task-allow=true appears in entitlements; signing enforcement is not checked.", location=entry["path"])
    result.limitations.extend([
        "Plist, Mach-O and XML entitlements are parsed; signature trust and provisioning validity require Apple tooling.",
        "Encrypted ranges need an authorized decrypted image. No iOS device installation, debugging, jailbreak or runtime bypass is attempted.",
    ])
    return result


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path is None:
        raise InvalidInput("Mobile package profile requires APK/AAB/DEX/IPA or an Apple bundle")
    return android(asset, path, output, budget) if asset.kind == "android" else apple(asset, path, output, budget)
