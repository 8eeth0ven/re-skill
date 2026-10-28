"""Observable protection indicators and next analysis routes; never claims a bypass."""


def annotate(kind: str, analysis: dict) -> dict:
    indicators, routes = [], []
    sections = analysis.get("sections", [])
    if not isinstance(sections, list):
        sections = []
    section_names = {str(item.get("name", "")).lower() for item in sections}
    if any(name.startswith(("upx", ".upx")) for name in section_names):
        indicators.append({"name": "upx-section-name", "basis": "section name", "confidence": "indicator"})
        routes.append({"operation": "isolate-and-unpack", "reason": "UPX-like section names; establish valid header and entry before selecting an unpacker", "reference": "platforms/01-windows/unpacking.md", "requires": ["isolated runtime", "authorized unpacker"]})
    high_entropy = [item.get("name") for item in sections if item.get("bytes", 0) >= 4096 and item.get("entropy", 0) >= 7.2]
    if high_entropy:
        indicators.append({"name": "high-entropy-sections", "basis": high_entropy, "confidence": "compression/encryption indicator, not proof of packing"})
        routes.append({"operation": "entry-to-runtime-code-transition", "reason": "Compare executable mappings and section changes within an isolated runtime", "reference": "techniques/03-unpacking/", "requires": ["isolated emulator/debugger", "matching architecture"]})
    symbols = [str(x).lower() for x in analysis.get("symbols", [])]
    imports = [str(symbol).lower() for entry in analysis.get("imports", []) for symbol in entry.get("symbols", [])]
    markers = set(symbols + imports)
    anti_debug = sorted(name for name in markers if any(token in name for token in ("isdebuggerpresent", "checkremotedebuggerpresent", "ptrace", "ntqueryinformationprocess", "sysctl")))[:20]
    if anti_debug:
        indicators.append({"name": "debugger-inspection-imports", "basis": anti_debug, "confidence": "API reference, call conditions unknown"})
        routes.append({"operation": "inspect-caller-and-syscall-boundary", "reason": "Trace API callers and compare instrumentation/no-instrumentation controls; an import alone does not prove blocking", "reference": "techniques/12-bypass/bypass-playbook.md", "requires": ["decompiler", "isolated debugger", "negative control"]})
    if kind == "binary" and not analysis.get("symbols") and analysis.get("format") not in ("wasm", "jvm-class", "jar"):
        indicators.append({"name": "no-symbols-returned", "basis": "symbol inventory", "confidence": "stripping or absent symbol table"})
        routes.append({"operation": "recover-functions-from-code-and-references", "reason": "Use imports, entry disassembly, cross references and platform ABI", "reference": "techniques/09-function-map/hook-fallback-playbook.md", "requires": ["native analysis provider"]})
    if analysis.get("format") == "mach-o-fat":
        # Fat containers declare encryption per slice; tag each range with the slice offset for locating.
        slices = analysis.get("slices", [])
        if not isinstance(slices, list):
            slices = []
        encrypted = [dict(item, slice_offset=slice_record.get("offset")) for slice_record in slices for item in slice_record.get("encrypted_ranges", [])]
        for slice_record in slices:
            ranges = [dict(item, slice_offset=slice_record.get("offset")) for item in slice_record.get("encrypted_ranges", [])]
            if any(item.get("crypt_id") for item in ranges):
                indicators.append({"name": "macho-encryption-command", "basis": ranges, "confidence": "declared encrypted range"})
    else:
        encrypted = analysis.get("encrypted_ranges", []) + [item for binary in analysis.get("executables", []) for item in binary.get("encrypted_ranges", [])]
        if any(item.get("crypt_id") for item in encrypted):
            indicators.append({"name": "macho-encryption-command", "basis": encrypted, "confidence": "declared encrypted range"})
    if any(item.get("crypt_id") for item in encrypted):
        routes.append({"operation": "authorized-decrypted-image", "reason": "Supply a matching decrypted image collected from an authorized device; rehash and correlate UUID/version", "reference": "techniques/03-unpacking/", "requires": ["authorized Apple device", "decrypted image"]})
    if kind == "android":
        native_count = len(analysis.get("native_libraries", []))
        dex_count = sum(item.get("method_count", 0) for item in analysis.get("dex", []))
        if native_count and dex_count < 20:
            indicators.append({"name": "native-heavy-with-small-dex", "basis": {"native_libraries": native_count, "dex_methods": dex_count}, "confidence": "architecture/loader indicator, not proof of a shell"})
        routes.append({"operation": "static-to-dynamic-escalation", "reason": "Use package/DEX/native inventory to select runtime trace and artifact collection; validate hooks with an uninstrumented control", "reference": "pipeline/pipeline.md", "requires": ["adb/device or emulator", "JADX/Apktool", "Frida when required"]})
    if indicators and not routes:
        routes.append({"operation": "manual-context-review", "reason": "Validate the indicator before selecting deeper tooling", "reference": "techniques/INDEX.md", "requires": ["contextual analysis"]})
    unpack_route = analysis.get("unpack_route")
    # The binary profile only attaches unpack_route after a packing indication,
    # so a succeeded status here implies the indication existed for this sample.
    if isinstance(unpack_route, dict) and unpack_route.get("status") == "succeeded":
        # Executed static-unpack record: `upx -d` rewrote a packed file into a
        # readable image without running the sample. This is evidence of a
        # completed data transformation only and is deliberately NOT folded
        # into bypass_executed, which asserts a protection was defeated at
        # runtime; no such claim is made here.
        routes.insert(0, {"route": "upx-static-unpack", "executed": True, "evidence": "unpack-upx/upx-unpack-run.json"})
    return {"indicators": indicators, "next_routes": routes, "bypass_executed": False}
