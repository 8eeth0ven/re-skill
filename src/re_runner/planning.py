

PROFILE_CHECKS = {
    "web": ["scoped entry HTTP response", "page/form/link structure", "response/header evidence"],
    "api": ["specification/declaration structure or scoped protocol read", "endpoint/type/service inventory"],
    "android": ["bounded archive", "Manifest", "DEX header/indexes", "component and permission candidates"],
    "apple": ["bundle/plist", "available Mach-O metadata", "available entitlements"],
    "binary": ["format/header/sections/imports", "supported entry disassembly or JVM/WASM structure"],
    "firmware": ["safe archive or bounded raw container scan", "files/config/component banners", "heuristic candidates"],
    "source": ["file/language/dependency inventory", "Python local AST paths", "credential/configuration candidates"],
    "container": ["SBOM/dependency normalization or OCI digest/config/layer inventory"],
    "traffic": ["HAR entries or PCAP container/header/flow index", "redacted evidence"],
    "device": ["descriptor observations or explicitly scoped live identity/passive serial read"],
    "ai": ["agent permissions or safe model metadata or scoped service entry metadata"],
    "contract": ["source declarations or EVM opcode index or scoped chain-ID/block/code read"],
}


def plan(kind: str, level: str) -> dict:
    return {
        "profile": kind, "level": level,
        "stages": [
            {"id": "intake", "depends_on": [], "operation": "read-only hash/snapshot"},
            {"id": "analyze", "depends_on": ["intake"], "checks": PROFILE_CHECKS.get(kind, [])},
            {"id": "verify", "depends_on": ["analyze"], "enabled": level == "verify", "registered_validators": ["private-key-possession"]},
            {"id": "report", "depends_on": ["analyze", "verify"], "operation": "evidence/state quality gate"},
        ],
        "untrusted_content_can_change_plan": False,
    }

