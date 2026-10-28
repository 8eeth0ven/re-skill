"""Conservative source paths and firmware component/configuration indexing."""
import ast
import re
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

from ..archive import decompress_gzip, extract_archive
from ..errors import BudgetExceeded, InvalidInput
from ..extractors import configured_executable, sevenzip_extract
from ..intake import iter_tree
from ..models import Asset, ProfileResult
from ..safety import Budget, read_bytes
from ..scanner import DANGEROUS_RULES, bandit_scan
from ..scope import ScopePolicy


SOURCE_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".h", ".cpp", ".go", ".rs", ".sh", ".php", ".rb", ".cs", ".sol", ".vy"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".env", ".xml"}
COMPONENTS = (
    ("busybox", rb"BusyBox v([0-9][0-9A-Za-z.]*)"),
    ("openssl", rb"OpenSSL ([0-9][0-9A-Za-z.]*)"),
    ("dropbear", rb"(?:dropbear_|SSH-2.0-dropbear_)([0-9][0-9A-Za-z.]*)"),
    ("dnsmasq", rb"dnsmasq[- /]([0-9][0-9A-Za-z.]*)"),
    ("linux", rb"Linux version ([0-9][0-9A-Za-z._-]*)"),
)
KEY_RE = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
PASSWORD_RE = re.compile(rb"(?im)^\s*(?:http_passwd|admin_password|password|api_key|secret_key)\s*[=:]\s*([^\r\n]{1,256})")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def python_paths(text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise InvalidInput(f"Python parse failed: {type(exc).__name__}") from exc
    results = []
    import_names = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            import_names.update({alias.asname or alias.name: alias.name for alias in node.names})
        elif isinstance(node, ast.ImportFrom):
            import_names.update({alias.asname or alias.name: f"{node.module}.{alias.name}" for alias in node.names})

    def qualified(node):
        name = _name(node)
        first, _, remaining = name.partition(".")
        return import_names.get(first, first) + ("." + remaining if remaining else "")

    def source(expression, known):
        if isinstance(expression, ast.Name) and expression.id in known:
            return known[expression.id]
        normalized_name = qualified(expression.value) if isinstance(expression, ast.Subscript) else qualified(expression.func) if isinstance(expression, ast.Call) else ""
        if normalized_name.startswith(("flask.", "django.http.")):
            normalized_name = normalized_name.split(".", 1)[1]
        if isinstance(expression, ast.Subscript) and normalized_name in (
            "request.args", "request.form", "request.values", "request.json", "sys.argv", "os.environ",
        ):
            return {"source_line": expression.lineno, "source": qualified(expression.value)}
        if isinstance(expression, ast.Call) and normalized_name in (
            "input", "request.args.get", "request.form.get", "request.values.get", "request.get_json", "os.getenv",
        ):
            return {"source_line": expression.lineno, "source": qualified(expression.func)}
        # Definite sanitizers are recorded as a different precondition, not proven universally safe.
        if isinstance(expression, ast.Call) and qualified(expression.func) in ("int", "float", "shlex.quote"):
            return None
        for child in ast.iter_child_nodes(expression):
            value = source(child, known)
            if value:
                return value
        return None

    def block(statements, known, function):
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                block(statement.body, {}, statement.name)
                continue
            if isinstance(statement, ast.ClassDef):
                block(statement.body, {}, statement.name)
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = source(statement.value, known) if statement.value is not None else None
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if value:
                            known[target.id] = value
                        else:
                            known.pop(target.id, None)
            # Avoid treating calls inside unexecuted nested blocks as a definite path.
            expressions = []
            for child in ast.iter_child_nodes(statement):
                if not isinstance(child, ast.stmt):
                    expressions.extend(ast.walk(child))
            for node in expressions:
                if not isinstance(node, ast.Call):
                    continue
                sink = qualified(node.func)
                dangerous = sink in ("os.system", "os.popen", "eval", "exec")
                if sink in ("subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"):
                    dangerous = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
                if dangerous and node.args:
                    value = source(node.args[0], known)
                    if value:
                        results.append({**value, "sink": sink, "sink_line": node.lineno, "function": function})
            if isinstance(statement, (ast.If, ast.For, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                # Flow through branches needs a CFG; only branch-local evidence is kept.
                for attr in ("body", "orelse", "finalbody"):
                    child_block = getattr(statement, attr, [])
                    block(child_block, dict(known), function)
                known.clear()
    block(tree.body, {}, "module")
    dedup = {(row["source_line"], row["sink_line"], row["sink"]): row for row in results}
    return list(dedup.values())[:1000]


def scan_tree(path: Path, result: ProfileResult, budget: Budget) -> None:
    files = list(iter_tree(path, budget)) if path.is_dir() else [path]
    root = path if path.is_dir() else path.parent
    language_counts, inventory, components, source_entries, dependencies = Counter(), [], [], [], []
    total = 0
    for item in files:
        budget.check()
        name = item.relative_to(root).as_posix()
        size = item.stat().st_size
        total += size
        if total > budget.limits["max_unpack_bytes"] or len(inventory) >= budget.limits["max_files"]:
            raise BudgetExceeded("Analysis tree bytes/files budget exceeded")
        inventory.append({"path": name, "bytes": size})
        if item.suffix.lower() in SOURCE_SUFFIXES:
            language_counts[item.suffix.lower()] += 1
        if item.name.lower() in ("requirements.txt", "package.json", "package-lock.json", "cargo.toml", "cargo.lock", "go.mod", "pom.xml", "pyproject.toml", "packages", "status"):
            dependencies.append(name)
        if size > 8_388_608:
            result.check("file-scan:" + name, "skipped", "File exceeds per-file rule budget")
            continue
        data = read_bytes(item, 8_388_608)
        for component, pattern in COMPONENTS:
            match = re.search(pattern, data)
            if match:
                components.append({"name": component, "version_banner": match[1].decode("ascii", "replace"), "path": name, "offset": match.start(), "evidence_class": "version-banner"})
        if KEY_RE.search(data):
            result.candidate(
                "asset-private-key", "Private-key material appears in the asset",
                "A PEM/OpenSSH private-key header appears in the indicated file. The validator can check whether an unencrypted supported key is usable.",
                location=name, severity="high", impact="A usable key may enable impersonation or decryption if the corresponding public key remains trusted; deployment trust is unknown.",
                remediation="Remove shared production secrets from distributable artifacts, rotate affected keys and review trust relationships.",
                validation={"validator": "private-key-possession", "location": name},
            )
        for match in list(PASSWORD_RE.finditer(data))[:10]:
            value = match[1].strip(b" \t\"'")
            if value and value not in (b"", b"${PASSWORD}", b"null", b"None", b"false"):
                result.candidate("asset-credential-literal", "Credential-like literal in configuration",
                                 "A credential assignment contains a literal. Value is redacted; test/example status and deployment use require review.",
                                 location=f"{name}:byte:{match.start()}", remediation="Use secret references instead of literal credentials and verify whether exposed values require rotation.")
        if item.suffix == ".py":
            try:
                text = data.decode("utf-8")
                paths = python_paths(text)
                source_entries.extend({"path": name, **row} for row in paths)
                for row in paths:
                    result.candidate("python-untrusted-execution-path", "External input reaches an execution sink",
                                     f"Within {row['function']}, {row['source']} at line {row['source_line']} propagates to {row['sink']} at line {row['sink_line']}. Branch feasibility and deployment reachability are unverified.",
                                     location=f"{name}:{row['sink_line']}", severity="high",
                                     impact="If reachable without sufficient validation, external input may control code or shell execution.",
                                     remediation="Pass structured argument lists, avoid eval/exec on external values and validate inputs at the trust boundary.")
            except (UnicodeError, InvalidInput) as exc:
                result.check("python-parse:" + name, "degraded", str(exc))
        if result.analysis.get("profile") == "firmware" and item.name in ("passwd", "shadow") and item.parent.name == "etc":
            for line in data.decode("utf-8", "replace").splitlines()[:1000]:
                columns = line.split(":")
                if len(columns) > 1 and columns[0] and columns[1] not in ("", "x", "*", "!", "!!"):
                    result.candidate("firmware-active-account-hash", "Account password hash is shipped in filesystem",
                                     f"Account {columns[0]} has an active hash entry; hash values are redacted. Login reachability and account state need verification.", location=name)
        if item.suffix in (".sh", ".rc", ".init") or item.name in ("rcS", "inittab"):
            for line in data.decode("utf-8", "replace").splitlines()[:10000]:
                if "telnetd" in line and not line.strip().startswith("#"):
                    result.candidate("firmware-telnet-startup", "Telnet daemon mentioned in startup configuration",
                                     "An uncommented startup line invokes or refers to telnetd; execution conditions and listening state require validation.", location=name,
                                     remediation="Disable unauthenticated/plaintext remote administration or replace with configured SSH.")
                    break
    result.analysis.update({
        "files": inventory, "file_count": len(inventory), "total_bytes": total,
        "languages": dict(language_counts), "component_banners": components,
        "dependency_manifests": dependencies, "python_source_paths": source_entries,
    })
    result.check("file-language-component-inventory")
    result.check("credential-and-configuration-rules")
    result.check("python-local-path-analysis", "succeeded" if language_counts.get(".py") else "skipped", "Function-local AST assignments; no interprocedural/branch reachability proof")


def _skipped_extractor(reason: str) -> dict:
    return {"tool": "7z", "format": None, "status": "skipped", "version": "unknown",
            "members": [], "member_count": 0, "files": 0, "bytes": 0, "error": reason}


def _unsupported_extractor(container_types: list[str]) -> dict:
    # 7-Zip has no UBI/TRX handler (verified against `7z i` for 25.01), so those
    # containers stay on the raw signature scan and the stage says so honestly.
    return {"tool": "7z", "format": None, "status": "degraded", "version": "unknown",
            "members": [], "member_count": 0, "files": 0, "bytes": 0,
            "error": "7-Zip provides no UBI/TRX filesystem extraction; "
                     + ", ".join(sorted(set(container_types))) + " stays on the raw signature scan"
                     + ("" if configured_executable() else " (RE_RUN_7Z is not configured either)")}


def firmware_image(path: Path, output: Path, budget: Budget) -> tuple[Path, list[str], dict]:
    data = read_bytes(path, budget.limits["max_input_bytes"])
    containers = []
    if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        extract_archive(path, output / "rootfs", budget)
        return output / "rootfs", [], {"container": "zip/tar"}
    if data[:2] == b"\x1f\x8b":
        inner = output / "gzip-payload.bin"
        decompress_gzip(path, inner, budget)
        if zipfile.is_zipfile(inner) or tarfile.is_tarfile(inner):
            extract_archive(inner, output / "rootfs", budget)
            return output / "rootfs", [], {"container": "gzip+archive"}
        return inner, ["gzip payload was expanded and scanned; nested filesystem parsing requires a supported isolated provider."], {"container": "gzip"}
    for magic, name in ((b"hsqs", "squashfs"), (b"sqsh", "squashfs-big-endian"), (b"HDR0", "trx"), (b"\x27\x05\x19\x56", "uimage"), (b"UBI#", "ubi"), (b"\x85\x19", "jffs2")):
        offset = data.find(magic, 0, 8_388_608)
        if offset != -1:
            containers.append({"type": name, "offset": offset})
    limitations = ["Opaque filesystem image was scanned for structure/banners. Squashfs/UBI/ext filesystems require an isolated extractor; untrusted external extraction is not run directly on the host."]
    metadata: dict = {"container_signatures": containers}
    selected = path
    # S1 unpack stage: a whole-image squashfs (magic at offset 0) is handed to
    # the trusted 7-Zip extractor, and the unpacked tree replaces the raw image
    # as the scan input so file/banner/secret rules cover real files. Only
    # listing/unpacking happens there; nothing extracted is ever executed.
    squashfs = next((c for c in containers if c["type"].startswith("squashfs") and c["offset"] == 0), None)
    if squashfs is not None:
        metadata["container"] = squashfs["type"]
        unpacked = sevenzip_extract(path, output / "rootfs-7z", budget)
        if unpacked is None:
            metadata["extractor"] = _skipped_extractor(
                "RE_RUN_7Z is not configured; set it to a trusted native 7z executable to unpack the squashfs image")
        else:
            metadata["extractor"] = unpacked
            if unpacked["status"] in ("succeeded", "degraded"):
                selected = output / "rootfs-7z"
                limitations = []
                if unpacked["status"] == "degraded":
                    limitations.append("7-Zip unpacked the filesystem with errors; some entries may be missing from the analysis tree (see firmware-filesystem-extract-7z).")
            else:
                limitations = limitations + ["7-Zip squashfs extraction failed; the raw signature scan is retained (see firmware-filesystem-extract-7z)."]
    elif any(c["type"] in ("ubi", "trx") for c in containers):
        metadata["extractor"] = _unsupported_extractor([c["type"] for c in containers])
    return selected, limitations, metadata


def _rule_engine(tree: Path, output: Path, result: ProfileResult, budget: Budget) -> None:
    # bandit complements the function-local AST paths with a real rule engine.
    # A rule hit is pattern evidence only, so candidates are titled
    # accordingly; the AST layer keeps its own rule ids and the two coexist.
    scan = bandit_scan(tree, output, budget)
    if scan is None:
        result.check(
            "source-rule-engine-bandit", "skipped",
            "bandit is not available on PATH (pyproject extra: source-deep)",
        )
        return
    findings = scan.get("findings", [])
    dangerous = [row for row in findings if row["severity"] == "HIGH" and row["rule"] in DANGEROUS_RULES]
    detail = (
        f"bandit {scan.get('version', 'unknown')}: {len(findings)} finding(s), "
        f"{len(dangerous)} dangerous-API hit(s)"
    )
    if scan.get("error"):
        detail += f"; {scan['error']}"
    result.check(
        "source-rule-engine-bandit",
        "degraded" if scan["status"] == "failed" else scan["status"], detail,
    )
    if scan["status"] not in ("succeeded", "degraded"):
        return
    result.analysis["rule_engine"] = findings
    for row in dangerous:
        result.candidate(
            "bandit-high-dangerous-api",
            f"Bandit rule {row['rule']} hit at {row['file']}:{row['line']}; requires contextual confirmation",
            f"Rule {row['rule']} reports: {row['issue_text']}. A rule hit is pattern-level evidence; "
            "reachability, input trust and deployment context are unverified.",
            location=f"{row['file']}:{row['line']}", severity="high",
            impact="If external input reaches this dangerous API unvalidated, code or command execution may be possible.",
            remediation="Confirm the data flow from the trust boundary, replace the dangerous API with a structured "
                        "alternative and validate with a controlled test.",
        )


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path is None:
        raise InvalidInput("Source/firmware profile requires a local file or tree; clone a Git repository before analysis")
    result = ProfileResult(analysis={"profile": asset.kind, "format": asset.format})
    selected = path
    if asset.kind == "firmware" and not path.is_dir():
        selected, limitations, metadata = firmware_image(path, output, budget)
        result.analysis.update(metadata)
        result.limitations.extend(limitations)
        result.check("firmware-container-inspection", "degraded" if limitations else "succeeded")
        extractor = metadata.get("extractor")
        if extractor is not None:
            # An extraction failure degrades the profile with its failure
            # signature; it never fails the analysis (raw scan is retained).
            status = "degraded" if extractor["status"] == "failed" else extractor["status"]
            detail = extractor.get("error") or (
                f"{extractor.get('files', 0)} file(s), {extractor.get('bytes', 0)} bytes unpacked from "
                f"{extractor.get('format') or 'container'} by {extractor.get('version', 'unknown')}"
            )
            result.check("firmware-filesystem-extract-7z", status, detail)
    scan_tree(selected, result, budget)
    if asset.kind == "source":
        _rule_engine(selected, output, result, budget)
    result.limitations.append("Rules produce candidates; version banners and literals do not prove exploitable flaws, missing backports or vulnerability novelty.")
    if asset.kind == "source":
        result.limitations.append("Python receives local AST path analysis; other source languages receive structure/literal indexing. No project code, build hooks or Git hooks are executed.")
    return result
