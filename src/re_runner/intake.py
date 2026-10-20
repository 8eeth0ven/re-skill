import hashlib
import ipaddress
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

from .errors import BudgetExceeded, IntegrityError, InvalidInput
from .models import Asset, AssetRequest, KINDS
from .safety import Budget, atomic_json, open_regular, parse_json, read_bytes, safe_relative, sha256_file
from .scope import ScopePolicy, normalize_url


def _json_kind(value: dict) -> tuple[str, str] | None:
    nested = value.get("data")
    if "openapi" in value or "swagger" in value or "__schema" in value or isinstance(nested, dict) and "__schema" in nested:
        return "api", "openapi" if "paths" in value else "graphql-introspection"
    if "log" in value and isinstance(value["log"], dict) and "entries" in value["log"]:
        return "traffic", "har"
    if "spdxVersion" in value or value.get("bomFormat") == "CycloneDX":
        return "container", "sbom"
    if "imageLayoutVersion" in value or "schemaVersion" in value and ("manifests" in value or "layers" in value):
        return "container", "oci-json"
    if value.get("asset_kind") in ("device", "ai", "contract"):
        return value["asset_kind"], "descriptor"
    if "tensors" in value and "metadata" in value:
        return "ai", "model-metadata"
    return None


def detect_file(path: Path, max_bytes: int = 16_777_216) -> tuple[str, str]:
    with open_regular(path) as stream:
        head = stream.read(4096)
    suffix = path.suffix.lower()
    if suffix == ".class" and head.startswith(b"\xca\xfe\xba\xbe"):
        return "binary", "jvm"
    magic = (
        (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"\x00asm", "wasm"),
        (b"\xfe\xed\xfa\xce", "mach-o"), (b"\xce\xfa\xed\xfe", "mach-o"),
        (b"\xfe\xed\xfa\xcf", "mach-o"), (b"\xcf\xfa\xed\xfe", "mach-o"),
        (b"\xca\xfe\xba\xbe", "jvm-or-fat-mach-o"), (b"\xbe\xba\xfe\xca", "mach-o-fat"),
        (b"\xca\xfe\xba\xbf", "mach-o-fat"),
    )
    for prefix, fmt in magic:
        if head.startswith(prefix):
            return "binary", fmt
    if head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")):
        return "traffic", "pcapng" if head[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
    if head.startswith((b"dex\n", b"cdex")):
        return "android", "dex"
    if head.startswith(b"GGUF") or suffix == ".safetensors":
        return "ai", "gguf" if head.startswith(b"GGUF") else "safetensors"
    if suffix in (".pt", ".pth", ".pkl", ".pickle", ".joblib", ".onnx"):
        return "ai", "unsafe-model" if suffix != ".onnx" else "onnx"
    if suffix in (".apk", ".aab"):
        return "android", suffix[1:]
    if suffix == ".ipa":
        return "apple", "ipa"
    if suffix in (".graphql", ".gql", ".proto"):
        return "api", "protobuf" if suffix == ".proto" else "graphql-sdl"
    if suffix in (".sol", ".vy", ".evm", ".hex"):
        return "contract", "solidity" if suffix == ".sol" else "vyper" if suffix == ".vy" else "evm-hex"
    if suffix == ".har":
        return "traffic", "har"
    if path.name.lower() in ("package-lock.json", "package.json", "requirements.txt", "cargo.lock", "cargo.toml", "go.mod", "pom.xml"):
        return "container", "dependencies"
    if suffix in (".json", ".yaml", ".yml") and path.stat().st_size <= max_bytes:
        if suffix == ".json":
            value = parse_json(read_bytes(path, max_bytes))
        else:
            from .parsing import load_yaml
            value = load_yaml(read_bytes(path, max_bytes))
        if isinstance(value, dict):
            detected = _json_kind(value)
            if detected:
                return detected
        return "source", "configuration"
    if suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".h", ".cpp", ".go", ".rs", ".sh", ".toml", ".xml", ".txt", ".md", ".ini", ".conf"):
        return "source", "source-file"
    if suffix in (".jar", ".class"):
        return "binary", "jar" if suffix == ".jar" else "jvm"
    if head.startswith((b"hsqs", b"sqsh", b"HDR0", b"\x27\x05\x19\x56", b"\x1f\x8b", b"PK\x03\x04")) or suffix in (".bin", ".img", ".trx", ".gz", ".tgz", ".tar", ".xz", ".zip", ".squashfs"):
        return "firmware", "gzip" if head[:2] == b"\x1f\x8b" else "firmware-image"
    raise InvalidInput("Unknown format; supply --type only when the intended profile is known")


def detect(request: AssetRequest) -> tuple[str, str, Path | None, str]:
    value = request.locator
    if not isinstance(value, str) or not value or len(value) > 8192 or "\x00" in value:
        raise InvalidInput("Asset locator must be a bounded nonempty string")
    if request.type not in ("auto", *KINDS):
        raise InvalidInput("Unknown asset type")
    path = Path(value).expanduser().absolute()
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InvalidInput("Root asset links/reparse points are rejected")
        if path.is_dir():
            if path.suffix.lower() == ".app" or (path / "Info.plist").is_file():
                kind, fmt = "apple", "app-bundle"
            elif (path / "oci-layout").is_file() or (path / "manifest.json").is_file() and (path / "repositories").exists():
                kind, fmt = "container", "oci-directory"
            elif (path / "etc").is_dir() and ((path / "bin").is_dir() or (path / "sbin").is_dir()):
                kind, fmt = "firmware", "rootfs"
            else:
                kind, fmt = "source", "source-tree"
        elif stat.S_ISREG(info.st_mode):
            if request.type == "auto":
                kind, fmt = detect_file(path)
            else:
                try:
                    kind, fmt = detect_file(path)
                except InvalidInput:
                    kind, fmt = request.type, "explicit-" + request.type
        else:
            raise InvalidInput("Asset must be a regular file, directory, or explicit locator")
        return request.type if request.type != "auto" else kind, fmt, path, str(path)
    if value.startswith(("http://", "https://", "ws://", "wss://", "grpc://", "grpcs://")):
        url = normalize_url(value)
        scheme = urlsplit(url).scheme
        kind = "api" if scheme in ("ws", "wss", "grpc", "grpcs") else "web"
        return request.type if request.type != "auto" else kind, scheme, None, url
    if value.startswith(("android://", "ios://", "serial://")):
        if not re.fullmatch(r"(?:android|ios|serial)://[A-Za-z0-9_./:-]{1,200}", value):
            raise InvalidInput("Invalid device locator")
        return "device" if request.type == "auto" else request.type, "live-device", None, value
    try:
        ip = ipaddress.ip_address(value)
        host = f"[{value}]" if ip.version == 6 else value
        return request.type if request.type != "auto" else "web", "http", None, normalize_url("http://" + host + "/")
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", value) and not value.startswith("."):
        if any(value.lower().endswith(extension) for extension in (".apk", ".aab", ".ipa", ".exe", ".dll", ".so", ".bin", ".json", ".py", ".pcap", ".har", ".wasm", ".sol")):
            raise InvalidInput("Asset file not found; use an explicit http(s) URL for a host with this suffix")
        try:
            ipaddress.ip_address(value)
            host = f"[{value}]" if ":" in value else value
        except ValueError:
            host = value
            if "." not in value and value != "localhost":
                raise InvalidInput("File not found; bare hostnames require a URL scheme")
        url = normalize_url("http://" + host + "/")
        return request.type if request.type != "auto" else "web", "http", None, url
    raise InvalidInput("Asset path does not exist or locator is not supported")


def iter_tree(root: Path, budget: Budget, *, skip_vcs: bool = True):
    stack = [(root, 0)]
    entry_count = 0
    while stack:
        directory, depth = stack.pop()
        budget.check()
        if depth > budget.limits["max_depth"]:
            raise BudgetExceeded("Directory depth budget exceeded")
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > budget.limits["max_files"]:
                    raise BudgetExceeded("Directory entry count budget exceeded")
                entries.append(entry)
        entries.sort(key=lambda x: x.name.casefold())
        for entry in entries:
            if skip_vcs and entry.name == ".git":
                continue
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise InvalidInput(f"Input tree contains link/reparse point: {entry.name}")
            path = Path(entry.path)
            safe_relative(path.relative_to(root).as_posix(), budget.limits["max_depth"])
            if stat.S_ISDIR(info.st_mode):
                stack.append((path, depth + 1))
            elif stat.S_ISREG(info.st_mode):
                yield path
            else:
                raise InvalidInput("Input tree contains a device, socket or named pipe")


def tree_hash(root: Path, budget: Budget) -> tuple[str, list[dict]]:
    records, total = [], 0
    for path in iter_tree(root, budget):
        total += path.stat().st_size
        if total > budget.limits["max_input_bytes"] or len(records) >= budget.limits["max_files"]:
            raise BudgetExceeded("Directory input size/file count budget exceeded")
        records.append({"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path, budget)})
    records.sort(key=lambda x: x["path"])
    digest = hashlib.sha256()
    for record in records:
        digest.update(f"{record['path']}\0{record['sha256']}\0{record['bytes']}\n".encode("utf-8"))
    return digest.hexdigest(), records


def snapshot(request: AssetRequest, asset_id: str, run_root: Path, scope: ScopePolicy, budget: Budget) -> Asset:
    kind, fmt, original, locator = detect(request)
    asset = Asset(asset_id, locator, kind, fmt)
    if original is None:
        # Validation is deferred to the profile so blocked runs still produce a report.
        return asset
    scope.require_path(original)
    if original.is_dir() and run_root.resolve().is_relative_to(original.resolve()):
        raise InvalidInput("Output directory may not be inside the input tree")
    target_root = run_root / "inputs" / asset_id
    if target_root.exists():
        raise IntegrityError("Incomplete intake directory exists; preserve evidence and start a fresh run")
    target_root.mkdir(parents=True, mode=0o700)
    # R1: mark the copy as in progress before the first byte lands. The marker
    # is removed only on success, so any surviving directory is provably an
    # interrupted partial copy the runner may safely rebuild (no evidence ever
    # cites it); a hard kill mid-copy therefore cannot poison future snapshots.
    atomic_json(target_root / ".incomplete", {"started": True})
    if original.is_dir():
        before, records = tree_hash(original, budget)
        target = target_root / "tree"
        target.mkdir(mode=0o700)
        for record in records:
            budget.check()
            budget.consume("files", 1)
            source = original / record["path"]
            destination = target / record["path"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            with open_regular(source) as inp, destination.open("xb") as out:
                count = 0
                while block := inp.read(65536):
                    count += len(block)
                    if count > record["bytes"]:
                        raise IntegrityError("Input grew during snapshot")
                    digest.update(block)
                    budget.consume("input_bytes", len(block))
                    out.write(block)
            if digest.hexdigest() != record["sha256"] or count != record["bytes"]:
                raise IntegrityError("Input changed during snapshot")
            destination.chmod(0o400)
        after, _ = tree_hash(original, budget)
        if before != after:
            raise IntegrityError("Original tree changed during snapshot")
        asset.sha256 = before
        asset.metadata.update({"file_count": len(records), "bytes": sum(x["bytes"] for x in records), "vcs_metadata_excluded": True})
        atomic_json(target_root / "manifest.json", records)
    else:
        target = target_root / ("sample" + original.suffix.lower())
        if original.stat().st_size > budget.limits["max_input_bytes"]:
            raise BudgetExceeded("Input file budget exceeded")
        before = sha256_file(original, budget)
        budget.consume("files", 1)
        with open_regular(original) as inp, target.open("xb") as out:
            count = 0
            while block := inp.read(65536):
                budget.check()
                count += len(block)
                if count > budget.limits["max_input_bytes"]:
                    raise BudgetExceeded("Input grew beyond budget")
                budget.consume("input_bytes", len(block))
                out.write(block)
        if before != sha256_file(target, budget) or before != sha256_file(original, budget):
            raise IntegrityError("Original input changed during snapshot")
        target.chmod(0o400)
        asset.sha256 = before
        asset.metadata["bytes"] = count
        asset.metadata["original_name"] = original.name
    asset.snapshot = target.relative_to(run_root).as_posix()
    (target_root / ".incomplete").unlink(missing_ok=True)
    return asset

