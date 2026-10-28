import hashlib
import re
import tarfile
import zipfile
from pathlib import Path

from ..archive import extract_archive
from ..errors import BudgetExceeded, IntegrityError, InvalidInput
from ..models import Asset, ProfileResult
from ..safety import Budget, load_json, read_bytes
from ..scope import ScopePolicy


def sbom(value: dict) -> tuple[list[dict], str]:
    components = []
    if value.get("bomFormat") == "CycloneDX":
        source = value.get("components", [])
        fmt = "cyclonedx"
        for item in source:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise InvalidInput("CycloneDX component requires a name")
            components.append({"name": item["name"], "version": item.get("version"), "purl": item.get("purl"), "type": item.get("type"), "reference": item.get("bom-ref"), "hashes": item.get("hashes", [])})
    elif "spdxVersion" in value:
        fmt = "spdx"
        for item in value.get("packages", []):
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise InvalidInput("SPDX package requires a name")
            purls = [entry.get("referenceLocator") for entry in item.get("externalRefs", []) if entry.get("referenceType") == "purl"]
            components.append({"name": item["name"], "version": item.get("versionInfo"), "purl": purls[0] if purls else None, "reference": item.get("SPDXID"), "hashes": item.get("checksums", [])})
    else:
        raise InvalidInput("Expected CycloneDX or SPDX JSON SBOM")
    if len(components) > 20000:
        raise BudgetExceeded("SBOM component budget exceeded")
    return components, fmt


def dependency_manifest(path: Path, name: str) -> list[dict]:
    data = read_bytes(path, 8_388_608)
    records = []
    if name in ("package-lock.json", "package.json"):
        value = load_json(path, max_bytes=8_388_608)
        if not isinstance(value, dict):
            raise InvalidInput("NPM manifest requires an object")
        if "packages" in value:
            for locator, package in value["packages"].items():
                if not isinstance(package, dict):
                    raise InvalidInput("Invalid NPM lock package")
                records.append({"name": package.get("name") or locator.split("node_modules/")[-1] or value.get("name"), "version": package.get("version"), "location": locator})
        else:
            for key in ("dependencies", "devDependencies", "optionalDependencies"):
                for package, version in value.get(key, {}).items():
                    records.append({"name": package, "version": version if isinstance(version, str) else version.get("version"), "group": key})
    elif name.endswith("requirements.txt"):
        for line in data.decode("utf-8", "replace").splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([=<>!~]{1,3}[^#;\s]+)?", line)
            if match:
                records.append({"name": match[1], "version_constraint": match[2]})
    elif name == "go.mod":
        for package, version in re.findall(r"(?m)^\s*(?:require\s+)?([A-Za-z0-9._/-]+)\s+(v[0-9][^\s]+)", data.decode("utf-8", "replace")):
            records.append({"name": package, "version": version})
    elif name in ("Cargo.toml", "Cargo.lock", "pyproject.toml"):
        import tomllib
        try:
            value = tomllib.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise InvalidInput("Malformed dependency TOML") from exc
        if name == "Cargo.lock":
            records = [{"name": p.get("name"), "version": p.get("version"), "source": p.get("source")} for p in value.get("package", [])]
        elif name == "Cargo.toml":
            for package, version in value.get("dependencies", {}).items():
                records.append({"name": package, "version_constraint": version if isinstance(version, str) else version.get("version")})
        else:
            records = [{"requirement": item} for item in value.get("project", {}).get("dependencies", [])]
    elif name == "pom.xml":
        from ..parsing import xml
        root = xml(data)
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] == "dependency":
                values = {child.tag.rsplit("}", 1)[-1]: child.text for child in node}
                records.append({"name": f"{values.get('groupId')}:{values.get('artifactId')}", "version": values.get("version"), "scope": values.get("scope")})
    else:
        raise InvalidInput("Unsupported dependency manifest format")
    if len(records) > 20000:
        raise BudgetExceeded("Dependency count budget exceeded")
    return records


def _descriptor_blob(root: Path, descriptor: dict, budget: Budget) -> Path:
    digest = descriptor.get("digest", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise InvalidInput("Only SHA256 OCI blob descriptors are supported")
    path = root / "blobs" / "sha256" / digest.split(":")[1]
    data = read_bytes(path, budget.limits["max_input_bytes"])
    if hashlib.sha256(data).hexdigest() != digest.split(":")[1] or descriptor.get("size") != len(data):
        raise IntegrityError("OCI blob digest or size mismatch")
    return path


def oci_directory(root: Path, output: Path, budget: Budget) -> dict:
    layout = load_json(root / "oci-layout", max_bytes=65536)
    if layout.get("imageLayoutVersion") != "1.0.0":
        raise InvalidInput("Unsupported OCI image layout")
    index = load_json(root / "index.json", max_bytes=8_388_608)
    manifests, layers, components = [], [], []
    descriptors = index.get("manifests")
    if not isinstance(descriptors, list) or not descriptors:
        raise InvalidInput("OCI index requires a nonempty manifests array")
    queue = [(item, 0) for item in descriptors]
    seen = set()
    while queue:
        descriptor, depth = queue.pop(0)
        if depth > 4 or len(seen) > 100:
            raise BudgetExceeded("OCI manifest nesting/count exceeded")
        if descriptor.get("digest") in seen:
            continue
        seen.add(descriptor.get("digest"))
        manifest_path = _descriptor_blob(root, descriptor, budget)
        manifest = load_json(manifest_path, max_bytes=8_388_608)
        if "manifests" in manifest:
            queue.extend((entry, depth + 1) for entry in manifest["manifests"])
            continue
        config_path = _descriptor_blob(root, manifest.get("config", {}), budget)
        config = load_json(config_path, max_bytes=8_388_608)
        configuration = config.get("config", {})
        manifests.append({
            "digest": descriptor["digest"], "architecture": config.get("architecture"), "os": config.get("os"),
            "user": configuration.get("User"), "entrypoint": configuration.get("Entrypoint"),
            "command": configuration.get("Cmd"), "exposed_ports": list(configuration.get("ExposedPorts", {})),
            "environment_names": [str(x).split("=", 1)[0] for x in configuration.get("Env", [])],
        })
        for layer in manifest.get("layers", []):
            if len(layers) >= 200:
                raise BudgetExceeded("OCI layer count exceeded")
            blob = _descriptor_blob(root, layer, budget)
            inventory = extract_archive(blob, output / f"layer-{len(layers):03d}", budget)
            layer_record = {"digest": layer["digest"], "files": inventory, "whiteouts": [x["path"] for x in inventory if Path(x["path"]).name.startswith(".wh.")]}
            layer_root = output / f"layer-{len(layers):03d}"
            for item in inventory:
                name = Path(item["path"]).name
                if name in ("package-lock.json", "package.json", "requirements.txt", "go.mod", "Cargo.toml", "Cargo.lock", "pyproject.toml", "pom.xml"):
                    components.extend({"layer": layer["digest"], "path": item["path"], **entry} for entry in dependency_manifest(layer_root / item["path"], name))
            layers.append(layer_record)
    return {"format": "oci-layout", "manifests": manifests, "layers": layers, "components": components, "layer_union_applied": False}


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path is None:
        raise InvalidInput("Container analysis requires a local OCI layout/archive, SBOM or dependency manifest; registry pulls are not automatic")
    result = ProfileResult()
    original_name = asset.metadata.get("original_name", path.name)
    if path.is_dir():
        result.analysis = oci_directory(path, output, budget)
        result.check("oci-digest-config-layer-analysis")
    elif zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        extract_archive(path, output / "oci", budget)
        if not (output / "oci" / "oci-layout").is_file():
            raise InvalidInput("Archive is not an OCI image layout; Docker-save legacy layout is not supported")
        result.analysis = oci_directory(output / "oci", output / "layers", budget)
        result.check("oci-digest-config-layer-analysis")
    elif original_name in ("package-lock.json", "package.json", "requirements.txt", "go.mod", "Cargo.toml", "Cargo.lock", "pyproject.toml", "pom.xml"):
        result.analysis = {"format": "dependency-manifest", "components": dependency_manifest(path, original_name)}
        result.check("dependency-normalization")
    else:
        value = load_json(path)
        if not isinstance(value, dict):
            raise InvalidInput("SBOM must be an object")
        components, fmt = sbom(value)
        result.analysis = {"format": fmt, "components": components, "component_count": len(components), "relationships": value.get("relationships", value.get("dependencies", []))}
        result.check("sbom-parse-and-normalization")
    for manifest in result.analysis.get("manifests", []):
        if manifest.get("user") in (None, "", "0", "root", "0:0"):
            result.candidate("container-default-root", "Container image defaults to root", "OCI configuration has no non-root User declaration; runtime user and isolation settings are unknown.", location=manifest["digest"], remediation="Set a least-privileged runtime user and review capabilities/mounts at deployment.")
    result.limitations.extend([
        "Components are inventory observations. No vulnerability advisory snapshot is bundled; version vulnerability/backport assessment is not automatically asserted.",
        "OCI layers are analyzed independently with whiteouts indexed; a merged live filesystem and registry/runtime configuration are not analyzed.",
    ])
    return result
