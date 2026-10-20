import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from .contracts import BUDGET_DEFAULTS, SCOPE_SCHEMA, validate
from .errors import InvalidInput, ScopeDenied


def normalize_url(value: str) -> str:
    if len(value) > 8192 or any(ord(c) < 33 or c == "\\" for c in value):
        raise InvalidInput("URL contains whitespace, controls or backslashes")
    try:
        p = urlsplit(value)
        if p.scheme not in ("http", "https", "ws", "wss", "grpc", "grpcs") or not p.hostname:
            raise InvalidInput("Expected an explicit supported URL scheme and host")
        if p.username is not None or p.password is not None:
            raise InvalidInput("Credentials in URLs are forbidden; use headers_env")
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = p.port
    except (ValueError, UnicodeError) as exc:
        raise InvalidInput("Invalid host or port") from exc
    path = p.path or "/"
    decoded = path
    try:
        for _ in range(4):
            next_value = unquote(decoded, errors="strict")
            if next_value == decoded:
                break
            decoded = next_value
    except UnicodeError as exc:
        raise InvalidInput("Invalid URL path character encoding") from exc
    # Ambiguous normalization must not cross a scope prefix after server decoding.
    if "%" in decoded or "\\" in decoded or any(ord(c) < 32 for c in decoded):
        raise InvalidInput("Ambiguous URL path encoding")
    if any(x in (".", "..") for x in decoded.split("/")) or "//" in decoded:
        raise InvalidInput("URL dot segments or repeated path separators rejected")
    default = 443 if p.scheme in ("https", "wss", "grpcs") else 80
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != default:
        authority += f":{port}"
    return urlunsplit((p.scheme, authority, path, p.query, ""))


def url_matches(value: str, prefix: str) -> bool:
    target, allowed = urlsplit(normalize_url(value)), urlsplit(normalize_url(prefix))
    if (target.scheme, target.netloc) != (allowed.scheme, allowed.netloc):
        return False
    path, base = unquote(target.path), unquote(allowed.path)
    if allowed.query:
        return target.path == allowed.path and target.query == allowed.query
    if base.endswith("/"):
        return path.startswith(base)
    return path == base or path.startswith(base + "/")


@dataclass
class ScopePolicy:
    allow_urls: list[str] = field(default_factory=list)
    exclude_urls: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_devices: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=lambda: ["read"])
    headers_env: dict[str, str] = field(default_factory=dict)
    budgets: dict[str, int] = field(default_factory=lambda: dict(BUDGET_DEFAULTS))

    @classmethod
    def from_dict(cls, value: dict, base: Path | None = None) -> "ScopePolicy":
        validate(value, SCOPE_SCHEMA)
        base = base or Path.cwd()
        result = cls(
            allow_urls=[normalize_url(x) for x in value.get("allow_urls", [])],
            exclude_urls=[normalize_url(x) for x in value.get("exclude_urls", [])],
            allow_paths=[str((base / x).resolve()) for x in value.get("allow_paths", [])],
            allow_devices=value.get("allow_devices", []),
            operations=value.get("operations", ["read"]),
            headers_env=value.get("headers_env", {}),
            budgets={**BUDGET_DEFAULTS, **value.get("budgets", {})},
        )
        forbidden = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "proxy-authorization"}
        if any(key.lower() in forbidden for key in result.headers_env):
            raise InvalidInput("Scope headers may not replace routing/framing headers")
        if result.headers_env:
            origins = {(urlsplit(x).scheme, urlsplit(x).netloc) for x in result.allow_urls}
            if len(origins) != 1:
                raise InvalidInput("Credential headers require exactly one allowed origin; use separate scopes for multiple identities/origins")
        return result

    def to_dict(self) -> dict:
        return {
            "version": 1, "allow_urls": self.allow_urls, "exclude_urls": self.exclude_urls,
            "allow_paths": self.allow_paths, "allow_devices": self.allow_devices,
            "operations": self.operations, "headers_env": self.headers_env, "budgets": self.budgets,
        }

    def require_url(self, value: str, operation: str = "read") -> str:
        value = normalize_url(value)
        if operation not in self.operations:
            raise ScopeDenied(f"Operation {operation} is outside scope")
        if any(url_matches(value, x) for x in self.exclude_urls):
            raise ScopeDenied("URL is explicitly excluded")
        if not any(url_matches(value, x) for x in self.allow_urls):
            raise ScopeDenied("URL is outside the explicit allowed origin/path")
        return value

    def require_path(self, path: Path) -> None:
        if self.allow_paths and not any(path.resolve().is_relative_to(Path(x)) for x in self.allow_paths):
            raise ScopeDenied("Local asset is outside allow_paths")
        if "read" not in self.operations:
            raise ScopeDenied("Local read operation is outside scope")

    def require_device(self, identity: str) -> None:
        if "device-read" not in self.operations or identity not in self.allow_devices:
            raise ScopeDenied("Device collection requires device-read and an exact allow_devices entry")

    def headers(self) -> dict[str, str]:
        headers = {}
        for name, variable in self.headers_env.items():
            value = os.environ.get(variable)
            if value is None:
                raise ScopeDenied(f"Credential environment variable is missing: {variable}")
            if len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise InvalidInput("Credential header contains invalid bytes")
            headers[name] = value
        return headers

