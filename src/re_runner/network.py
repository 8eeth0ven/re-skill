"""Budgeted, scope-checked network reads with pinned DNS and verified TLS."""
import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .errors import BudgetExceeded, InvalidInput, NetworkError, ScopeDenied
from .safety import Budget, public_url, redact
from .scope import ScopePolicy


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, addresses: list[str], timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.addresses = addresses

    def connect(self) -> None:
        error = None
        for address in self.addresses:
            try:
                self.sock = socket.create_connection((address, self.port), self.timeout)
                return
            except OSError as exc:
                error = exc
        raise NetworkError(f"Connection failed: {type(error).__name__}")


class _PinnedHTTPS(_PinnedHTTP):
    def connect(self) -> None:
        super().connect()
        try:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
        except BaseException:
            self.close()
            raise


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    records: list[dict]


class NetworkClient:
    def __init__(self, scope: ScopePolicy, budget: Budget):
        self.scope, self.budget = scope, budget
        self.pins: dict[tuple[str, int], list[str]] = {}
        self.last_request = 0.0
        self.records: list[dict] = []

    def addresses(self, host: str, port: int) -> list[str]:
        key = (host, port)
        if key not in self.pins:
            self.budget.check()
            try:
                results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise NetworkError(f"DNS resolution failed: {type(exc).__name__}") from exc
            values = list(dict.fromkeys(row[4][0] for row in results))[:16]
            if not values:
                raise NetworkError("DNS returned no usable addresses")
            for value in values:
                ip = ipaddress.ip_address(value.split("%")[0])
                if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                    raise ScopeDenied("Unspecified, multicast and link-local targets are not read targets")
            # Private/loopback networks are allowed only via explicit host scope.
            self.pins[key] = values
        return self.pins[key]

    def pace(self) -> None:
        delay = 1 / self.budget.limits["requests_per_second"] - (time.monotonic() - self.last_request)
        while delay > 0:
            self.budget.check()
            time.sleep(min(delay, 0.05))
            delay = 1 / self.budget.limits["requests_per_second"] - (time.monotonic() - self.last_request)
        self.budget.consume("requests", 1)
        self.last_request = time.monotonic()

    def request(
        self, url: str, *, method: str = "GET", body: bytes | None = None,
        headers: dict[str, str] | None = None, operation: str = "read", redirects: int = 3,
    ) -> Response:
        if method not in ("GET", "HEAD", "POST"):
            raise InvalidInput("Only bounded read/query HTTP methods are implemented")
        if method == "POST" and operation not in ("api-query", "chain-read", "ai-test"):
            raise ScopeDenied("POST requires a specific query operation")
        initial_host = None
        records = []
        for hop in range(redirects + 1):
            url = self.scope.require_url(url, operation)
            p = urlsplit(url)
            if p.scheme not in ("http", "https"):
                raise InvalidInput("HTTP request requires http(s)")
            origin = (p.scheme, p.netloc)
            if initial_host is None:
                initial_host = origin
            self.pace()
            timeout = min(15, self.budget.limits["tool_timeout_seconds"])
            port = p.port or (443 if p.scheme == "https" else 80)
            connection_type = _PinnedHTTPS if p.scheme == "https" else _PinnedHTTP
            connection = connection_type(p.hostname, port, self.addresses(p.hostname, port), timeout)
            request_headers = {"User-Agent": "re-skill-runner/0.1", "Accept-Encoding": "identity", "Connection": "close"}
            if origin == initial_host:
                request_headers.update(self.scope.headers())
                request_headers.update(headers or {})
            target = p.path or "/"
            if p.query:
                target += "?" + p.query
            try:
                connection.request(method, target, body=body, headers=request_headers)
                response = connection.getresponse()
                pairs = response.getheaders()
                if len(pairs) > 100 or sum(len(k) + len(v) for k, v in pairs) > 65536:
                    raise BudgetExceeded("HTTP header budget exceeded")
                response_headers = {key.lower(): value for key, value in pairs}
                framing = [key.lower() for key, _ in pairs if key.lower() in ("content-length", "transfer-encoding", "location")]
                if len(framing) != len(set(framing)) or ("content-length" in framing and "transfer-encoding" in framing):
                    raise InvalidInput("Ambiguous HTTP framing/redirect headers")
                chunks, total = [], 0
                # Rejected redirect bodies cannot consume unbounded memory either.
                if method != "HEAD":
                    length = response_headers.get("content-length")
                    if length and (not length.isdigit() or int(length) > self.budget.limits["max_download_bytes"]):
                        raise BudgetExceeded("HTTP Content-Length exceeds budget or is malformed")
                    while True:
                        self.budget.check()
                        block = response.read(min(65536, self.budget.limits["max_download_bytes"] - total + 1))
                        if not block:
                            break
                        total += len(block)
                        self.budget.consume("download_bytes", len(block))
                        if total > self.budget.limits["max_download_bytes"]:
                            raise BudgetExceeded("Response body budget exceeded")
                        chunks.append(block)
                record = {
                    "url": public_url(url), "method": method, "status": response.status,
                    "headers": redact(response_headers), "bytes": total,
                    "peer_addresses": self.pins[(p.hostname, port)],
                }
                records.append(record)
                self.records.append(record)
                if response.status in (301, 302, 303, 307, 308) and "location" in response_headers:
                    if hop == redirects:
                        raise NetworkError("Redirect limit reached")
                    if method == "POST":
                        raise ScopeDenied("Query POST redirects are not followed")
                    url = urljoin(url, response_headers["location"])
                    # Scope is checked before the next DNS resolution/request.
                    continue
                if response_headers.get("content-encoding", "identity").lower() not in ("identity", ""):
                    raise InvalidInput("Server ignored identity encoding; compressed HTTP bodies are not accepted")
                return Response(url, response.status, response_headers, b"".join(chunks), records)
            except (OSError, http.client.HTTPException) as exc:
                raise NetworkError(f"HTTP transport failed: {type(exc).__name__}") from exc
            finally:
                connection.close()
        raise NetworkError("Redirect limit reached")

    def query_json(self, url: str, payload: dict, operation: str) -> Response:
        data = json.dumps(payload, allow_nan=False).encode("utf-8")
        if len(data) > 65536:
            raise BudgetExceeded("Query payload too large")
        return self.request(url, method="POST", body=data, headers={"Content-Type": "application/json"}, operation=operation)

