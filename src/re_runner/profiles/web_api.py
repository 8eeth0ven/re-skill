import base64
import hashlib
import re
import socket
import ssl
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..errors import BudgetExceeded, CapabilityMissing, InvalidInput
from ..models import Asset, ProfileResult
from ..network import NetworkClient
from ..parsing import structured
from ..safety import Budget, atomic_json, parse_json, public_url, read_bytes, redact
from ..scope import ScopePolicy


class PageIndex(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts, self.title = [], [], [], ""
        self.in_title = False
        self.current_form = None
        self.elements = 0

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        if self.elements > 50000:
            raise BudgetExceeded("HTML element budget exceeded")
        values = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "a" and "href" in values and len(self.links) < 1000:
            self.links.append(values["href"])
        if tag == "script" and values.get("src") and len(self.scripts) < 1000:
            self.scripts.append(values["src"])
        if tag == "form" and len(self.forms) < 100:
            self.current_form = {"method": values.get("method", "GET").upper(), "action": values.get("action", ""), "fields": []}
            self.forms.append(self.current_form)
        if tag == "input" and self.current_form and len(self.current_form["fields"]) < 100:
            # Input values can contain tokens or private data; only names/types are indexed.
            self.current_form["fields"].append({"name": values.get("name", ""), "type": values.get("type", "text")})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if self.in_title and len(self.title) < 256:
            self.title += data[:256 - len(self.title)]


def openapi(value: dict) -> ProfileResult:
    result = ProfileResult()
    version = value.get("openapi", value.get("swagger"))
    if not isinstance(version, str) or not version.startswith(("2.", "3.")) or not isinstance(value.get("paths"), dict):
        raise InvalidInput("Invalid OpenAPI/Swagger document")
    endpoints = []
    global_security = value.get("security")
    for path, item in value["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            raise InvalidInput("OpenAPI paths require slash-prefixed paths and object definitions")
        for method, operation in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options", "head", "trace"):
                continue
            if not isinstance(operation, dict):
                raise InvalidInput("OpenAPI operation must be an object")
            if len(endpoints) >= 10000:
                raise BudgetExceeded("API endpoint budget exceeded")
            parameters = [
                {"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False)}
                for p in operation.get("parameters", []) if isinstance(p, dict)
            ]
            security = operation.get("security", global_security)
            endpoints.append({
                "path": path, "method": method.upper(), "operation_id": operation.get("operationId"),
                "parameters": parameters, "security": security,
                "security_declared": security is not None, "references": operation.get("$ref"),
            })
    components = value.get("components", {})
    security_schemes = components.get("securitySchemes", value.get("securityDefinitions", {})) if isinstance(components, dict) else {}
    result.analysis = {
        "protocol": "openapi", "version": version, "title": value.get("info", {}).get("title"),
        "endpoints": endpoints, "endpoint_count": len(endpoints),
        "servers": value.get("servers", []), "security_schemes": security_schemes,
        "references_fetched": False,
    }
    result.check("specification-structure", detail=f"{len(endpoints)} declared operations")
    result.limitations.append("Specification declarations do not establish deployed routes or authorization enforcement; external $ref documents are not fetched.")
    return result


def graphql_schema(value: dict) -> ProfileResult:
    nested = value.get("data")
    schema = value.get("__schema", nested.get("__schema") if isinstance(nested, dict) else None)
    if not isinstance(schema, dict) or not isinstance(schema.get("types"), list):
        raise InvalidInput("Invalid GraphQL introspection document")
    types = []
    for item in schema["types"][:10000]:
        if not isinstance(item, dict):
            raise InvalidInput("Invalid GraphQL type")
        types.append({"name": item.get("name"), "kind": item.get("kind"), "fields": [
            {"name": f.get("name"), "args": [a.get("name") for a in f.get("args", []) if isinstance(a, dict)]}
            for f in item.get("fields") or [] if isinstance(f, dict)
        ]})
    result = ProfileResult(analysis={"protocol": "graphql", "types": types, "query_type": schema.get("queryType"), "mutation_type": schema.get("mutationType")})
    result.check("graphql-introspection-parse")
    result.limitations.append("Schema inspection does not validate resolver permissions or execute mutations.")
    return result


def definition_file(path: Path) -> ProfileResult:
    data = read_bytes(path, 8_388_608).decode("utf-8", "replace")
    result = ProfileResult()
    if path.suffix == ".proto":
        services = []
        for service in re.finditer(r"\bservice\s+(\w+)\s*\{([^}]{0,100000})\}", data):
            methods = [
                {"name": m[0], "request": m[1], "response": m[2]}
                for m in re.findall(r"\brpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)", service[2])
            ]
            services.append({"name": service[1], "methods": methods})
        result.analysis = {"protocol": "grpc-protobuf", "services": services, "imports": re.findall(r'\bimport\s+"([^"\n]+)"', data)}
        result.check("protobuf-declarations")
    else:
        declarations = [
            {"kind": kind, "name": name}
            for kind, name in re.findall(r"\b(type|input|enum|interface|scalar|union)\s+([A-Za-z_]\w*)", data)
        ]
        result.analysis = {"protocol": "graphql-sdl", "declarations": declarations}
        result.check("graphql-sdl-declarations")
    result.limitations.append("Declaration indexing is lexical; imported definitions and service execution are not resolved.")
    return result


def websocket(asset: Asset, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    url = scope.require_url(asset.locator, "api-query")
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "wss" else 80)
    client = NetworkClient(scope, budget)
    client.pace()
    addresses = client.addresses(p.hostname, port)
    sock = socket.create_connection((addresses[0], port), timeout=10)
    key = base64.b64encode(__import__("os").urandom(16)).decode("ascii")
    try:
        if p.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=p.hostname)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        headers = {"Host": p.netloc, "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13", **scope.headers()}
        request = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        sock.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            budget.check()
            block = sock.recv(4096)
            if not block:
                raise InvalidInput("Truncated WebSocket handshake")
            budget.consume("download_bytes", len(block))
            response.extend(block)
            if len(response) > 65536:
                raise BudgetExceeded("WebSocket handshake headers exceed budget")
        head = bytes(response).split(b"\r\n\r\n", 1)[0].decode("latin1")
        lines = head.split("\r\n")
        values = {k.lower().strip(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:] if ":" in line)}
        status = int(lines[0].split()[1])
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        valid = status == 101 and values.get("sec-websocket-accept") == expected and values.get("upgrade", "").lower() == "websocket"
        if status == 101 and not valid:
            raise InvalidInput("Invalid WebSocket handshake acceptance")
        result = ProfileResult(analysis={"protocol": "websocket", "url": public_url(url), "status": status, "handshake_valid": valid, "headers": redact(values)})
        result.check("websocket-handshake", "succeeded" if valid else "degraded", f"HTTP {status}")
        result.limitations.append("Handshake only; no application frames or authentication/authorization behavior are tested.")
        return result
    finally:
        sock.close()


def grpc_services(asset: Asset, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    url = scope.require_url(asset.locator, "api-query")
    try:
        import grpc
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    except ImportError as exc:
        raise CapabilityMissing("Install re-skill-runner[grpc] for gRPC reflection") from exc
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "grpcs" else 80)
    client = NetworkClient(scope, budget)
    addresses = client.addresses(p.hostname, port)
    budget.consume("requests", 1)
    target = f"[{addresses[0]}]:{port}" if ":" in addresses[0] else f"{addresses[0]}:{port}"
    options = [("grpc.max_receive_message_length", min(budget.limits["max_download_bytes"], 4_194_304))]
    options.append(("grpc.ssl_target_name_override", p.hostname))
    if p.scheme == "grpcs":
        channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(), options=options)
    else:
        channel = grpc.insecure_channel(target, options=options)
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        responses = stub.ServerReflectionInfo(iter([request]), timeout=10, metadata=[(k.lower(), v) for k, v in scope.headers().items()])
        response = next(responses)
        budget.consume("download_bytes", response.ByteSize())
        if response.HasField("error_response"):
            raise InvalidInput(f"gRPC reflection error: {response.error_response.error_code}")
        services = [s.name for s in response.list_services_response.service]
        result = ProfileResult(analysis={"protocol": "grpc", "services": services, "reflection": True})
        result.check("grpc-service-reflection")
        result.limitations.append("Service reflection only; application RPCs are not invoked.")
        return result
    except grpc.RpcError as exc:
        raise InvalidInput(f"gRPC reflection unavailable: {exc.code().name}") from exc
    finally:
        channel.close()


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path:
        if path.suffix in (".proto", ".graphql", ".gql"):
            return definition_file(path)
        value = structured(path)
        if not isinstance(value, dict):
            raise InvalidInput("API specification requires an object")
        if "openapi" in value or "swagger" in value:
            return openapi(value)
        return graphql_schema(value)
    if asset.locator.startswith(("ws://", "wss://")):
        return websocket(asset, scope, budget)
    if asset.locator.startswith(("grpc://", "grpcs://")):
        return grpc_services(asset, scope, budget)
    client = NetworkClient(scope, budget)
    response = client.request(asset.locator)
    content_type = response.headers.get("content-type", "")
    value = None
    if "json" in content_type or response.body[:1] == b"{":
        value = parse_json(response.body)
    if isinstance(value, dict) and ("openapi" in value or "swagger" in value):
        result = openapi(value)
    elif isinstance(value, dict) and ("__schema" in value or isinstance(value.get("data"), dict) and "__schema" in value["data"]):
        result = graphql_schema(value)
    else:
        page = PageIndex()
        if "html" in content_type or response.body.lstrip().startswith(b"<"):
            page.feed(response.body.decode("utf-8", "replace"))
        result = ProfileResult(analysis={
            "protocol": "http", "url": public_url(response.url), "status": response.status,
            "content_type": content_type, "title": page.title, "forms": page.forms,
            "discovered_links": [public_url(urljoin(response.url, link)) for link in page.links if link.startswith(("http:", "https:", "/", "?"))],
            "script_sources": [public_url(urljoin(response.url, link)) for link in page.scripts],
            "json_keys": list(value)[:200] if isinstance(value, dict) else None,
        })
        result.check("http-response-and-structure", "succeeded" if response.status < 400 else "degraded", f"HTTP {response.status}")
        result.limitations.append("Only the scoped entry response was read; discovered links are indexed and not automatically tested.")
    result.analysis["http_records"] = response.records
    result.analysis["body_sha256"] = hashlib.sha256(response.body).hexdigest()
    # Store structure/header evidence rather than hostile page instructions or raw credentials.
    atomic_json(output / "http.json", redact({"records": response.records, "body_sha256": result.analysis["body_sha256"]}))
    if asset.kind == "api" and "api-query" in scope.operations and value is None:
        gql = client.query_json(response.url, {"query": "query ReRunnerIdentity { __typename }"}, "api-query")
        body = parse_json(gql.body)
        if isinstance(body, dict) and isinstance(body.get("data"), dict) and "__typename" in body["data"]:
            result.analysis["graphql_query_type"] = body["data"]["__typename"]
            result.check("graphql-read-query")
        else:
            result.check("graphql-read-query", "degraded", "No GraphQL query response")
    if any(f.get("method") == "GET" and any(x.get("type") == "password" for x in f.get("fields", [])) for f in result.analysis.get("forms", [])):
        result.candidate(
            "web-password-get-form", "Password field submitted using GET", "HTML form uses GET with a password input; deployment and submission behavior require review.",
            location="HTML form", impact="Credentials may enter browser history or request logs if this form is used.",
            remediation="Submit credentials using HTTPS POST and avoid logging secret values.",
        )
    return result
