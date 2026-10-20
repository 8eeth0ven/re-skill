"""Local experiment services for acceptance runs: web page, OpenAPI, GraphQL
introspection, WebSocket handshake, gRPC reflection and a JSON-RPC chain stub.

Bound to 127.0.0.1 only. No external network is contacted.
"""
import base64
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

PAGE = """<!doctype html><html><head><title>re-skill local lab</title></head>
<body><h1>local lab</h1>
<form action="/search" method="get"><input name="password" type="password"><button>go</button></form>
<a href="/openapi.json">api spec</a><a href="https://external.example/">outer link</a>
</body></html>"""

OPENAPI = {
    "openapi": "3.0.3", "info": {"title": "Local lab API", "version": "1.0.0"},
    "paths": {
        "/items/{id}": {"get": {"operationId": "getItem",
                                 "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                                 "responses": {"200": {"description": "OK"}}}},
        "/graphql": {"post": {"operationId": "graphql", "responses": {"200": {"description": "OK"}}}},
    },
}

GRAPHQL_INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [{"name": "Query", "kind": "OBJECT", "fields": [
        {"name": "item", "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}]}]}],
}}}

CHAIN = {"chain_id": 31337, "code": "0x6080604052348015600f57600080fd5b50", "block": 42}


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep acceptance logs small
        pass

    def _json(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/openapi.json":
            self._json(OPENAPI)
        elif path == "/graphql":
            # GraphQL servers commonly answer GET on the endpoint too; the runner
            # probes with GET before deciding to send an introspection POST.
            self._json(GRAPHQL_INTROSPECTION)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(min(length, 1_048_576))
        path = self.path.split("?")[0]
        if path == "/graphql":
            self._json(GRAPHQL_INTROSPECTION)
        elif path == "/rpc":
            try:
                request = json.loads(payload or b"{}")
            except ValueError:
                self._json({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}, "id": None})
                return
            method = request.get("method", "")
            result = {"eth_chainId": "0x7a69", "eth_blockNumber": hex(CHAIN["block"]),
                      "eth_getCode": CHAIN["code"]}.get(method)
            if result is None:
                self._json({"jsonrpc": "2.0", "error": {"code": -32601, "message": "method not found"}, "id": request.get("id")})
            else:
                self._json({"jsonrpc": "2.0", "result": result, "id": request.get("id")})
        else:
            self._json({"error": "not found"}, 404)

    def handle_ws(self):
        """Minimal RFC6455 handshake on /ws; accept, send one text frame, keep open."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        frame = b"lab-ready"
        self.wfile.write(b"\x81" + bytes([len(frame)]) + frame)
        try:  # stay open briefly so the client handshake completes
            self.connection.settimeout(2)
            self.connection.recv(4096)
        except OSError:
            pass


def serve_grpc(port: int) -> tuple:
    from grpc_tools import protoc
    out = REPO / "tools" / "protos" / "_gen"
    out.mkdir(exist_ok=True)
    proto = str(REPO / "tools" / "protos" / "demo.proto")
    if not (out / "demo_pb2.py").exists():
        rc = protoc.main(["protoc", f"-I{proto.rsplit(chr(92), 1)[0] if chr(92) in proto else str(Path(proto).parent)}",
                          f"--python_out={out}", f"--grpc_python_out={out}", proto])
        if rc != 0:
            raise RuntimeError("protoc failed")
    sys.path.insert(0, str(out))
    import grpc
    from concurrent import futures
    from grpc_reflection.v1alpha import reflection
    import demo_pb2
    import demo_pb2_grpc  # noqa: E402

    class Echo(demo_pb2_grpc.EchoServicer):
        def Ping(self, request, context):
            return demo_pb2.PingReply(message=request.message)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    demo_pb2_grpc.add_EchoServicer_to_server(Echo(), server)
    reflection.enable_server_reflection(("demo.Echo",), server)
    server.add_insecure_port(f"127.0.0.1:{port}")
    server.start()
    return server


def main() -> int:
    base, grpc_port, rpc_port = 8765, 8766, 8767

    class Handler(LabHandler):
        pass

    def route_ws(self):
        if self.path.split("?")[0] == "/ws":
            self.handle_ws()
            return True
        return False

    Handler.do_GET = lambda self: (None if route_ws(self) else LabHandler.do_GET(self))
    httpd = ThreadingHTTPServer(("127.0.0.1", base), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    server = serve_grpc(grpc_port)
    print(json.dumps({"http": base, "grpc": grpc_port, "rpc": rpc_port, "ready": True}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        server.stop(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
