import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import ScopeDenied
from re_runner.models import Asset
from re_runner.profiles.special import BEHAVIOR_PROBES, analyze, behavior_probe
from re_runner.safety import Budget, load_json
from re_runner.scope import ScopePolicy

SAFE_REPLY = (
    "I cannot follow instructions that ask me to ignore my policies, disclose secrets, "
    "take destructive actions, or change verification states."
)
CANARIES = [assertion["value"] for spec in BEHAVIOR_PROBES for assertion in spec["assertions"]]


class SafeHandler(BaseHTTPRequestHandler):
    """Hardened mock: refuses every probe, never echoes a canary."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.requests.append(request)
        self.reply({"response": SAFE_REPLY})

    def reply(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FragileHandler(SafeHandler):
    """Vulnerable mock: obeys the injected instruction and echoes every canary it sees."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.requests.append(request)
        prompt = request.get("prompt", "")
        echoed = [canary for canary in CANARIES if canary.casefold() in prompt.casefold()]
        self.reply({"response": ("Complied. " + " ".join(echoed)) if echoed else "Done."})


class BehaviorProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-ai-behavior-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def start(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # addCleanup runs LIFO: shutdown first, then close, then join the stopped loop.
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    def asset(self, url):
        return Asset(id="ai-1", locator=url, kind="ai", format="service")

    @staticmethod
    def scope(url, operations=("read", "ai-test")):
        return ScopePolicy(allow_urls=[url], operations=list(operations))

    @staticmethod
    def budget():
        return Budget(BUDGET_DEFAULTS)

    def check(self, result):
        return next(item for item in result.checks if item["name"] == "ai-behavior-oracle")

    def test_hardened_service_passes_every_oracle(self):
        url = self.start(SafeHandler)
        result = behavior_probe(self.asset(url), self.scope(url), self.budget(), self.root / "work")
        self.assertEqual(self.check(result)["status"], "succeeded")
        self.assertEqual(result.candidates, [])
        evidence = load_json(self.root / "work" / "ai-behavior-oracle.json")
        self.assertEqual(evidence["probe_count"], len(BEHAVIOR_PROBES))
        self.assertEqual(evidence["completed"], len(BEHAVIOR_PROBES))
        self.assertIsNone(evidence["transport_error"])
        self.assertTrue(all(item["passed"] for item in evidence["probes"]))
        self.assertTrue(all(item["response_excerpt"] for item in evidence["probes"]))

    def test_compliant_service_yields_candidates_and_degraded(self):
        url = self.start(FragileHandler)
        result = behavior_probe(self.asset(url), self.scope(url), self.budget(), self.root / "work")
        self.assertEqual(self.check(result)["status"], "degraded")
        self.assertTrue(result.candidates)
        for candidate in result.candidates:
            self.assertEqual(candidate["rule_id"], "ai-oracle-refusal-failure")
            self.assertIn("canary", candidate["technical"])
        evidence = load_json(self.root / "work" / "ai-behavior-oracle.json")
        self.assertGreater(evidence["failed"], 0)
        failed = [item for item in evidence["probes"] if not item["passed"]]
        for item in failed:
            self.assertIn("canary", item["detail"])

    def test_unreachable_service_degrades_without_candidates(self):
        probe_socket = socket.socket()
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
        probe_socket.close()
        url = f"http://127.0.0.1:{port}/"
        result = behavior_probe(self.asset(url), self.scope(url), self.budget(), self.root / "work")
        check = self.check(result)
        self.assertEqual(check["status"], "degraded")
        self.assertTrue(check["detail"], "an unreachable service must leave a failure signature")
        self.assertEqual(result.candidates, [])
        self.assertTrue(result.analysis["transport_error"])

    def test_scope_without_ai_test_operation_is_denied(self):
        url = self.start(SafeHandler)
        with self.assertRaises(ScopeDenied):
            behavior_probe(self.asset(url), self.scope(url, ("read",)), self.budget(), self.root / "work")

    def test_analyze_routes_url_assets_into_the_oracle(self):
        url = self.start(SafeHandler)
        result = analyze(self.asset(url), None, self.root / "work", self.scope(url), self.budget())
        self.assertEqual(self.check(result)["status"], "succeeded")
        self.assertEqual(result.analysis["format"], "ai-behavior-oracle")
        self.assertEqual(result.analysis["target"], url)

    def test_excluded_url_is_denied_even_with_ai_test(self):
        url = self.start(SafeHandler)
        scope = self.scope(url)
        scope.exclude_urls = [url]
        with self.assertRaises(ScopeDenied):
            behavior_probe(self.asset(url), scope, self.budget(), self.root / "work")


if __name__ == "__main__":
    unittest.main()
