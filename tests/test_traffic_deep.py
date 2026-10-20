"""scapy TCP-reassembly acceptance for the traffic deep layer.

Offline and deterministic: the HTTP capture is the factory's fixture-http.pcap
(TCP handshake, a segmented HTTP GET/response, FIN). When the regen copy exists
under re-runs/fixtures it is checked byte-identical to the factory output and
used directly. Without scapy the positive tests are skipped and the honest
"skipped" negative control still runs. Nothing here contacts a network.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fixture_factory import http_stream_pcap, pcap as udp_pcap
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import InvalidInput
from re_runner.models import Asset
from re_runner.profiles.traffic import analyze as traffic_analyze, deep_reassembly
from re_runner.safety import Budget
from re_runner.scope import ScopePolicy

REPO = Path(__file__).resolve().parents[1]
REGEN_HTTP_PCAP = REPO / "re-runs" / "fixtures" / "fixture-http.pcap"

try:
    import scapy  # noqa: F401
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False


def budget() -> Budget:
    return Budget(dict(BUDGET_DEFAULTS))


def http_capture(root: Path) -> Path:
    """Prefer the regen fixture; verify it matches the factory bytes."""
    if REGEN_HTTP_PCAP.is_file():
        assert REGEN_HTTP_PCAP.read_bytes() == http_stream_pcap(), "regen fixture drifted from fixture_factory"
        return REGEN_HTTP_PCAP
    path = root / "fixture-http.pcap"
    path.write_bytes(http_stream_pcap())
    return path


def traffic_result(path: Path):
    return traffic_analyze(
        Asset(id="traffic-http", locator=str(path), kind="traffic", format="pcap"),
        path, Path(tempfile.gettempdir()), ScopePolicy(), budget(),
    )


class HttpStreamReassemblyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-traffic-deep-")
        self.addCleanup(self.temporary.cleanup)
        self.capture = http_capture(Path(self.temporary.name))

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed (pyproject extra: traffic-deep)")
    def test_http_stream_is_reassembled_across_segments(self):
        result = traffic_result(self.capture)
        checks = {check["name"]: check for check in result.checks}
        self.assertEqual(checks["packet-container-and-flow-index"]["status"], "succeeded")
        deep = checks["traffic-deep-reassembly"]
        self.assertEqual(deep["status"], "succeeded", deep["detail"])
        self.assertEqual(result.analysis["deep_packets_scanned"], 7)
        streams = result.analysis["http_streams"]
        self.assertEqual(result.analysis["http_stream_count"], 1)
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(stream["source"], "10.0.0.1:49152")
        self.assertEqual(stream["destination"], "10.0.0.2:80")
        request = stream["request"]
        self.assertEqual(request["method"], "GET")
        self.assertTrue(request["path"].startswith("/secret/login"), request["path"])
        self.assertIn("?", request["path"], "query values must be present but redacted")
        self.assertNotIn("lab", request["path"])
        self.assertEqual(request["host"], "lab.local")
        self.assertEqual(request["segments"], 2, "the GET was split across two TCP segments")
        self.assertEqual(request["sequence_gaps"], 0)
        self.assertFalse(request["truncated"])
        self.assertIn("Host", request["header_names"])
        self.assertIn("Authorization", request["header_names"])
        self.assertTrue(request["credentials_present"])
        response = stream["response"]
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["protocol"], "HTTP/1.1")
        self.assertFalse(response["credentials_present"])

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed (pyproject extra: traffic-deep)")
    def test_no_token_value_reaches_the_analysis(self):
        result = traffic_result(self.capture)
        blob = json.dumps(result.to_dict())
        self.assertNotIn("lab-token-123456", blob)
        self.assertNotIn("Bearer lab-token", blob)
        # Header VALUES are never stored, only their names and presence.
        stream = json.dumps(result.analysis["http_streams"])
        self.assertIn('"Authorization"', stream)
        self.assertNotIn("lab-token", stream)
        self.assertNotIn("Authorization: ", blob)

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed (pyproject extra: traffic-deep)")
    def test_udp_and_tls_traffic_produce_no_http_streams(self):
        udp = Path(self.temporary.name) / "fixture.pcap"
        udp.write_bytes(udp_pcap())
        result = traffic_result(udp)
        self.assertEqual(result.analysis["http_streams"], [])
        self.assertEqual(result.analysis["http_stream_count"], 0)
        self.assertEqual({c["name"]: c for c in result.checks}["traffic-deep-reassembly"]["status"], "succeeded")
        # The base flow index stays authoritative and untouched.
        self.assertEqual(result.analysis["flows"][0]["protocol"], "udp")
        self.assertEqual(result.analysis["flows"][0]["source_port"], 12345)

    def test_missing_scapy_is_an_honest_skip(self):
        with patch.dict(sys.modules, {"scapy.utils": None}):
            self.assertIsNone(deep_reassembly(self.capture, budget()))
            result = traffic_result(self.capture)
        check = {c["name"]: c for c in result.checks}["traffic-deep-reassembly"]
        self.assertEqual(check["status"], "skipped")
        self.assertIn("scapy", check["detail"])
        self.assertNotIn("http_streams", result.analysis)
        # The built-in index runs untouched in the same analysis.
        self.assertEqual({c["name"]: c for c in result.checks}["packet-container-and-flow-index"]["status"], "succeeded")

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed (pyproject extra: traffic-deep)")
    def test_corrupt_container_degrades_with_signature_without_crashing(self):
        corrupt = Path(self.temporary.name) / "corrupt.pcap"
        corrupt.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x02\x04\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")
        deep = deep_reassembly(corrupt, budget())
        self.assertIsNotNone(deep)
        self.assertEqual(deep["status"], "degraded")
        self.assertIn("scapy reassembly stopped early", deep["error"])
        self.assertEqual(deep["streams"], [])
        # Layering: the unchanged strict base layer surfaces container
        # corruption as an intake error for the profile.
        with self.assertRaises(InvalidInput):
            traffic_result(corrupt)

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed (pyproject extra: traffic-deep)")
    def test_reassembly_failure_mid_stream_degrades_without_crash(self):
        class ExplodingReader:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                raise RuntimeError("fixture-explosion")

            def close(self):
                pass

        with patch("scapy.utils.PcapReader", ExplodingReader):
            deep = deep_reassembly(self.capture, budget())
        self.assertEqual(deep["status"], "degraded")
        self.assertIn("RuntimeError", deep["error"])
        self.assertIn("fixture-explosion", deep["error"])


if __name__ == "__main__":
    unittest.main()
