"""B-lane round-3 remediation tests: frida / vyper / s3 / ai adapters + fork contract.

Three verification states are asserted explicitly and never conflated:
  real-run        — the thing actually executed (frida attach, vyper CLI, moto HTTP)
  contract-level  — protocol exercised on synthetic transports, no external service
  not-run         — environment missing, reported honestly with the reason

Run: <venv-python> -m pytest tests/test_b_lane.py -v
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from re_runner.ai_adapter import AiStreamAdapter, InvalidInput, RetryableError
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.safety import Budget

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / "re-runs" / "blane-verification" / "runs"
FRIDA_AVAILABLE = importlib.util.find_spec("frida") is not None
VYPER_AVAILABLE = importlib.util.find_spec("vyper") is not None
MOTO_AVAILABLE = importlib.util.find_spec("moto") is not None

GOOD_A = (
    "import B as B\n"
    "\n"
    "@external\n"
    "@view\n"
    "def view_other(x: address) -> uint256:\n"
    "    # vyper 0.4: call an imported implementation through its derived interface\n"
    "    return staticcall B.__interface__(x).get()\n"
)
GOOD_B = (
    "stored: uint256\n"
    "\n"
    "@external\n"
    "@view\n"
    "def get() -> uint256:\n"
    "    return self.stored\n"
)
BROKEN = "contract broken\n@external\ndef f( :\n"
SELF_IMPORT = "import A as A\n\n@external\ndef f() -> uint256:\n    return 1\n"


class TempCase(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.temporary = tempfile.TemporaryDirectory(prefix="re-b-lane-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def out(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def budget(self) -> Budget:
        return Budget(BUDGET_DEFAULTS)


@unittest.skipUnless(FRIDA_AVAILABLE, "frida binding not importable in this interpreter")
class TestFridaAdapter(TempCase):
    """real-run: attach to a self-spawned, harmless child process only."""

    def test_real_attach_to_self_spawned_child(self):
        from re_runner.frida_adapter import trace_self_child

        record = trace_self_child(self.out("frida-ok"))
        self.assertEqual(record["verification_state"], "real-run")
        self.assertEqual(record["status"], "succeeded", f"attach run failed: {record.get('error')}")
        self.assertGreater(record["modules_total"], 0)
        self.assertTrue(record["hook"]["ok"], "getuid export must resolve via frida-17 API")
        self.assertGreater(record["hit_count"], 0, "hooked getuid must have been hit")
        self.assertIn("self-spawned", record["scope"])

    def test_missing_pid_failure_path(self):
        from re_runner.frida_adapter import trace_missing_pid

        record = trace_missing_pid(self.out("frida-miss"), pid=999999)
        self.assertEqual(record["verification_state"], "real-run")
        self.assertEqual(record["status"], "failed")
        self.assertTrue(record["error"], "failure path must carry a concrete error")


class TestVyperAdapter(TempCase):
    """real-run when vyper is installed; otherwise an honest skip."""

    def setUp(self):
        super().setUp()
        if not VYPER_AVAILABLE:
            self.skipTest("vyper not installed — compile paths recorded as not-run in evidence")

    def test_single_contract_real_compile(self):
        from re_runner.vyper_adapter import vyper_compile

        source = self.root / "Vault.vy"
        source.write_text(
            "stored: uint256\n"
            "@external\ndef store(amount: uint256):\n    self.stored = amount\n",
            encoding="utf-8",
        )
        result = vyper_compile(source, self.out("vyper-single"), self.budget())
        self.assertIsNotNone(result)
        self.assertEqual(result["verification_state"], "real-run")
        self.assertEqual(result["status"], "succeeded", f"compile failed: {result.get('error')}")
        self.assertGreater(result["contracts"][0]["bytecode_bytes"], 0)
        self.assertGreater(result["contracts"][0]["abi_entries"], 0)

    def test_two_contract_import_real_compile(self):
        from re_runner.vyper_adapter import vyper_compile_project

        (self.root / "B.vy").write_text(GOOD_B, encoding="utf-8")
        (self.root / "A.vy").write_text(GOOD_A, encoding="utf-8")
        result = vyper_compile_project(self.root, "A.vy", self.out("vyper-import"), self.budget())
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "succeeded", f"import compile failed: {result.get('error')}")
        self.assertEqual(result["mode"], "project-import")
        self.assertGreater(result["contracts"][0]["abi_entries"], 0)

    def test_syntax_error_failure_path(self):
        from re_runner.vyper_adapter import vyper_compile

        source = self.root / "Broken.vy"
        source.write_text(BROKEN, encoding="utf-8")
        result = vyper_compile(source, self.out("vyper-broken"), self.budget())
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["stderr_signature"], "failure must carry a stderr signature")

    def test_self_import_cycle_failure_path(self):
        from re_runner.vyper_adapter import vyper_compile

        source = self.root / "A.vy"
        source.write_text(SELF_IMPORT, encoding="utf-8")
        result = vyper_compile(source, self.out("vyper-cycle"), self.budget())
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["stderr_signature"] or result["error"])


class TestS3Adapter(TempCase):
    """real-run against a local in-process moto endpoint (declared: not AWS)."""

    def test_put_get_and_error_codes(self):
        if not MOTO_AVAILABLE:
            self.skipTest("moto not installed — S3 path recorded as not-run in evidence")
        from re_runner.s3_adapter import s3_probe

        record = s3_probe(self.out("s3"))
        self.assertEqual(record["verification_state"], "real-run")
        self.assertEqual(record["status"], "succeeded", f"s3 probe failed: {record.get('error')}")
        self.assertIn("not AWS", record["service"])
        codes = {op["op"]: op for op in record["operations"]}
        self.assertTrue(codes["get_object"]["roundtrip_equal"])
        self.assertEqual(codes["get_object_missing_key"]["error_code"], "NoSuchKey")
        self.assertEqual(codes["get_object_missing_bucket"]["error_code"], "NoSuchBucket")


class TestAiStreamAdapter(TempCase):
    """contract-level: every path exercised on synthetic streams, no network."""

    ADAPTER = AiStreamAdapter(max_context_chars=64, max_retries=2, backoff_seconds=0.001)

    def sse(self, *texts: str, finish: str = "stop", split: int = 3) -> list[bytes]:
        frames = []
        for i, text in enumerate(texts):
            frames.append(
                f'data: {{"choices":[{{"delta":{{"content":"{text}"}}}}]}}\n'.encode()
            )
        frames.append(f'data: {{"choices":[{{"delta":{{}},"finish_reason":"{finish}"}}]}}\n'.encode())
        frames.append(b"data: [DONE]\n\n")
        stream = b"".join(frames)
        # Slice the whole stream into uneven pieces to force boundary reassembly.
        size = max(1, len(stream) // split)
        return [stream[i:i + size] for i in range(0, len(stream), size)]

    def test_stream_parse_reassembles_split_chunks(self):
        result = self.ADAPTER.parse_sse_stream(self.sse("Hel", "lo", "!"))
        self.assertEqual(result.text, "Hello!")
        self.assertEqual(result.finish_reason, "stop")
        self.assertEqual(result.malformed_lines, [])

    def test_malformed_lines_collected_not_fatal(self):
        stream = iter([b"data: not-json\n", b"garbage line\n", b"data: [DONE]\n"])
        result = self.ADAPTER.parse_sse_stream(stream)
        self.assertEqual(len(result.malformed_lines), 2)
        self.assertEqual(result.finish_reason, "done")

    def test_context_truncation_keeps_system_and_newest(self):
        messages = [
            {"role": "system", "content": "S" * 10},
            {"role": "user", "content": "U" * 40},
            {"role": "assistant", "content": "A" * 40},  # overflows the 64-char budget
            {"role": "user", "content": "U" * 8},
        ]
        kept, dropped = self.ADAPTER.truncate_context(messages)
        self.assertEqual(kept[0]["role"], "system")
        self.assertEqual(kept[-1]["content"], "U" * 8)
        self.assertEqual(dropped, 1)  # only the overflowing middle turn is dropped
        self.assertLessEqual(sum(len(m["content"]) for m in kept), 64)

    def test_build_request_validation(self):
        with self.assertRaises(InvalidInput):
            self.ADAPTER.build_request([{"role": "user"}])
        body = self.ADAPTER.build_request([{"role": "user", "content": "hi"}])
        self.assertTrue(body["stream"])
        self.assertEqual(body["model"], self.ADAPTER.model)

    def test_retry_then_success(self):
        attempts = {"n": 0}

        def send_fn(body):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RetryableError("429 synthetic")
            return self.sse("ok")

        record = self.ADAPTER.run(send_fn, [{"role": "user", "content": "x"}])
        self.assertEqual(record["status"], "succeeded")
        self.assertEqual(record["attempts"], 2)
        self.assertEqual(record["assistant_text"], "ok")
        self.assertEqual(record["verification_state"], "contract-level")

    def test_retries_exhausted_failure_path(self):
        def send_fn(body):
            raise RetryableError("503 synthetic")

        record = self.ADAPTER.run(send_fn, [{"role": "user", "content": "x"}])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["attempts"], 3)
        self.assertIn("503", record["error"])

    def test_fatal_error_no_retry(self):
        attempts = {"n": 0}

        def send_fn(body):
            attempts["n"] += 1
            raise ValueError("fatal synthetic")

        record = self.ADAPTER.run(send_fn, [{"role": "user", "content": "x"}])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(attempts["n"], 1)


class TestForkContract(TempCase):
    """not-run by design: anvil/foundry intentionally not installed (no heavy chain)."""

    def test_fork_probe_declares_missing_environment(self):
        from re_runner.vyper_adapter import anvil_fork_probe

        record = anvil_fork_probe(self.out("fork"))
        self.assertEqual(record["verification_state"], "not-run")
        self.assertEqual(record["status"], "not-run")
        import shutil

        if shutil.which("anvil"):
            self.skipTest("anvil present on this host — probe reports available-not-exercised")
        self.assertIn("anvil", record["error"])
        self.assertIn("RE_RUN_ANVIL_RPC", record["fork_contract"]["enable_condition"])


if __name__ == "__main__":
    unittest.main()
