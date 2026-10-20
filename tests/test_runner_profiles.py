import tempfile
import unittest
from pathlib import Path

from fixture_factory import make_assets
from re_runner.models import AssetRequest
from re_runner.reporting import evidence_gate
from re_runner.runner import Runner
from re_runner.scope import ScopePolicy


class ProfileIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="re-profiles-")
        cls.root = Path(cls.temporary.name)
        cls.assets = make_assets(cls.root / "assets")
        requests = [AssetRequest(str(path), id=name) for name, path in cls.assets.items()]
        cls.runner = Runner.new(cls.root / "runs", requests, ScopePolicy(), "triage", "zh")
        cls.state = cls.runner.execute()

    @classmethod
    def tearDownClass(cls):
        # Runner snapshots deliberately make input copies read-only.
        import os
        for directory, _, files in os.walk(cls.root):
            for name in files:
                try:
                    (Path(directory) / name).chmod(0o600)
                except OSError:
                    pass
        cls.temporary.cleanup()

    def analysis(self, name):
        entry = self.state["assets"][name]
        self.assertIn(entry["status"], ("succeeded", "degraded"), entry.get("error"))
        return entry["result"]["analysis"]

    def test_all_twelve_categories_have_executed_paths(self):
        kinds = {entry["asset"]["kind"] for entry in self.state["assets"].values() if "asset" in entry}
        # The web category is tested using an actual local HTTP service in network tests.
        self.assertEqual(kinds, {"api", "android", "apple", "binary", "source", "firmware", "container", "traffic", "device", "ai", "contract"})
        for name in self.assets:
            with self.subTest(name=name):
                self.analysis(name)

    def test_openapi_oracle(self):
        analysis = self.analysis("api")
        self.assertEqual(analysis["endpoint_count"], 1)
        self.assertEqual(analysis["endpoints"][0]["method"], "GET")
        self.assertEqual(analysis["endpoints"][0]["path"], "/items/{id}")

    def test_graphql_oracle(self):
        self.assertEqual(self.analysis("graphql")["types"][0]["fields"][0]["name"], "item")

    def test_android_real_binary_xml_and_dex(self):
        for name in ("android", "aab"):
            with self.subTest(name=name):
                analysis = self.analysis(name)
                self.assertEqual(analysis["package"], "org.example.fixture")
                self.assertEqual(analysis["application"]["debuggable"], "true")
                self.assertTrue(analysis["dex"][0]["checksum_valid"])
                self.assertEqual(analysis["components"][0]["name"], ".MainActivity")

    def test_apple_bundle_and_macho_oracle(self):
        analysis = self.analysis("apple")
        self.assertEqual(analysis["bundles"][0]["identifier"], "org.example.fixture")
        self.assertIn("X86_64", analysis["executables"][0]["architecture"])

    def test_elf_and_disassembly_oracle(self):
        analysis = self.analysis("binary")
        self.assertEqual(analysis["entrypoint"], "0x400078")
        self.assertEqual(analysis["entry_disassembly"][0]["mnemonic"], "ret")

    def test_jvm_and_wasm_oracle(self):
        self.assertEqual(self.analysis("jvm")["class"], "Fixture")
        self.assertEqual(self.analysis("wasm")["exports"][0]["name"], "memory")

    def test_source_ast_path_has_both_locations(self):
        rows = self.analysis("source")["python_source_paths"]
        self.assertEqual(rows[0]["source_line"], 4)
        self.assertEqual(rows[0]["sink_line"], 6)
        self.assertEqual(rows[0]["sink"], "os.system")

    def test_firmware_banner_is_not_verified_vulnerability(self):
        analysis = self.analysis("firmware")
        self.assertEqual(analysis["component_banners"][0]["version_banner"], "1.30.0")
        self.assertTrue(all(f["status"] == "candidate" for f in self.state["findings"] if f["asset_id"] == "firmware"))

    def test_oci_digest_and_layer_component_oracle(self):
        analysis = self.analysis("container")
        self.assertEqual(analysis["manifests"][0]["architecture"], "amd64")
        self.assertEqual(analysis["components"][0]["version_constraint"], "==1.2.3")
        self.assertEqual(self.analysis("sbom")["components"][0]["purl"], "pkg:pypi/example-package@1.2.3")

    def test_traffic_flow_and_har_redaction(self):
        for name in ("traffic", "pcapng"):
            analysis = self.analysis(name)
            self.assertEqual(analysis["packet_count"], 1)
            self.assertEqual(analysis["flows"][0]["source_port"], 12345)
            self.assertEqual(analysis["flows"][0]["destination"], "10.0.0.2")
        har = self.analysis("har")
        self.assertEqual(har["entries"][0]["status"], 200)
        self.assertNotIn("fixture-secret", har["entries"][0]["url"])

    def test_device_observations_are_not_live_identity(self):
        analysis = self.analysis("device")
        self.assertEqual(analysis["interfaces"][0]["baud"], 115200)
        self.assertFalse(analysis["live_device_verified"])

    def test_ai_injection_cannot_execute_or_promote(self):
        analysis = self.analysis("ai")
        self.assertFalse(analysis["prompt_instructions_executed"])
        self.assertEqual(analysis["tools"][0]["permissions"], ["shell"])
        self.assertFalse(any(f["status"] == "verified" for f in self.state["findings"]))

    def test_model_structural_oracles(self):
        self.assertEqual(self.analysis("safetensors")["tensors"][0]["shape"], [1])
        self.assertEqual(self.analysis("gguf")["metadata"]["general.name"], "fixture")

    def test_contract_source_and_evm_oracles(self):
        self.assertEqual(self.analysis("contract")["functions"], ["caller"])
        self.assertEqual(self.analysis("evm")["push4_constants"], ["0x12345678"])

    def test_report_quality_gate_and_secrets(self):
        evidence_gate(self.runner.root, self.state)
        for name in ("report.json", "report.md", "assets.json", "findings.json", "evidence/index.json", "events.jsonl"):
            data = (self.runner.root / name).read_text("utf-8")
            self.assertNotIn("fixture-secret", data)
            self.assertNotIn("private-fixture", data)

    def test_successful_resume_does_not_repeat_tools(self):
        count = len(self.state["tool_runs"])
        resumed = Runner.resume(self.runner.root).execute()
        self.assertEqual(len(resumed["tool_runs"]), count)
        self.assertEqual(len(resumed["findings"]), len(self.state["findings"]))


if __name__ == "__main__":
    unittest.main()

