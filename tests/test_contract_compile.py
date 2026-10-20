import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_runner.compilers import solc_compile
from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.models import Asset
from re_runner.profiles.special import analyze
from re_runner.safety import Budget, load_json
from re_runner.scope import ScopePolicy

REPO = Path(__file__).resolve().parents[1]


def _solc_path() -> Path:
    value = os.environ.get("RE_RUN_SOLC")
    return Path(value) if value else REPO / "tools-env" / "solc-windows-0.8.37.exe"


SOLC = _solc_path()

GOOD_SOURCE = (
    "// SPDX-License-Identifier: UNLICENSED\n"
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    uint256 private stored;\n"
    "    function store(uint256 value) external { stored = value; }\n"
    "    function get() external view returns (uint256) { return stored; }\n"
    "    function withdraw() external payable { stored = 0; }\n"
    "}\n"
)
BAD_SOURCE = "pragma solidity ^0.8.0;\ncontract Broken { function f( { }\n"


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-contract-compile-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def budget(self):
        return Budget(BUDGET_DEFAULTS)

    @staticmethod
    def asset(path):
        return Asset(id="contract-1", locator=str(path), kind="contract", format="solidity")


class UnconfiguredTests(TempCase):
    def test_solc_compile_returns_none_without_configuration(self):
        source = self.write("vault.sol", GOOD_SOURCE)
        clean = {key: value for key, value in os.environ.items() if key != "RE_RUN_SOLC"}
        with patch.dict(os.environ, clean, clear=True):
            self.assertIsNone(solc_compile(source, self.root / "out", self.budget()))


@unittest.skipUnless(SOLC.is_file(), "trusted solc executable is not present on this host")
class SolcCompileTests(TempCase):
    def configured(self):
        return patch.dict(os.environ, {"RE_RUN_SOLC": str(SOLC)})

    def test_positive_compile_produces_artifacts_and_parseable_abi(self):
        source = self.write("vault.sol", GOOD_SOURCE)
        output = self.root / "out"
        with self.configured():
            result = solc_compile(source, output, self.budget())
        self.assertEqual(result["tool"], "solc")
        self.assertEqual(result["status"], "succeeded")
        self.assertIsNone(result["error"])
        self.assertTrue(str(result["version"]).startswith("0.8."))
        vault = next(item for item in result["contracts"] if item["name"] == "Vault")
        self.assertGreater(vault["bytecode_len"], 0)
        self.assertIn("withdraw", {entry["name"] for entry in vault["abi"]})
        self.assertTrue((output / "solc-version-run.json").is_file())
        self.assertTrue((output / "solc-compile-run.json").is_file())
        artifacts = sorted(output.glob("solc-contract-*.json"))
        self.assertEqual(len(artifacts), 1)
        record = load_json(artifacts[0])
        self.assertEqual(record["contract"], "Vault")
        self.assertGreater(record["bytecode_len"], 0)
        self.assertIn("stateMutability", {key for entry in record["abi"] for key in entry})

    def test_profile_wires_compile_check_abi_evidence_and_candidate(self):
        source = self.write("vault.sol", GOOD_SOURCE)
        work = self.root / "work"
        with self.configured():
            result = analyze(self.asset(source), source, work, ScopePolicy(), self.budget())
        checks = {item["name"]: item["status"] for item in result.checks}
        self.assertEqual(checks["contract-source-declarations"], "succeeded")
        self.assertEqual(checks["contract-compile-solc"], "succeeded")
        compilation = result.analysis["compilation"]
        self.assertEqual(compilation["status"], "succeeded")
        self.assertEqual(compilation["contracts"][0]["name"], "Vault")
        self.assertTrue(any(work.glob("solc-contract-*.json")), "ABI/bytecode artifacts must land in the work directory")
        self.assertEqual(
            [(item["rule_id"], item["location"]) for item in result.candidates],
            [("contract-unprotected-state-mutating", "abi:Vault:withdraw")],
        )

    def test_syntax_error_degrades_with_stderr_signature(self):
        source = self.write("broken.sol", BAD_SOURCE)
        with self.configured():
            result = analyze(self.asset(source), source, self.root / "work", ScopePolicy(), self.budget())
        checks = {item["name"]: item for item in result.checks}
        self.assertEqual(checks["contract-source-declarations"]["status"], "succeeded")
        self.assertEqual(checks["contract-compile-solc"]["status"], "degraded")
        compilation = result.analysis["compilation"]
        self.assertEqual(compilation["status"], "failed")
        self.assertEqual(compilation["contracts"], [])
        self.assertTrue(compilation.get("stderr_signature"), "a compile failure must carry a stderr signature")
        self.assertIn("rror", compilation["stderr_signature"])
        self.assertEqual(result.candidates, [])

    def test_unconfigured_solc_marks_check_skipped(self):
        source = self.write("vault.sol", GOOD_SOURCE)
        clean = {key: value for key, value in os.environ.items() if key != "RE_RUN_SOLC"}
        with patch.dict(os.environ, clean, clear=True):
            result = analyze(self.asset(source), source, self.root / "work", ScopePolicy(), self.budget())
        checks = {item["name"]: item["status"] for item in result.checks}
        self.assertEqual(checks["contract-compile-solc"], "skipped")
        self.assertNotIn("compilation", result.analysis)
        self.assertEqual(result.candidates, [])


if __name__ == "__main__":
    unittest.main()
