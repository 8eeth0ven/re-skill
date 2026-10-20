"""bandit rule-engine acceptance for the source deep layer.

Offline and deterministic: each test scans a tiny temporary tree. The positive
controls use a fixture that trips both the in-process AST taint paths and real
bandit rules (B602 subprocess shell=True, B605 os.system, B506 yaml.load), so
the two layers are shown to coexist. Without bandit the positive tests are
skipped and the honest "skipped" negative control still runs. Nothing here
executes fixture code: bandit parses it as text.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import InvalidInput
from re_runner.models import Asset
from re_runner.profiles.source_firmware import analyze as source_analyze
from re_runner.scanner import bandit_scan
from re_runner.safety import Budget
from re_runner.scope import ScopePolicy

HAVE_BANDIT = shutil.which("bandit") is not None

# Lines: 8 request.args.get (AST source), 10 os.system (AST sink + B605),
# 11 subprocess.call(shell=True) (B602), 12 yaml.load (B506).
APP = (
    "from flask import request\n"
    "import os\n"
    "import subprocess\n"
    "import yaml\n"
    "\n"
    "\n"
    "def route():\n"
    "    value = request.args.get('q')\n"
    "    command = 'echo ' + value\n"
    "    os.system(command)\n"
    "    subprocess.call(value, shell=True)\n"
    "    yaml.load(value)\n"
)
CLEAN = 'print("hello")\n'


def budget() -> Budget:
    return Budget(dict(BUDGET_DEFAULTS))


def write_tree(root: Path, content: str) -> Path:
    tree = root / "src"
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "app.py").write_text(content, encoding="utf-8")
    return tree


def source_result(root: Path, content: str = APP):
    tree = write_tree(root, content)
    return source_analyze(
        Asset(id="source", locator=str(tree), kind="source", format="tree"),
        tree, root / "out", ScopePolicy(), budget(),
    )


class BanditScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-source-deep-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "out"
        self.output.mkdir()

    @unittest.skipUnless(HAVE_BANDIT, "bandit is not installed (pyproject extra: source-deep)")
    def test_scan_normalizes_findings_and_writes_evidence(self):
        scan = bandit_scan(write_tree(self.root, APP), self.output, budget())
        self.assertIsNotNone(scan)
        self.assertEqual(scan["tool"], "bandit")
        self.assertEqual(scan["status"], "succeeded", scan.get("error"))
        self.assertIsNone(scan["error"])
        self.assertRegex(scan["version"], r"^\d+\.\d+")
        rules = {row["rule"] for row in scan["findings"]}
        self.assertIn("B602", rules, rules)
        self.assertIn("B506", rules, rules)
        shell = next(row for row in scan["findings"] if row["rule"] == "B602")
        self.assertEqual(shell["file"], "app.py")
        self.assertEqual(shell["line"], 11)
        self.assertEqual(shell["severity"], "HIGH")
        self.assertTrue(shell["issue_text"])
        self.assertLessEqual(len(scan["findings"]), 200)
        self.assertGreater(scan["metrics"].get("loc", 0), 0)
        for name in ("bandit-version-run.json", "bandit-run.json", "bandit.json"):
            evidence = self.output / name
            self.assertTrue(evidence.is_file(), name)
            json.loads(evidence.read_text("utf-8"))

    @unittest.skipUnless(HAVE_BANDIT, "bandit is not installed (pyproject extra: source-deep)")
    def test_profile_layer_coexists_with_ast_paths(self):
        result = source_result(self.root)
        checks = {check["name"]: check for check in result.checks}
        engine = checks["source-rule-engine-bandit"]
        self.assertEqual(engine["status"], "succeeded", engine["detail"])
        self.assertIn("bandit", engine["detail"])
        rule_ids = {row["rule_id"] for row in result.candidates}
        self.assertIn("python-untrusted-execution-path", rule_ids, "AST layer must stay intact")
        self.assertIn("bandit-high-dangerous-api", rule_ids, rule_ids)
        hits = {row["location"] for row in result.candidates if row["rule_id"] == "bandit-high-dangerous-api"}
        self.assertEqual(hits, {"app.py:11", "app.py:10"}, hits)
        for row in result.candidates:
            if row["rule_id"] == "bandit-high-dangerous-api":
                self.assertIn("requires contextual confirmation", row["title"])
                self.assertEqual(row["severity"], "high")
        self.assertTrue(result.analysis["rule_engine"])
        self.assertEqual(result.analysis["python_source_paths"][0]["sink"], "os.system")

    @unittest.skipUnless(HAVE_BANDIT, "bandit is not installed (pyproject extra: source-deep)")
    def test_clean_tree_yields_zero_findings_and_candidates(self):
        result = source_result(self.root, CLEAN)
        checks = {check["name"]: check for check in result.checks}
        self.assertEqual(checks["source-rule-engine-bandit"]["status"], "succeeded")
        self.assertEqual(result.analysis["rule_engine"], [])
        self.assertNotIn("bandit-high-dangerous-api", {row["rule_id"] for row in result.candidates})

    @unittest.skipUnless(HAVE_BANDIT, "bandit is not installed (pyproject extra: source-deep)")
    def test_empty_directory_succeeds_without_findings(self):
        empty = self.root / "empty"
        empty.mkdir()
        scan = bandit_scan(empty, self.output, budget())
        self.assertIsNotNone(scan)
        self.assertEqual(scan["status"], "succeeded", scan.get("error"))
        self.assertEqual(scan["findings"], [])
        self.assertEqual(scan["metrics"].get("loc", 0), 0)

    @unittest.skipUnless(HAVE_BANDIT, "bandit is not installed (pyproject extra: source-deep)")
    def test_explicit_executable_is_accepted_and_garbage_rejected(self):
        tree = write_tree(self.root, APP)
        scan = bandit_scan(tree, self.output, budget(), executable=shutil.which("bandit"))
        self.assertEqual(scan["status"], "succeeded", scan.get("error"))
        with self.assertRaises(InvalidInput):
            bandit_scan(tree, self.output, budget(), executable="definitely-not-bandit.exe")

    def test_missing_bandit_is_an_honest_skip(self):
        with patch("re_runner.scanner.shutil.which", return_value=None):
            self.assertIsNone(bandit_scan(write_tree(self.root, APP), self.output, budget()))
            result = source_result(self.root / "skipped")
        checks = {check["name"]: check for check in result.checks}
        self.assertEqual(checks["source-rule-engine-bandit"]["status"], "skipped")
        self.assertIn("bandit", checks["source-rule-engine-bandit"]["detail"])
        self.assertNotIn("rule_engine", result.analysis)
        self.assertNotIn("bandit-high-dangerous-api", {row["rule_id"] for row in result.candidates})
        # The built-in AST layer runs untouched in the same analysis.
        self.assertEqual(checks["python-local-path-analysis"]["status"], "succeeded")
        self.assertEqual(result.analysis["python_source_paths"][0]["sink"], "os.system")


if __name__ == "__main__":
    unittest.main()
