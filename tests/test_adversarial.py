import gzip
import json
import os
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from re_runner.archive import decompress_gzip, extract_archive
from re_runner.contracts import BUDGET_DEFAULTS, MANIFEST_SCHEMA, SCOPE_SCHEMA, validate
from re_runner.errors import AnalysisError, BudgetExceeded, IntegrityError, InvalidInput, Locked
from re_runner.execution import run_command
from re_runner.intake import iter_tree
from re_runner.locking import FileLock
from re_runner.models import AssetRequest
from re_runner.parsing import load_yaml, xml
from re_runner.profiles.binary import jvm, uleb, wasm
from re_runner.profiles.mobile import axml, dex_metadata
from re_runner.profiles.source_firmware import python_paths
from re_runner.profiles.special import evm_bytecode, safetensors
from re_runner.profiles.traffic import pcap, pcapng
from re_runner.reporting import evidence_gate
from re_runner.runner import Runner
from re_runner.safety import Budget, atomic_json, load_json, markdown_text, parse_json, redact, safe_relative
from re_runner.scope import ScopePolicy, normalize_url, url_matches
from re_runner.state import read_state
from re_runner.validators import verification_gate


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-adversarial-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for directory, _, files in os.walk(self.root):
            for name in files:
                try:
                    (Path(directory) / name).chmod(0o600)
                except OSError:
                    pass
        self.temporary.cleanup()

    def budget(self, **values):
        return Budget({**BUDGET_DEFAULTS, **values})


class ArchiveAdversarialTests(TempCase):
    def archive(self, members):
        path = self.root / "sample.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, body in members:
                archive.writestr(name, body)
        return path

    def test_zip_traversal_rejected_before_writing_good_member(self):
        archive = self.archive([("good.txt", b"good"), ("../escaped.txt", b"evil")])
        with self.assertRaises(InvalidInput):
            extract_archive(archive, self.root / "output", self.budget())
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertFalse((self.root / "output/good.txt").exists())

    def test_platform_paths_and_unicode_obfuscation(self):
        for name in ("/absolute", "C:/escape", "x\\..\\escape", "a/../escape", "nul.txt", "a:x", "a./b", "a\u202eb", "a//b"):
            with self.subTest(name=name), self.assertRaises(InvalidInput):
                safe_relative(name)

    def test_case_collision_and_file_directory_conflict(self):
        for members in ([('A', b'x'), ('a', b'y')], [('a', b'x'), ('a/b', b'y')]):
            archive = self.archive(members)
            output = self.root / f"out-{len(list(self.root.iterdir()))}"
            with self.assertRaises(InvalidInput):
                extract_archive(archive, output, self.budget())

    def test_zip_symlink_rejected(self):
        path = self.root / "linked.zip"
        with zipfile.ZipFile(path, "w") as archive:
            member = zipfile.ZipInfo("link")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "../../outside")
        with self.assertRaises(InvalidInput):
            extract_archive(path, self.root / "output", self.budget())

    def test_tar_links_and_devices_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            path = self.root / f"archive-{kind.decode()}.tar"
            with tarfile.open(path, "w") as archive:
                member = tarfile.TarInfo("unsafe")
                member.type, member.linkname = kind, "../../outside"
                archive.addfile(member)
            with self.subTest(kind=kind), self.assertRaises(InvalidInput):
                extract_archive(path, self.root / f"out-{kind.decode()}", self.budget())

    def test_gzip_bomb_is_bounded_and_original_preserved(self):
        path = self.root / "bomb.gz"
        original = gzip.compress(b"x" * 1_000_000)
        path.write_bytes(original)
        target = self.root / "expanded"
        with self.assertRaises(BudgetExceeded):
            decompress_gzip(path, target, self.budget(max_unpack_bytes=4096))
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(target.exists())

    def test_zip_count_budget(self):
        path = self.archive([(f"file-{i}", b"x") for i in range(4)])
        with self.assertRaises(BudgetExceeded):
            extract_archive(path, self.root / "output", self.budget(max_files=3))

    def test_directory_links_are_not_read(self):
        outside = self.root / "outside"
        outside.write_text("secret")
        tree = self.root / "tree"
        tree.mkdir()
        try:
            (tree / "link").symlink_to(outside)
        except OSError:
            self.skipTest("Host does not allow creating symlinks")
        with self.assertRaises(InvalidInput):
            list(iter_tree(tree, self.budget()))

    def test_empty_directory_count_is_bounded(self):
        tree = self.root / "tree"
        tree.mkdir()
        for i in range(10):
            (tree / str(i)).mkdir()
        with self.assertRaises(BudgetExceeded):
            list(iter_tree(tree, self.budget(max_files=4)))


class ContractAdversarialTests(unittest.TestCase):
    def test_json_duplicate_nonfinite_and_deep_data(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', '[' * 60 + '0' + ']' * 60):
            with self.subTest(value=value[:30]), self.assertRaises(AnalysisError):
                parse_json(value)

    def test_yaml_alias_python_constructor_and_duplicate_keys(self):
        for value in (b'a: &a [*a]', b'a: !!python/object/apply:os.system [echo hacked]', b'a: 1\na: 2'):
            with self.subTest(value=value), self.assertRaises(AnalysisError):
                load_yaml(value)

    def test_xml_external_entity_rejected(self):
        value = b'<!DOCTYPE data [<!ENTITY x SYSTEM "file:///etc/passwd">]><data>&x;</data>'
        with self.assertRaises(InvalidInput):
            xml(value)

    def test_unknown_scope_fields_and_budget_types(self):
        for value in ({"operations": ["shell"]}, {"budgets": {"max_requests": "many"}}, {"trust_model_verdict": True}):
            with self.assertRaises(InvalidInput):
                validate(value, SCOPE_SCHEMA)
        with self.assertRaises(InvalidInput):
            validate({"assets": [{"locator": "x", "type": "arbitrary-shell"}]}, MANIFEST_SCHEMA)

    def test_report_redaction_and_markdown_injection(self):
        value = {"authorization": "Bearer ABC", "password": "secret", "url": "https://example.test/?email=alice%40example.com&token=abc"}
        public = json.dumps(redact(value))
        self.assertNotIn("Bearer ABC", public)
        self.assertNotIn("alice", public)
        rendered = markdown_text('# forged\n![image](https://evil.example/a)<script>x</script>')
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("![image]", rendered)

    def test_url_prefix_is_not_host_prefix_or_sibling_path(self):
        self.assertTrue(url_matches("https://example.test/api/item", "https://example.test/api"))
        self.assertFalse(url_matches("https://example.test.evil/api/item", "https://example.test/api"))
        self.assertFalse(url_matches("https://example.test/apix", "https://example.test/api"))
        for url in ("https://example.test/api/%2e%2e/admin", "https://example.test/api/%252e%252e/admin", "https://example.test/api//admin", "https://user:secret@example.test/"):
            with self.subTest(url=url), self.assertRaises(InvalidInput):
                normalize_url(url)

    def test_model_cannot_manufacture_verified(self):
        self.assertFalse(verification_gate({"validator": "llm", "passed": True, "positive_control": {"accepted": True}, "negative_control": {"accepted": False}, "tool_run_id": "t-1", "evidence_id": "e-1"}))

    def test_source_cooccurrence_is_not_dataflow(self):
        self.assertEqual(python_paths("import os\nfrom flask import request\ndef f():\n    q = request.args.get('q')\n    os.system('echo safe')\n"), [])
        self.assertEqual(python_paths("import os\nfrom flask import request\ndef f():\n    q = request.args.get('q')\n    q = 'safe'\n    os.system(q)\n"), [])
        self.assertEqual(python_paths("import os\nfrom flask import request\ndef f():\n    q = int(request.args.get('q'))\n    os.system(str(q))\n"), [])


class ParserAdversarialTests(unittest.TestCase):
    def test_invalid_lengths_are_explained(self):
        values = (
            (lambda x: wasm(x), b"\x00asm\x01\x00\x00\x00\x02\xff\xff\xff\xff\x0f"),
            (jvm, b"\xca\xfe\xba\xbe" + bytes(6)),
            (dex_metadata, b"dex\n035\x00" + bytes(104)),
            (axml, struct.pack("<HHI", 3, 8, 100)),
            (safetensors, struct.pack("<Q", 2**63)),
            (lambda x: pcap(x, Budget(BUDGET_DEFAULTS)), b"\xd4\xc3\xb2\xa1"),
            (lambda x: pcapng(x, Budget(BUDGET_DEFAULTS)), b"\x0a\x0d\x0d\x0a"),
        )
        for decoder, data in values:
            with self.subTest(decoder=decoder), self.assertRaises(AnalysisError):
                decoder(data)

    def test_leb128_overflow_and_evm_truncated_push(self):
        with self.assertRaises(InvalidInput):
            uleb(b"\xff" * 6, 0)
        with self.assertRaises(InvalidInput):
            evm_bytecode("0x7f00")

    def test_tensor_overlap_and_shape_mismatch(self):
        for header in (
            {"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}},
            {"a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}, "b": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}},
        ):
            encoded = json.dumps(header).encode()
            with self.assertRaises(InvalidInput):
                safetensors(struct.pack("<Q", len(encoded)) + encoded + bytes(4))


class ProcessAndStateTests(TempCase):
    def source(self, content="print('safe')\n"):
        path = self.root / "app.py"
        path.write_text(content, encoding="utf-8")
        return path

    def test_timeout_kills_process_tree(self):
        script = self.root / "sleep.py"
        child_pid = self.root / "child.pid"
        script.write_text("import subprocess,sys,time\np=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\nopen(sys.argv[1],'w').write(str(p.pid))\ntime.sleep(60)\n", encoding="utf-8")
        result = run_command([sys.executable, str(script), str(child_pid)], self.root, self.budget(), timeout=1)
        self.assertEqual(result.status, "timed-out")
        self.assertLess(result.duration, 8)
        pid = int(child_pid.read_text())
        if os.name == "nt":
            import ctypes
            kernel = ctypes.WinDLL("kernel32")
            kernel.OpenProcess.restype = ctypes.c_void_p
            handle = kernel.OpenProcess(0x1000, False, pid)
            if handle:
                code = ctypes.c_ulong()
                kernel.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
                kernel.CloseHandle(ctypes.c_void_p(handle))
                self.assertNotEqual(code.value, 259, "Child process survived job termination")
        else:
            status = Path(f"/proc/{pid}/stat")
            if status.exists():
                self.assertIn(status.read_text().split()[2], ("Z", "X"))

    def test_command_arguments_do_not_invoke_a_shell(self):
        marker = self.root / "owned"
        value = f"$(touch {marker}); & echo malicious"
        result = run_command([sys.executable, "-c", "import sys;print(sys.argv[1])", value], self.root, self.budget())
        self.assertEqual(result.status, "succeeded")
        self.assertIn("$(touch", result.stdout)
        self.assertFalse(marker.exists())

    def test_output_flood_is_bounded(self):
        result = run_command([sys.executable, "-c", "import sys;sys.stdout.write('X'*5000000)"], self.root, self.budget(max_tool_output_bytes=4096))
        self.assertEqual(result.status, "output-exceeded")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 8192)

    def test_kernel_lock_excludes_concurrent_owner_and_recovers(self):
        path = self.root / ".lock"
        with FileLock(path):
            with self.assertRaises(Locked):
                FileLock(path).acquire()
            process = subprocess.run([sys.executable, "-c", "from pathlib import Path; from re_runner.locking import FileLock; import sys; FileLock(Path(sys.argv[1])).acquire()", str(path)], capture_output=True, timeout=10)
            self.assertNotEqual(process.returncode, 0)
        with FileLock(path):
            self.assertTrue(path.exists())

    def test_missing_scope_yields_blocked_report_without_network(self):
        runner = Runner.new(self.root / "runs", [AssetRequest("https://example.test/")], ScopePolicy(), "triage", "en")
        with patch("socket.getaddrinfo", side_effect=AssertionError("Should not resolve")):
            state = runner.execute()
        self.assertEqual(state["status"], "blocked")
        self.assertEqual(state["assets"]["asset-001"]["error"]["code"], "scope-denied")
        self.assertTrue((runner.root / "report.json").exists())

    def test_corrupt_binary_reports_failed_and_no_findings(self):
        path = self.root / "bad.exe"
        path.write_bytes(b"MZbroken")
        runner = Runner.new(self.root / "runs", [AssetRequest(str(path))], ScopePolicy(), "verify", "en")
        state = runner.execute()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["findings"], [])
        self.assertTrue((runner.root / "report.md").exists())

    def test_modified_original_is_rejected_on_resume(self):
        path = self.source()
        runner = Runner.new(self.root / "runs", [AssetRequest(str(path))], ScopePolicy(), "triage", "en")
        state = runner.execute()
        self.assertEqual(state["status"], "succeeded")
        count = len(state["tool_runs"])
        path.write_text("print('changed')\n")
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "failed")
        self.assertEqual(len(resumed["tool_runs"]), count)
        self.assertIn("changed", resumed["assets"]["asset-001"]["error"]["message"])

    def test_corrupt_evidence_is_rejected_and_report_not_successful(self):
        path = self.source("import os\nq=input()\nos.system(q)\n")
        runner = Runner.new(self.root / "runs", [AssetRequest(str(path))], ScopePolicy(), "triage", "en")
        state = runner.execute()
        self.assertTrue(state["findings"])
        evidence_path = runner.root / state["evidence"][0]["path"]
        evidence_path.write_text("{}")
        resumed = Runner.resume(runner.root).execute()
        self.assertEqual(resumed["status"], "failed")
        self.assertEqual(load_json(runner.root / "report.json")["status"], "failed")

    def test_immutable_scope_change_rejected(self):
        runner = Runner.new(self.root / "runs", [AssetRequest(str(self.source()))], ScopePolicy(), "triage", "en")
        request = load_json(runner.root / "request.json")
        request["scope"]["allow_urls"] = ["https://evil.example/"]
        atomic_json(runner.root / "request.json", request)
        with self.assertRaises(IntegrityError):
            read_state(runner.root)

    def test_verified_key_requires_positive_and_negative_control(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        tree = self.root / "keys"
        tree.mkdir()
        key_path = tree / "fixture.pem"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        runner = Runner.new(self.root / "runs", [AssetRequest(str(tree))], ScopePolicy(), "verify", "en")
        state = runner.execute()
        verified = [finding for finding in state["findings"] if finding["status"] == "verified"]
        self.assertEqual(len(verified), 1, state["errors"])
        finding = verified[0]
        self.assertTrue(finding["validation"]["positive_control"]["accepted"])
        self.assertFalse(finding["validation"]["negative_control"]["accepted"])
        evidence_gate(runner.root, state)
        self.assertNotIn("BEGIN PRIVATE KEY", (runner.root / "report.json").read_text())


if __name__ == "__main__":
    unittest.main()

