import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from re_runner.models import Asset
from re_runner.profiles.binary import analyze as analyze_binary
from re_runner.protections import annotate
from re_runner.safety import Budget
from re_runner.scope import ScopePolicy


def thin_macho(cryptid=1, cryptsize=16):
    # Minimal x86-64 MH_EXECUTE: 32-byte header plus one LC_ENCRYPTION_INFO_64 and its declared range.
    image = struct.pack("<IIiiIIiI", 0xFEEDFACF, 0x01000007, 3, 2, 1, 20, 0, 0)
    image += struct.pack("<IiIII", 0x2C, 20, 64, cryptsize, cryptid)
    return image + bytes(64 - len(image)) + bytes(range(cryptsize))


def plain_macho():
    # Header-only x86-64 object with no load commands; lief still extracts base metadata.
    return struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 1, 0, 0, 0, 0)


def fat_macho(magic, slices, is64=True, align=12):
    # Wrap thin images behind a big-endian fat header; slice offsets honor the declared alignment.
    width, unit = (32 if is64 else 20), 1 << align
    entries, images = b"", b""
    start = (8 + len(slices) * width + unit - 1) // unit * unit
    images += bytes(start - (8 + len(slices) * width))
    offset = start
    for cpu, subtype, image in slices:
        padded = image + bytes(-len(image) % unit)
        fields = (cpu, subtype, offset, len(image), align) + ((0,) if is64 else ())
        entries += struct.pack(">IIQQII" if is64 else ">IIIII", *fields)
        images += padded
        offset += len(padded)
    return struct.pack(">II", magic, len(slices)) + entries + images


def jvm_class(major):
    # Same shape as the fixture class but with a controlled major version for the CAFEBABE probe.
    def utf8(value):
        raw = value.encode("utf-8")
        return b"\x01" + struct.pack(">H", len(raw)) + raw

    pool = utf8("Fixture") + b"\x07\x00\x01" + utf8("java/lang/Object") + b"\x07\x00\x03"
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, major, 5) + pool + struct.pack(">HHHHHHH", 0x21, 2, 4, 0, 0, 0, 0)


class FatMachoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="re-fat-macho-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_analyze(self, name, data, fmt):
        path = self.root / name
        path.write_bytes(data)
        output = self.root / (path.stem + "-out")
        output.mkdir()
        asset = Asset(id=path.stem, locator=str(path), kind="binary", format=fmt)
        return analyze_binary(asset, path, output, ScopePolicy(), Budget(ScopePolicy().budgets))

    def test_fat64_slices_keep_own_ranges_and_share_top_level_tail(self):
        data = fat_macho(0xCAFEBABF, [(0x01000007, 3, thin_macho(cryptsize=16)), (0x0100000C, 0, thin_macho(cryptsize=32))])
        result = self.run_analyze("fat64.bin", data, "mach-o-fat")
        analysis = result.analysis
        self.assertEqual(analysis["format"], "mach-o-fat")
        self.assertEqual([s["cpu"] for s in analysis["slices"]], [0x01000007, 0x0100000C])
        self.assertEqual([s["offset"] for s in analysis["slices"]], [4096, 8192])
        self.assertEqual(analysis["slices"][0]["encrypted_ranges"], [{"offset": 64, "bytes": 16, "crypt_id": 1}])
        self.assertEqual(analysis["slices"][1]["encrypted_ranges"], [{"offset": 64, "bytes": 32, "crypt_id": 1}])
        # Top level carries the deduplicated union so protections.annotate can see it.
        self.assertEqual(analysis["encrypted_ranges"], [{"offset": 64, "bytes": 16, "crypt_id": 1}, {"offset": 64, "bytes": 32, "crypt_id": 1}])
        self.assertEqual(analysis["sha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("runtime_markers", analysis)
        self.assertTrue(any("Encrypted Mach-O ranges" in item for item in result.limitations))

    def test_fat_encryption_annotation_is_per_slice_with_offset(self):
        data = fat_macho(0xCAFEBABF, [(0x01000007, 3, thin_macho(cryptsize=16)), (0x0100000C, 0, thin_macho(cryptsize=32))])
        result = self.run_analyze("fat64-annotate.bin", data, "mach-o-fat")
        protection = annotate("binary", result.analysis)
        flagged = [item for item in protection["indicators"] if item["name"] == "macho-encryption-command"]
        self.assertEqual([item["basis"][0]["slice_offset"] for item in flagged], [4096, 8192])
        self.assertEqual([item["basis"][0]["crypt_id"] for item in flagged], [1, 1])
        self.assertTrue(any(route["operation"] == "authorized-decrypted-image" for route in protection["next_routes"]))
        self.assertFalse(protection["bypass_executed"])

    def test_fat_without_encrypted_slices_is_not_flagged(self):
        data = fat_macho(0xCAFEBABF, [(0x01000007, 3, plain_macho())])
        result = self.run_analyze("fat64-plain.bin", data, "mach-o-fat")
        self.assertEqual(result.analysis["slices"][0]["encrypted_ranges"], [])
        self.assertEqual(result.analysis["encrypted_ranges"], [])
        protection = annotate("binary", result.analysis)
        self.assertNotIn("macho-encryption-command", [item["name"] for item in protection["indicators"]])
        self.assertFalse(any(route["operation"] == "authorized-decrypted-image" for route in protection["next_routes"]))

    def test_cafebabe_with_many_arches_parses_as_fat_not_jvm(self):
        data = fat_macho(0xCAFEBABE, [(7, 3, thin_macho()) for _ in range(48)], is64=False, align=4)
        # nfat_arch=48 lands in the JVM major-version window, but a valid fat table wins.
        result = self.run_analyze("fat-cafebabe.bin", data, "jvm-or-fat-mach-o")
        self.assertEqual(result.analysis["format"], "mach-o-fat")
        self.assertEqual(len(result.analysis["slices"]), 48)
        self.assertEqual(result.analysis["slices"][0]["encrypted_ranges"], [{"offset": 64, "bytes": 16, "crypt_id": 1}])
        self.assertEqual(result.analysis["encrypted_ranges"], [{"offset": 64, "bytes": 16, "crypt_id": 1}])
        self.assertEqual(result.analysis["sha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("runtime_markers", result.analysis)

    def test_cafebabe_class_file_still_routes_to_jvm(self):
        data = jvm_class(major=52)
        result = self.run_analyze("Fixture.bin", data, "jvm-or-fat-mach-o")
        self.assertEqual(result.analysis["format"], "jvm-class")
        self.assertEqual(result.analysis["class"], "Fixture")
        self.assertEqual(result.analysis["version"], {"major": 52, "minor": 0})
        self.assertEqual(result.analysis["sha256"], hashlib.sha256(data).hexdigest())

    def test_thin_macho_encryption_reaches_protections(self):
        data = thin_macho()
        result = self.run_analyze("thin.bin", data, "mach-o")
        self.assertEqual(result.analysis["encrypted_ranges"], [{"offset": 64, "bytes": 16, "crypt_id": 1}])
        self.assertEqual(result.analysis["sha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("runtime_markers", result.analysis)
        protection = annotate("binary", result.analysis)
        self.assertIn("macho-encryption-command", [item["name"] for item in protection["indicators"]])


if __name__ == "__main__":
    unittest.main()
