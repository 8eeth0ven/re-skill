"""A-lane round-3 acceptance: UBI/TRX containers, OCI merged rootfs + registry,
Ghidra headless decompile adapter.

Covers the 6d acceptance gaps with positive runs, negative controls (bad magic,
structural violations, missing blobs, digest mismatches, truncation) and quota
enforcement, following the test_firmware_extract.py conventions: everything is
offline; real-tool positives are skipped when the tool is absent; negative
controls always run.

Oracle chains:
- UBI volume payload is verified byte-for-byte against the fixture payload AND
  independently with unsquashfs when available (the payload is a real squashfs).
- TRX CRC is verified against a deliberately corrupted image (degraded) and a
  structurally lying header (failed).
- OCI merged rootfs is asserted by final tree state after whiteout semantics.
- Registry blobs are digest-verified; tampered blobs must fail.
- Ghidra: real bpalogin (MIPS ELF, read-only reference) must yield at least one
  decompiled function body.
"""
import binascii
import hashlib
import http.server
import io
import json
import os
import shutil
import struct
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.errors import InvalidInput, NetworkError
from re_runner.extractors_ext import (
    UBI_LAYOUT_VOLUME_ID,
    _TRX_HDR,
    oci_layout_extract,
    registry_fetch,
    trx_extract,
    ubi_extract,
)
from re_runner.ghidra_adapter import configured_headless, headless_decompile
from re_runner.safety import Budget

REPO = Path(__file__).resolve().parents[1]
# Environment-gated fixtures: point these at a local MIPS ELF and a Ghidra install
# to enable the real-run tests; unset → those tests self-skip (same convention as RE_RUN_*).
BPALOGIN = Path(os.environ["RE_BPALOGIN"]) if os.environ.get("RE_BPALOGIN") else None
GHIDRA = Path(os.environ["RE_GHIDRA_HOME"]) if os.environ.get("RE_GHIDRA_HOME") else None
MKSWITCHFS = shutil.which("mksquashfs")
UNSQUASHFS = shutil.which("unsquashfs")
SEVENZIP = shutil.which("7z") or shutil.which("7zz")


def budget(**overrides) -> Budget:
    limits = dict(BUDGET_DEFAULTS)
    limits.update(overrides)
    return Budget(limits)


def _crc(data: bytes) -> bytes:
    return struct.pack(">I", binascii.crc32(data) & 0xFFFFFFFF)


# ---- fixture builders -------------------------------------------------------

def make_squashfs(work: Path, marker: str = "alane-inner") -> bytes:
    """A real squashfs (mksquashfs) so the located inner image is genuine."""
    tree = work / f"sqfs-tree-{marker}"
    (tree / "etc").mkdir(parents=True, exist_ok=True)
    (tree / "etc" / "banner").write_text(f"fixture {marker}\n", encoding="utf-8")
    (tree / "bin").mkdir(exist_ok=True)
    (tree / "bin" / "busybox-fixture").write_text("#!/bin/sh\necho fixture\n", encoding="utf-8")
    out = work / f"{marker}.sqfs"
    proc = subprocess_run_quiet([str(MKSWITCHFS), str(tree), str(out),
                                 "-noappend", "-no-recovery", "-no-progress", "-all-root", "-no-xattrs"])
    shutil.rmtree(tree, ignore_errors=True)
    if proc != 0 or not out.is_file():
        return b""
    return out.read_bytes()


def subprocess_run_quiet(argv: list[str]) -> int:
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True, timeout=120).returncode


def build_squashfs_once() -> bytes:
    if not MKSWITCHFS:
        return b""
    base = Path(tempfile.mkdtemp(prefix="alane-sqfs-"))
    try:
        return make_squashfs(base, "shared")
    finally:
        shutil.rmtree(base, ignore_errors=True)


SQFS_PAYLOAD = build_squashfs_once()
if not SQFS_PAYLOAD:
    # Negative controls never need a real squashfs; positives skip without one.
    SQFS_PAYLOAD = b"\x00" * 4096


def ec_header(vid_offset: int = 0x800, data_offset: int = 0x1000) -> bytes:
    hdr = struct.pack(">4sB3xqIII32x", b"UBI#", 1, 0, vid_offset, data_offset, 0x51)
    return hdr + _crc(hdr)


def vid_header(vol_id: int, lnum: int, vol_type: int, data_size: int = 0,
               used_ebs: int = 0, data_crc: int = 0) -> bytes:
    hdr = struct.pack(">4sBBBBII4xIIII4xQ12x", b"UBI!", 1, vol_type, 0, 0,
                      vol_id, lnum, data_size, used_ebs, 0, data_crc, 0)
    return hdr + _crc(hdr)


def vtbl_record(vol_id: int, name: bytes, reserved_pebs: int = 1) -> bytes:
    body = struct.pack(">IIIBBH", reserved_pebs, 1, 0, 1, 0, len(name))
    body += name.ljust(128, b"\x00") + struct.pack(">B", 0) + b"\x00" * 23
    return body + _crc(body)


VTBL_SIZE = 172


def build_ubi(payload: bytes, peb: int = 0x20000, static: bool = True) -> bytes:
    """Minimal spec-faithful UBI: 2 layout PEBs + data volume carrying payload."""
    vid_offset, data_offset = 0x800, 0x1000
    data_per_peb = peb - data_offset
    chunks = [payload[i:i + data_per_peb] for i in range(0, len(payload), data_per_peb)] or [b""]

    def peb_bytes(vid: bytes, body: bytes) -> bytes:
        block = bytearray(b"\xff" * peb)
        block[0:64] = ec_header(vid_offset, data_offset)
        block[vid_offset:vid_offset + 64] = vid
        block[data_offset:data_offset + len(body)] = body
        return bytes(block)

    # Layout volume (internal id), dynamic type, two copies of the volume table.
    table = vtbl_record(0, b"rootfs", reserved_pebs=len(chunks))
    vtbl = table.ljust(VTBL_SIZE * 128, b"\x00")
    image = b""
    for lnum in (0, 1):
        image += peb_bytes(vid_header(UBI_LAYOUT_VOLUME_ID, lnum, 0), vtbl)
    # User volume: static (per-LEB data_size + data_crc) or dynamic.
    for lnum, chunk in enumerate(chunks):
        vid = vid_header(0, lnum, 1 if static else 0,
                         data_size=len(chunk) if static else 0,
                         used_ebs=len(chunks) if static else 0,
                         data_crc=(binascii.crc32(chunk) & 0xFFFFFFFF) if static else 0)
        image += peb_bytes(vid, chunk)
    return image


def build_trx(partitions: list[bytes], flag_version: int = 0, fix_crc: bool = True) -> bytes:
    offs = []
    pos = _TRX_HDR.size
    for part in partitions:
        offs.append(pos)
        pos += len(part)
    offs += [0] * (3 - len(offs))          # header always declares 3 offsets
    length = pos
    # TRX CRC-32 covers flag_version through the END of the image, i.e. the
    # rest of the header (offsets included) plus every partition byte.
    tail = struct.pack("<I", flag_version) + struct.pack("<3I", *offs) + b"".join(partitions)
    crc = (binascii.crc32(tail) & 0xFFFFFFFF) if fix_crc else 0xDEADBEEF
    return struct.pack("<4sIII", b"HDR0", length, crc, flag_version) + struct.pack("<3I", *offs) + b"".join(partitions)


def tar_bytes(entries: list[tuple[str, bytes | None, str]]) -> bytes:
    """entries: (name, content|None, kind) with kind in file/dir/sym."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                tar.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = (content or b"").decode("utf-8")
                tar.addfile(info)
            else:
                data = content or b""
                info.size = len(data)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _digest_blob(data: bytes) -> tuple[str, str]:
    hexdigest = hashlib.sha256(data).hexdigest()
    return f"sha256:{hexdigest}", hexdigest


def build_oci_layout(layer_tars: list[bytes]) -> bytes:
    """Wrap layer tars into an OCI image layout tar (oci-layout/index/manifest)."""
    layer_descs = []
    blobs: dict[str, bytes] = {}
    for lt in layer_tars:
        digest, hexd = _digest_blob(lt)
        blobs[hexd] = lt
        layer_descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar",
                            "digest": digest, "size": len(lt)})
    config = json.dumps({"architecture": "mips", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode()
    cfg_digest, cfg_hex = _digest_blob(config)
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": len(config)},
        "layers": layer_descs,
    }).encode()
    man_digest, man_hex = _digest_blob(manifest)
    index = json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": man_digest, "size": len(manifest)}],
    }).encode()
    layout = io.BytesIO()
    with tarfile.open(fileobj=layout, mode="w") as tar:

        def add(name: str, data: bytes):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        add("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        add("index.json", index)
        add(f"blobs/sha256/{man_hex}", manifest)
        add(f"blobs/sha256/{cfg_hex}", config)
        for hexd, blob in blobs.items():
            add(f"blobs/sha256/{hexd}", blob)
    return layout.getvalue()


class FakeRegistry:
    """Minimal OCI Distribution API v2 (contract-level) on an ephemeral port."""

    def __init__(self, manifests: dict[str, bytes], blobs: dict[str, bytes]):
        self.manifests = manifests
        self.blobs = blobs
        self.hits: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits.append(self.path)
                path = self.path
                if path in ("/v2/", "/v2"):
                    return self._reply(200, b"{}")
                if "/manifests/" in path:
                    ref = path.rsplit("/", 1)[-1]
                    blob = outer.manifests.get(ref)
                    return self._reply(200 if blob is not None else 404, blob or b"not found")
                if "/blobs/" in path:
                    ref = path.rsplit(":", 1)[-1] if ":" in path else path.rsplit("/", 1)[-1]
                    blob = outer.blobs.get(ref)
                    return self._reply(200 if blob is not None else 404, blob or b"not found")
                return self._reply(404, b"not found")

            def _reply(self, code: int, body: bytes):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Docker-Content-Digest", f"sha256:{hashlib.sha256(body).hexdigest()}")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def registry_payload(layer_tars: list[bytes], tag: str = "v1"):
    """(manifest-bytes, blobs-by-digest) served by the fake registry."""
    layer_descs, blobs = [], {}
    for lt in layer_tars:
        digest, hexd = _digest_blob(lt)
        blobs[hexd] = lt
        layer_descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar",
                            "digest": digest, "size": len(lt)})
    config = json.dumps({"os": "linux"}).encode()
    cfg_digest, cfg_hex = _digest_blob(config)
    blobs[cfg_hex] = config
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": len(config)},
        "layers": layer_descs,
    }).encode()
    return {tag: manifest, "sha256:deadbeef": manifest}, blobs


# ---- UBI --------------------------------------------------------------------

class UbiExtractionTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="alane-ubi-"))
        self.image = self.work / "image.ubi"

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _write(self, data: bytes):
        self.image.write_bytes(data)
        return self.image

    @unittest.skipUnless(MKSWITCHFS, "mksquashfs unavailable")
    def test_ubi_good_static_volume_with_real_squashfs(self):
        result = ubi_extract(self._write(build_ubi(SQFS_PAYLOAD)), self.work / "out", budget())
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertEqual(result["erase_block"], 0x20000)
        self.assertEqual(result["bad_crc_blocks"], 0)
        volumes = [v for v in result["volumes"] if v["vol_id"] == "0x0"]
        self.assertEqual(len(volumes), 1)
        volume = volumes[0]
        self.assertEqual(volume["bytes"], len(SQFS_PAYLOAD))
        extracted = (self.work / "out" / volume["file"]).read_bytes()
        self.assertEqual(extracted, SQFS_PAYLOAD, "static volume payload must round-trip")
        self.assertEqual(volume["inner_kind"], "squashfs")

    @unittest.skipUnless(MKSWITCHFS and UNSQUASHFS, "mksquashfs/unsquashfs unavailable")
    def test_ubi_payload_independently_unsquashable(self):
        result = ubi_extract(self._write(build_ubi(SQFS_PAYLOAD)), self.work / "out", budget())
        volume = next(v for v in result["volumes"] if v["vol_id"] == "0x0")
        listing = subprocess_run([UNSQUASHFS, "-l", str(self.work / "out" / volume["file"])])
        self.assertIn("etc/banner", listing)
        self.assertIn("bin/busybox-fixture", listing)

    def test_ubi_bad_magic(self):
        bad = self.work / "bad.bin"
        bad.write_bytes(b"\x00" * 0x20000)
        result = ubi_extract(bad, self.work / "out-bad", budget())
        self.assertEqual(result["status"], "failed")
        self.assertIn("Bad EC header magic", result["error"])

    def test_ubi_over_quota(self):
        result = ubi_extract(self._write(build_ubi(SQFS_PAYLOAD)), self.work / "out-quota",
                             budget(max_unpack_bytes=1024))
        self.assertEqual(result["status"], "degraded")
        self.assertIn("stopped at total unpack budget", result["error"])
        self.assertEqual(result["bytes"], 0, "no quota-crossing block may reach disk")

    def test_ubi_truncated(self):
        # The payload must span more than one data PEB so cutting the image can
        # remove a declared LEB (used_ebs=2) instead of only 0xFF padding.
        data_per_peb = 0x20000 - 0x1000
        padded = SQFS_PAYLOAD + b"TAIL" * (data_per_peb // 4)
        good = build_ubi(padded, static=True)
        self.assertEqual(len(good) % 0x20000, 0)
        result = ubi_extract(self._write(good[:len(good) - 0x10000]), self.work / "out-trunc", budget())
        self.assertEqual(result["status"], "degraded", result["error"])
        self.assertIn("truncated", result["error"])


def subprocess_run(argv: list[str]) -> str:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return proc.stdout + proc.stderr


# ---- TRX --------------------------------------------------------------------

class TrxExtractionTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="alane-trx-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _partitions(self) -> list[bytes]:
        kernel = b"\x27\x19\x4f\x19" + b"A" * 512          # fake lzma kernel head
        filler = b"B" * 1024
        inner = b"\x00" * 96 + SQFS_PAYLOAD                 # squashfs at NONZERO offset
        return [kernel, filler + inner]

    @unittest.skipUnless(MKSWITCHFS, "mksquashfs unavailable")
    def test_trx_good_locates_inner_squashfs_at_nonzero_offset(self):
        image = self.work / "fw.trx"
        image.write_bytes(build_trx(self._partitions()))
        result = trx_extract(image, self.work / "out", budget())
        self.assertEqual(result["status"], "succeeded", result["error"])
        self.assertTrue(result["crc_verified"])
        self.assertEqual(len(result["members"]), 2)
        second = result["members"][1]
        self.assertEqual(second["kind"], "squashfs")
        payload_file = self.work / "out" / second["file"]
        blob = payload_file.read_bytes()
        self.assertEqual(blob.find(SQFS_PAYLOAD[:4]) % 4, 0)
        self.assertIn(SQFS_PAYLOAD[:64], blob)
        self.assertEqual(second["inner_path"], payload_file.name)

    def test_trx_bad_magic(self):
        image = self.work / "bad.trx"
        image.write_bytes(b"XDR0" + b"\x00" * 64)
        result = trx_extract(image, self.work / "out-bad", budget())
        self.assertEqual(result["status"], "failed")
        self.assertIn("Bad TRX magic", result["error"])

    def test_trx_length_beyond_file(self):
        image = self.work / "liar.trx"
        raw = bytearray(build_trx(self._partitions()))
        struct.pack_into("<I", raw, 4, 0xFFFFFF)  # len field lies
        image.write_bytes(bytes(raw))
        result = trx_extract(image, self.work / "out-liar", budget())
        self.assertEqual(result["status"], "failed")
        self.assertIn("exceeds file size", result["error"])

    def test_trx_crc_mismatch_degrades(self):
        image = self.work / "crc.trx"
        image.write_bytes(build_trx(self._partitions(), fix_crc=False))
        result = trx_extract(image, self.work / "out-crc", budget())
        self.assertEqual(result["status"], "degraded")
        self.assertIn("CRC mismatch", result["error"])

    def test_trx_over_quota(self):
        image = self.work / "quota.trx"
        image.write_bytes(build_trx(self._partitions()))
        result = trx_extract(image, self.work / "out-quota", budget(max_unpack_bytes=256))
        self.assertEqual(result["status"], "degraded")
        self.assertIn("stopped at total unpack budget", result["error"])
        self.assertEqual(result["bytes"], 0)


# ---- OCI layout -------------------------------------------------------------

class OciLayoutTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="alane-oci-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _layers(self) -> list[bytes]:
        layer1 = tar_bytes([
            ("etc", None, "dir"),
            ("etc/banner", b"layer1\n", "file"),
            ("etc/old.conf", b"obsolete\n", "file"),
            ("bin", None, "dir"),
            ("bin/tool", b"v1\n", "file"),
        ])
        layer2 = tar_bytes([
            ("etc", None, "dir"),
            ("etc/.wh.old.conf", b"", "file"),          # whiteout removes old.conf
            ("bin/.wh..wh..opq", b"", "file"),          # opaque: clear bin/
        ])
        layer3 = tar_bytes([
            ("bin", None, "dir"),
            ("bin/tool", b"v2-final\n", "file"),
            ("etc/motd", b"welcome\n", "file"),
            ("lib", None, "dir"),
            ("lib/libc.so", b"target/lib/libc-real.so", "sym"),
        ])
        return [layer1, layer2, layer3]

    def test_oci_layout_good_merged_rootfs(self):
        image = self.work / "layout.tar"
        image.write_bytes(build_oci_layout(self._layers()))
        result = oci_layout_extract(image, self.work / "out", budget())
        self.assertEqual(result["status"], "succeeded", result.get("error"))
        self.assertEqual(len(result["layers"]), 3)
        rootfs = self.work / "out" / "rootfs"
        self.assertEqual((rootfs / "etc" / "banner").read_text(), "layer1\n")
        self.assertFalse((rootfs / "etc" / "old.conf").exists(), "whiteout must remove the file")
        self.assertEqual((rootfs / "bin" / "tool").read_text(), "v2-final\n")
        self.assertTrue((rootfs / "etc" / "motd").is_file())
        # No symlink is ever created: link members become small regular files.
        self.assertTrue((rootfs / "lib" / "libc.so").is_file())
        self.assertFalse((rootfs / "lib" / "libc.so").is_symlink())
        self.assertEqual((rootfs / "lib" / "libc.so").read_text(), "target/lib/libc-real.so")
        self.assertEqual(result["layers"][1]["whiteouts"], 2)
        self.assertGreaterEqual(result["layers"][2]["symlinks_materialized"], 1)

    def test_oci_layout_missing_marker(self):
        raw = build_oci_layout(self._layers())
        stripped = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(fileobj=stripped, mode="w") as dst:
            for member in src:
                if member.name != "oci-layout":
                    dst.addfile(member, src.extractfile(member))
        image = self.work / "nomarker.tar"
        image.write_bytes(stripped.getvalue())
        with self.assertRaises(InvalidInput):
            oci_layout_extract(image, self.work / "out-nomarker", budget())

    def test_oci_layout_missing_layer_blob(self):
        raw = build_oci_layout(self._layers())
        stripped = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(fileobj=stripped, mode="w") as dst:
            for member in src:
                if not member.name.startswith("blobs/") or member.name.endswith(manifest_digest_of(raw)):
                    dst.addfile(member, src.extractfile(member) if member.isfile() else None)
        image = self.work / "missing-layer.tar"
        image.write_bytes(stripped.getvalue())
        with self.assertRaises(InvalidInput):
            oci_layout_extract(image, self.work / "out-missing", budget())

    def test_oci_layout_layer_digest_mismatch(self):
        layers = self._layers()
        raw = build_oci_layout(layers)
        # Rewrite the LAST layer blob member in place: same blob name (same
        # declared digest), different bytes -> the manifest's digest check
        # (not the missing-blob check) must fire.
        tampered = layers[-1][:-8] + b"tampered"
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(fileobj=out, mode="w") as dst:
            for member in src:
                content = src.extractfile(member).read() if member.isfile() else None
                if content == layers[-1]:
                    member.size = len(tampered)
                    content = tampered
                dst.addfile(member, io.BytesIO(content) if content is not None else None)
        image = self.work / "tampered.tar"
        image.write_bytes(out.getvalue())
        with self.assertRaises(InvalidInput) as ctx:
            oci_layout_extract(image, self.work / "out-tamper", budget())
        self.assertIn("digest mismatch", str(ctx.exception))

    def test_oci_layout_over_quota(self):
        image = self.work / "layout.tar"
        image.write_bytes(build_oci_layout(self._layers()))
        with self.assertRaises(InvalidInput) as ctx:
            oci_layout_extract(image, self.work / "out-quota", budget(max_unpack_bytes=512))
        self.assertIn("unpack budget", str(ctx.exception))


def manifest_digest_of(raw_layout: bytes) -> str:
    with tarfile.open(fileobj=io.BytesIO(raw_layout)) as tar:
        index = json.load(tar.extractfile("index.json"))
        return index["manifests"][0]["digest"].split(":", 1)[1]


# ---- registry ---------------------------------------------------------------

class RegistryFetchTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="alane-reg-"))
        self.layers = OciLayoutTests._layers(self)

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _registry(self, manifests, blobs) -> FakeRegistry:
        reg = FakeRegistry(manifests, blobs)
        self.addCleanup(reg.stop)
        return reg

    def test_registry_pull_good(self):
        manifests, blobs = registry_payload(self.layers)
        reg = self._registry(manifests, blobs)
        result = registry_fetch("demo/app", "v1", self.work / "out", budget(), port=reg.port)
        self.assertEqual(result["status"], "succeeded", result.get("error"))
        self.assertTrue(result["manifest_digest"].startswith("sha256:"))
        rootfs = self.work / "out" / "rootfs"
        self.assertEqual((rootfs / "bin" / "tool").read_text(), "v2-final\n")
        self.assertFalse((rootfs / "etc" / "old.conf").exists())

    def test_registry_unknown_tag_404(self):
        manifests, blobs = registry_payload(self.layers)
        reg = self._registry(manifests, blobs)
        with self.assertRaises(NetworkError) as ctx:
            registry_fetch("demo/app", "missing-tag", self.work / "out-404", budget(), port=reg.port)
        self.assertIn("404", str(ctx.exception))

    def test_registry_missing_blob_404(self):
        manifests, blobs = registry_payload(self.layers)
        first_layer = json.loads(manifests["v1"])["layers"][0]["digest"].split(":", 1)[1]
        del blobs[first_layer]
        reg = self._registry(manifests, blobs)
        with self.assertRaises(NetworkError) as ctx:
            registry_fetch("demo/app", "v1", self.work / "out-noblob", budget(), port=reg.port)
        self.assertIn("404", str(ctx.exception))

    def test_registry_blob_digest_mismatch(self):
        manifests, blobs = registry_payload(self.layers)
        first_layer = json.loads(manifests["v1"])["layers"][0]["digest"].split(":", 1)[1]
        blobs[first_layer] = b"tampered-bytes"
        reg = self._registry(manifests, blobs)
        with self.assertRaises(NetworkError) as ctx:
            registry_fetch("demo/app", "v1", self.work / "out-tamper", budget(), port=reg.port)
        self.assertIn("digest mismatch", str(ctx.exception))


# ---- Ghidra adapter ---------------------------------------------------------

@unittest.skipUnless(GHIDRA and GHIDRA.is_dir(), "Ghidra home not configured (set RE_GHIDRA_HOME)")
class GhidraAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.headless = GHIDRA / "support" / "analyzeHeadless"

    def test_unconfigured_returns_none(self):
        saved = os.environ.pop("RE_RUN_GHIDRA", None)
        try:
            self.assertIsNone(configured_headless())
            self.assertIsNone(headless_decompile(BPALOGIN, Path(tempfile.mkdtemp()), budget()))
        finally:
            if saved is not None:
                os.environ["RE_RUN_GHIDRA"] = saved

    def test_missing_binary_raises(self):
        with self.assertRaises(InvalidInput):
            headless_decompile(self.make_work() / "nope.elf", self.make_work() / "out",
                               budget(), executable=str(self.headless))

    def make_work(self) -> Path:
        work = Path(tempfile.mkdtemp(prefix="alane-ghidra-"))
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        return work

    @unittest.skipUnless(BPALOGIN and BPALOGIN.is_file(), "bpalogin fixture not configured (set RE_BPALOGIN)")
    def test_real_bpalogin_functions_and_decompilation(self):
        out = self.make_work() / "out"
        result = headless_decompile(BPALOGIN, out, budget(tool_timeout_seconds=420),
                                    executable=str(self.headless), max_functions=8)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "succeeded", result.get("error"))
        self.assertGreaterEqual(result["function_count_total"], 50)
        self.assertGreaterEqual(len(result["functions"]), 8)
        self.assertGreaterEqual(len(result["decompiled"]), 1)
        code = result["decompiled"][0]["code"]
        self.assertIn("(", code)
        self.assertIn("return", code.replace("\n", " ") + "(")
        # Derived outputs folded into usage (ghidra-functions.json + scripts + work).
        self.assertGreaterEqual(result["derived_files"], 1)
        evidence = out / "ghidra-headless-run.json"
        self.assertTrue(evidence.is_file(), "redacted evidence JSON must exist")
        self.assertTrue((out / "ghidra-functions.json").is_file())

    @unittest.skipUnless(BPALOGIN and BPALOGIN.is_file(), "bpalogin fixture not configured (set RE_BPALOGIN)")
    def test_bad_input_fails_honestly(self):
        junk = self.make_work() / "junk.bin"
        junk.write_bytes(b"this is not an ELF file\n" * 10)
        result = headless_decompile(junk, self.make_work() / "out-junk",
                                    budget(tool_timeout_seconds=420),
                                    executable=str(self.headless))
        self.assertIsNotNone(result)
        self.assertIn(result["status"], ("failed", "degraded"))
        if result["status"] == "failed":
            self.assertIn("no function dump", result["error"])
        else:
            self.assertEqual(result["decompiled"], [])


if __name__ == "__main__":
    unittest.main()
