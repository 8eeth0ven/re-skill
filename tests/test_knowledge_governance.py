"""Offline knowledge-metadata contracts, not hardware or target acceptance.

Even the well-formed physical-device records below are temporary schema fixtures;
this suite proves rejection/selection/traceability rules, not their asserted origin.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("re_knowledge_validator_tests", ROOT / "scripts" / "validate_knowledge.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
TODAY = dt.date(2026, 10, 28)


def metadata(stable_id="re.fixture.article"):
    return {
        "schema": "re-knowledge/v1", "id": stable_id, "kind": "article",
        "host_platforms": ["any"], "target_platforms": ["android"],
        "target_versions": [], "last_tested": None, "confidence": "inference",
        "evidence": [{"id": "e-note", "kind": "analysis", "ref": "#rationale",
                      "provenance": "inference", "observed_at": None, "target_versions": []}],
        "claims": [{"id": "c-main", "statement": "A bounded schema-fixture hypothesis.",
                    "confidence": "inference", "evidence": ["e-note"]}],
        "review_after": "2026-12-01",
        "decay": {"mode": "event", "max_age_days": None,
                  "triggers": ["build-change"], "note": "Review only; not a measured result."},
        "related_ids": [],
    }


class KnowledgeGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-knowledge-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "library"
        self.root.mkdir()

    def write(self, name="article.md", meta=None, body=None):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = "# Fixture\n\n## Rationale\n\nOffline schema fixture only.\n" if body is None else body
        if meta is not None:
            text = VALIDATOR.MARKER + "\n" + json.dumps(meta, indent=2) + "\n-->\n\n" + text
        path.write_text(text, encoding="utf-8")
        return path

    def check(self, paths=None, strict=False, today=TODAY, **kwargs):
        return VALIDATOR.validate_library(self.root, paths, strict=strict, today=today, **kwargs)

    @staticmethod
    def codes(result):
        return {item["code"] for item in result["errors"]}

    def physical_fixture(self):
        meta = metadata()
        evidence = self.root / "evidence" / "minimal.txt"
        evidence.parent.mkdir()
        evidence.write_bytes(b"OFFLINE SCHEMA FIXTURE ONLY; no actual physical-device test.\n")
        version, observed = "fixture-build-1", "2026-10-20"
        meta.update(confidence="verified-on-device", last_tested=observed, target_versions=[version])
        meta["claims"][0]["confidence"] = "verified-on-device"
        meta["evidence"][0].update(kind="device-log", provenance="physical-device",
                                   ref="evidence/minimal.txt", observed_at=observed,
                                   target_versions=[version], sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
        return meta, evidence

    def test_legacy_discovery_remains_pending_even_in_global_strict_mode(self):
        self.write("legacy.md")
        self.write("new.md", metadata())
        result = self.check(strict=True)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["pending"], [{"path": "legacy.md", "status": "legacy-pending"}])
        self.assertEqual(result["counts"]["governed"], 1)

    def test_explicit_strict_legacy_selection_requires_metadata(self):
        self.write("legacy.md")
        self.assertIn("metadata-required", self.codes(self.check(["legacy.md"], strict=True)))
        self.assertTrue(self.check(["legacy.md"])["ok"])

    def test_source_claim_is_traceable_without_becoming_device_verification(self):
        meta = metadata()
        meta["confidence"] = meta["claims"][0]["confidence"] = "source-claimed"
        meta["evidence"][0].update(kind="source", provenance="source", ref="source.py#L1-L2")
        (self.root / "source.py").write_text("# fixture source\nVALUE = 1\n", encoding="utf-8")
        self.write(meta=meta)
        result = self.check(strict=True)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["articles"][0]["confidence"], "source-claimed")
        self.assertEqual(result["evidence_status"][0]["reexecution"], "not-attempted")

    def test_claim_cannot_reference_an_undeclared_evidence_id(self):
        meta = metadata()
        meta["claims"][0]["evidence"] = ["e-missing"]
        self.write(meta=meta)
        self.assertIn("claim-evidence-gap", self.codes(self.check()))

    def test_attributed_user_report_supports_only_a_source_claim_without_fake_dates(self):
        meta = metadata()
        meta["confidence"] = meta["claims"][0]["confidence"] = "source-claimed"
        meta["claims"][0]["statement"] = "The user reported this behavior; versions and independent reproduction are unknown."
        meta["evidence"][0].update(kind="user-report", provenance="user-report")
        self.write(meta=meta)
        result = self.check(strict=True)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["articles"][0]["confidence"], "source-claimed")
        self.assertIsNone(meta["last_tested"])
        self.assertEqual(result["evidence_status"][0]["reexecution"], "not-attempted")

    def test_an_analysis_note_cannot_be_promoted_to_a_source_claim(self):
        meta = metadata()
        meta["confidence"] = meta["claims"][0]["confidence"] = "source-claimed"
        self.write(meta=meta)
        self.assertIn("source-evidence-required", self.codes(self.check()))

    def test_verified_claim_without_date_versions_or_device_proof_is_rejected(self):
        meta = metadata()
        meta["confidence"] = meta["claims"][0]["confidence"] = "verified-on-device"
        self.write(meta=meta)
        self.assertTrue({"verified-scope-required", "device-proof-required"} <= self.codes(self.check(strict=True)))

    def test_source_emulator_and_user_report_cannot_upgrade_to_physical_verification(self):
        for kind, provenance in (("source", "source"), ("device-log", "emulator"), ("user-report", "user-report")):
            with self.subTest(kind=kind, provenance=provenance):
                meta, _ = self.physical_fixture_once()
                meta["evidence"][0].update(kind=kind, provenance=provenance)
                self.write(meta=meta)
                self.assertIn("device-proof-required", self.codes(self.check(strict=True)))

    def physical_fixture_once(self):
        # Reuse one temporary evidence attachment across table-driven subtests.
        path = self.root / "evidence" / "minimal.txt"
        if path.exists():
            path.unlink()
            path.parent.rmdir()
        return self.physical_fixture()

    def test_well_formed_physical_record_validates_only_its_schema_and_hash(self):
        meta, _ = self.physical_fixture()
        self.write(meta=meta)
        result = self.check(strict=True)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["evidence_status"][0]["availability"], "available")
        self.assertEqual(result["evidence_status"][0]["reexecution"], "not-attempted")

    def test_missing_historical_attachment_degrades_without_rewriting_claim(self):
        meta, attachment = self.physical_fixture()
        article = self.write(meta=meta)
        before = article.read_bytes()
        attachment.unlink()
        result = self.check()
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["articles"][0]["confidence"], "verified-on-device")
        self.assertEqual(result["evidence_status"][0]["availability"], "unavailable")
        self.assertEqual(article.read_bytes(), before)
        self.assertIn("evidence-unavailable", self.codes(self.check(["article.md"], strict=True)))

    def test_changed_evidence_hash_is_degraded_normally_and_rejected_strictly(self):
        meta, attachment = self.physical_fixture()
        self.write(meta=meta)
        attachment.write_bytes(b"altered fixture")
        result = self.check()
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["evidence_status"][0]["availability"], "hash-mismatch")
        self.assertIn("evidence-hash-mismatch", self.codes(self.check(strict=True)))

    def test_verified_proof_needs_matching_date_version_and_digest(self):
        for change in ("date", "version", "digest"):
            with self.subTest(change=change):
                meta, _ = self.physical_fixture_once()
                if change == "date":
                    meta["evidence"][0]["observed_at"] = "2026-10-19"
                elif change == "version":
                    meta["evidence"][0]["target_versions"] = ["different-build"]
                else:
                    del meta["evidence"][0]["sha256"]
                self.write(meta=meta)
                self.assertIn("device-proof-required", self.codes(self.check(strict=True)))

    def test_duplicate_stable_id_is_found_outside_the_selected_file(self):
        self.write("one.md", metadata())
        self.write("other/two.md", metadata())
        result = self.check(["one.md"], strict=True)
        self.assertIn("duplicate-stable-id", self.codes(result))
        self.assertEqual(len(result["articles"]), 1)
        self.assertFalse(result["articles"][0]["valid"])

    def test_relative_reference_cannot_escape_the_declared_root(self):
        (self.parent / "private.txt").write_text("not library evidence", encoding="utf-8")
        meta = metadata()
        meta["evidence"][0]["ref"] = "../private.txt"
        self.write(meta=meta)
        self.assertIn("reference-outside-root", self.codes(self.check(strict=True)))

    def test_absolute_machine_path_is_not_portable_even_inside_root(self):
        target = self.root / "private.txt"
        target.write_text("fixture", encoding="utf-8")
        meta = metadata()
        meta["evidence"][0]["ref"] = str(target)
        self.write(meta=meta)
        self.assertIn("nonportable-reference", self.codes(self.check(strict=True)))

    def test_symlink_cannot_hide_an_outside_evidence_path(self):
        outside = self.parent / "outside.txt"
        outside.write_text("private fixture", encoding="utf-8")
        try:
            (self.root / "alias.txt").symlink_to(outside)
        except OSError:
            self.skipTest("host forbids symlink creation")
        meta = metadata()
        meta["evidence"][0]["ref"] = "alias.txt"
        self.write(meta=meta)
        self.assertIn("reference-outside-root", self.codes(self.check(strict=True)))

    def test_source_anchor_and_body_routes_are_checked(self):
        meta = metadata()
        self.write(meta=meta, body="# Fixture\n\n## Rationale\n\n[broken](missing.md)\n")
        self.assertIn("missing-local-reference", self.codes(self.check()))
        meta["evidence"][0]["ref"] = "#no-such-heading"
        self.write(meta=meta)
        self.assertIn("missing-reference-anchor", self.codes(self.check()))

    def test_reference_style_links_and_images_cannot_hide_missing_targets(self):
        bodies = (
            "[read][guide]\n\n[guide]: missing.md\n",
            "[guide][]\n\n[guide]: missing.md\n",
            "[guide]\n\n[guide]: missing.md\n",
            "![preview][image]\n\n[image]: missing.png\n",
        )
        for route in bodies:
            with self.subTest(route=route):
                self.write(meta=metadata(), body="# Fixture\n\n## Rationale\n\n" + route)
                self.assertIn("missing-local-reference", self.codes(self.check(strict=True)))

    def test_html_image_resources_are_checked_with_a_real_local_positive_control(self):
        assets = self.root / "assets"
        assets.mkdir()
        (assets / "present.png").write_bytes(b"schema-fixture-image-bytes")
        self.write(meta=metadata(), body='# Fixture\n\n## Rationale\n\n<img src="assets/present.png" alt="fixture">\n')
        self.assertTrue(self.check(strict=True)["ok"])
        self.write(meta=metadata(), body='# Fixture\n\n## Rationale\n\n<img src="assets/missing.png" alt="fixture">\n')
        self.assertIn("missing-local-reference", self.codes(self.check(strict=True)))

    def test_reference_routes_in_code_examples_are_not_live_dependencies(self):
        body = '# Fixture\n\n## Rationale\n\n```markdown\n[x][id]\n[id]: missing.md\n<img src="missing.png">\n```\n'
        self.write(meta=metadata(), body=body)
        self.assertTrue(self.check(strict=True)["ok"])

    def test_related_stable_ids_are_routed_without_loading_legacy_bodies(self):
        meta = metadata()
        meta["related_ids"] = ["re.fixture.related"]
        self.write(meta=meta)
        self.assertIn("unknown-related-id", self.codes(self.check()))
        self.write("related.md", metadata("re.fixture.related"))
        self.write("legacy.md", body="# Existing article\n")
        self.assertTrue(self.check(["article.md"], strict=True)["ok"])

    def test_review_due_uses_an_injected_clock_and_actual_claim_age(self):
        meta = metadata()
        meta["last_tested"] = "2026-09-28"
        meta["decay"].update(mode="time", max_age_days=30)
        self.write(meta=meta)
        self.assertFalse(self.check(today=dt.date(2026, 10, 27))["review_due"])
        result = self.check(today=TODAY)
        self.assertEqual(len(result["review_due"]), 1)
        self.assertTrue(all(x["due_on"] == "2026-10-28" for x in result["review_due"][0]["items"]))

    def test_invalid_and_future_observation_dates_are_rejected(self):
        for date, code in (("2026-02-30", "date-format"), ("20261020", "date-format"), ("2026-10-29", "future-observation")):
            with self.subTest(date=date):
                meta = metadata()
                meta["last_tested"] = date
                self.write(meta=meta)
                self.assertIn(code, self.codes(self.check()))

    def test_mixed_article_must_not_overstate_its_weakest_claim(self):
        meta, _ = self.physical_fixture()
        meta["claims"].append({"id": "c-guess", "statement": "An untested extension.",
                                "confidence": "inference", "evidence": ["e-note"]})
        self.write(meta=meta)
        self.assertIn("article-confidence-overstatement", self.codes(self.check(strict=True)))
        meta["confidence"] = "inference"
        self.write(meta=meta)
        self.assertTrue(self.check(strict=True)["ok"])

    def test_dossier_status_and_claim_routes_need_their_actual_proof(self):
        meta = metadata()
        meta["kind"] = "variant-dossier"
        meta["variants"] = [{"id": "v-one", "status": "verified-on-device", "claim_ids": ["c-main"]}]
        self.write(meta=meta)
        self.assertIn("variant-proof-required", self.codes(self.check()))
        meta["variants"][0].update(status="unassessed", claim_ids=["c-missing"])
        self.write(meta=meta)
        self.assertIn("variant-claim-gap", self.codes(self.check()))

    def test_duplicate_json_keys_unknown_fields_and_invalid_enums_fail_honestly(self):
        article = self.write(meta=metadata())
        text = article.read_text().replace('"schema": "re-knowledge/v1",', '"schema": "re-knowledge/v1", "schema": "other",', 1)
        article.write_text(text)
        self.assertIn("metadata-json", self.codes(self.check()))
        for field, value, expected in (("confidence", [], "confidence-enum"), ("kind", {}, "document-kind"), ("invented", True, "unknown-field")):
            with self.subTest(field=field):
                meta = metadata()
                meta[field] = value
                self.write(meta=meta)
                self.assertIn(expected, self.codes(self.check()))

    def test_local_evidence_and_claim_labels_can_use_uppercase_without_weakening_stable_ids(self):
        meta = metadata()
        meta["evidence"][0]["id"] = "E1"
        meta["claims"][0].update(id="C1", evidence=["E1"])
        meta.update(kind="variant-dossier", variants=[{"id": "V1", "status": "unassessed", "claim_ids": ["C1"]}])
        self.write(meta=meta)
        self.assertTrue(self.check(strict=True)["ok"])
        meta["id"] = "RE.Fixture"
        self.write(meta=meta)
        self.assertIn("invalid-id", self.codes(self.check()))

    def test_invalid_nested_metadata_reports_errors_instead_of_crashing(self):
        for change in ("decay", "evidence", "claim", "variant", "age"):
            with self.subTest(change=change):
                meta = metadata()
                if change == "decay":
                    meta["decay"]["mode"] = []
                elif change == "evidence":
                    meta["evidence"][0].update(kind=[], provenance={})
                elif change == "claim":
                    meta["claims"][0]["confidence"] = {}
                elif change == "variant":
                    meta.update(kind="variant-dossier", variants=[{"id": "v1", "status": {}, "claim_ids": ["c-main"]}])
                else:
                    meta["last_tested"] = "2026-10-01"
                    meta["decay"].update(mode="time", max_age_days=10 ** 100)
                self.write(meta=meta)
                self.assertFalse(self.check()["ok"])

    def test_threshold_value_labels_are_explicit_enum_contracts(self):
        meta = metadata()
        for label in ("measured", "example", "policy"):
            meta["claims"][0]["value_kind"] = label
            self.write(meta=meta)
            self.assertTrue(self.check()["ok"])
        meta["claims"][0]["value_kind"] = "probably-fast"
        self.write(meta=meta)
        self.assertIn("claim-value-kind", self.codes(self.check()))

    def test_digest_byte_limit_refuses_large_proof_without_reading_it_as_text(self):
        meta, _ = self.physical_fixture()
        self.write(meta=meta)
        self.assertIn("evidence-too-large", self.codes(self.check(strict=True, max_evidence_bytes=4)))

    def test_cli_review_queue_is_offline_and_legacy_does_not_break_a_clone(self):
        meta = metadata()
        meta["review_after"] = "2026-10-28"
        self.write(meta=meta)
        self.write("legacy.md")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / "validate_knowledge.py"),
             "--root", str(self.root), "--strict", "--review-due", "--today", "2026-10-28", "--json"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["counts"]["legacy_pending"], 1)
        self.assertEqual(report["review_due"][0]["id"], meta["id"])
        self.assertEqual(report["evidence_status"][0]["reexecution"], "not-attempted")

    def _unicode_cli_fixture(self, name, valid):
        meta = metadata()
        meta["target_platforms"] = ["安卓"]
        meta["review_after"] = TODAY.isoformat()
        if not valid:
            meta["confidence"] = "unsupported"
        article = self.write(f"审计-{name}/证据.md", meta=meta)
        return article.parent, article.name

    def test_cli_json_redirected_to_cp1252_preserves_unicode_paths_and_exit_codes(self):
        for valid in (True, False):
            with self.subTest(valid=valid):
                directory, filename = self._unicode_cli_fixture(f"json-{valid}", valid)
                result = subprocess.run(
                    [sys.executable, "-B", str(ROOT / "scripts" / "validate_knowledge.py"),
                     "--root", str(directory), "--strict", "--today", TODAY.isoformat(), "--json"],
                    env={**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONDONTWRITEBYTECODE": "1"},
                    capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0 if valid else 1, result.stderr.decode("cp1252", errors="replace"))
                self.assertNotIn(b"Traceback", result.stderr)
                report = json.loads(result.stdout.decode("ascii"))
                self.assertEqual(report["root"], str(directory.resolve()))
                self.assertEqual(report["articles"][0]["path"], filename)
                self.assertEqual(report["articles"][0]["target_platforms"], ["安卓"])
                self.assertEqual(report["ok"], valid)

    def test_cli_plain_cp1252_falls_back_but_utf8_keeps_unicode_and_exit_codes(self):
        for encoding in ("cp1252", "utf-8"):
            for valid in (True, False):
                with self.subTest(encoding=encoding, valid=valid):
                    directory, filename = self._unicode_cli_fixture(f"plain-{encoding}-{valid}", valid)
                    result = subprocess.run(
                        [sys.executable, "-B", str(ROOT / "scripts" / "validate_knowledge.py"),
                         "--root", str(directory), "--strict", "--review-due", "--today", TODAY.isoformat()],
                        env={**os.environ, "PYTHONIOENCODING": encoding, "PYTHONDONTWRITEBYTECODE": "1"},
                        capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0 if valid else 1, result.stderr.decode(encoding, errors="replace"))
                    self.assertNotIn(b"Traceback", result.stderr)
                    text = result.stdout.decode(encoding)
                    displayed = filename.encode(encoding, errors="backslashreplace").decode(encoding)
                    self.assertIn(displayed, text)
                    self.assertIn("REVIEW", text)
                    if not valid:
                        self.assertIn("confidence-enum", text)
                    if encoding == "utf-8":
                        self.assertIn(filename, text)

    def test_public_pilots_and_templates_have_no_fabricated_device_claims(self):
        result = VALIDATOR.validate_library(ROOT, ["examples/knowledge", "templates"], strict=True, today=TODAY)
        self.assertTrue(result["ok"], result["errors"])
        expected = {
            "re.example.offline-intake", "re.example.format-boundaries", "re.example.archive-variants",
            "re.template.article", "re.template.variant-dossier",
        }
        by_id = {article["id"]: article for article in result["articles"]}
        self.assertTrue(expected <= by_id.keys())
        self.assertTrue(all(by_id[stable]["confidence"] in {"inference", "source-claimed"} for stable in expected))


if __name__ == "__main__":
    unittest.main()
