#!/usr/bin/env python3
"""Validate opt-in RE knowledge metadata and produce a manual review queue.

Standard library only. No imports of target/analysis tools, network requests,
article execution, metadata rewriting, or scheduler creation are performed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

SCHEMA = "re-knowledge/v1"
MARKER = "<!-- re-knowledge-metadata"
CONFIDENCE = {"verified-on-device", "source-claimed", "inference"}
RANK = {"inference": 0, "source-claimed": 1, "verified-on-device": 2}
KINDS = {"article", "variant-dossier"}
PROVENANCE = {
    "device-log": {"physical-device", "emulator"},
    "source": {"source"},
    "offline-test": {"offline"},
    "analysis": {"inference"},
    "historical": {"historical"},
    "user-report": {"user-report"},
}
OBSERVATION_MODES = {"host", "fixture", "mock"}
VARIANT_STATES = {"unassessed", "documented", "verified-on-device", "not-reproduced", "blocked", "retired"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "data", "tools-env", "re-runs", "__pycache__", "环境快照", "输出"}
HEADER_LIMIT = 65536
ARTICLE_LIMIT = 4 * 1024 * 1024
EVIDENCE_LIMIT = 16 * 1024 * 1024
ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
LOCAL_ID = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
ROOT_FIELDS = {
    "schema", "id", "kind", "host_platforms", "target_platforms", "target_versions",
    "last_tested", "confidence", "evidence", "claims", "review_after", "decay",
    "related_ids", "variants",
}
ROOT_REQUIRED = ROOT_FIELDS - {"related_ids", "variants"}
CLAIM_FIELDS = {"id", "statement", "confidence", "evidence", "last_tested", "target_versions", "value_kind"}
EVIDENCE_FIELDS = {"id", "kind", "ref", "provenance", "observed_at", "target_versions", "sha256", "observation_mode"}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_header(path: Path):
    """Return (metadata, error). No marker means legacy, not a broken draft."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(HEADER_LIMIT + 1)
    except OSError as exc:
        return None, f"Cannot read document: {type(exc).__name__}"
    text = raw.decode("utf-8-sig", errors="replace")
    if not text.lstrip().startswith(MARKER):
        return None, None
    match = re.match(r"\A\s*<!-- re-knowledge-metadata\s*\r?\n(.*?)\r?\n-->(?:\r?\n|$)", text, re.S)
    if not match:
        return None, "Metadata must be a complete first comment block within 64 KiB"
    try:
        value = json.loads(match.group(1), object_pairs_hook=_object,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Nonfinite JSON: {value}")))
    except (ValueError, TypeError) as exc:
        return None, str(exc)
    if not isinstance(value, dict):
        return None, "Metadata JSON must be an object"
    return value, None


def headings(text: str):
    result, counts, fence = set(), Counter(), None
    for line in text.splitlines():
        token = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if token:
            mark, tail = token.groups()
            if fence is None:
                fence = mark
            elif mark[0] == fence[0] and len(mark) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence:
            continue
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*$", line)
        if match:
            title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", match.group(1)).replace("`", "").lower()
            title = re.sub(r"<[^>]*>", "", title)
            slug = "".join(c for c in title if c.isalnum() or c in "_- ").replace(" ", "-")
            result.add(slug + (f"-{counts[slug]}" if counts[slug] else ""))
            counts[slug] += 1
    return result


# Load the one owned stdlib route parser by file path. This works both for CLI
# execution and importlib.spec_from_file_location consumers without sys.path edits.
_ROUTE_SPEC = importlib.util.spec_from_file_location(
    "re_knowledge_markdown_routes", Path(__file__).with_name("markdown_routes.py")
)
_ROUTE_MODULE = importlib.util.module_from_spec(_ROUTE_SPEC)
sys.modules[_ROUTE_SPEC.name] = _ROUTE_MODULE
_ROUTE_SPEC.loader.exec_module(_ROUTE_MODULE)


def body_links(text: str):
    return _ROUTE_MODULE.extract_routes(text)


def _concrete(versions):
    excluded = {"unknown", "unspecified", "unverified", "not-tested", "not-applicable", "latest", "any", "n/a", "pending", "*"}
    return bool(versions) and all(v.strip().lower() not in excluded and not re.search(r"[<>=~^*]|\.x\b", v) for v in versions)


class Checker:
    def __init__(self, root, today, strict=False, max_evidence_bytes=EVIDENCE_LIMIT):
        self.root, self.today, self.strict = root, today, strict
        self.max_evidence_bytes = max_evidence_bytes
        self.errors, self.warnings, self.evidence_status = [], [], []
        self._text = {}

    def display(self, path):
        try:
            return Path(path).relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def issue(self, code, path, message, field=None, warning=False):
        item = {"code": code, "path": self.display(path), "message": message}
        if field:
            item["field"] = field
        (self.warnings if warning else self.errors).append(item)

    def shape(self, value, required, allowed, path, field):
        if not isinstance(value, dict):
            self.issue("object-required", path, "Expected an object", field)
            return False
        for name in sorted(required - value.keys()):
            self.issue("missing-field", path, f"Required field: {name}", f"{field}.{name}")
        for name in sorted(value.keys() - allowed):
            self.issue("unknown-field", path, f"Unsupported field: {name}", f"{field}.{name}")
        return True

    def strings(self, value, path, field, nonempty=False):
        if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
            self.issue("string-list-required", path, "Expected a list of nonempty strings", field)
            return []
        if nonempty and not value:
            self.issue("empty-list", path, "At least one value is required", field)
        if len(value) != len(set(value)):
            self.issue("duplicate-value", path, "Repeated list value", field)
        return value

    def identifier(self, value, path, field):
        pattern = ID if field == "id" else LOCAL_ID
        if not isinstance(value, str) or len(value) > 128 or not pattern.fullmatch(value):
            self.issue("invalid-id", path, "Use an identifier of at most 128 characters; article ids are lowercase", field)
            return None
        return value

    def date(self, value, path, field, nullable=False, observed=False):
        if value is None and nullable:
            return None
        try:
            if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                raise ValueError
            parsed = dt.date.fromisoformat(value)
        except ValueError:
            self.issue("date-format", path, "Expected a real YYYY-MM-DD calendar date" + (" or null" if nullable else ""), field)
            return None
        if observed and parsed > self.today:
            self.issue("future-observation", path, "An observation/test date cannot be in the future", field)
        return parsed

    def text(self, path):
        if path not in self._text:
            if path.stat().st_size > ARTICLE_LIMIT:
                raise ValueError("Reference exceeds 4 MiB; use a bounded evidence excerpt")
            self._text[path] = path.read_text(encoding="utf-8-sig")
        return self._text[path]

    def reference(self, ref, owner, field, evidence=False, digest=None):
        """Separate availability from claim confidence; never execute a reference."""
        result = {"availability": "invalid", "local": False, "reexecution": "not-attempted"}
        if not isinstance(ref, str) or not ref.strip():
            self.issue("reference-required", owner, "A traceable reference is required", field)
            return result
        try:
            url = urlsplit(ref)
        except ValueError:
            self.issue("invalid-reference", owner, "Malformed reference", field)
            return result
        if url.scheme or url.netloc:
            if url.scheme not in {"http", "https"} or not url.netloc or url.username or url.password:
                self.issue("invalid-reference", owner, "Use a credential-free HTTP(S) source or a portable relative file reference", field)
                return result
            result["availability"] = "external-unchecked"
            return result
        decoded = unquote(url.path)
        if "\\" in decoded or Path(decoded).is_absolute() or url.query:
            self.issue("nonportable-reference", owner, "Local references must be relative POSIX paths without a query", field)
            return result
        try:
            target = (owner.parent / decoded).resolve() if decoded else owner
            if not target.is_relative_to(self.root):
                self.issue("reference-outside-root", owner, "Reference escapes the declared library/workspace root", field)
                return result
            result["local"] = True
            result["path"] = self.display(target)
            if not target.is_file():
                result["availability"] = "unavailable"
                self.issue("evidence-unavailable" if evidence else "missing-local-reference", owner,
                           f"Local reference is unavailable: {ref}", field,
                           warning=evidence and not self.strict)
                return result
            if url.fragment:
                fragment = unquote(url.fragment)
                if target.suffix.lower() == ".md":
                    valid = fragment in headings(self.text(target))
                else:
                    line = re.fullmatch(r"L(\d+)(?:-L?(\d+))?", fragment)
                    valid = bool(line) and 1 <= int(line.group(1)) <= int(line.group(2) or line.group(1)) <= len(self.text(target).splitlines())
                if not valid:
                    self.issue("missing-reference-anchor", owner, f"Reference anchor is absent: {ref}", field)
                    return result
            result["availability"] = "available"
            if digest is not None:
                if target.stat().st_size > self.max_evidence_bytes:
                    result["availability"] = "unavailable"
                    self.issue("evidence-too-large", owner, "Use a minimal redacted evidence attachment within the configured byte limit", field, warning=not self.strict)
                    return result
                value = hashlib.sha256()
                total = 0
                with target.open("rb") as stream:
                    for block in iter(lambda: stream.read(65536), b""):
                        total += len(block)
                        if total > self.max_evidence_bytes:
                            raise ValueError("Evidence grew beyond the configured byte limit")
                        value.update(block)
                if value.hexdigest() != digest:
                    result["availability"] = "hash-mismatch"
                    self.issue("evidence-hash-mismatch", owner, "Evidence bytes differ from the recorded digest; the historical claim is preserved", field, warning=not self.strict)
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            result["availability"] = "unavailable"
            self.issue("evidence-unavailable" if evidence else "unreadable-reference", owner, str(exc), field, warning=evidence and not self.strict)
        return result

    def document(self, path, meta, registry):
        start = len(self.errors)
        self.shape(meta, ROOT_REQUIRED, ROOT_FIELDS, path, "metadata")
        stable_id = self.identifier(meta.get("id"), path, "id")
        if meta.get("schema") != SCHEMA:
            self.issue("schema-version", path, f"Expected schema {SCHEMA}", "schema")
        if not isinstance(meta.get("kind"), str) or meta.get("kind") not in KINDS:
            self.issue("document-kind", path, "Expected article or variant-dossier", "kind")
        host = self.strings(meta.get("host_platforms"), path, "host_platforms", True)
        target = self.strings(meta.get("target_platforms"), path, "target_platforms", True)
        versions = self.strings(meta.get("target_versions"), path, "target_versions")
        tested = self.date(meta.get("last_tested"), path, "last_tested", True, True)
        confidence = meta.get("confidence")
        if not isinstance(confidence, str) or confidence not in CONFIDENCE:
            self.issue("confidence-enum", path, "Confidence must be verified-on-device, source-claimed, or inference", "confidence")
        review = self.date(meta.get("review_after"), path, "review_after")
        decay = meta.get("decay")
        age = None
        if self.shape(decay, {"mode", "max_age_days", "triggers", "note"}, {"mode", "max_age_days", "triggers", "note"}, path, "decay"):
            mode, age = decay.get("mode"), decay.get("max_age_days")
            if not isinstance(mode, str) or mode not in {"time", "version", "event", "none"}:
                self.issue("decay-mode", path, "Unknown decay mode", "decay.mode")
            if age is not None and (type(age) is not int or age < 1):
                self.issue("decay-age", path, "max_age_days must be a positive integer or null", "decay.max_age_days")
                age = None
            triggers = self.strings(decay.get("triggers"), path, "decay.triggers")
            if mode == "time" and age is None:
                self.issue("decay-age", path, "Time decay requires max_age_days", "decay.max_age_days")
            if isinstance(mode, str) and mode in {"version", "event"} and not triggers:
                self.issue("decay-trigger", path, "Version/event decay needs an explicit reopening trigger", "decay.triggers")
            if mode == "none" and (age is not None or triggers):
                self.issue("decay-none", path, "None decay has no age or triggers; explain it in note", "decay")
            if not isinstance(decay.get("note"), str) or not decay["note"].strip():
                self.issue("decay-note", path, "Explain what becomes stale and what remains historical evidence", "decay.note")
        evidence, evs = {}, meta.get("evidence")
        if not isinstance(evs, list):
            self.issue("evidence-list", path, "evidence must be a list", "evidence")
            evs = []
        for index, ev in enumerate(evs):
            field = f"evidence[{index}]"
            if not self.shape(ev, EVIDENCE_FIELDS - {"sha256", "observation_mode"}, EVIDENCE_FIELDS, path, field):
                continue
            eid = self.identifier(ev.get("id"), path, field + ".id")
            if eid in evidence:
                self.issue("duplicate-evidence-id", path, "Evidence ids are unique within an article", field)
            kind = ev.get("kind")
            if not isinstance(kind, str) or kind not in PROVENANCE or not isinstance(ev.get("provenance"), str) or ev.get("provenance") not in PROVENANCE.get(kind, set()):
                self.issue("evidence-provenance", path, "Evidence kind and provenance do not agree", field)
            mode = ev.get("observation_mode", "unspecified") if kind == "offline-test" else None
            if "observation_mode" in ev:
                if kind != "offline-test":
                    self.issue("observation-mode-kind", path, "observation_mode is only defined for offline-test evidence", field + ".observation_mode")
                elif not isinstance(mode, str) or mode not in OBSERVATION_MODES:
                    self.issue("observation-mode", path, "Explicit observation_mode must be host, fixture, or mock; omit it for legacy unspecified evidence", field + ".observation_mode")
            date = self.date(ev.get("observed_at"), path, field + ".observed_at", True, True)
            ev_versions = self.strings(ev.get("target_versions"), path, field + ".target_versions")
            digest = ev.get("sha256")
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                self.issue("evidence-digest", path, "sha256 must be 64 lowercase hexadecimal characters", field + ".sha256")
                digest = None
            access = self.reference(ev.get("ref"), path, field + ".ref", True, digest)
            self.evidence_status.append({"article_id": stable_id, "evidence_id": eid, "kind": kind,
                                         "provenance": ev.get("provenance"), "observation_mode": mode,
                                         **access, "claim_confidence_preserved": True})
            if eid:
                evidence[eid] = {**ev, "observation_mode": mode, "date": date, "versions": ev_versions,
                                 "access": access, "digest_valid": bool(digest)}
        claims, cs = {}, meta.get("claims")
        if not isinstance(cs, list) or not cs:
            self.issue("claims-required", path, "Declare at least one bounded claim with evidence ids", "claims")
            cs = []
        for index, claim in enumerate(cs):
            field = f"claims[{index}]"
            if not self.shape(claim, {"id", "statement", "evidence"}, CLAIM_FIELDS, path, field):
                continue
            cid = self.identifier(claim.get("id"), path, field + ".id")
            if cid in claims:
                self.issue("duplicate-claim-id", path, "Claim ids are unique within an article", field)
            if not isinstance(claim.get("statement"), str) or not claim["statement"].strip():
                self.issue("claim-statement", path, "State the bounded assertion being supported", field + ".statement")
            cc = claim.get("confidence", confidence)
            if not isinstance(cc, str) or cc not in CONFIDENCE:
                self.issue("confidence-enum", path, "Unknown claim confidence", field + ".confidence")
            value_kind = claim.get("value_kind")
            if "value_kind" in claim and (not isinstance(value_kind, str) or value_kind not in {"measured", "example", "policy"}):
                self.issue("claim-value-kind", path, "Explicit thresholds/values use measured, example, or policy", field + ".value_kind")
            refs = self.strings(claim.get("evidence"), path, field + ".evidence", True)
            missing = [ref for ref in refs if ref not in evidence]
            if missing:
                self.issue("claim-evidence-gap", path, "Unknown evidence ids: " + ", ".join(missing), field)
            sources = [evidence[ref] for ref in refs if ref in evidence]
            cv = self.strings(claim["target_versions"], path, field + ".target_versions") if "target_versions" in claim else versions
            ct = self.date(claim["last_tested"], path, field + ".last_tested", True, True) if "last_tested" in claim else tested
            if cc == "source-claimed":
                attributed = any(isinstance(ev.get("kind"), str) and ev.get("kind") in {"source", "historical", "user-report"} for ev in sources)
                # Confidence and observation domain are separate. A portable dated
                # offline record can support its bounded observation, including a
                # fixture/mock result, without claiming physical-device behavior.
                # Availability is checked by reference(): normal review preserves
                # an honest historical claim as degraded; strict review rejects it.
                recorded = any(ev.get("kind") == "offline-test" and ev.get("provenance") == "offline"
                               and isinstance(ev.get("observation_mode"), str) and ev["observation_mode"] in OBSERVATION_MODES
                               and ct is not None and ev["date"] == ct
                               and ev["access"]["local"] and ev["digest_valid"] for ev in sources)
                if not attributed and not recorded:
                    code = "offline-observation-required" if any(ev.get("kind") == "offline-test" for ev in sources) else "source-evidence-required"
                    self.issue(code, path, "Source-claimed needs an attributed source/historical/user record, or an offline-test observation with explicit host/fixture/mock mode, matching test date and portable local SHA-256 proof", field)
            if cc == "verified-on-device":
                if ct is None or not _concrete(cv) or not target or any(p in {"any", "unspecified"} for p in target):
                    self.issue("verified-scope-required", path, "Device verification requires a test date, concrete versions and bounded target platforms", field)
                proof = [ev for ev in sources if ev.get("kind") == "device-log" and ev.get("provenance") == "physical-device" and ev["date"] == ct and _concrete(ev["versions"]) and set(cv) <= set(ev["versions"]) and ev["access"]["local"] and ev["digest_valid"]]
                if not proof:
                    self.issue("device-proof-required", path, "Require a matching physical-device evidence attachment, date, versions and SHA-256; source/user/emulator/offline evidence cannot upgrade this claim", field)
            if isinstance(confidence, str) and isinstance(cc, str) and RANK.get(confidence, 0) > RANK.get(cc, 0):
                self.issue("article-confidence-overstatement", path, "Mixed articles default to inference; higher confidence belongs to explicit supported claims", field)
            if cid:
                claims[cid] = {"confidence": cc, "last_tested": ct}
        if meta.get("kind") == "variant-dossier":
            variants = meta.get("variants")
            if not isinstance(variants, list) or not variants:
                self.issue("variants-required", path, "A dossier needs at least one explicit variant record", "variants")
                variants = []
            ids = set()
            for index, variant in enumerate(variants):
                field = f"variants[{index}]"
                if not self.shape(variant, {"id", "status", "claim_ids"}, {"id", "status", "claim_ids"}, path, field):
                    continue
                vid = self.identifier(variant.get("id"), path, field + ".id")
                if vid in ids:
                    self.issue("duplicate-variant-id", path, "Repeated variant id", field)
                ids.add(vid)
                refs = self.strings(variant.get("claim_ids"), path, field + ".claim_ids", True)
                if any(ref not in claims for ref in refs):
                    self.issue("variant-claim-gap", path, "Variant references an undeclared claim", field)
                if not isinstance(variant.get("status"), str) or variant.get("status") not in VARIANT_STATES:
                    self.issue("variant-status", path, "Unknown variant status", field)
                if variant.get("status") == "verified-on-device" and not any(claims.get(ref, {}).get("confidence") == "verified-on-device" for ref in refs):
                    self.issue("variant-proof-required", path, "Verified variant status requires an explicitly verified claim", field)
        elif "variants" in meta:
            self.issue("unexpected-variants", path, "Use kind variant-dossier for variant records", "variants")
        related = self.strings(meta.get("related_ids", []), path, "related_ids")
        for ref in related:
            if ref not in registry:
                self.issue("unknown-related-id", path, f"No metadata article with stable id {ref}", "related_ids")
        try:
            # A visible citation to an already checked evidence reference retains
            # that reference's strict/degraded policy rather than becoming a new
            # hard body-route error during historical review.
            evidence_refs = {ev.get("ref") for ev in evidence.values() if isinstance(ev.get("ref"), str)}
            for number, ref in body_links(self.text(path)):
                if ref not in evidence_refs and not urlsplit(ref).scheme and not urlsplit(ref).netloc:
                    self.reference(ref, path, f"body:{number}")
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            self.issue("document-body", path, str(exc))
        due = []
        if review is not None and review <= self.today:
            due.append({"due_on": review.isoformat(), "reason": "review_after reached", "claim_id": None})
        if age:
            dated = [(None, tested)] + [(cid, value["last_tested"]) for cid, value in claims.items()]
            for cid, date in dated:
                if date:
                    try:
                        expires = date + dt.timedelta(days=age)
                    except OverflowError:
                        self.issue("decay-age-overflow", path, "max_age_days exceeds the calendar range", "decay.max_age_days")
                        continue
                    if expires <= self.today:
                        due.append({"due_on": expires.isoformat(), "reason": "max_age_days reached", "claim_id": cid})
        return {"path": self.display(path), "id": stable_id, "kind": meta.get("kind"), "confidence": confidence,
                "host_platforms": host, "target_platforms": target, "claims": list(claims),
                "review_after": meta.get("review_after"), "valid": len(self.errors) == start, "due": due}


def markdown_files(root):
    found = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not Path(directory, d).is_symlink())
        for name in sorted(files):
            path = Path(directory, name)
            if path.suffix.lower() == ".md":
                try:
                    resolved = path.resolve()
                    if resolved.is_relative_to(root) and resolved.is_file():
                        found.add(resolved)
                except (OSError, ValueError, RuntimeError):
                    continue
    return sorted(found)


def validate_library(root, paths=None, *, strict=False, today=None, max_evidence_bytes=EVIDENCE_LIMIT):
    root = Path(root).resolve()
    today = today or dt.date.today()
    check = Checker(root, today, strict, max_evidence_bytes)
    report = {"schema": SCHEMA, "root": str(root), "today": today.isoformat(), "strict": strict,
              "selection": "explicit" if paths else "discovered", "articles": [], "pending": [], "review_due": []}
    if not root.is_dir():
        check.issue("root-unavailable", root, "The declared root must be an existing directory")
        all_paths, selected = [], set()
    else:
        all_paths = markdown_files(root)
        selected = set(all_paths) if not paths else set()
        for value in paths or []:
            try:
                path = Path(value)
                path = (root / path).resolve() if not path.is_absolute() else path.resolve()
            except (OSError, ValueError, RuntimeError) as exc:
                check.issue("selected-path-unavailable", root, f"Cannot resolve selected path: {type(exc).__name__}")
                continue
            if not path.is_relative_to(root):
                check.issue("selected-path-outside-root", path, "Selected files must be inside --root")
            elif path.is_dir():
                selected.update(markdown_files(path))
            elif path.is_file() and path.suffix.lower() == ".md":
                selected.add(path)
            else:
                check.issue("selected-path-unavailable", path, "Select an existing Markdown file or directory")
    headers = {path: read_header(path) for path in sorted(set(all_paths) | selected)}
    registry = defaultdict(list)
    for path, (meta, _) in headers.items():
        if meta and isinstance(meta.get("id"), str):
            registry[meta["id"]].append(path)
    for path in sorted(selected):
        meta, error = headers[path]
        if error:
            check.issue("metadata-json", path, error)
            continue
        if meta is None:
            report["pending"].append({"path": check.display(path), "status": "legacy-pending"})
            if strict and paths:
                check.issue("metadata-required", path, "Explicit strict selection requires the new metadata header")
            continue
        if isinstance(meta.get("id"), str) and len(registry[meta["id"]]) > 1:
            check.issue("duplicate-stable-id", path, "Stable id also appears in: " + ", ".join(check.display(p) for p in registry[meta["id"]] if p != path), "id")
        article = check.document(path, meta, registry)
        article["valid"] = not any(item["path"] == check.display(path) for item in check.errors)
        report["articles"].append(article)
        if article["due"]:
            report["review_due"].append({"id": article["id"], "path": article["path"], "items": article["due"]})
    report.update(errors=check.errors, warnings=check.warnings, evidence_status=check.evidence_status,
                  ok=not check.errors, status="invalid" if check.errors else "degraded" if check.warnings else "valid")
    report["counts"] = {"governed": len(report["articles"]), "legacy_pending": len(report["pending"]),
                        "errors": len(check.errors), "warnings": len(check.warnings), "review_due": len(report["review_due"])}
    return report


def _print_cli(text):
    """Preserve UTF-8 output; escape only characters the redirected stream lacks."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Files/directories relative to --root; omitted selects maintained Markdown")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict", action="store_true", help="Require metadata for explicit legacy selections and reject unavailable evidence; discovered legacy files remain pending")
    parser.add_argument("--json", action="store_true", help="Write machine-readable results to stdout")
    parser.add_argument("--review-due", action="store_true", help="Show the manual review queue, without creating a schedule")
    parser.add_argument("--today", help="Fixed YYYY-MM-DD clock for reproducible offline review")
    parser.add_argument("--max-evidence-bytes", type=int, default=EVIDENCE_LIMIT)
    args = parser.parse_args(argv)
    try:
        today = dt.date.fromisoformat(args.today) if args.today and re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.today) else None
        if args.today and today is None:
            raise ValueError("--today requires YYYY-MM-DD")
        if args.max_evidence_bytes < 1:
            raise ValueError("--max-evidence-bytes must be positive")
    except ValueError as exc:
        parser.error(str(exc))
    result = validate_library(args.root, args.paths, strict=args.strict, today=today, max_evidence_bytes=args.max_evidence_bytes)
    if args.json:
        _print_cli(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        _print_cli(f"{result['status'].upper()}: {result['counts']}")
        if args.review_due:
            for item in result["review_due"]:
                reasons = "; ".join(f"{x['due_on']}: {x['reason']}" + (f" ({x['claim_id']})" if x['claim_id'] else "") for x in item["items"])
                _print_cli(f"REVIEW {item['id']} {item['path']}: {reasons}")
        for level in ("errors", "warnings"):
            for item in result[level]:
                _print_cli(f"{level.upper()} {item['path']} {item['code']}: {item['message']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
