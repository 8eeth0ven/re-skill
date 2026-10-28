<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.governance.knowledge-engineering",
  "kind": "article",
  "host_platforms": [
    "any"
  ],
  "target_platforms": [
    "documentation"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "inference",
  "evidence": [
    {
      "id": "e-basis",
      "kind": "analysis",
      "ref": "#b-claim-and-evidence-boundaries",
      "provenance": "inference",
      "observed_at": null,
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-scope",
      "statement": "This document specifies a bounded knowledge-maintenance design; it is not a device test result.",
      "confidence": "inference",
      "evidence": [
        "e-basis"
      ],
      "value_kind": "policy"
    }
  ],
  "review_after": "2027-01-31",
  "decay": {
    "mode": "event",
    "max_age_days": null,
    "triggers": [
      "metadata-schema-change",
      "evidence-policy-change"
    ],
    "note": "The review date is a proposed maintenance date, not an observed test date."
  },
  "related_ids": []
}
-->

# Knowledge Engineering: Claims, Variants, Evidence, and Progressive Adoption

This is an opt-in maintenance layer for the existing RE library. It does not delete
articles, rename branches, replace their INDEX ownership, narrow method coverage,
or certify installed tools. The host's single skill entry chooses a workflow;
a branch INDEX still chooses articles by their **when-to-open** condition.

## A. Routing and Ownership

Keep one maintained method body for one decision-changing technique. Link related
articles rather than copy their complete procedures. Preserve genuinely different
variants, negative controls, historical constraints, offsets, payloads and source
anchors. A long article can expose a section router without turning it into a
short generic checklist or imposing a fixed article-count ceiling.

Use stable ids across renames. `related_ids` links governed articles by id; normal
relative Markdown links route people to the actual article/section. New files get
one relevant branch INDEX row describing the observed surface or requested outcome.
The validator checks declared ids and links, but does not choose a branch or edit
an INDEX on the author's behalf. Existing legacy articles remain usable unchanged.

## B. Claim and Evidence Boundaries

Confidence has exactly three values:

| Confidence | Meaning | Does not establish |
|---|---|---|
| `inference` | A bounded hypothesis or analysis, with its assumptions identified | That a source asserted it, that code was executed, or that a device result exists |
| `source-claimed` | The identified source, historical record, or attributed user report supports the stated scope | Independent reproduction or current real-device behavior |
| `verified-on-device` | A specific claim was observed on a physical device for the recorded versions/date with traceable evidence | Every version/variant, present availability, a current rerun, or general bypass success |

Mixed articles default to `inference`; give each decision-changing claim an id and
explicit evidence ids. Claim-level confidence/date/version overrides let a narrow
verified statement coexist with design inferences. Do not promote the whole page
because one snippet once worked. Source code, user statements, old smoke-test
summaries, emulator output, mock tests and a tool's exit code cannot automatically
become physical-device verification. A reported failure can itself be a verified
bounded observation when the actual physical-device evidence supports it.

Evidence kind and provenance must agree:

| Kind | Allowed provenance | Typical role |
|---|---|---|
| `device-log` | `physical-device`, `emulator` | Measured runtime observation; only the physical case can support device verification |
| `source` | `source` | Official documentation, source code, a cited report |
| `offline-test` | `offline` | Parser/mock/fixture tests; orchestration evidence only |
| `analysis` | `inference` | A documented derivation or hypothesis |
| `historical` | `historical` | A preserved older record with its actual uncertainty |
| `user-report` | `user-report` | A user's field account; not independent measurement |

For device verification, the effective claim needs a real `last_tested` date,
concrete target versions/builds and bounded target platforms. At least one cited
`device-log` with `physical-device` provenance must carry that same date, cover
those versions, and refer to a local portable evidence attachment with matching
SHA-256. A source claim needs `source`, `historical`, or explicitly attributed `user-report`
evidence. A user-report claim states only that the user reported the bounded
phenomenon, with unknown version/platform scope retained as unknown; it does not
claim independent reproduction or general behavior. Keep that attribution visible
in the body. Do not relabel user reports as source code or force them into inference
when a real report exists. The validator cannot decide whether a natural-language
paraphrase stays within the source; human review checks that boundary. Every claim names
at least one declared evidence id, including inference with its analysis note.
Untagged prose remains inference even when the page contains source-supported or
verified claims. The linter checks explicit declarations and references; it cannot
semantically discover every natural-language criterion, threshold, or behavior
claim. Human review must map those statements to sources and controls.
Label numerical values `measured`, `example`, or `policy` using optional claim
`value_kind` and a visible body annotation; a request budget is policy, not measured
throughput. Missing this label cannot be inferred reliably from arbitrary prose.

## Schema Contract

The first non-whitespace block is an HTML comment beginning exactly
`<!-- re-knowledge-metadata`, followed by strict JSON, then `-->` on its own line.
There is no YAML parser or third-party dependency. Duplicate JSON keys, NaN and
unknown fields are rejected. Policy bounds (not benchmark measurements): 64 KiB
metadata headers, 4 MiB referenced text, and 16 MiB digest inputs by default.

| Field | Contract |
|---|---|
| `schema` | Exactly `re-knowledge/v1` |
| `id` | Stable lowercase id, at most 128 characters; segments use letters/digits and `.`, `_`, `-`; unique within the root |
| `kind` | `article` or `variant-dossier` |
| `host_platforms` / `target_platforms` | Nonempty lists of nonempty unique strings; distinguish tool host from analyzed target |
| `target_versions` | Unique strings; empty is allowed for an untested inference/source scope; device claims need concrete versions/builds |
| `last_tested` | A real `YYYY-MM-DD` date or null; never invent a test date |
| `confidence` | Exactly one of the three values above |
| `evidence` | Records with `id`, `kind`, `ref`, `provenance`, `observed_at` (date/null), `target_versions`; optional lowercase `sha256` |
| `claims` | Nonempty records with `id`, `statement`, `evidence` ids; optional confidence/date/version overrides and `value_kind` (`measured`, `example`, `policy`) |
| `review_after` | A real `YYYY-MM-DD` review date; a plan, not a test observation |
| `decay` | `mode`, `max_age_days`, `triggers`, `note`; details below |
| `related_ids` | Optional stable ids of governed articles under the same root |
| `variants` | Required for a dossier: records with local `id`, `status`, nonempty `claim_ids` |

Dates must be calendar-valid; observed/test dates cannot be in the future relative
to the supplied clock. Claim/evidence ids are local to one article and unique there; uppercase labels such
as `E1` / `C1` are permitted. Stable article ids remain lowercase.
`ref` is a relative POSIX file/anchor path or a credential-free HTTP(S) source URL.
Local references stay inside the declared library/workspace root; absolute machine
paths and backslash paths are not portable. Remote sources are never fetched by
the validator. Markdown anchors and source `#L10-L20` line anchors are checked.

A header is an assertion ledger, not an authenticity oracle: a file existing and
hashing correctly does not prove it came from the claimed physical device. Human
review must establish the provenance, controls, build identity, and consequence.

## C. Variant Dossiers

Use the [variant template](../templates/variant-dossier.md) when a family has
version/platform/packer/runtime differences that change recognition or method
choice. Keep each row bounded; an empty row means unassessed, not safe or impossible.

The body matrix owns recognition, version/build, host/target platform, evidence,
attack surface, breakpoint/observation point, countermeasure, result, and reopening
condition. Metadata gives each variant an id and claim links rather than copying
the full method into JSON. Variant states are `unassessed`, `documented`,
`verified-on-device`, `not-reproduced`, `blocked`, and `retired`. A verified variant
must point to an explicitly verified claim; a documented row is still not a rerun.

Record effective and ineffective approaches with the condition that made them
so. A tool failure or empty lane can be useful evidence. Retire an obsolete route
with its applicability note and replacement pointer; do not erase historical cases
that still help analyze old samples. A new version/build, changed call path, tool
API drift or a contrary control can reopen the specific row.

## D. Layers Without a Second Entry System

| Layer | Belongs here | Promotion boundary |
|---|---|---|
| Project workspace | Raw logs, sensitive sessions, target identifiers, failed experiments, large binaries | Keep originals and acquisition provenance; do not copy them wholesale into the skill |
| Reusable article | Minimal method, scope, controls, bounded claims and references | Remove target secrets; retain all distinct decision-changing methods |
| Variant dossier | Same-family differences that change route choice | Attach each status to its exact claim/version/evidence |
| Existing branch INDEX | One-line when-to-open routing | Link the authoritative body; avoid another duplicated capability catalog |
| Corpus/source lookup | Historical source titles, source paths and coverage/skip ledger | Source universe is not a claim of completed extraction or reproduction |

Start with the [article template](../templates/article.md). Domain knowledge still
goes to `platforms/`, techniques to `techniques/`, historical cases to `corpus/`.
This layer neither replaces those meanings nor migrates the old library in bulk.

## E. Freshness and Manual Review

`decay.mode` is `time`, `version`, `event`, or `none`. `max_age_days` is a positive
integer or null. Time decay requires an age; version/event decay requires explicit
reopening triggers. None decay has no age/triggers and explains why in `note`.
Every article still has `review_after`. The queue includes an article when its
review date or a dated claim's maximum age is reached. Version/event triggers need
human input; the script does not pretend to observe a new release or device build.

For evasion/version-sensitive drafts, fill the dedicated visible Decay Warning
section in the [article template](../templates/article.md#decay-warning) or
[variant dossier](../templates/variant-dossier.md#decay-warning). Record tested
scope/date or not-tested, current applicability unknown/needs-review, version/event
triggers and an actual replacement pointer when known. Stable knowledge explains
its none-decay rationale. Do not invent a version/date or promote an old verified
observation into a statement of present efficacy.

Keep three separate facts: the historical claim and its confidence; whether the
referenced evidence is currently readable and hash-matching; and whether a new
rerun has happened. The validator always reports `reexecution: not-attempted`.
Missing evidence is `unavailable`, altered evidence is `hash-mismatch`; a normal
review reports `degraded` without rewriting the historical confidence. Strict
new-draft review rejects unavailable/mismatching proof. A due review is a queue
entry, not an automatic confidence downgrade or a fabricated new test date.

For a human weekly review, run `--review-due`; choose the due subset, check evidence
access and changed prerequisites, and rerun only where requested and feasible.
Record “not rerun” or a concrete degraded/blocked result honestly. This command
creates no external automation, reminder, schedule or network monitor.

## F. Workspace-to-Library Promotion and the Minimum Evidence Package

1. State the reusable invariant and the exact input/version/platform boundary.
   Extract criteria and controls, a known version/platform counterexample (or an
   explicit untested gap), and the failure/reopening trigger. Separate project-specific
   observations from a general method and its variants.
2. Compare the authoritative article/dossier before writing. Merge only identical
   methods; keep different semantics, negative controls and reopening conditions.
3. Derive a **minimal redacted evidence package** beside the article, for example
   `evidence/<article-id>/<observation-id>.txt`: concise reproduction/controls,
   physical-device vs emulator identity, relevant build/version, real test date,
   observed result, and the excerpt's SHA-256. A tiny reproducible input/script may
   accompany it when shareable. Keep raw long logs, sessions and private identifiers
   in the project workspace. No private data upload is required.
4. Ensure redaction does not destroy the decisive boundary. If the necessary proof
   cannot be shared safely or legally as a small portable attachment, leave the
   library claim `source-claimed` or `inference` with its limits; do not satisfy the
   schema by copying private logs or inventing physical-device facts.
5. Assign stable ids, update the existing branch INDEX when-to-open row and relevant
   links, and run strict validation on the new/changed drafts. Confirm that a clean
   clone has the required small attachments; an absolute path on the author's
   machine is not portable proof.
6. Record what was actually reviewed/tested and preserve the original project
   evidence separately. A readable excerpt is not a claim that the current clone
   can rerun a hardware experiment; missing current access never silently rewrites
   an honest earlier observation.

## G. Validator CLI and Progressive Adoption

Run from the skill root:

```bash
python3 scripts/validate_knowledge.py --json
python3 scripts/validate_knowledge.py examples/knowledge --strict --json
python3 scripts/validate_knowledge.py --review-due --today 2027-01-31
python3 scripts/validate_knowledge.py path/to/new-article.md --strict --json
```

`--root DIR` selects the library or a project staging root; relative selected paths
resolve against it. Without paths, maintained Markdown is discovered while raw
corpus data, installed environments, runs and node_modules are excluded. Legacy
files without a first metadata block are reported `legacy-pending` and remain
usable. Even `--strict` without explicit paths does not force all legacy files to
migrate. Explicit strict selections require metadata, including when selecting a
directory; use a narrow selection intentionally.

Article migration is separate from routing-node formats. Keep `SKILL.md`'s loader
frontmatter first; do not prepend this article comment ahead of its YAML or force
an INDEX to become a method article. Discovery includes such Markdown as pending
for inventory purposes. Select actual article drafts for strict intake, and use
the structural gate for the entry/INDEX contracts. A raw pending count is therefore
not an article-migration completion metric; reconcile it against the article inventory.

New metadata is checked for shape, stable-id uniqueness, claim/evidence provenance,
portable references and due dates. Explicit-file review still scans other **headers**
to detect id collisions, but does not impose their full migration. `--strict` also
rejects currently unavailable/mismatching evidence; normal review preserves the
historical claim and reports the separate degraded access condition.

`--json` writes the machine report to stdout. `--review-due` selects the human queue
view (JSON also retains errors/status). `--today` injects a fixed date for offline
review/tests. Exit code 0 means no validation errors, including a non-strict
`degraded` availability report; 1 means invalid content, and argument errors use 2.
`--max-evidence-bytes` bounds local digest reads (default 16 MiB); use a small excerpt
rather than relaxing this to include an entire private run.

Publication uses two distinct gates, both required:

```bash
python3 scripts/validate_library.py --json
python3 scripts/validate_knowledge.py path/to/new-article.md --strict --json
```

The structural gate owns maintained library/INDEX coverage and local resource
routes, including legacy documents. The knowledge gate owns opted-in metadata,
claim/evidence completeness and the review queue. A legacy-pending result says
nothing about that file's links or INDEX coverage; it must not be presented as a
structural pass. Shared stdlib Markdown route extraction covers a documented subset of inline links,
reference definitions/usages and HTML image resources; it is not a complete CommonMark
or arbitrary HTML/CSS renderer. Neither gate proves the semantics of every prose
assertion or live tool/device success. The three [offline examples](../examples/knowledge/offline-intake.md),
[hypothesis example](../examples/knowledge/format-boundaries.md), and
[variant example](../examples/knowledge/archive-variants.md) intentionally contain
no real-device verification claim or fabricated test date.
