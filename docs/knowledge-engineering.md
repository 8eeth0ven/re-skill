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

## Addendum: Observation Domain and Bounded Offline Records

This is a backward-compatible extension of section B's `source-claimed` gate.
The three confidence values and existing physical-device gate remain unchanged.
Confidence describes the bounded assertion's support; observation domain describes
where the recorded result came from. An actual host execution can have a measured
result, while a generalization from that result remains inference. The earlier
`offline-test` table's typical orchestration role now also includes explicitly
scoped host, fixture and mock observations under the following proof conditions.
The [validator](../scripts/validate_knowledge.py) implements these gates. Its
behavioral checks were run before the regression suite was archived outside the
public distribution; they are not a bundled runtime dependency.

| Optional evidence field | Accepted input | Meaning |
|---|---|---|
| `observation_mode` on `kind=offline-test`, `provenance=offline` | `host` | The named host program actually ran; record host/tool versions and the exact observed scope |
| Same field/kind/provenance | `fixture` | The recorded outcome belongs to a controlled offline input/harness |
| Same field/kind/provenance | `mock` | The recorded outcome belongs to simulated dependencies or responses |
| Field omitted | No new field required for old records | The report emits `unspecified`; it does not infer a mode or upgrade confidence |

Only `host`, `fixture` and `mock` are accepted as explicit values. The emitted
`unspecified` value is the compatibility default, not a new input enum or evidence
of execution. Other evidence kinds reject `observation_mode`; a physical-device
record cannot acquire a host/fixture label to bypass its own provenance contract.

A `source-claimed` claim may now cite an `offline-test` observation when all of
these conditions hold:

1. Its explicit mode is host, fixture or mock, with offline provenance.
2. The effective claim `last_tested` is an actual date matching the evidence's
   `observed_at`. Record the real host/tool and target/input versions when known;
   retain an explicit unknown scope rather than invent a version.
3. The observation refers to a portable local attachment and supplies its final
   stored-byte SHA-256. Strict intake requires readable, hash-matching proof within
   the configured evidence bound. A remote URL alone cannot supply this proof.
4. The visible claim states only what that record establishes in its stated mode,
   including its positive/negative controls. Fixture/mock outcomes describe the
   fixture/mock. A successful host calculation does not establish target-shell,
   Android, device, bypass or all-version behavior. Human review checks that scope.

Normal historical review preserves the claim and reports unavailable or changed
proof as degraded; strict intake rejects it. A visible body citation to the same
declared evidence reference follows that evidence policy. Unrelated broken body
routes still fail, and the separate structural publication gate remains required.
The JSON `evidence_status` exposes kind, provenance, normalized `observation_mode`,
availability and `reexecution: not-attempted` separately from article confidence.
Validation reads records; it does not repeat their experiments.

Existing v1 records without this optional field continue to validate under their
previous rules. Explicit mode alone supplies no proof, and none of these three
modes can support `verified-on-device`. The
[host observation example](../examples/knowledge/host-observation.md) records a
small real Python arithmetic/encoding exercise and limits its result to that host.

## Addendum: Per-Article Legacy Migration and Acceptance

Keep a migration ledger outside the article body, in the project/maintenance
workspace. Discover actual articles in the existing platform, technique, corpus
and breach-table branches; classify routing nodes such as SKILL/INDEX separately.
The current branch inventory is an input to migration, not proof that its articles
have been reviewed. A few governed examples do not constitute full-library migration.

| Ledger field | Record for each article |
|---|---|
| Identity and owner | Existing path, stable id, kind, owning INDEX, preserved old headings/anchors |
| Priority | Version-sensitive/evasion/API/device behavior first; explain actual use/risk and batch selection |
| Progress | inventory-only, header-draft, claims-reviewed, evidence-checked, routes-checked, accepted; record blocked/degraded separately |
| Source review | Claim ids for decision-changing criteria, thresholds and behavior; explicit measured/example/policy labels; reviewer/date and remaining gaps |
| Scope and evidence | Known versions/date or null/unknown, counterexample or untested gap, portable proof and current access, current rerun state |
| Next step and acceptance | Concrete missing observation/action, review date, actual two-gate results and human review receipt |

For each selected legacy article:

1. Record its existing owner, callers, unique methods, evidence/source anchors and
   variant distinctions before adding a header. Assign a stable id; preserve the
   current branch and working entry/INDEX contracts.
2. Read its full decision-bearing content. Map every criterion, threshold and
   behavior conclusion to a claim/source/control; separate source attribution,
   actual observed scope and inference. Record missing sources explicitly.
3. Draft the v1 header with conservative confidence, actual versions/dates only,
   and minimal portable references. A generic template policy claim does not cover
   the article's unreviewed assertions. Merely adding a header is header-draft.
4. Review each variant/counterexample, failed route and reopening condition. Add a
   Decay Warning for version-sensitive/evasion content; explain stable none-decay.
   Keep unresolved claims/gaps visible rather than manufacture a measurement.
5. Check the redacted proof package and record its current access separately from
   historical confidence. Use the observation domain above for host/fixture/mock
   measurements. Keep private raw logs and original provenance in the workspace.
6. Preserve old anchors, update the existing INDEX when-to-open row and affected
   references, then run both publication gates from section G. Record actual
   results against this article; a legacy-pending count is not a route verdict.
7. Complete a human missed-assertion/provenance/scope review, record reviewer/date,
   unresolved limitations and the next review trigger, and only then mark accepted.
   Validation success alone does not certify a placeholder or unreviewed body.

Report completed body reviews, evidence checks, accepted articles and blockers per
batch, with the underlying article paths. Resume from ledger state. Global strict
continues to leave untouched legacy articles pending; explicit strict intake is
for the actual selected drafts. This process requires no bulk rewrite or deletion.

## Addendum: Manual Review Receipt and Deferral

Use the following row in the article/dossier or its maintenance ledger after an
actual review. An event trigger needs human input; the CLI does not monitor releases.

| Review date / reviewer | Trigger / scope | Source and attachment checks | Rerun state / environment | Claim changes / retained history | Outcome | Next review / reason |
|---|---|---|---|---|---|---|
| Fill after an actual review | Due, version or contrary result | Readable, unavailable or hash mismatch | not-rerun or a bounded actual result | Claim ids and preserved earlier dates | reviewed, deferred, blocked or retired | Planned date with explicit rationale |

Changing `review_after` schedules another review; it does not prove a review or
rerun happened. Keep earlier receipts, record an unperformed review as deferred
with its reason, and retain unknown test dates as null. A completed source review
can honestly say not-rerun. A fresh measurement gets its own dated evidence rather
than silently replacing an earlier observation.
