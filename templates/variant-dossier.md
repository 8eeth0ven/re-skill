<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.template.variant-dossier",
  "kind": "variant-dossier",
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
      "ref": "../docs/knowledge-engineering.md#c-variant-dossiers",
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
  "related_ids": [
    "re.governance.knowledge-engineering"
  ],
  "variants": [
    {
      "id": "variant-a",
      "status": "unassessed",
      "claim_ids": [
        "c-scope"
      ]
    }
  ]
}
-->

# Variant Dossier Template

Evidence default: inference; only tagged claims inherit listed evidence.

Assign a family-specific stable id before use. Keep the existing article as the
method authority; this dossier records differences that change method selection.
The initial design claim and unassessed row are placeholders, not test outcomes.

## Family Boundary and Entry Router

State the family/variant recognition rule, what is deliberately outside it, and
which observation selects each row. Define host versus target platforms. Unknown
variants remain unknown; neither a source universe nor a sampled version proves
full family coverage.

## Variant Matrix

| Variant id / recognition | Target version/build | Host → target platform | Claim / evidence ids | Status | Attack surface / input control | Breakpoint / observation point | Detection / countermeasure | Effective / ineffective and control | Reopen when |
|---|---|---|---|---|---|---|---|---|---|
| variant-a / not yet identified | Unassessed | Unassessed | c-scope / e-basis | unassessed | Record the actual exposed boundary | Record the real executing path; do not guess an equivalent API is used | Record the observed signal and applicable alternative | Not tested; add positive/negative controls before an efficacy claim | A concrete version/build/path/prerequisite changes |

Add one metadata `variants` record per maintained row. `documented` means a source
supports the row, not an independent rerun. `not-reproduced` describes the attempted
scope and environment; it does not mean safe. `blocked` names the missing prerequisite.
Use `verified-on-device` only with a matching explicitly verified physical-device claim.

## Per-Variant Procedure and Acceptance

For each selected row, state recognition → preconditions → bounded steps → measured
result → controls/falsifiers → next route. Keep shared method text in its authority;
write only the decision-changing variant delta here. Retain both effective and
ineffective approaches and explain why they differ.

## Evidence and Provenance

Attach minimal redacted reproduction/evidence excerpts with actual date, build,
platform and hash when available. Preserve source-claimed and inferred rows as
such. Do not import private long logs, sessions or target identifiers simply to
fill a verified field. Reading a historical attachment and rerunning today are
separate observations.

## Coverage Gaps and Reopening Queue

| Variant / cluster | What is missing | Why it is pending | Smallest next observation | Reopen trigger |
|---|---|---|---|---|
| variant-a | Exact recognition and input/version boundary | No observation supplied | Collect a permitted bounded baseline | A sample/version and suitable environment become available |

## Related Authority and INDEX Row

Link the owning technique/platform/corpus article and the relevant acceptance gate.
Do not create a second branch taxonomy. One when-to-open row is sufficient:

```text
| [family-variants.md](relative/family-variants.md) | Open when <family signature> matches and version/platform differences change the observation point or acceptance control |
```

## Decay Warning

Required for evasion or other version-sensitive content. For stable knowledge,
state why `decay.mode=none` is justified rather than silently omit the warning.

- Tested scope/date: **not tested** in this template; unknown versions remain
  unknown and `last_tested` stays null until there is a real observation.
- Current applicability: **unknown / needs review** for any new target/build.
- Version/event triggers: name the concrete build, call-path, tool-API, detection,
  or prerequisite change that would invalidate or reopen the bounded claim.
- Replacement pointer: none identified by this template; link an actual maintained
  alternative when its applicability is known, without inventing a replacement.
- Historical confidence: retain the earlier scope/date/evidence honestly. An old
  verified observation is not a claim that the method is effective today.

## Review

Use `review_after`, version/event triggers and dated claim age to prepare a manual
review queue. Preserve historical claims when current proof is unavailable, mark
access degraded, and require traceable proof before promoting any new verified row.

## Addendum: Copyable Per-Variant Section

Copy the following section for each selected matrix row. Link the common method
authority and fill only decision-changing deltas. Keep unknown values and an
`unassessed` state until a real source or observation supports a narrower claim.
Default confidence remains inference; a filled template is not an observed result.

```markdown
### <variant-id>: <version/build>

#### Recognition and Exclusion
- Metadata variant id / claim ids / evidence ids: unassigned.
- Positive recognition signals and required conjunction: unknown.
- Conflicting signatures, exclusions and unresolved family assignment: unknown.
- Minimal input/sample hash and version/build/ABI: unknown; not tested.
- Known version/platform counterexample, or explicit untested gap: untested.

#### Host and Target Preconditions
- Host OS/tool/runtime versions: unknown.
- Target platform/build and required access/state: unknown.
- Shared method authority; exact variant delta and actual executing call path: unknown.
- Missing prerequisite and blocked condition: no observation supplied.

#### Attack Surface and Input Control
- Controllable boundary/field/bytes and preserved baseline: unknown.
- Required input shape, scope and maximum permitted consequence: unknown.
- Breakpoint/observation point and evidence that this path executes: unknown.
- Equivalent API/path that may be misleading and how to distinguish it: unknown.

#### Countermeasure Status and Bounded Procedure
- Detection/countermeasure signal, scope and evidence: unassessed.
- Applicable alternative and its proven prerequisite, or unresolved prerequisite: unknown.
1. Preserve the input/state and collect the smallest baseline at the actual observation point.
2. Match this variant's recognition claim and check its exclusions and host/target prerequisites.
3. Select the shared method plus the specific delta; record concrete inputs/commands before use.
4. Collect incremental output and controls; stop at the stated consequence or a blocked condition.
5. Route to an alternative only when its prerequisite is supported by the observed evidence.

#### Acceptance Criteria, Controls and Result Source
| Route / countermeasure | Preconditions | Expected / actual | Positive control | Negative control / falsifier | Effective / ineffective / unknown | Claim / evidence ids |
|---|---|---|---|---|---|---|
| Not tested | Unknown | No observation | Not run | Not run | Unknown | Populate from real records |

- Competing explanation and tool/environment failure discriminator: unknown.
- Result source: inference until supported; cite source/user report or a dated observation.
- Observation domain: host/fixture/mock/emulator/physical-device or unspecified; do not infer one.
- Current status: unassessed. Reading a source or attachment is separate from a current rerun.
- Historical date/build, current proof access/hash, current rerun state: null/unknown/not-rerun.

#### Failure, Coverage Gaps and Reopening
- Failed or ineffective approach and the boundary that explains it: no result supplied.
- Smallest next observation and required environment: unknown.
- Concrete version/call-path/tool/detection/prerequisite change that reopens this row: unknown.
- Replacement pointer: none identified.
- Preserve earlier bounded claims and their evidence when a current route is retired.
```

Apply the guide's [observation-domain and proof gate](../docs/knowledge-engineering.md#addendum-observation-domain-and-bounded-offline-records)
to host/fixture/mock results; their mode never grants physical-device verification.
