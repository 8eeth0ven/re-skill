<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.template.article",
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
      "ref": "../docs/knowledge-engineering.md#b-claim-and-evidence-boundaries",
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
  ]
}
-->

# Article Template

Evidence default: inference; only tagged claims inherit listed evidence.

Copy this file into the existing owning branch. Assign a new stable id and replace
the metadata's design claim, scope, evidence and relative references with actual
information. Keep null/unknown values when untested; a template is not proof.

## Problem and When to Open

State the observed surface or requested outcome this method addresses. Explain
what evidence selects this article, the relevant input shape and the stopping
boundary. For a long article, add a small section router rather than preload all
related material.

## Claims and Acceptance Criteria

| Claim id | Bounded assertion | Value kind (measured/example/policy) | Required positive control | Negative control / falsifier | Evidence ids | Confidence |
|---|---|---|---|---|---|---|
| c-scope | Replace the design claim with the actual scoped assertion | policy (template criterion, not a benchmark) | Identify the observable consequence | Identify the competing explanation | e-basis | inference until supported |

Match metadata claim ids to the assertions that change decisions. Mixed material
keeps article confidence inference; stronger claims need explicit per-claim proof.

## Preconditions and Procedure

1. Identify exact input, target version/build, host tool version, and available
   interfaces. Readiness is distinct from successful analysis.
2. Preserve the original input and baseline. Select the smallest method that can
   resolve the actual hypothesis and respect the active task's boundaries.
3. Record incremental outputs, controls and failures. Follow a relevant alternative
   only when its preconditions are present; keep distinct variants separate.
4. Stop at the demonstrated consequence or a concrete blocked/degraded condition.
   Do not convert a marker, status code or tool exit into an unproven outcome.

## Validation and Evidence

Record commands/inputs, expected and actual outputs, controls, version/build and
real observation date. Distinguish offline fixture, emulator and physical device.
Link minimal redacted portable evidence; retain private raw logs in the project.
Mark current evidence access and rerun status separately from historical confidence.

## Pitfalls and Negative Results

List parsing/context traps, false positives, side effects, incompatible variants,
and when the apparent result is actually a tool/environment failure. State what
would reopen the hypothesis after a version or interface change.

## Related Methods and Ownership

Link the authoritative method/dossier and explain when to follow it. Do not paste
an overlapping procedure merely to make this file self-contained. Preserve old
case/source anchors as evidence without asserting their current applicability.

## INDEX When-to-Open Row

Replace the placeholder path and paste one row into the existing owning INDEX:

```text
| [article-name.md](relative/article-name.md) | Open when <observed surface/input/outcome>; start at <matching section>; result boundary is <specific assertion> |
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

## Review and Promotion

Choose a real maintenance review date and concrete decay/reopening triggers. Run
strict validation on the new draft, review source/claim gaps, and confirm that a
clean clone can read its minimal proof package. Follow the
[promotion gate](../docs/knowledge-engineering.md#f-workspace-to-library-promotion-and-the-minimum-evidence-package).
