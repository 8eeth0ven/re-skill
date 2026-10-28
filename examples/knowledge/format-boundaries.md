<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.example.format-boundaries",
  "kind": "article",
  "host_platforms": [
    "any"
  ],
  "target_platforms": [
    "offline-artifact"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "inference",
  "evidence": [
    {
      "id": "e-basis",
      "kind": "analysis",
      "ref": "#hypothesis",
      "provenance": "inference",
      "observed_at": null,
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-scope",
      "statement": "A format marker alone should be treated as a hypothesis until parsing and a negative control resolve competing interpretations.",
      "confidence": "inference",
      "evidence": [
        "e-basis"
      ]
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

# Format Boundaries: An Explicit Inference

## Hypothesis

Claim `c-scope` proposes a review rule: a marker alone does not show that the full
structure is valid. The rationale is that unrelated data can contain the same
bytes; a bounded parser and malformed control can distinguish those cases.

## Steps and Validation Plan

Preserve input bytes, record the candidate marker, inspect the relevant structure,
and compare a malformed control. This is a proposed offline validation plan; no
sample was parsed and no result is asserted here.

## Pitfall and Relation

Do not convert this inference into a source statement or a device success. Use the
[article template](../../templates/article.md) when an actual scoped method and
its observations are available.
