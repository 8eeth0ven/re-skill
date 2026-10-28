<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.example.offline-intake",
  "kind": "article",
  "host_platforms": [
    "any"
  ],
  "target_platforms": [
    "local-files"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "source-claimed",
  "evidence": [
    {
      "id": "e-basis",
      "kind": "source",
      "ref": "../../docs/runner.md#manifest-and-scope",
      "provenance": "source",
      "observed_at": null,
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-scope",
      "statement": "The runner guide documents 1\u2013100 manifest assets and local inputs without network scope; this example has not executed the runner.",
      "confidence": "source-claimed",
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

# Offline Intake: A Documentation-Supported Boundary

## Problem

A local batch should be distinguished from a request to fetch discovered URLs.

## Criterion and Steps

Claim `c-scope` is supported by the [runner guide](../../docs/runner.md#manifest-and-scope).
Read the manifest limits, keep output outside the input tree, and treat discovered
addresses as data until the task supplies the required scope.

## Validation and Limits

No runner or target was executed for this example. `last_tested` and `observed_at`
remain null. Documentation support is `source-claimed`, not physical-device proof.

## Pitfall and Related Route

A manifest's 100-asset bound and a tree's file-count budget are different. Follow
[knowledge evidence gates](../../docs/knowledge-engineering.md#b-claim-and-evidence-boundaries)
before promoting any observation.
