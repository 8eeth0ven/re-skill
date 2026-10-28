<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.example.archive-variants",
  "kind": "variant-dossier",
  "host_platforms": [
    "any"
  ],
  "target_platforms": [
    "offline-artifact"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "source-claimed",
  "evidence": [
    {
      "id": "e-basis",
      "kind": "source",
      "ref": "../../docs/runner.md#asset-matrix",
      "provenance": "source",
      "observed_at": null,
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-zip",
      "statement": "The runner guide documents bounded ZIP/TAR firmware intake; this row is a documentation claim, not a test.",
      "confidence": "source-claimed",
      "evidence": [
        "e-basis"
      ]
    },
    {
      "id": "c-gzip",
      "statement": "The runner guide documents gzip firmware intake; nested filesystem depth depends on the selected supported route.",
      "confidence": "source-claimed",
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
    "re.example.offline-intake",
    "re.example.format-boundaries"
  ],
  "variants": [
    {
      "id": "zip-or-tar",
      "status": "documented",
      "claim_ids": [
        "c-zip"
      ]
    },
    {
      "id": "gzip",
      "status": "documented",
      "claim_ids": [
        "c-gzip"
      ]
    }
  ]
}
-->

# Archive Intake Variants: Documentation Only

The [runner matrix](../../docs/runner.md#asset-matrix) is the source authority.
These two rows demonstrate dossier structure, not complete archive-family coverage.

| Variant id / recognition | Version/build | Host → target | Claim / evidence | Status | Attack surface | Observation point | Countermeasure | Effective / ineffective | Reopen when |
|---|---|---|---|---|---|---|---|---|---|
| zip-or-tar / parser recognizes container | Unspecified by this example | Any → offline archive | c-zip / e-basis | documented | Archive members and declared sizes | Intake/extraction result, not target execution | Bounded path/member/byte checks documented | No execution performed; efficacy unassessed | Container/parser contract changes |
| gzip / compressed stream | Unspecified by this example | Any → offline archive | c-gzip / e-basis | documented | Expanded bytes and nested format | Decompression plus supported inner route | Expansion limits and explicit depth reporting documented | No execution performed; opaque inner formats remain a separate question | Nested-format support changes |

## Validation and Gaps

No test date, device build or successful extraction is invented. Both claims are
source-claimed; an actual local parser test would add offline evidence and still
would not become a physical-device claim. Use the [dossier template](../../templates/variant-dossier.md)
to record a real family's additional variants and reopening conditions.
