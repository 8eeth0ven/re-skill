# Copyable Input Examples

These text-only examples describe the runner input contract. Example configuration
does not establish successful execution, physical-device validation, or a confirmed
vulnerability. Supply your own scoped input and replace documented placeholders.

```bash
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

The manifest includes an API specification, AI configuration, device descriptor,
EVM bytecode, and SBOM. API servers/links and device observations are registered as
data and are not contacted automatically. `scope.localhost.json` demonstrates an
explicit loopback scope; any service must be supplied separately.

See [the runner guide](../docs/runner.md) for the shared input/scope contract.
The knowledge examples demonstrate article metadata, evidence boundaries, and
variant structure; open them through [knowledge engineering](../docs/knowledge-engineering.md).
