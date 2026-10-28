# Copyable Input Examples

These text-only demonstration assets describe the input contract. They were not executed in
the documentation handoff that introduced this page and do not establish device or vulnerability
verification. Installation and testing were assigned to the receiving execution agent:

```bash
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

The local manifest includes an API specification, AI configuration, device descriptor, EVM
bytecode, and SBOM. API servers/links and device observations are registered as data and are
not contacted automatically. `scope.localhost.json` permits only local port 8765; the execution
agent supplies the test service.

Generate the complete 12-category synthetic fixture set with
`tests/fixture_factory.py <output>`, including APK/AAB, IPA, ELF/JVM/WASM, rootfs, OCI, and PCAP.
These fixtures are structural oracles; they do not replace production assets, physical devices,
or adversarial execution acceptance. See [the runner guide](../docs/runner.md) for the shared
input/scope contract and [the historical acceptance ledger](../docs/execution-acceptance.md)
for recorded execution results.
