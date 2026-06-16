# NVMe/TCP TLS Field Fuzz Harness

This repository is a grammar-aware starting point for NVMe/TCP TLS protocol
field fuzzing. It does not mutate TLS ciphertext. Mutations are applied after
TLS termination to NVMe/TCP cleartext PDUs.

The Python runtime path has no third-party dependencies. See
`OFFLINE_DEPLOYMENT.md` for intranet deployment and air-gap packaging.

## Components

- `field_catalog.yaml`: editable catalog of fuzzable NVMe/TCP/TLS-key fields.
- `CaseGenerator`: deterministic seed-based case generation.
- `MutationEngine`: byte-level mutation engine for common PDU header fields.
- `OracleAnalyzer`: classifies each run into `PASS_*` or `FAIL_*` verdicts.
- `FakeTarget`: async target-side harness for target-to-host PDU injection.
- `SplitProxy`: async proxy harness for host-to-target and host-to-host PDU mutation.

Python 3.11 `ssl` does not expose TLS-PSK callbacks. For real PSK runs, put a
PSK-capable TLS terminator in front of the fake target/proxy, or replace the
SSL context factory with bindings that support TLS 1.3 PSK.

## Examples

Generate a reproducible C2HData mutation case:

```powershell
python -m nvmetcp_tls_fuzz.cli generate-case --seed 1337 --direction target --pdu-type c2hdata --command read
```

Generate the default 1,500,000-case campaign with 10% random-value mutations:

```powershell
python -m nvmetcp_tls_fuzz.cli generate-campaign --seed 20260617 --output artifacts\campaign.jsonl --summary
```

Analyze collected artifacts:

```powershell
python -m nvmetcp_tls_fuzz.cli analyze --dmesg artifacts\dmesg.log --fio-json artifacts\fio.json --nvme-before artifacts\nvme-before.json --nvme-after artifacts\nvme-after.json
```

## Safety Defaults

- Destructive writes are disabled in `config.example.yaml`.
- Legal-but-boundary cases may pass; malformed cases may reject or disconnect.
- Kernel crash, hung task, cleanup leak, and silent data corruption are always failures.
