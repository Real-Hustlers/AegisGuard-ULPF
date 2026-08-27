# Hash Chain Traceability

## Integrity model

AegisGuard-ULPF uses tamper-evident cryptographic integrity, not blockchain.
`RawEvidenceStore` preserves authoritative raw bytes separately from
normalized and OCSF copies.

For each stored event it records:

- a deterministic `event_id`, derived from raw SHA-256 and stable source
  identity context;
- a stable `raw_id`, derived from the event ID;
- SHA-256 of the exact raw bytes;
- a sequential chain hash that commits to this record and the prior chain
  hash.

The first record uses a fixed genesis hash. Each subsequent record includes
the preceding chain hash, so alteration of a blob or manifest record is
detected during verification.

## Traceability path

```text
OCSF raw_data.raw_id and raw_data.u_id
  -> RawEvidenceStore evidence record
  -> original raw bytes
  -> SHA-256 verification
  -> sequential hash-chain verification
```

The CommonEvent-to-OCSF mapper carries CommonEvent traceability identifiers as
`raw_data.u_id` and `raw_data.raw_id`; no raw bytes are copied into that OCSF
traceability object.

## Verify from the CLI

After installation, run:

```powershell
ulpf verify EVT-<sha256-derived-id> --store demo/evidence
```

During source-tree development, the equivalent command is:

```powershell
python -m aegisguard_ulpf.cli.main verify EVT-<sha256-derived-id> --store demo/evidence
```

Expected successful result:

```text
Original event found: YES
Raw SHA-256 verified: PASS
Hash chain verified: PASS
Integrity: PASS
```

## Demo

Run the existing raw-to-CommonEvent-to-OCSF demo and then verify the latest
OCSF traceability reference in one command:

```powershell
python demo/run_traceability_demo.py
```

The demo prints the OCSF `raw_id` plus the same evidence, SHA-256, chain, and
overall integrity statuses.
