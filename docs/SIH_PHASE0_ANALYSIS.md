# SIH26156 Phase 0: Repository Analysis

## Current implementation

The repository is a standalone ULPF preprocessing framework. It already
contains the core processing boundary required before SIEM or data-lake
ingestion:

- `RawEvidenceStore` stores exact raw bytes in a blob store, records SHA-256,
  deterministic IDs, and a sequential hash chain in
  `evidence_manifest.jsonl`.
- `RawEvent`, `ProcessingPipeline`, source/format detection, parser registry,
  fidelity measurement, Tier-0 fallback, CommonEvent normalization, OCSF
  mapping, and JSONL output are present.
- FortiGate, Cisco, PAN-OS, and Windows processing are implemented and
  covered by tests and demonstrations.
- Semantic Packs have a signed, validated declarative runtime and an example
  vendor pack.
- `ulpf verify <event_id> --store <path>` verifies a raw blob and the chain.
- SIEM translation remains an opt-in output adapter; no SIEM code is in this
  repository.
- An offline Docker image workflow and air-gap bundle checksum verifier exist.

Baseline verification on this branch:

```text
python demo/run_sih_final_validation.py  -> PASS
pytest -q                              -> 336 passed, 3 xfailed
```

## Missing or incomplete SIH requirements

| Requirement | Gap in this repository |
|---|---|
| (a) Raw preservation | The authoritative evidence manifest/blob store is complete, but `raw_events.jsonl` is only a RawEvent view and does not expose the requested hash-chain envelope. The CLI resolves an event ID, not a raw ID. |
| (b) Source parsing | No dedicated Linux Syslog parser exists. |
| (c) Common taxonomy + OCSF | Existing implementation is substantially complete; final work should be validation-only and preserve current contracts. |
| (d) Traceability | Raw retrieval/verification exists, but there is no `traceability.jsonl` view or `ulpf trace` command connecting OCSF/CommonEvent references to raw evidence. |
| (e) Onboarding | Dynamic registry and semantic packs exist; parser metadata is Python-based, not per-source `metadata.yaml`. |
| (f) Unified visibility | There is no `unified_events.jsonl` timeline output or Windows + FortiGate + Linux demonstration. |
| (g) Export layer | JSONL output and SIEM adapters exist; CSV and Parquet exporters are absent. |
| (h) ML readiness | No feature extraction module or `features.csv` writer exists. |
| (i) Reduced parser effort | No measurement script/report exists. Measurements must be generated from inspected repository facts rather than invented durations. |
| (j) Air gap | Local wheelhouse image install and image-export bundle verification exist; no repository-level offline bundle containing source, dependencies, schemas, and semantic packs. |
| (k) Container deployment | `docker/Dockerfile` exists; `compose.yaml` is empty and no `ulpf-runtime` service is defined. |

## Files expected to change by phase

1. Raw and lineage views: `traceability/raw_store.py`, CLI command handling,
   a focused traceability writer/model, and corresponding tests.
2. Linux onboarding: a new Linux Syslog parser package, registry metadata,
   samples, and parser tests. Existing vendor parsers remain unchanged.
3. Output and data readiness: focused exporters, unified-timeline writer,
   ML feature extractor, tests, and demonstrations.
4. Operational readiness: benchmark script, offline-bundle script/tests,
   `compose.yaml`, container test/docs, and the final validation runner.

## Implementation order

1. Complete (a), (b), and (d), then run focused tests.
2. Add (f), (g), and (h) using current CommonEvent/OCSF/JSONL contracts.
3. Add (i), (j), and (k) without introducing SIEM, database, dashboard, or
   cloud dependencies.
4. Add the final validation demo and run the full test suite after every
   milestone.

## Constraints retained

No old AegisGuard SIEM implementation, dashboard, database, or correlation
logic will be added or modified. Stable ULPF parsing, normalization, OCSF,
traceability, and semantic-pack contracts will be extended only where a
verified requirement gap requires it.
