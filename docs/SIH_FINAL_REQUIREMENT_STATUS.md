# SIH26156 Requirement Status

| Requirement | Status | Evidence | Demo/command |
|---|---|---|---|
| (a) Raw preservation | Complete | RawEvidenceStore, hash chain, raw-event JSONL view | `ulpf verify <event-id>` |
| (b) Source parsing | Partial | FortiGate/Cisco/PAN-OS/Windows and Linux parser | `python demo/run_parser_validation.py` |
| (c) Taxonomy + OCSF | Complete | CommonEvent, validation, pinned OCSF bindings | `python demo/run_demo.py` |
| (d) Traceability | Complete | evidence manifest, traceability JSONL, trace CLI | `ulpf trace <event-id>` |
| (e) Onboarding | Complete | Registry, signed semantic packs, onboarding docs | `python demo/run_semantic_pack_demo.py` |
| (f) Unified visibility | Complete | CommonEvent timeline projection | `python demo/run_unified_visibility_validation.py` |
| (g) Data-lake export | Complete | JSONL/CSV and optional Parquet exporter | `python demo/run_data_pipeline_validation.py` |
| (h) ML readiness | Complete | deterministic feature CSV, no model | `python demo/run_data_pipeline_validation.py` |
| (i) Parser effort | Complete | measured file-size benchmark script | `python scripts/measure_parser_effort.py` |
| (j) Air gap | Complete | source/wheels/schemas/semantic-packs/checksums ZIP bundle plus local image export/checksum verifier | `python scripts/create_offline_bundle.py` |
| (k) Container | Implemented, runtime validation pending | single-service, network-isolated Compose runtime; Docker is unavailable in the validation environment | `docker compose up --build` |

Parquet requires the optional local `pyarrow` dependency. Linux automatic source detection remains a future enhancement; the Linux parser is available for registry registration. Docker Compose runtime execution requires Docker to be installed on the target host.
