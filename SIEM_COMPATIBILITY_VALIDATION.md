# SIEM compatibility validation

## Scope and evidence

This is a read-only comparison of `AegisGuard-ULPF` with the public
[`Real-Hustlers/AegisGuard`](https://github.com/Real-Hustlers/AegisGuard)
repository at commit
[`653dec2afcfd92951888b3c2a1eaf05456493b28`](https://github.com/Real-Hustlers/AegisGuard/tree/653dec2afcfd92951888b3c2a1eaf05456493b28).
No SIEM or ULPF implementation files were changed for this validation.

## 1. `merged_logs.json` consumer

The SIEM's `backend/analyzer/ingestion/import_merge.py` creates
`backend/analyzer/output/merged_logs.json`. Its immediate consumer is
`backend/analyzer/ingestion/classifier.py`, which loads that file as a JSON
array. The classifier enriches each log and writes
`backend/analyzer/output/classified_logs.json`; the correlation engine then
consumes that classified output.

Relevant source files:

- [`import_merge.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/analyzer/ingestion/import_merge.py)
- [`classifier.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/analyzer/ingestion/classifier.py)
- [`correlation_engine.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/analyzer/ingestion/correlation_engine.py)

## 2. SIEM ingestion entry point

The working ingestion entry point is `POST /api/upload_logs` in
`backend/analyzer/app.py`. It expects one machine envelope:

```json
{
  "machine_id": "...",
  "hostname": "...",
  "os": "...",
  "logs": [
    { "record_id": 1, "...": "..." }
  ]
}
```

The endpoint writes the envelope to `backend/analyzer/test/<machine_id>.json`,
deduplicates entries using `record_id`, and invokes merge, classification, and
correlation. The SIEM's own collector posts this same envelope to the endpoint.

Relevant source files:

- [`app.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/analyzer/app.py)
- [`collector.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/collector/collector.py)

## 3. Expected event fields

`import_merge.py` reads these fields from every input log and creates a new
`merged_logs.json` record. `log_id`, `machine_id`, `hostname`, and `os` are
added from the machine envelope.

| SIEM field | Used by | Required for intended behavior |
| --- | --- | --- |
| `timestamp` | merger, classifier, correlation | Yes; correlation parses it as ISO-8601. |
| `event_type` | classifier and correlation rules | Yes. |
| `user` | classifier and brute-force grouping | Yes for authentication correlation. |
| `hostname` | correlation grouping and dashboard/database | Yes. |
| `source_ip` | classifier and brute-force grouping | Yes for authentication correlation. |
| `destination_ip` | incident data | Expected. |
| `process` | process/malware correlation | Yes for process activity. |
| `file_path` | incident data | Expected. |
| `severity` | classifier scoring | Expected; comparisons are case-insensitive. |
| `raw_log` | correlation incident construction and database | Yes once a correlation rule matches. |
| `record_id` | upload endpoint deduplication | Required for safe use of the HTTP ingestion endpoint. |

The SIEM uses a fixed event-type vocabulary. For the three Windows events in
scope, its collector maps 4625 to `FAILED_LOGIN` and 4688 to
`PROCESS_CREATED`. It maps 4624 to `LOGON_SUCCESS`, while the classifier and
the brute-force success-after-failure rule check for `SUCCESSFUL_LOGIN`.
This inconsistency already exists in the SIEM: a ULPF connector cannot assume
that `LOGON_SUCCESS` and `SUCCESSFUL_LOGIN` are interchangeable without an
explicit SIEM-owned decision.

Relevant source: [`parser.py`](https://github.com/Real-Hustlers/AegisGuard/blob/653dec2afcfd92951888b3c2a1eaf05456493b28/backend/collector/parser.py).

## 4. Comparison with the ULPF adapter

`src/aegisguard_ulpf/integration/siem_adapter.py` currently writes a JSON
array with:

```text
timestamp, severity, vendor, product, event_id, source_ip,
destination_ip, user, hostname, raw_id, ulpf_original_event
```

| SIEM requirement | ULPF adapter result | Compatibility |
| --- | --- | --- |
| JSON array | Produces a JSON array | Compatible only when writing directly to the SIEM merged-file location. |
| `timestamp` | ISO-8601 UTC timestamp | Compatible. |
| `severity` | Lowercase severity label | Compatible with classifier comparisons, which uppercase the value. |
| `user`, `hostname`, `source_ip`, `destination_ip` | Produced when available | Compatible. |
| `event_type` | Not produced | Incompatible: classification and correlation rules depend on it. |
| `process` | Not produced | Incompatible for 4688 process correlation. |
| `file_path` | Not produced | Missing expected SIEM field. |
| `raw_log` | Not produced; full OCSF is under `ulpf_original_event` | Incompatible when correlation constructs incident related-log text. |
| `machine_id`, `os`, `log_id` | Not produced | Missing for the merged-file/database contract; the SIEM merger normally supplies them. |
| machine upload envelope and `record_id` | Not produced | Cannot be posted directly to `/api/upload_logs`. |

The adapter's `event_id`, `raw_id`, `vendor`, `product`, and
`ulpf_original_event` are additive traceability information; they are not
fields selected by the SIEM merger for its analyzer contract.

## 5. Analyzer compatibility verdict

**The current `siem_adapter.py` output cannot be consumed directly by the old
AegisGuard SIEM pipeline.**

It can be deserialized as a JSON list by `classifier.py`, but it lacks
`event_type`, so known authentication and process rules cannot be selected.
It also lacks `raw_log`, which the correlation engine indexes directly after a
rule match, and it is not in the machine envelope required by
`/api/upload_logs`. Its output path (`demo/output/merged_logs.json`) is also
different from the SIEM analyzer's merged-file path.

Accordingly, direct consumption has not been validated and should be treated
as incompatible. This conclusion is limited to the inspected commit above;
no SIEM detection, correlation, dashboard, database, collector, or ULPF code
was changed.
