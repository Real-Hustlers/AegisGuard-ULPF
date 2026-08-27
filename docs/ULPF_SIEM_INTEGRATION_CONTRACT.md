# ULPF–SIEM Integration Contract

## 1. System boundary

### AegisGuard-ULPF responsibility

AegisGuard-ULPF is the SIH26156 Universal Log Pre-processing Framework. Its
responsibility ends after it has preserved raw evidence, parsed supported log
sources, normalized them, and emitted validated OCSF JSONL records.

ULPF owns:

- raw-log preservation and traceability references;
- source and event-family detection;
- parsing and semantic mapping;
- CommonEvent normalization;
- validated OCSF JSONL output.

### Old AegisGuard SIEM responsibility

The old AegisGuard SIEM remains the cybersecurity monitoring and analysis
system. It consumes adapter-produced events and retains responsibility for:

- classification through `classifier.py`;
- ML-model use;
- correlation through `correlation_engine.py`;
- persistence using its existing database schema;
- dashboard visualization.

## 2. Current data flow

```text
Windows Logs
    |
    v
AegisGuard-ULPF
    |
    v
Validated OCSF JSONL
    |
    v
SIEM Contract Translation Layer
    |
    v
Old AegisGuard SIEM
```

The adapter is the only boundary between the two systems. ULPF does not invoke
SIEM classifier, correlation, database, or dashboard code directly.

## 3. Integration layer responsibility

### Input from ULPF

The adapter consumes one JSON object per line from ULPF's OCSF JSONL output.
The input record is a validated OCSF event and includes, where available:

- `time` as Unix epoch milliseconds;
- `severity_id`;
- OCSF `class_uid`, `activity_id`, and `type_uid`;
- `src_endpoint.ip` and `dst_endpoint.ip`;
- `metadata.product.vendor_name` and `metadata.product.name`;
- `raw_data.u_id` and `raw_data.raw_id` for traceability.

### Output to the SIEM

The adapter emits one SIEM ingestion event per input OCSF JSONL record. The
adapter-owned event envelope uses the following SIEM-facing fields:

```json
{
  "timestamp": "ISO-8601 UTC timestamp",
  "severity": "SIEM severity value",
  "vendor": "product vendor or null",
  "product": "product name or null",
  "event_id": "ULPF event identifier or null",
  "source_ip": "source address or null",
  "destination_ip": "destination address or null",
  "user": "user identifier or null",
  "hostname": "host/device identifier or null",
  "raw_id": "ULPF raw-evidence identifier or null",
  "ulpf_original_event": "the unchanged OCSF event"
}
```

The adapter is responsible only for converting transport, field names, and
representations. It does not classify, correlate, score, store, or visualize
events.

## 4. Build #12 SIEM contract translation

`src/aegisguard_ulpf/integration/siem_contract_mapper.py` translates ULPF
OCSF JSONL into the old SIEM's post-merge `merged_logs.json` record format.
It preserves every legacy adapter field and `ulpf_original_event`, then adds
the fields consumed by the SIEM classifier and correlation engine:

```text
log_id, machine_id, hostname, os, timestamp, event_type, user,
source_ip, destination_ip, process, file_path, severity, raw_log
```

The entry point is `translate_ocsf_jsonl_to_siem_merged_logs()`. It is an
explicit ULPF-side file conversion and does not call, configure, or change the
SIEM analyzer, classifier, correlation engine, database, or dashboard.

For the SIEM's actual `POST /api/upload_logs` boundary,
`translate_ocsf_jsonl_to_siem_ingestion_envelope()` writes the required
per-machine JSON object with `machine_id`, `hostname`, `os`, and `logs`.
Each log receives a stable `record_id` and the exact fields consumed by
`import_merge.py`. The old SIEM merger intentionally projects that envelope
to its merged-log schema, so use the direct merged-log translator when the
output file itself must retain `ulpf_original_event` and other ULPF fields.

For the initially supported Windows mappings, the translator emits the SIEM
event vocabulary used by its analyzer:

| OCSF identity | SIEM `event_type` |
|---|---|
| Authentication (`class_uid: 3002`), Logon (`activity_id: 1`), Success (`status_id: 1`) | `SUCCESSFUL_LOGIN` |
| Authentication (`class_uid: 3002`), Logon (`activity_id: 1`), Failure (`status_id: 2`) | `FAILED_LOGIN` |
| Process Activity (`class_uid: 1007`), Launch (`activity_id: 1`) | `PROCESS_CREATED` |

The mapper rejects unsupported class/activity/status combinations rather than
emitting an invented SIEM event type. `raw_data` becomes `raw_log`: a raw-data
string is preserved verbatim, while the established ULPF traceability object
is serialized as canonical JSON. `machine_id` and `os` can be supplied as
translation options; otherwise machine ID falls back to the hostname and OS is
inferred as `Windows` only for Microsoft Windows products, or `UNKNOWN`.

The original `siem_adapter.py` remains available and unchanged as the legacy
adapter. Build #12 does not remove its fields or modify existing Windows
ingestion.

## 5. Field mapping

| OCSF field | SIEM field | Transformation |
|---|---|---|
| `time` | `timestamp` | Convert Unix epoch milliseconds to an ISO-8601 UTC timestamp. |
| `severity_id` | `severity` | Translate the OCSF numeric severity to the SIEM's existing severity value. |
| `src_endpoint.ip` | `source_ip` | Copy when present; otherwise emit `null`. |
| `dst_endpoint.ip` | `destination_ip` | Copy when present; otherwise emit `null`. |
| `user.name` or `actor.user.name` | `user` | Copy the available OCSF user identity; otherwise emit `null`. |
| `device.hostname` or `device.name` | `hostname` | Copy the available OCSF device identity; otherwise emit `null`. |
| `metadata.product.vendor_name` | `vendor` | Copy when present; otherwise emit `null`. |
| `metadata.product.name` | `product` | Copy when present; otherwise emit `null`. |
| `raw_data.u_id` | `event_id` | Copy when the OCSF record carries the ULPF traceability object; otherwise emit `null`. |
| `raw_data.raw_id` | `raw_id` | Copy when the OCSF record carries the ULPF traceability object; otherwise emit `null`. |
| complete OCSF record | `ulpf_original_event` | Preserve the unmodified OCSF event for traceability and forward compatibility. |

## 6. Non-modification guarantee

This integration contract does not require changes to the old AegisGuard SIEM.
The following remain unchanged:

- `classifier.py`;
- the ML model;
- `correlation_engine.py`;
- the database schema;
- the dashboard.

## 7. Development phases

### Phase 1: Create adapter

Create the boundary adapter that converts ULPF OCSF JSONL records into the
defined SIEM ingestion-event envelope.

### Phase 2: Test with sample OCSF events

Validate the adapter with representative ULPF OCSF JSONL records.

### Phase 3: Connect Windows logs

Provide Windows log input to the ULPF side of the boundary and continue using
the same OCSF-to-adapter contract.

### Phase 4: End-to-end demo

Demonstrate the complete flow from Windows logs through ULPF, OCSF, the
adapter, and the existing SIEM.
