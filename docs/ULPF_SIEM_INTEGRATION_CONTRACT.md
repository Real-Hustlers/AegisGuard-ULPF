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
Integration Adapter
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
  "event_type": "OCSF-derived event type",
  "source_ip": "source address or null",
  "destination_ip": "destination address or null",
  "user": "user identifier or null",
  "hostname": "host/device identifier or null",
  "vendor": "product vendor or null",
  "product": "product name or null",
  "raw_event_reference": {
    "u_id": "ULPF event identifier",
    "raw_id": "ULPF raw-evidence identifier"
  }
}
```

The adapter is responsible only for converting transport, field names, and
representations. It does not classify, correlate, score, store, or visualize
events.

## 4. Field mapping

| OCSF field | SIEM field | Transformation |
|---|---|---|
| `time` | `timestamp` | Convert Unix epoch milliseconds to an ISO-8601 UTC timestamp. |
| `severity_id` | `severity` | Translate the OCSF numeric severity to the SIEM's existing severity value. |
| `class_uid`, `activity_id`, `type_uid` | `event_type` | Use the OCSF class/activity identity as the SIEM event-type value. |
| `src_endpoint.ip` | `source_ip` | Copy when present; otherwise emit `null`. |
| `dst_endpoint.ip` | `destination_ip` | Copy when present; otherwise emit `null`. |
| `user.name` or `actor.user` | `user` | Copy the available OCSF user identity; otherwise emit `null`. |
| `device.hostname` or `device.name` | `hostname` | Copy the available OCSF device identity; otherwise emit `null`. |
| `metadata.product.vendor_name` | `vendor` | Copy when present; otherwise emit `null`. |
| `metadata.product.name` | `product` | Copy when present; otherwise emit `null`. |
| `raw_data.u_id`, `raw_data.raw_id` | `raw_event_reference` | Preserve both ULPF traceability identifiers as an object. |

## 5. Non-modification guarantee

This integration contract does not require changes to the old AegisGuard SIEM.
The following remain unchanged:

- `classifier.py`;
- the ML model;
- `correlation_engine.py`;
- the database schema;
- the dashboard.

## 6. Development phases

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
