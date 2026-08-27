# OCSF import adapter for the existing SIEM

## Scope

`src/aegisguard_ulpf/integration/siem_adapter.py` is the OCSF import adapter.
It reads ULPF OCSF JSONL records and writes the existing SIEM file-ingestion
format, `merged_logs.json`. It does not call or modify the detection engine,
correlation engine, dashboard, database, or any existing SIEM workflow.

```text
ULPF OCSF JSONL -> OCSF import adapter -> merged_logs.json -> existing SIEM
```

## Invocation

```python
from aegisguard_ulpf.integration.siem_adapter import adapt_ocsf_jsonl_to_siem

adapt_ocsf_jsonl_to_siem(
    "demo/output/ocsf_events.jsonl",
    "demo/output/merged_logs.json",
)
```

`demo/run_siem_integration.py` performs the same explicit conversion after
running the ULPF demo. No feature flag is needed: the adapter is opt-in and
does not alter the existing Windows ingestion path or any default workflow.

## Compatibility contract

The established in-repository SIEM input object has these fields:

| OCSF input | SIEM output | Handling |
| --- | --- | --- |
| `time` | `timestamp` | Unix milliseconds converted to UTC ISO-8601. |
| `severity_id` | `severity` | Numeric OCSF severity converted to the existing string level. |
| `metadata.product.vendor_name` | `vendor` | Copied when present. |
| `metadata.product.name` | `product` | Copied when present. |
| `raw_data.u_id` | `event_id` | Preserved for established ULPF OCSF records. |
| `raw_data.raw_id` | `raw_id` | Preserved for established ULPF OCSF records. |
| `src_endpoint.ip` | `source_ip` | Copied when present. |
| `dst_endpoint.ip` | `destination_ip` | Copied when present. |
| `user.name` or `actor.user.name` | `user` | Supports Authentication and actor-based OCSF classes. |
| `device.hostname` or `device.name` | `hostname` | Copied when present. |
| full OCSF object | `ulpf_original_event` | Preserved unchanged. |

Windows-specific OCSF records keep their raw event as an OCSF `raw_data`
string. Because that representation has no ULPF `u_id` or `raw_id`, the
connector emits `null` for those two legacy fields while preserving the whole
OCSF event, including its raw data, in `ulpf_original_event`. This avoids
inventing traceability identifiers.

The old SIEM repository is not part of this checkout. The compatibility
contract above is therefore the existing ULPF adapter contract, exercised by
`tests/integration/test_siem_adapter.py`; no SIEM source files are changed.

## Examples

- Input JSONL: `examples/ocsf_siem_import_input.jsonl`
- SIEM JSON list output: `examples/ocsf_siem_import_output.json`
- Windows Authentication OCSF compatibility is covered using
  `examples/windows_ocsf_4625.json` in the integration test.
