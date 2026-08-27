# Windows Security Event adapter

## Purpose

The Windows Security Event adapter converts an externally supplied Windows
Security Event Log record into the ULPF `RawEvent` input contract. It does not
collect events from Windows, select a parser, normalize data, or produce OCSF.

## Input

`WindowsSecurityEventAdapter.adapt()` accepts either:

- a mapping containing a complete Windows Security event; or
- a JSON object string representing that event.

The mapping input is encoded as JSON for `RawEvent.raw`. A JSON string input
is retained exactly as received in `RawEvent.raw`.

## ULPF output

The adapter returns `RawEvent` with:

- `transport`: `windows_event_log`;
- `metadata.source.vendor`: `Microsoft`;
- `metadata.source.product`: `Windows Security`;
- `metadata.source.type`: `event_log`;
- `metadata.raw_event`: the complete structured Windows event.

This keeps the raw event available both as the ULPF raw payload and as a
structured metadata copy for source-aware downstream handling.

## Files changed

| File | Purpose |
|---|---|
| `src/aegisguard_ulpf/ingestion/windows.py` | Windows Security Event-to-`RawEvent` adapter. |
| `src/aegisguard_ulpf/ingestion/__init__.py` | Public adapter exports. |
| `tests/unit/ingestion/test_windows_adapter.py` | Adapter unit tests. |
| `examples/windows_security_event.json` | Sample Windows Security event input. |
| `examples/windows_security_ulpf_raw_event.json` | Sample adapter `RawEvent` output. |
