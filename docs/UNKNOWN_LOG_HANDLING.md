# Unknown / Adaptive Log Handling

## Purpose

`aegisguard_ulpf.fallback` provides an isolated, evidence-backed path for a
log that has no dedicated semantic parser. It complements the existing Tier 0
structural fallback; it does not change parser selection, normalization, OCSF,
SIEM translation, or any detection/correlation workflow.

## Behavior

1. The handler stores the exact incoming bytes in `RawEvidenceStore` before
   detection.
2. It detects only structural format (`json`, `syslog`, `cef`, `leef`, `xml`,
   `key_value`, `csv`, or `plain_text`) and non-authoritative vendor/product
   hints.
3. It returns a `FallbackEvent` / `UnknownEvent`; it does not assign security
   category, event type, outcome, severity, or action.
4. It keeps `fidelity_available: true` to indicate the Build 6 field-fidelity
   API can be applied once a structural or semantic representation is chosen.

## Usage

```python
from aegisguard_ulpf.fallback import handle_unknown_log
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore

event = handle_unknown_log(
    raw_bytes,
    evidence_store=RawEvidenceStore("evidence"),
    identity_context={"source": "unknown.log", "sequence": 1},
    transport="file",
)
```

Example result:

```json
{
  "status": "unknown_format",
  "detected_format": "syslog",
  "possible_vendor": "unknown",
  "possible_product": "unknown",
  "raw_preserved": true,
  "fidelity_available": true
}
```

The returned record also includes the evidence `event_id`, `raw_id`, and
`raw_sha256`, allowing the exact original raw bytes to be retrieved and
verified. Unknown logs are therefore retained for future parser onboarding
instead of being discarded.
