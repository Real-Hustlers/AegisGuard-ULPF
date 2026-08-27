# Mapping Fidelity Measurement

## Purpose

The Build 6 fidelity layer answers, for each normalized event, what happened
to every meaningful field audited at the parser/normalization boundary. It is
transparent metadata: it does not modify vendor parsers, the normalization
engine, the returned `CommonEvent`, OCSF mapping, SIEM translation, or an
existing workflow.

The existing `aegisguard_ulpf.normalization.fidelity` audit remains the source
of truth for field classification. `aegisguard_ulpf.fidelity` exposes its
concise public report and JSON output APIs.

## Field dispositions

| Disposition | Meaning |
| --- | --- |
| `mapped` | A meaningful parser field is represented semantically in `CommonEvent`. |
| `unmapped` | A received field is preserved as vendor/unmapped context but has no semantic `CommonEvent` representation. |
| `dropped` | A caller deliberately excluded the field. It remains named in `field_details`; it is never hidden. |

`detected_fields` is the total number of meaningful audited fields. Control
identifiers (`u_id`, `raw_id`, and `mapping_status`) and absent values are not
counted as semantic source data. This avoids reporting artificial coverage for
empty fields.

## Use after normalization

```python
from aegisguard_ulpf.fidelity import calculate_fidelity, write_fidelity_report
from aegisguard_ulpf.normalization.engine import NormalizationEngine

event = NormalizationEngine().normalize(
    parser_fields,
    observed_time=observed_time,
)

report = calculate_fidelity(
    parser_fields,
    event,
    dropped_fields=("debug_blob",),
)

write_fidelity_report(report, "demo/output/fidelity_report.json")
```

`calculate_fidelity()` is called after `NormalizationEngine.normalize()` and
does not mutate the `CommonEvent` it receives.

## Output

```json
{
  "detected_fields": 3,
  "mapped_fields": 2,
  "unmapped_fields": 1,
  "dropped_fields": 0,
  "coverage": 66.7,
  "field_details": {
    "src_ip": "mapped",
    "dst_ip": "mapped",
    "vendor_fields.vendor_field_x": "unmapped"
  }
}
```

Coverage is `(mapped_fields / detected_fields) * 100`, rounded to one decimal.
For an empty audited event, coverage is `0.0` so consumers never encounter a
division error.
