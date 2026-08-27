# Build #14: End-to-End Integration Demo Plan

## Scope and boundary

Build #14 will demonstrate a file-based path from representative Windows
Security events through AegisGuard-ULPF and into the existing AegisGuard SIEM
ingestion contract. It will not modify the SIEM, its detection logic, database
schema, correlation engine, or dashboard.

The demo will reuse existing ULPF adapters, Windows mappings, output writers,
and SIEM contract translation APIs. It is not a live Windows Event Log
collector.

## Current pipeline status

| Stage | Existing implementation | Status |
| --- | --- | --- |
| Windows input adaptation | `ingestion/windows.py` (`WindowsSecurityEventAdapter`) | Available; accepts a supplied JSON object or JSON string. |
| Raw preservation | `RawEvidenceStore` and `RawEvent` | Available. |
| Generic parsing | `core/pipeline.py`, `DetectionEngine`, `ParserRegistry` | Available, but no Windows Security parser is registered. |
| Generic normalization | `normalization/engine.py` | Available for the generic parser flow. |
| Windows semantic normalization | `normalization/ocsf/windows.py` | Available for Event IDs 4624, 4625, and 4688; creates a `CommonEvent` and OCSF event. |
| OCSF output | `outputs/json_file.py` (`JsonlOutputWriter`) | Available; writes raw, normalized, and OCSF JSONL streams. |
| SIEM contract translation | `integration/siem_contract_mapper.py` | Available; translates OCSF JSONL into the legacy SIEM upload envelope. |
| Runtime compatibility | Build #13 validation | Verified against the existing SIEM without SIEM source changes. |

```text
Windows Security JSON object
  -> WindowsSecurityEventAdapter
  -> map_windows_security_event_to_common_event()
  -> map_windows_security_event_to_ocsf()
  -> JsonlOutputWriter.ocsf_events.jsonl
  -> translate_ocsf_jsonl_to_siem_ingestion_envelope()
  -> SIEM upload envelope
```

The generic parser/normalization pipeline is intentionally not in this path:
the parser registry has no Windows Security parser, while the existing Windows
mapping module already provides the supported semantic path.

## Missing connections

1. The Windows adapter is not a live Windows Event Log collector. The demo
   must use committed sample Windows event JSON and must not claim capture
   through `Get-WinEvent` or another Windows API.
2. `demo/run_demo.py` demonstrates the FortiGate/generic path. It neither uses
   the Windows Security mappings nor the SIEM contract translator.
3. `demo/run_siem_integration.py` invokes the earlier general SIEM adapter; it
   does not produce the upload envelope used by the validated legacy-SIEM path.
4. No single runner currently writes Windows raw/normalized/OCSF artifacts and
   produces the SIEM contract artifact from the resulting OCSF JSONL file.
5. The SIEM repository is external. An optional runtime demonstration must be
   given an explicit local SIEM checkout path and must not edit its source.

## Files required for the demo

| File | Action | Purpose |
| --- | --- | --- |
| `demo/run_windows_siem_demo.py` | Add | Orchestrate existing Windows mapping, JSONL writer, and SIEM envelope translator. |
| `examples/windows_security_demo_events.json` | Add | Versioned deterministic fixture containing only 4624, 4625, and 4688 events. |
| `tests/integration/test_demo_windows_siem_flow.py` | Add | Verify output artifacts, OCSF records, and the SIEM ingestion-envelope contract. |
| `BUILD14_DEMO_PLAN.md` | Added now | Build plan and run instructions. |

The runner must reuse these modules without modification:

- `WindowsSecurityEventAdapter` and Windows raw-event helpers;
- `map_windows_security_event_to_common_event()` and
  `map_windows_security_event_to_ocsf()`;
- `JsonlOutputWriter`;
- `translate_ocsf_jsonl_to_siem_ingestion_envelope()`.

No old-SIEM file is an implementation target.

## Minimal implementation steps

1. Add a versioned fixture with representative Event IDs 4624, 4625, and 4688.
   Include multiple 4625 events only when demonstrating the current SIEM
   correlation behavior.
2. Add a Windows-focused demo runner that reads the fixture and uses the
   existing adapter, preserving every input event verbatim in the raw artifact.
3. Persist raw inputs through `RawEvidenceStore` where evidence artifacts are
   required, then use the existing Windows raw-event mapping helpers for
   semantic conversion. Do not register a new Windows parser.
4. Write the existing ULPF artifact set:

   ```text
   <output-dir>/raw_events.jsonl
   <output-dir>/normalized_events.jsonl
   <output-dir>/ocsf_events.jsonl
   ```

5. Pass `ocsf_events.jsonl` to
   `translate_ocsf_jsonl_to_siem_ingestion_envelope()` and write
   `<output-dir>/siem_ingestion_envelope.json`.
6. Add focused tests using a temporary output directory. Assert OCSF JSONL
   exists, the envelope is valid JSON, required legacy fields are present, and
   `ulpf_original_event` is retained where the translation contract permits it.
7. For an opt-in runtime demo only, accept a supplied SIEM checkout path and
   invoke its existing import, classifier, and correlation commands against
   the generated envelope. This operates on runtime data only, never SIEM
   source files.

## Complete-demo commands

The exact CLI option names are Build #14 implementation work. The planned
commands are:

```powershell
# ULPF-only, deterministic artifact generation
.\.venv\Scripts\python.exe demo\run_windows_siem_demo.py

# Focused regression coverage
.\.venv\Scripts\python.exe -m pytest -q tests\integration\test_demo_windows_siem_flow.py

# Full ULPF suite and whitespace validation
.\.venv\Scripts\python.exe -m pytest -q
git diff --check

# Optional runtime path against an explicit local SIEM checkout
python demo\run_windows_siem_demo.py --siem-root C:\path\to\AegisGuard
```

The default command should stop after generating ULPF JSONL plus the SIEM
upload envelope, allowing this repository to run without the old SIEM checkout
or its Python dependencies.

## Risks and controls

| Risk | Control |
| --- | --- |
| Windows adapter is not a live collector | Use static sample data and label this as a file-based demo. |
| Only 4624, 4625, and 4688 are mapped | Keep the fixture within this set and retain unmapped Windows fields. |
| Generic parser registry does not parse Windows Security | Use the specialized Windows mapping module; do not change parser architecture. |
| Re-running JSONL can append duplicates | Use a fresh caller-selected output directory or a dedicated run directory. |
| Raw evidence and specialized mapping have separate entry points | Use evidence-backed raw events and add a traceability assertion to the demo test. |
| Legacy SIEM import projects to a fixed schema | Preserve `ulpf_original_event` in ULPF translation output; document that SIEM projection may not retain extras. |
| SIEM runtime dependencies differ from the ULPF virtual environment | Keep runtime execution optional and use the SIEM checkout's established environment. |
| Runtime demo writes SIEM test/import data | Require an explicit `--siem-root` and a disposable or dedicated SIEM checkout. |

## Acceptance criteria

The completed demo will produce the following artifacts from Windows sample
events:

```text
demo/output/<run>/raw_events.jsonl
demo/output/<run>/normalized_events.jsonl
demo/output/<run>/ocsf_events.jsonl
demo/output/<run>/siem_ingestion_envelope.json
```

It will demonstrate the existing Windows-to-OCSF mappings and the existing
SIEM contract translation without modifying old SIEM code, detections,
correlation, database schema, dashboard, or ULPF core architecture.
