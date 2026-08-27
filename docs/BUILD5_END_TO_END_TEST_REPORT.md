# Build 5 End-to-End Integration Test Report

## 1. Test environment

| Item | Value |
| --- | --- |
| ULPF repository revision | `fe813b3` |
| Python | 3.14.6 (`.venv`) |
| Test type | Isolated, file-based integration test; no SIEM source was modified. |
| Windows test data | `examples/build5_windows_integration_cases.json` |
| ULPF test case | `tests/integration/test_build5_end_to_end.py` |
| SIEM contract under test | `translate_ocsf_events_to_siem_ingestion_envelope()` |
| SIEM runtime evidence | `SIEM_RUNTIME_VALIDATION.md`, using old SIEM commit `653dec2afcfd92951888b3c2a1eaf05456493b28` |

The current checkout does not contain the old SIEM source. The ULPF-to-SIEM
boundary was executed locally. The classifier/correlation result for Test 3
is the already recorded runtime validation against the external SIEM checkout;
it was inspected but not re-run in this checkout.

## 2. Integration flow inspected

```text
Windows Security event JSON
  -> WindowsSecurityEventAdapter
  -> RawEvent
  -> Windows CommonEvent / Windows OCSF mapper
  -> JsonlOutputWriter (raw_events, normalized_events, ocsf_events)
  -> OCSF SIEM contract mapper
  -> { machine_id, hostname, os, logs[] }
  -> old SIEM import_merge.py
  -> classifier.py / correlation_engine.py
```

Findings about the current boundary:

- Windows input is accepted as a supplied mapping or JSON object string. It
  is not a live Windows Event Log collector.
- `RawEvidenceStore` can preserve and integrity-check supplied raw bytes, but
  `demo/run_windows_siem_demo.py` writes a `RawEvent` JSONL view and does not
  instantiate `RawEvidenceStore`.
- `JsonlOutputWriter` emits `raw_events.jsonl`, `normalized_events.jsonl`, and
  `ocsf_events.jsonl`.
- The actual SIEM import format is a machine envelope:

  ```json
  {
    "machine_id": "...",
    "hostname": "...",
    "os": "...",
    "logs": [{"record_id": "...", "timestamp": "...", "event_type": "..."}]
  }
  ```

  This is produced by `translate_ocsf_jsonl_to_siem_ingestion_envelope()` and
  is consumed by the old SIEM's `import_merge.py`. A post-merge
  `merged_logs.json` is not the input to that importer.

## 3. Test cases and results

| ID | Input | Expected result | Actual result | Status |
| --- | --- | --- | --- | --- |
| 1 | One 4624 successful login | Raw preservation, CommonEvent, OCSF Authentication Success, and SIEM receipt | Raw/normalized/OCSF JSONL records were written; evidence integrity passed when `RawEvidenceStore` was explicitly composed; SIEM envelope event type was `SUCCESSFUL_LOGIN`. | Pass at the ULPF boundary |
| 2 | Three 4625 failures | Preserve and translate every event | Three evidence records and three OCSF records were produced; SIEM envelope contained three `FAILED_LOGIN` logs. | Pass |
| 3 | 4625, 4625, 4625, 4624 | SIEM correlation identifies brute force | Existing SIEM runtime validation processed the equivalent three-failure/success sequence, classified all inputs, and generated `Multiple Failed Login Attempts` (HIGH) and `Possible Brute Force Attack` (CRITICAL). | Pass, historical runtime evidence |
| 4 | One 4688 process creation | OCSF Process Activity and SIEM receipt | OCSF class UID was `1007`, process name was `cmd.exe`, and SIEM envelope event type was `PROCESS_CREATED`. | Pass |
| 5a | Malformed Windows JSON | No crash, raw preservation, recorded validation failure | The adapter raises `ValueError` safely, but rejects before `RawEvidenceStore` and has no failure-record output. | Fail against expected behavior |
| 5b | Missing Event ID / corrupted fields | No crash, preserve raw, validation failure | The adapter accepts and raw evidence can be persisted before mapping; the Windows mapper then rejects safely. No validation-failure record is emitted. | Partial |
| 5c | Missing Windows timestamp | Validation failure recorded | The mapper substitutes the observed processing time and generates an event; no validation failure is emitted. | Fail against expected behavior |
| 6a | OCSF missing `class_uid` or `time` | Adapter rejects safely | The validator rejects both; the SIEM contract translator also raises `ValueError` for these inputs. | Pass |
| 6b | OCSF `severity_id: 42` | Adapter rejects safely | The validator rejects it, but the SIEM contract translator maps it to `UNKNOWN` and accepts it. | Fail against expected behavior |

## 4. Input events

The versioned Build 5 fixture contains:

- 4624: `build5-user` login from `10.5.0.10` to `BUILD5-WIN-01`;
- three 4625 events for the same user, host, and source address at one-minute
  intervals;
- 4688: `cmd.exe /c whoami` launched by `build5-user`;
- malformed, incomplete, and corrupted Windows event variants;
- invalid OCSF variants with missing `class_uid`, missing `time`, and invalid
  `severity_id`.

See `examples/build5_windows_integration_cases.json` for the exact input.

## 5. Commands and test output

Executed focused test command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider tests\integration\test_build5_end_to_end.py
```

Result:

```text
6 passed, 3 xfailed in 0.74s
```

The three strict expected failures are intentionally retained as executable
evidence of Tests 5a, 5c, and 6b. They do not change runtime behavior.

`git diff --check` completed without whitespace errors.

## 6. Bugs found and minimal fixes

1. **Invalid raw Windows input is not evidence-preserved or failure-recorded.**
   The adapter parses input before an evidence record exists, and no rejection
   ledger exists at this boundary. Minimal fix: have the existing ingestion
   coordinator store supplied raw bytes in `RawEvidenceStore` before parsing,
   then record the adapter/mapping error against that evidence reference.

2. **A missing Windows timestamp silently falls back to observed time.**
   This conflicts with this test's required failure-record behavior. Minimal
   fix: choose an explicit timestamp policy at the Windows boundary: reject
   absent timestamps with a recorded validation error, or retain the fallback
   only if it is explicitly declared acceptable for the source.

3. **The SIEM contract translator does not enforce OCSF validation.**
   Invalid `severity_id` values become `UNKNOWN`. Minimal fix: validate each
   input with the existing `OCSFValidator` before translation and raise its
   validation errors. This is a boundary guard, not a change to the OCSF
   mapper or SIEM.

No fixes were implemented as part of this independent test activity.

## 7. Data-loss verification

- For valid Windows events, raw event bytes were preserved in
  `RawEvidenceStore`; every generated evidence record returned `integrity:
  PASS`.
- The ULPF Windows OCSF mapper preserves the source Windows JSON in
  `raw_data` and places remaining fields under `unmapped.windows_security`.
- The direct ULPF SIEM contract record retains `ulpf_original_event`.
- The old SIEM's `import_merge.py` intentionally projects the machine envelope
  to its fixed schema and drops additive ULPF fields such as
  `ulpf_original_event`. This is known downstream schema projection, not a
  silent ULPF mapper loss.
- Invalid inputs are the exception: malformed Windows JSON is not
  automatically preserved by the current adapter path, as recorded in Test
  5a.

## 8. Final integration status

**Conditional pass.** The supported Windows 4624, 4625, and 4688 paths
produce valid OCSF events and the exact old-SIEM ingestion envelope. Existing
runtime evidence confirms the old SIEM can import, classify, correlate, and
produce brute-force incidents from the translated data without SIEM changes.

The integration does not yet meet the requested invalid-input handling
guarantee: raw malformed input has no automatic evidence/failure record,
missing Windows timestamps are silently substituted, and invalid OCSF
severity values are not rejected at the SIEM translation boundary.
