"""Integration coverage for the old AegisGuard SIEM merged-log contract."""

from __future__ import annotations

import json

from pathlib import Path

from aegisguard_ulpf.integration.siem_contract_mapper import (
    SIEM_INGESTION_LOG_FIELDS,
    SIEM_MERGED_LOG_FIELDS,
    map_ocsf_event_to_siem_contract,
    translate_ocsf_events_to_siem_ingestion_envelope,
    translate_ocsf_jsonl_to_siem_ingestion_envelope,
    translate_ocsf_jsonl_to_siem_merged_logs,
)
from aegisguard_ulpf.normalization.ocsf.windows import (
    map_windows_security_event_to_ocsf,
)


def authentication_event() -> dict:
    return {
        "class_uid": 3002,
        "activity_id": 1,
        "status_id": 1,
        "time": 1_788_299_400_000,
        "severity_id": 1,
        "metadata": {
            "product": {
                "vendor_name": "Microsoft",
                "name": "Windows Security",
            },
        },
        "raw_data": {
            "u_id": "EVT-ULPF-4624",
            "raw_id": "RAW-ULPF-4624",
        },
        "user": {"name": "alice"},
        "src_endpoint": {"ip": "192.0.2.42"},
        "device": {"hostname": "AUTH-SRV-01"},
    }


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def windows_process_event() -> dict:
    return {
        "EventID": 4688,
        "TimeCreated": "2026-08-27T09:32:00Z",
        "SubjectUserName": "administrator",
        "Computer": "WORKSTATION-02",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "NewProcessId": "1234",
        "CommandLine": "cmd.exe /c whoami",
    }


def test_authentication_ocsf_maps_to_siem_analyzer_event_type():
    original = authentication_event()

    mapped = map_ocsf_event_to_siem_contract(original, sequence=7)

    assert mapped["log_id"] == "LOG-000007"
    assert mapped["machine_id"] == "AUTH-SRV-01"
    assert mapped["hostname"] == "AUTH-SRV-01"
    assert mapped["os"] == "Windows"
    assert mapped["timestamp"] == "2026-09-01T21:50:00Z"
    assert mapped["event_type"] == "SUCCESSFUL_LOGIN"
    assert mapped["user"] == "alice"
    assert mapped["source_ip"] == "192.0.2.42"
    assert mapped["destination_ip"] == ""
    assert mapped["process"] == ""
    assert mapped["file_path"] == ""
    assert mapped["severity"] == "INFORMATIONAL"
    assert json.loads(mapped["raw_log"]) == original["raw_data"]
    assert mapped["event_id"] == "EVT-ULPF-4624"
    assert mapped["raw_id"] == "RAW-ULPF-4624"
    assert mapped["vendor"] == "Microsoft"
    assert mapped["product"] == "Windows Security"
    assert mapped["ulpf_original_event"] == original
    assert set(SIEM_MERGED_LOG_FIELDS).issubset(mapped)


def test_windows_log_event_maps_process_and_raw_log():
    original = map_windows_security_event_to_ocsf(windows_process_event())

    mapped = map_ocsf_event_to_siem_contract(original, sequence=1)

    assert mapped["event_type"] == "PROCESS_CREATED"
    assert mapped["machine_id"] == "WORKSTATION-02"
    assert mapped["hostname"] == "WORKSTATION-02"
    assert mapped["os"] == "Windows"
    assert mapped["user"] == "administrator"
    assert mapped["process"] == "cmd.exe"
    assert mapped["raw_log"] == original["raw_data"]
    assert json.loads(mapped["raw_log"])["EventID"] == 4688
    assert mapped["severity"] == "INFORMATIONAL"
    assert mapped["ulpf_original_event"] == original


def test_jsonl_translation_writes_expected_merged_logs_contract(tmp_path):
    process_event = map_windows_security_event_to_ocsf(windows_process_event())
    input_path = tmp_path / "ocsf_events.jsonl"
    output_path = tmp_path / "merged_logs.json"
    write_jsonl(input_path, [authentication_event(), process_event])

    result_path = translate_ocsf_jsonl_to_siem_merged_logs(
        input_path,
        output_path,
        machine_id="SIEM-IMPORT-01",
        os_name="Windows 11",
    )
    payload = json.loads(result_path.read_text(encoding="utf-8"))

    assert result_path == output_path
    assert isinstance(payload, list)
    assert [event["log_id"] for event in payload] == [
        "LOG-000001",
        "LOG-000002",
    ]
    assert [event["event_type"] for event in payload] == [
        "SUCCESSFUL_LOGIN",
        "PROCESS_CREATED",
    ]
    assert all(set(SIEM_MERGED_LOG_FIELDS).issubset(event) for event in payload)
    assert all(event["machine_id"] == "SIEM-IMPORT-01" for event in payload)
    assert all(event["os"] == "Windows 11" for event in payload)
    assert payload[0]["ulpf_original_event"] == authentication_event()
    assert payload[1]["ulpf_original_event"] == process_event


def test_ocsf_events_translate_to_the_siem_machine_ingestion_envelope(tmp_path):
    original = authentication_event()
    input_path = tmp_path / "ocsf_events.jsonl"
    output_path = tmp_path / "siem_upload.json"
    write_jsonl(input_path, [original])

    envelope = translate_ocsf_events_to_siem_ingestion_envelope(
        [original],
        machine_id="SIEM-IMPORT-01",
        hostname="AUTH-SRV-01",
        os_name="Windows 11",
    )
    result_path = translate_ocsf_jsonl_to_siem_ingestion_envelope(
        input_path,
        output_path,
        machine_id="SIEM-IMPORT-01",
        hostname="AUTH-SRV-01",
        os_name="Windows 11",
    )

    assert envelope["machine_id"] == "SIEM-IMPORT-01"
    assert envelope["hostname"] == "AUTH-SRV-01"
    assert envelope["os"] == "Windows 11"
    assert envelope["logs"][0]["record_id"] == "EVT-ULPF-4624"
    assert envelope["logs"][0]["event_type"] == "SUCCESSFUL_LOGIN"
    assert set(SIEM_INGESTION_LOG_FIELDS).issubset(envelope["logs"][0])
    assert "ulpf_original_event" not in envelope["logs"][0]
    assert json.loads(result_path.read_text(encoding="utf-8")) == envelope
