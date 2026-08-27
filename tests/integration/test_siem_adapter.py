import json
from pathlib import Path

from aegisguard_ulpf.integration.siem_adapter import (
    SIEM_MERGED_LOGS_FILENAME,
    adapt_ocsf_jsonl_to_siem,
    map_ocsf_event_to_siem,
    read_ocsf_jsonl,
)


def ocsf_event() -> dict:
    return {
        "time": 1_778_064_000_123,
        "severity_id": 4,
        "metadata": {
            "product": {
                "vendor_name": "Example Security",
                "name": "Example Firewall",
            },
        },
        "raw_data": {
            "u_id": "EVT-ULPF-001",
            "raw_id": "RAW-ULPF-001",
        },
        "src_endpoint": {"ip": "192.0.2.10"},
        "dst_endpoint": {"ip": "198.51.100.20"},
        "actor": {"user": {"name": "alice"}},
        "device": {"hostname": "fw-01"},
    }


def write_ocsf_jsonl(path, events: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(event) + "\n"
            for event in events
        ),
        encoding="utf-8",
    )


def test_ocsf_jsonl_input_loads(tmp_path):
    input_path = tmp_path / "ocsf_events.jsonl"
    event = ocsf_event()
    write_ocsf_jsonl(input_path, [event])

    assert read_ocsf_jsonl(input_path) == [event]


def test_ocsf_fields_map_to_siem_fields():
    mapped = map_ocsf_event_to_siem(ocsf_event())

    assert mapped == {
        "timestamp": "2026-05-06T10:40:00.123000Z",
        "severity": "high",
        "vendor": "Example Security",
        "product": "Example Firewall",
        "event_id": "EVT-ULPF-001",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "user": "alice",
        "hostname": "fw-01",
        "raw_id": "RAW-ULPF-001",
        "ulpf_original_event": ocsf_event(),
    }


def test_traceability_and_original_ocsf_event_are_preserved(tmp_path):
    input_path = tmp_path / "ocsf_events.jsonl"
    original = ocsf_event()
    write_ocsf_jsonl(input_path, [original])

    output_path = adapt_ocsf_jsonl_to_siem(input_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert output_path.name == SIEM_MERGED_LOGS_FILENAME
    assert payload[0]["event_id"] == original["raw_data"]["u_id"]
    assert payload[0]["raw_id"] == original["raw_data"]["raw_id"]
    assert payload[0]["ulpf_original_event"] == original


def test_output_is_valid_json_array_for_every_ocsf_input_event(tmp_path):
    input_path = tmp_path / "ocsf_events.jsonl"
    first = ocsf_event()
    second = ocsf_event()
    second["raw_data"] = {
        "u_id": "EVT-ULPF-002",
        "raw_id": "RAW-ULPF-002",
    }
    write_ocsf_jsonl(input_path, [first, second])

    output_path = adapt_ocsf_jsonl_to_siem(
        input_path,
        tmp_path / "output" / SIEM_MERGED_LOGS_FILENAME,
    )

    with output_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    assert isinstance(payload, list)
    assert [event["event_id"] for event in payload] == [
        "EVT-ULPF-001",
        "EVT-ULPF-002",
    ]


def test_windows_authentication_ocsf_uses_top_level_user_without_changing_contract():
    repository_root = Path(__file__).resolve().parents[2]
    original = json.loads(
        (repository_root / "examples" / "windows_ocsf_4625.json").read_text(
            encoding="utf-8"
        )
    )

    mapped = map_ocsf_event_to_siem(original)

    assert mapped["timestamp"] == "2026-08-27T09:31:00Z"
    assert mapped["severity"] == "low"
    assert mapped["vendor"] == "Microsoft"
    assert mapped["product"] == "Windows Security"
    assert mapped["source_ip"] == "10.0.0.5"
    assert mapped["user"] == "test"
    assert mapped["hostname"] == "SERVER-01"
    assert mapped["event_id"] is None
    assert mapped["raw_id"] is None
    assert mapped["ulpf_original_event"] == original


def test_documented_ocsf_import_example_matches_adapter_output(tmp_path):
    repository_root = Path(__file__).resolve().parents[2]
    input_path = repository_root / "examples" / "ocsf_siem_import_input.jsonl"
    expected_path = repository_root / "examples" / "ocsf_siem_import_output.json"

    output_path = adapt_ocsf_jsonl_to_siem(
        input_path,
        tmp_path / SIEM_MERGED_LOGS_FILENAME,
    )

    assert json.loads(output_path.read_text(encoding="utf-8")) == json.loads(
        expected_path.read_text(encoding="utf-8")
    )
