"""End-to-end evidence coverage for the five-source SIH dashboard demo."""

from __future__ import annotations

import json

from pathlib import Path

from demo.run_multi_vendor_demo import INPUT_DIR, run_demo
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator


def _jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_multi_vendor_demo_generates_traceable_dashboard_artifacts(tmp_path):
    output = tmp_path / "output"
    evidence = tmp_path / "evidence"

    result = run_demo(
        input_dir=INPUT_DIR,
        output_dir=output,
        evidence_dir=evidence,
    )

    assert result.sources_processed == 5
    assert result.events_generated == 9
    assert result.ocsf_events == 9
    assert result.traceability_passed is True

    raw_events = _jsonl(output / "raw_events.jsonl")
    normalized_events = _jsonl(output / "normalized_events.jsonl")
    ocsf_events = _jsonl(output / "ocsf_events.jsonl")
    merged_logs = json.loads((output / "merged_logs.json").read_text(encoding="utf-8"))

    assert len(raw_events) == len(normalized_events) == len(ocsf_events) == 9
    assert len(merged_logs) == 9
    assert {
        (event["vendor"]["vendor"], event["vendor"]["product"])
        for event in normalized_events
    } == {
        ("Fortinet", "FortiGate"),
        ("Cisco", "ASA"),
        ("Palo Alto Networks", "PAN-OS"),
        ("Suricata", "IDS"),
        ("Linux", "Syslog"),
    }

    raw_ids = {event["raw_id"] for event in raw_events}
    assert {event["traceability"]["raw_id"] for event in normalized_events} == raw_ids
    assert {event["raw_data"]["raw_id"] for event in ocsf_events} == raw_ids
    assert all(event["raw_sha256"] for event in raw_events)
    assert all(event["details"]["raw_sha256"] for event in normalized_events)
    assert all(event["raw_data"]["raw_sha256"] for event in ocsf_events)
    assert all(OCSFValidator().validate(event).valid for event in ocsf_events)

    classes = {event["class_name"] for event in ocsf_events}
    assert {
        "Network Activity",
        "Authentication",
        "Detection Finding",
        "Process Activity",
    }.issubset(classes)
