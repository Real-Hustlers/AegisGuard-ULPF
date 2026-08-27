"""Tests for the Build 6 public mapping-fidelity measurement layer."""

from __future__ import annotations

import json

from datetime import datetime, timezone

from aegisguard_ulpf.fidelity import calculate_fidelity, write_fidelity_report
from aegisguard_ulpf.normalization.engine import NormalizationEngine


NOW = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)


def _fields() -> dict:
    return {
        "u_id": "EVT-FIDELITY-001",
        "raw_id": "RAW-FIDELITY-001",
        "timestamp": "2026-09-01T10:00:00Z",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "category": "network_activity",
        "type": "traffic",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
    }


def _normalized(fields: dict):
    return NormalizationEngine().normalize(
        fields,
        observed_time=NOW,
        processed_time=NOW,
    )


def test_all_audited_fields_mapped_has_full_coverage():
    fields = _fields()
    event = _normalized(fields)
    original = event.model_dump()

    report = calculate_fidelity(fields, event)

    assert report.detected_fields == report.mapped_fields
    assert report.unmapped_fields == 0
    assert report.dropped_fields == 0
    assert report.coverage == 100.0
    assert report.field_details["src_ip"] == "mapped"
    assert event.model_dump() == original


def test_partial_mapping_reports_unmapped_fields():
    fields = _fields()
    fields["vendor_fields"] = {"vendor_field_x": "not semantically mapped"}

    report = calculate_fidelity(fields, _normalized(fields))

    assert report.unmapped_fields > 0
    assert report.field_details["vendor_fields.vendor_field_x"] == "unmapped"
    assert report.coverage < 100.0


def test_dropped_fields_remain_visible_in_json_output(tmp_path):
    fields = _fields()
    fields["debug_blob"] = "intentionally excluded"
    report = calculate_fidelity(
        fields,
        _normalized(fields),
        dropped_fields=["debug_blob"],
    )

    output_path = write_fidelity_report(report, tmp_path / "fidelity_report.json")
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert report.dropped_fields == 1
    assert report.field_details["debug_blob"] == "dropped"
    assert payload["field_details"]["debug_blob"] == "dropped"


def test_empty_event_has_zero_coverage_without_division_error():
    report = calculate_fidelity({}, None, mapping_status="incomplete")

    assert report.detected_fields == 0
    assert report.mapped_fields == 0
    assert report.unmapped_fields == 0
    assert report.dropped_fields == 0
    assert report.coverage == 0.0
    assert report.field_details == {}
