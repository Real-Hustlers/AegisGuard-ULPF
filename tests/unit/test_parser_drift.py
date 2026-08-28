"""Tests for the isolated parser-fidelity drift detector."""

import json

from datetime import datetime, timezone

from aegisguard_ulpf.drift import (
    build_parser_drift_report,
    detect_parser_drift,
)
from aegisguard_ulpf.fidelity import calculate_fidelity
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from demo.run_parser_drift_demo import generate_drift_report


def _detect(previous: float, current: float):
    return detect_parser_drift(
        previous_coverage=previous,
        current_coverage=current,
        vendor="Fortigate",
        product="FortiGate",
        event_type="Traffic",
    )


def test_coverage_decrease_generates_a_drift_alert():
    alert = _detect(95, 65)

    assert alert is not None
    assert alert.to_dict() == {
        "type": "PARSER_DRIFT",
        "source": "Fortigate",
        "product": "FortiGate",
        "event_type": "Traffic",
        "previous": "95%",
        "current": "65%",
        "change": "-30%",
        "threshold": "20%",
    }


def test_stable_coverage_does_not_generate_an_alert():
    assert _detect(95, 95) is None


def test_small_coverage_change_is_ignored():
    assert _detect(95, 80) is None


def test_demo_creates_calculated_parser_drift_evidence(tmp_path):
    output_path = tmp_path / "parser_drift" / "drift_report.json"

    report = generate_drift_report(output_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload == report
    assert payload["vendor"] == "Fortinet"
    assert payload["product"] == "FortiGate"
    assert payload["event_family"] == "Traffic"

    for snapshot in (payload["baseline"], payload["current"]):
        expected_coverage = round(
            snapshot["mapped_fields"]
            / snapshot["total_fields"]
            * 100,
            1,
        )
        assert snapshot["coverage"] == expected_coverage

    assert payload["current"]["coverage"] < payload["baseline"]["coverage"]
    assert payload["field_loss"] == (
        payload["baseline"]["mapped_fields"]
        - payload["current"]["mapped_fields"]
    )
    assert payload["status"] == "DETECTED"


def test_stable_fidelity_reports_produce_no_drift_status():
    fields = {
        "u_id": "EVT-DRIFT-STABLE",
        "raw_id": "RAW-DRIFT-STABLE",
        "timestamp": "2026-08-28T00:00:00Z",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "category": "network_activity",
        "type": "traffic",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
    }
    observed_time = datetime(2026, 8, 28, tzinfo=timezone.utc)
    normalized = NormalizationEngine().normalize(
        fields,
        observed_time=observed_time,
        processed_time=observed_time,
    )
    fidelity = calculate_fidelity(
        fields,
        normalized,
    )

    report = build_parser_drift_report(
        fidelity,
        fidelity,
        vendor="Fortinet",
        product="FortiGate",
        event_family="Traffic",
    )

    assert report["baseline"] == report["current"]
    assert report["field_loss"] == 0
    assert report["status"] == "STABLE"
