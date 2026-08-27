"""Tests for the isolated parser-fidelity drift detector."""

from aegisguard_ulpf.drift import detect_parser_drift


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
