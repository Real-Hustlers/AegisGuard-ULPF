import pytest
from pydantic import ValidationError

from aegisguard_ulpf.core.models import DetectionResult


def test_detection_result():
    result = DetectionResult(
        vendor="Fortinet",
        product="FortiGate",
        event_family="system",
        format="key_value",
        parser_id="fortinet.fortigate.system",
        confidence=0.98,
        evidence=[
            "devname present",
            "type=event",
            "subtype=system",
        ],
    )

    assert result.vendor == "Fortinet"

    assert result.product == "FortiGate"

    assert result.event_family == "system"

    assert result.format == "key_value"

    assert result.parser_id == "fortinet.fortigate.system"

    assert result.confidence == 0.98

    assert "subtype=system" in result.evidence


def test_detection_confidence_cannot_exceed_one():
    with pytest.raises(ValidationError):
        DetectionResult(
            vendor="Fortinet",
            confidence=1.5,
        )


def test_detection_can_be_partial():
    result = DetectionResult(
        format="json",
        confidence=0.40,
        evidence=[
            "valid JSON structure",
        ],
    )

    assert result.format == "json"

    assert result.vendor is None

    assert result.parser_id is None