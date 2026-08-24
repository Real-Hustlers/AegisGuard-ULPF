from aegisguard_ulpf.core.models import (
    DetectionResult,
    RawEvent,
)
from aegisguard_ulpf.detection.source_detector import SourceDetector


def detect(
    raw: str,
    format_name: str,
):
    detector = SourceDetector()

    event = RawEvent(
        raw=raw,
        transport="file",
    )

    format_result = DetectionResult(
        format=format_name,
        confidence=1.0,
        evidence=["test format"],
    )

    return detector.detect(
        event,
        format_result,
    )


def test_detect_fortigate():
    result = detect(
        'date=2026-08-24 '
        'time=20:10:00 '
        'devname="FGT-01" '
        'devid="FGT60FTK12345678" '
        'logid="0100032001" '
        'type="event" '
        'subtype="system" '
        'vd="root"',
        "key_value",
    )

    assert result.vendor == "Fortinet"
    assert result.product == "FortiGate"
    assert result.format == "key_value"
    assert result.confidence >= 0.50


def test_detect_cisco_asa():
    result = detect(
        '<166>Aug 24 20:20:15 firewall '
        '%ASA-6-302013: Built outbound TCP connection '
        '12345 for outside:8.8.8.8/443',
        "syslog",
    )

    assert result.vendor == "Cisco"
    assert result.product == "ASA"
    assert result.format == "syslog"
    assert result.confidence == 1.0


def test_detect_palo_alto_traffic():
    result = detect(
        '1,2026/08/24 20:25:10,001122334455,'
        'TRAFFIC,end,1,2026/08/24 20:25:10,'
        '10.0.0.10,8.8.8.8,192.0.2.1,8.8.8.8,'
        'rule1,user1,user2,web-browsing',
        "csv",
    )

    assert result.vendor == "Palo Alto Networks"
    assert result.product == "PAN-OS"
    assert result.format == "csv"
    assert result.confidence >= 0.70


def test_detect_palo_alto_system():
    result = detect(
        '1,2026/08/24 20:25:10,001122334455,'
        'SYSTEM,general,1,2026/08/24 20:25:10,'
        'vsys1,event,informational,system,event,message',
        "csv",
    )

    assert result.vendor == "Palo Alto Networks"
    assert result.product == "PAN-OS"
    assert result.format == "csv"


def test_generic_key_value_is_not_assigned_vendor():
    result = detect(
        'username=admin '
        'action=login '
        'status=success',
        "key_value",
    )

    assert result.vendor is None
    assert result.product is None
    assert result.confidence == 0.0


def test_generic_csv_is_not_palo_alto():
    result = detect(
        'john,login,success,10.0.0.10',
        "csv",
    )

    assert result.vendor is None
    assert result.product is None


def test_generic_syslog_is_not_cisco():
    result = detect(
        '<134>Aug 24 20:30:00 linux-server '
        'sshd: user logged in',
        "syslog",
    )

    assert result.vendor is None
    assert result.product is None


def test_empty_event():
    detector = SourceDetector()

    event = RawEvent(
        raw="",
        transport="file",
    )

    result = detector.detect(event)

    assert result.vendor is None
    assert result.product is None
    assert result.confidence == 0.0