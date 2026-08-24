from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.detection.format_detector import FormatDetector


def detect(raw: str):
    detector = FormatDetector()

    event = RawEvent(
        raw=raw,
        transport="file",
    )

    return detector.detect(event)


def test_detect_json():
    result = detect(
        '{"event":"login","user":"admin"}'
    )

    assert result.format == "json"
    assert result.confidence == 1.0


def test_detect_xml():
    result = detect(
        '<event><user>admin</user></event>'
    )

    assert result.format == "xml"
    assert result.confidence == 1.0


def test_detect_cef():
    result = detect(
        'CEF:0|Fortinet|FortiGate|7.4|100|Traffic Event|5|src=10.0.0.1'
    )

    assert result.format == "cef"


def test_detect_syslog_wrapped_cef():
    result = detect(
        '<134>Aug 24 20:00:00 host CEF:0|Vendor|Product|1|100|Event|5|src=10.0.0.1'
    )

    assert result.format == "cef"


def test_detect_leef():
    result = detect(
        'LEEF:2.0|Vendor|Product|1.0|100|src=10.0.0.1'
    )

    assert result.format == "leef"


def test_detect_syslog():
    result = detect(
        '<134>Aug 24 20:00:00 firewall interface changed state'
    )

    assert result.format == "syslog"


def test_detect_key_value():
    result = detect(
        'date=2026-08-24 time=20:01:10 devname="FGT-01" subtype="system"'
    )

    assert result.format == "key_value"


def test_detect_csv():
    result = detect(
        '2026-08-24,admin,login,success'
    )

    assert result.format == "csv"


def test_detect_plain_text():
    result = detect(
        'Application startup completed successfully'
    )

    assert result.format == "plain_text"


def test_empty_event():
    result = detect("")

    assert result.format == "plain_text"
    assert result.confidence == 0.0