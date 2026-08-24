from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.detection.engine import DetectionEngine


def detect(raw: str):
    engine = DetectionEngine()

    event = RawEvent(
        raw=raw,
        transport="file",
    )

    return engine.detect(event)


def test_detection_engine_fortigate_system():
    result = detect(
        'date=2026-08-24 '
        'time=20:10:00 '
        'devname="FGT-01" '
        'devid="FGT60FTK12345678" '
        'logid="0100032001" '
        'type="event" '
        'subtype="system" '
        'vd="root"'
    )

    assert result.format == "key_value"

    assert result.vendor == "Fortinet"

    assert result.product == "FortiGate"

    assert result.event_family == "system"

    assert (
        result.parser_id
        == "fortinet.fortigate.system"
    )


def test_detection_engine_fortigate_traffic():
    result = detect(
        'date=2026-08-24 '
        'time=20:10:00 '
        'devname="FGT-01" '
        'devid="FGT60FTK12345678" '
        'logid="0000000013" '
        'type="traffic" '
        'subtype="forward" '
        'vd="root"'
    )

    assert result.vendor == "Fortinet"

    assert result.product == "FortiGate"

    assert result.event_family == "traffic"

    assert (
        result.parser_id
        == "fortinet.fortigate.traffic"
    )


def test_detection_engine_cisco_asa_traffic():
    result = detect(
        '<166>Aug 24 20:20:15 firewall '
        '%ASA-6-302013: '
        'Built outbound TCP connection'
    )

    assert result.format == "syslog"

    assert result.vendor == "Cisco"

    assert result.product == "ASA"

    assert result.event_family == "traffic"

    assert (
        result.parser_id
        == "cisco.asa.traffic"
    )


def test_detection_engine_palo_alto_traffic():
    result = detect(
        '1,2026/08/24 20:25:10,'
        '001122334455,TRAFFIC,end,1,'
        '2026/08/24 20:25:10,'
        '10.0.0.10,8.8.8.8,'
        '192.0.2.1,8.8.8.8,'
        'rule1,user1,user2,web-browsing'
    )

    assert result.format == "csv"

    assert (
        result.vendor
        == "Palo Alto Networks"
    )

    assert result.product == "PAN-OS"

    assert result.event_family == "traffic"

    assert (
        result.parser_id
        == "paloalto.pan_os.traffic"
    )


def test_detection_engine_unknown_source():
    result = detect(
        'username=admin '
        'action=login '
        'status=success'
    )

    assert result.format == "key_value"

    assert result.vendor is None

    assert result.product is None

    assert result.event_family is None

    assert result.parser_id is None


def test_detection_engine_plain_text_unknown():
    result = detect(
        "Application started successfully"
    )

    assert result.format == "plain_text"

    assert result.vendor is None

    assert result.parser_id is None


def test_detection_engine_empty_event():
    result = detect("")

    assert result.vendor is None

    assert result.product is None

    assert result.parser_id is None

    assert result.confidence == 0.0