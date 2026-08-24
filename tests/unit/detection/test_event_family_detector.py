from aegisguard_ulpf.core.models import (
    DetectionResult,
    RawEvent,
)
from aegisguard_ulpf.detection.event_family_detector import (
    EventFamilyDetector,
)


def source(
    vendor: str,
    product: str,
    format_name: str,
):
    return DetectionResult(
        vendor=vendor,
        product=product,
        format=format_name,
        confidence=1.0,
        evidence=["source detected"],
    )


def test_fortigate_traffic():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'type="traffic" '
            'subtype="forward"'
        )
    )

    result = detector.detect(
        event,
        source(
            "Fortinet",
            "FortiGate",
            "key_value",
        ),
    )

    assert result.event_family == "traffic"
    assert result.parser_id == "fortinet.fortigate.traffic"


def test_fortigate_vpn():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'type="event" '
            'subtype="vpn"'
        )
    )

    result = detector.detect(
        event,
        source(
            "Fortinet",
            "FortiGate",
            "key_value",
        ),
    )

    assert result.event_family == "vpn"
    assert result.parser_id == "fortinet.fortigate.vpn"


def test_fortigate_system():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'type="event" '
            'subtype="system"'
        )
    )

    result = detector.detect(
        event,
        source(
            "Fortinet",
            "FortiGate",
            "key_value",
        ),
    )

    assert result.event_family == "system"
    assert result.parser_id == "fortinet.fortigate.system"


def test_fortigate_router():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'type="event" '
            'subtype="router"'
        )
    )

    result = detector.detect(
        event,
        source(
            "Fortinet",
            "FortiGate",
            "key_value",
        ),
    )

    assert result.event_family == "router"
    assert result.parser_id == "fortinet.fortigate.router"


def test_cisco_asa_traffic():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '%ASA-6-302013: '
            'Built outbound TCP connection'
        )
    )

    result = detector.detect(
        event,
        source(
            "Cisco",
            "ASA",
            "syslog",
        ),
    )

    assert result.event_family == "traffic"
    assert result.parser_id == "cisco.asa.traffic"


def test_cisco_asa_vpn():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '%ASA-5-722033: '
            'AnyConnect VPN connection established'
        )
    )

    result = detector.detect(
        event,
        source(
            "Cisco",
            "ASA",
            "syslog",
        ),
    )

    assert result.event_family == "vpn"
    assert result.parser_id == "cisco.asa.vpn"


def test_palo_alto_traffic():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '1,2026/08/24 20:25:10,001122334455,'
            'TRAFFIC,end,1,2026/08/24 20:25:10,'
            '10.0.0.1,8.8.8.8'
        )
    )

    result = detector.detect(
        event,
        source(
            "Palo Alto Networks",
            "PAN-OS",
            "csv",
        ),
    )

    assert result.event_family == "traffic"
    assert result.parser_id == "paloalto.pan_os.traffic"


def test_palo_alto_system():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '1,2026/08/24 20:25:10,001122334455,'
            'SYSTEM,general,1,2026/08/24 20:25:10'
        )
    )

    result = detector.detect(
        event,
        source(
            "Palo Alto Networks",
            "PAN-OS",
            "csv",
        ),
    )

    assert result.event_family == "system"
    assert result.parser_id == "paloalto.pan_os.system"


def test_palo_alto_router():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '1,2026/08/24 20:25:10,001122334455,'
            'SYSTEM,routing,1,2026/08/24 20:25:10'
        )
    )

    result = detector.detect(
        event,
        source(
            "Palo Alto Networks",
            "PAN-OS",
            "csv",
        ),
    )

    assert result.event_family == "router"
    assert result.parser_id == "paloalto.pan_os.router"


def test_palo_alto_vpn():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw=(
            '1,2026/08/24 20:25:10,001122334455,'
            'GLOBALPROTECT,login,1,'
            '2026/08/24 20:25:10'
        )
    )

    result = detector.detect(
        event,
        source(
            "Palo Alto Networks",
            "PAN-OS",
            "csv",
        ),
    )

    assert result.event_family == "vpn"
    assert result.parser_id == "paloalto.pan_os.vpn"


def test_unknown_family_does_not_invent_parser():
    detector = EventFamilyDetector()

    event = RawEvent(
        raw="unknown log"
    )

    result = detector.detect(
        event,
        source(
            "Fortinet",
            "FortiGate",
            "plain_text",
        ),
    )

    assert result.event_family is None
    assert result.parser_id is None