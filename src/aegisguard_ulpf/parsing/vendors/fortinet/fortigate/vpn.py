import re
import json
import uuid
from typing import Dict, Any, Optional


# ============================================================
# AEGISGUARD ULPF - COMMON TAXONOMY V1
# ============================================================

def empty_common_event() -> Dict[str, Any]:
    return {
        "u_id": None,
        "raw_id": None,

        "timestamp": None,

        "vendor": None,
        "product": None,

        "category": None,
        "type": None,
        "subtype": None,
        "outcome": None,

        "severity": None,

        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,

        "user": None,

        "action": None,
        "reason": None,

        "object_type": None,
        "object_name": None,

        "details": {},

        "vendor_event_id": None,

        # Parsed vendor-specific fields are preserved here.
        # The original raw log itself is NOT stored here.
        "vendor_fields": {}
    }


# ============================================================
# GENERIC FORTIGATE KEY=VALUE PARSER
# ============================================================

FIELD_PATTERN = re.compile(
    r'(?P<key>[\w.\-]+)='
    r'(?:"(?P<quoted>(?:\\.|[^"])*)"|(?P<bare>[^\s]+))'
)


def parse_key_values(raw_log: str) -> Dict[str, str]:
    """
    Extract all FortiGate key=value fields.

    Supports:
        action="ssl-login-fail"
        stage=2
        user="alice"

    Any syslog prefix before the key=value portion is ignored.
    """
    parsed = {}

    for match in FIELD_PATTERN.finditer(raw_log):
        key = match.group("key")

        value = (
            match.group("quoted")
            if match.group("quoted") is not None
            else match.group("bare")
        )

        parsed[key] = value

    return parsed


# ============================================================
# DETECTION
# ============================================================

def detect(raw_log: str) -> bool:
    """
    Return True only when this looks like a FortiGate VPN event.
    """
    fields = parse_key_values(raw_log)

    subtype = fields.get("subtype", "").lower()
    logdesc = fields.get("logdesc", "").lower()
    tunneltype = fields.get("tunneltype", "").lower()

    return (
        subtype in {"vpn", "ipsec", "sslvpn", "ssl-vpn"}
        or "vpn" in logdesc
        or "ipsec" in logdesc
        or "ssl" in tunneltype
    )


# ============================================================
# HELPERS
# ============================================================

def short_log_id(logid: Optional[str]) -> Optional[str]:
    """
    FortiGate may use IDs such as:

        0101039426

    We care about the event suffix:

        39426
    """
    if not logid:
        return None

    digits = "".join(c for c in str(logid) if c.isdigit())

    if len(digits) >= 5:
        return digits[-5:]

    return digits or None


def build_timestamp(fields: Dict[str, str]) -> Optional[str]:
    date = fields.get("date")
    time = fields.get("time")
    tz = fields.get("tz")

    if not date or not time:
        return None

    timestamp = f"{date}T{time}"

    if tz:
        timestamp += tz

    return timestamp


def convert_port(value: Optional[str]):
    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return value


def normalize_protocol(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    mapping = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPV6"
    }

    return mapping.get(str(value), str(value).upper())


def identify_vpn_type(fields: Dict[str, str]) -> Optional[str]:
    subtype = fields.get("subtype", "").lower()
    tunneltype = fields.get("tunneltype", "").lower()
    logdesc = fields.get("logdesc", "").lower()

    if (
        "ssl" in tunneltype
        or "ssl vpn" in logdesc
        or subtype in {"sslvpn", "ssl-vpn"}
    ):
        return "SSL_VPN"

    if (
        subtype == "ipsec"
        or "ipsec" in logdesc
        or fields.get("action", "").lower() == "negotiate"
    ):
        return "IPSEC"

    return None

# ============================================================
# CLEANING
# ============================================================

def clean_value(value: Optional[str]) -> Optional[str]:
    """
    Convert vendor placeholder values into None
    for the common taxonomy.

    Original values remain untouched in vendor_fields.
    """
    if value is None:
        return None

    cleaned = str(value).strip()

    if cleaned.lower() in {
        "",
        "n/a",
        "na",
        "none",
        "null",
        "-",
        "unknown"
    }:
        return None

    return cleaned

# ============================================================
# VPN CLASSIFICATION
# ============================================================

def classify(fields: Dict[str, str]) -> Dict[str, Any]:
    """
    Convert FortiGate-specific VPN semantics into
    AegisGuard Common Taxonomy semantics.
    """

    event_id = short_log_id(fields.get("logid"))
    action = fields.get("action", "").lower()
    status = fields.get("status", "").lower()
    reason = fields.get("reason", "").lower()

    classification = {
        "category": "VPN",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }

    # --------------------------------------------------------
    # SSL-VPN
    # --------------------------------------------------------

    if event_id == "39943" or action == "ssl-new-con":
        classification.update({
            "type": "CONNECTION",
            "subtype": "CONNECTION_INITIATED",
            "outcome": "UNKNOWN"
        })

    elif event_id == "39426" or action == "ssl-login-fail":
        classification.update({
            "type": "AUTHENTICATION",
            "subtype": "LOGIN_FAILURE",
            "outcome": "FAILURE"
        })

    elif event_id == "39424":
        classification.update({
            "type": "TUNNEL",
            "subtype": "USER_TUNNEL_UP",
            "outcome": "SUCCESS"
        })

    elif event_id == "39947":
        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_UP",
            "outcome": "SUCCESS"
        })

    elif event_id == "39948":
        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_DOWN",

            # A tunnel closing is not automatically a failure.
            "outcome": "UNKNOWN"
        })

    elif event_id in {"39944", "39951"}:
        classification.update({
            "type": "ERROR",
            "subtype": "TUNNEL_ERROR",
            "outcome": "FAILURE"
        })

    # --------------------------------------------------------
    # IPsec
    # --------------------------------------------------------

    elif event_id == "37129":
        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_SUCCESS",
            "outcome": "SUCCESS"
        })

    elif event_id in {"37128", "37124"}:
        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_FAILURE",
            "outcome": "FAILURE"
        })

    # --------------------------------------------------------
    # Fallback semantics
    # --------------------------------------------------------

    elif action == "negotiate" and status == "success":
        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_SUCCESS",
            "outcome": "SUCCESS"
        })

    elif action == "negotiate" and (
        status in {"failure", "failed", "negotiate_error", "error"}
        or "error" in reason
    ):
        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_FAILURE",
            "outcome": "FAILURE"
        })

    elif action == "tunnel-up":
        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_UP",
            "outcome": "SUCCESS"
        })

    elif action == "tunnel-down":
        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_DOWN",
            "outcome": "UNKNOWN"
        })

    return classification

# ============================================================
# INTEGER CONVERSION
# ============================================================

def convert_int(value: Optional[str]):
    if value is None:
        return None

    try:
        return int(value)
    except (ValueError, TypeError):
        return value

# ============================================================
# NORMALIZATION
# ============================================================

def normalize(
    raw_log: str,
    raw_id: str,
    u_id: Optional[str] = None
) -> Dict[str, Any]:

    if not detect(raw_log):
        raise ValueError("Input does not appear to be a FortiGate VPN log")

    fields = parse_key_values(raw_log)
    classification = classify(fields)

    event = empty_common_event()

    # IDs
    event["raw_id"] = raw_id
    event["u_id"] = u_id or f"UEV-{uuid.uuid4()}"

    # Timestamp
    event["timestamp"] = build_timestamp(fields)

    # Source identity
    event["vendor"] = "Fortinet"
    event["product"] = "FortiGate"

    # Semantic classification
    event["category"] = classification["category"]
    event["type"] = classification["type"]
    event["subtype"] = classification["subtype"]
    event["outcome"] = classification["outcome"]

    # Severity
    event["severity"] = fields.get("level")

    # Network
    event["src_ip"] = (
        fields.get("remip")
        or fields.get("srcip")
    )

    event["src_port"] = convert_port(
        fields.get("remport")
        or fields.get("srcport")
    )

    event["dst_ip"] = (
        fields.get("locip")
        or fields.get("dstip")
    )

    event["dst_port"] = convert_port(
        fields.get("locport")
        or fields.get("dstport")
    )

    event["protocol"] = normalize_protocol(
        fields.get("proto")
        or fields.get("protocol")
    )

    # Identity
    event["user"] = clean_value(fields.get("user"))

    # Action / reason
    event["action"] = fields.get("action")

    event["reason"] = clean_value(
        fields.get("reason")
        or fields.get("error_reason")
    )

    # Object
    if fields.get("vpntunnel"):
        event["object_type"] = "VPN_TUNNEL"
        event["object_name"] = fields.get("vpntunnel")

    # Category-specific normalized fields
    event["details"] = {
        "vpn_type": identify_vpn_type(fields),
        "tunnel_type": fields.get("tunneltype"),
        "tunnel_name": fields.get("vpntunnel"),
        "tunnel_ip": fields.get("tunnelip"),
        "vpn_phase": convert_int(fields.get("stage")),
        "duration": convert_int(fields.get("duration"))
    }

    # Vendor-specific provenance
    event["vendor_event_id"] = fields.get("logid")

    # IMPORTANT:
    # Preserve every parsed FortiGate field.
    # Raw bytes remain separately stored under raw_id.
    event["vendor_fields"] = fields.copy()

    return event


# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        # ----------------------------------------------------
        # SSL VPN - New Connection
        # ----------------------------------------------------

        (
            'date=2024-07-24 '
            'time=17:19:52 '
            'logid="0101039943" '
            'type="event" '
            'subtype="vpn" '
            'level="information" '
            'logdesc="SSL VPN new connection" '
            'action="ssl-new-con" '
            'user="N/A" '
            'remip="203.0.113.10" '
            'tunnelid=0 '
            'tunneltype="ssl" '
            'reason="N/A"'
        ),


        # ----------------------------------------------------
        # SSL VPN - User Tunnel Up
        # ----------------------------------------------------

        (
            'date=2024-07-24 '
            'time=17:20:01 '
            'logid="0101039424" '
            'type="event" '
            'subtype="vpn" '
            'level="information" '
            'logdesc="SSL VPN tunnel up" '
            'action="tunnel-up" '
            'user="alice" '
            'remip="203.0.113.11" '
            'tunneltype="ssl-tunnel"'
        ),


        # ----------------------------------------------------
        # SSL VPN - Login Failure
        # ----------------------------------------------------

        (
            'date=2022-12-29 '
            'time=09:36:07 '
            'logid="0101039426" '
            'type="event" '
            'subtype="vpn" '
            'level="alert" '
            'logdesc="SSL VPN login fail" '
            'action="ssl-login-fail" '
            'tunneltype="ssl-web" '
            'remip="203.0.113.25" '
            'user="alice" '
            'reason="sslvpn_login_permission_denied"'
        ),


        # ----------------------------------------------------
        # SSL VPN - Tunnel Up
        # ----------------------------------------------------

        (
            'date=2023-12-15 '
            'time=03:24:25 '
            'logid="0101039947" '
            'type="event" '
            'subtype="vpn" '
            'level="information" '
            'logdesc="SSL VPN tunnel up" '
            'action="tunnel-up" '
            'tunneltype="ssl-tunnel" '
            'remip="203.0.113.30" '
            'tunnelip="10.1.250.2" '
            'user="alice" '
            'reason="DTLS tunnel established"'
        ),


        # ----------------------------------------------------
        # SSL VPN - Tunnel Down
        # ----------------------------------------------------

        (
            'date=2023-12-15 '
            'time=05:44:59 '
            'logid="0101039948" '
            'type="event" '
            'subtype="vpn" '
            'level="information" '
            'logdesc="SSL VPN tunnel down" '
            'action="tunnel-down" '
            'tunneltype="ssl-tunnel" '
            'remip="203.0.113.30" '
            'tunnelip="10.1.250.2" '
            'user="alice" '
            'reason="User requested termination of service" '
            'duration=1415'
        ),


        # ----------------------------------------------------
        # SSL VPN - Tunnel Error
        # ----------------------------------------------------

        (
            'date=2024-07-24 '
            'time=17:25:11 '
            'logid="0101039951" '
            'type="event" '
            'subtype="vpn" '
            'level="error" '
            'logdesc="SSL VPN tunnel error" '
            'action="tunnel-error" '
            'tunneltype="ssl-tunnel" '
            'remip="203.0.113.35" '
            'user="alice" '
            'reason="SSL session error"'
        ),


        # ----------------------------------------------------
        # IPsec - Negotiation Success
        # ----------------------------------------------------

        (
            'date=2024-04-12 '
            'time=08:33:25 '
            'logid="0101037129" '
            'type="event" '
            'subtype="vpn" '
            'level="notice" '
            'logdesc="Progress IPsec phase 2" '
            'action="negotiate" '
            'remip="203.0.113.40" '
            'locip="198.51.100.10" '
            'remport=4500 '
            'locport=4500 '
            'vpntunnel="Branch-VPN" '
            'status="success" '
            'stage=2 '
            'result="DONE"'
        ),


        # ----------------------------------------------------
        # IPsec - Negotiation Failure
        # ----------------------------------------------------

        (
            'date=2024-04-12 '
            'time=08:34:02 '
            'logid="0101037128" '
            'type="event" '
            'subtype="ipsec" '
            'level="error" '
            'logdesc="Progress IPsec phase 1" '
            'action="negotiate" '
            'remip="203.0.113.41" '
            'locip="198.51.100.10" '
            'vpntunnel="Branch-VPN" '
            'status="failure" '
            'stage=1 '
            'result="ERROR" '
            'reason="peer SA proposal not match local policy"'
        )
    ]


    # ========================================================
    # NORMALIZE INGESTED RAW LOGS
    # ========================================================

    normalized_events = []


    for index, raw_log in enumerate(
        raw_logs,
        start=1
    ):

        if not detect(raw_log):
            continue


        normalized_event = normalize(
            raw_log=raw_log,
            raw_id=(
                f"RAW-FG-VPN-{index:06d}"
            ),
            u_id=(
                f"UEV-FG-VPN-{index:06d}"
            )
        )


        normalized_events.append(
            normalized_event
        )


    # ========================================================
    # SAVE NORMALIZED EVENTS
    # ========================================================

    with open(
        "fortigate_vpn_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )