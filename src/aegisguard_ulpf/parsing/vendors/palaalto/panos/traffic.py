import csv
import io
import json
import re
import uuid
from datetime import datetime
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

        # Preserve parsed PAN-OS fields.
        "vendor_fields": {}
    }


# ============================================================
# PAN-OS TRAFFIC CSV FIELD ORDER
# ============================================================

# PAN-OS Traffic logs are positional CSV records.
#
# These names follow Palo Alto Networks' documented field order.
# Later PAN-OS versions may append more fields.
#
# Therefore:
# - We map all fields we know.
# - Extra fields are preserved as field_<index>.
# - Missing trailing fields do not crash parsing.

TRAFFIC_FIELD_NAMES = [
    "future_use_1",            # 0
    "receive_time",            # 1
    "serial",                  # 2
    "type",                    # 3
    "subtype",                 # 4
    "config_version",          # 5
    "time_generated",          # 6
    "src",                     # 7
    "dst",                     # 8
    "natsrc",                  # 9
    "natdst",                  # 10
    "rule",                    # 11
    "srcuser",                 # 12
    "dstuser",                 # 13
    "app",                     # 14
    "vsys",                    # 15
    "from_zone",               # 16
    "to_zone",                 # 17
    "inbound_if",              # 18
    "outbound_if",             # 19
    "logset",                  # 20
    "future_use_2",            # 21
    "sessionid",               # 22
    "repeatcnt",               # 23
    "sport",                   # 24
    "dport",                   # 25
    "natsport",                # 26
    "natdport",                # 27
    "flags",                   # 28
    "proto",                   # 29
    "action",                  # 30
    "bytes",                   # 31
    "bytes_sent",              # 32
    "bytes_received",          # 33
    "packets",                 # 34
    "start",                   # 35
    "elapsed",                 # 36
    "category",                # 37
    "future_use_3",            # 38
    "seqno",                   # 39
    "actionflags",             # 40
    "srcloc",                  # 41
    "dstloc",                  # 42
    "future_use_4",            # 43
    "pkts_sent",               # 44
    "pkts_received",           # 45
    "session_end_reason",      # 46
    "dg_hier_level_1",         # 47
    "dg_hier_level_2",         # 48
    "dg_hier_level_3",         # 49
    "dg_hier_level_4",         # 50
    "vsys_name",               # 51
    "device_name",             # 52
    "action_source",           # 53
    "src_uuid",                # 54
    "dst_uuid",                # 55
    "tunnel_id_imsi",          # 56
    "monitor_tag_imei",        # 57
    "parent_session_id",       # 58
    "parent_start_time",       # 59
    "tunnel_type",             # 60
    "sctp_association_id",     # 61
    "sctp_chunks",             # 62
    "sctp_chunks_sent",        # 63
    "sctp_chunks_received",    # 64
    "rule_uuid",               # 65
    "http2_connection",        # 66
    "app_flap_count",          # 67
    "policy_id"                # 68
]


# ============================================================
# HELPERS
# ============================================================

def clean_value(value: Optional[str]) -> Optional[str]:
    """
    Convert blank/vendor placeholder values into None
    in the normalized representation.

    vendor_fields retains the parsed original value.
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
        "-"
    }:
        return None

    return cleaned


def convert_int(value: Optional[str]):
    if value is None:
        return None

    value = str(value).strip()

    if value == "":
        return None

    try:
        return int(value)

    except (ValueError, TypeError):
        return value


def convert_port(value: Optional[str]):
    return convert_int(value)


def normalize_protocol(
    value: Optional[str]
) -> Optional[str]:

    value = clean_value(value)

    if value is None:
        return None

    mapping = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPV6"
    }

    return mapping.get(
        str(value).lower(),
        str(value).upper()
    )


def parse_timestamp(
    value: Optional[str]
) -> Optional[str]:

    value = clean_value(value)

    if not value:
        return None

    formats = [
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f"
    ]

    for fmt in formats:

        try:
            parsed = datetime.strptime(
                value,
                fmt
            )

            return parsed.isoformat()

        except ValueError:
            continue

    # Preserve usable timestamp even when
    # the specific PAN-OS format is unknown.
    return value


# ============================================================
# EXTRACT PAN-OS CSV FROM SYSLOG WRAPPER
# ============================================================

def extract_csv_payload(raw_log: str) -> str:
    """
    PAN-OS logs may have a Syslog prefix, for example:

        <14>Jan 5 12:51:34 PAN1 1,2015/01/05...

    or RFC5424-style content.

    Find the beginning of the PAN-OS CSV payload:

        1,YYYY/MM/DD HH:MM:SS,...
    """

    raw_log = raw_log.strip()

    match = re.search(
        r'(?<!\d)1,\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},',
        raw_log
    )

    if match:
        return raw_log[match.start():].strip()

    # Maybe the caller passed the pure CSV payload.
    if raw_log.startswith("1,"):
        return raw_log

    raise ValueError(
        "Could not locate PAN-OS CSV payload"
    )


# ============================================================
# PAN-OS CSV PARSER
# ============================================================

def parse_csv_fields(
    raw_log: str
) -> Dict[str, str]:

    payload = extract_csv_payload(raw_log)

    reader = csv.reader(
        io.StringIO(payload)
    )

    try:
        values = next(reader)

    except StopIteration:
        raise ValueError(
            "PAN-OS Traffic log is empty"
        )

    parsed = {}

    for index, value in enumerate(values):

        if index < len(TRAFFIC_FIELD_NAMES):
            key = TRAFFIC_FIELD_NAMES[index]

        else:
            # Preserve fields added by newer PAN-OS versions.
            key = f"field_{index}"

        parsed[key] = value

    return parsed


# ============================================================
# DETECTION
# ============================================================

def detect(raw_log: str) -> bool:
    """
    Detect any PAN-OS Traffic log.

    Classification support may be narrower than detection support.
    Unknown Traffic subtypes must still be preserved.
    """

    try:
        fields = parse_csv_fields(raw_log)

    except (ValueError, csv.Error):
        return False

    log_type = fields.get(
        "type",
        ""
    ).strip().upper()

    return log_type == "TRAFFIC"


# ============================================================
# OUTCOME NORMALIZATION
# ============================================================

BLOCK_ACTIONS = {
    "deny",
    "drop",
    "drop-icmp",
    "drop icmp",
    "reset-client",
    "reset client",
    "reset-server",
    "reset server",
    "reset-both",
    "reset both"
}


def outcome_from_action(
    action: Optional[str]
) -> str:

    action = (
        clean_value(action)
        or ""
    ).lower()

    if action == "allow":
        return "SUCCESS"

    if action in BLOCK_ACTIONS:
        return "FAILURE"

    return "UNKNOWN"


# ============================================================
# TRAFFIC CLASSIFICATION
# ============================================================

def classify(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    subtype = fields.get(
        "subtype",
        ""
    ).lower()

    action = fields.get(
        "action"
    )

    classification = {
        "category": "TRAFFIC",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


    # --------------------------------------------------------
    # PAN-OS START
    # --------------------------------------------------------

    if subtype == "start":

        classification.update({
            "type": "SESSION",
            "subtype": "SESSION_START",
            "outcome": outcome_from_action(action)
        })


    # --------------------------------------------------------
    # PAN-OS END
    # --------------------------------------------------------

    elif subtype == "end":

        classification.update({
            "type": "SESSION",
            "subtype": "SESSION_END",
            "outcome": outcome_from_action(action)
        })


    # --------------------------------------------------------
    # PAN-OS DROP
    # --------------------------------------------------------

    elif subtype == "drop":

        classification.update({
            "type": "POLICY",
            "subtype": "TRAFFIC_DROP",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # PAN-OS DENY
    # --------------------------------------------------------

    elif subtype == "deny":

        classification.update({
            "type": "POLICY",
            "subtype": "TRAFFIC_DENY",
            "outcome": "FAILURE"
        })


    return classification


# ============================================================
# DETAILS
# ============================================================

def build_details(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    details = {
        # NAT
        "nat_src_ip":
            normalize_nat_ip(fields.get("natsrc")),

        "nat_dst_ip":
            normalize_nat_ip(fields.get("natdst")),

        "nat_src_port":
            normalize_nat_port(fields.get("natsport")),

        "nat_dst_port":
            normalize_nat_port(fields.get("natdport")),


        # Application
        "application":
            clean_value(fields.get("app")),

        "url_category":
            clean_value(fields.get("category")),


        # Users
        "dst_user":
            clean_value(fields.get("dstuser")),


        # Policy
        "rule":
            clean_value(fields.get("rule")),

        "action_source":
            clean_value(fields.get("action_source")),

        "rule_uuid":
            clean_value(fields.get("rule_uuid")),

        "policy_id":
            convert_int(fields.get("policy_id")),


        # Network location
        "source_zone":
            clean_value(fields.get("from_zone")),

        "destination_zone":
            clean_value(fields.get("to_zone")),

        "inbound_interface":
            clean_value(fields.get("inbound_if")),

        "outbound_interface":
            clean_value(fields.get("outbound_if")),

        "source_location":
            clean_value(fields.get("srcloc")),

        "destination_location":
            clean_value(fields.get("dstloc")),


        # Session
        "session_id":
            convert_int(fields.get("sessionid")),

        "repeat_count":
            convert_int(fields.get("repeatcnt")),

        "start_time":
            parse_timestamp(fields.get("start")),

        "elapsed_seconds":
            convert_int(fields.get("elapsed")),

        "session_end_reason":
            clean_value(
                fields.get("session_end_reason")
            ),


        # Traffic counters
        "bytes_total":
            convert_int(fields.get("bytes")),

        "bytes_sent":
            convert_int(fields.get("bytes_sent")),

        "bytes_received":
            convert_int(fields.get("bytes_received")),

        "packets_total":
            convert_int(fields.get("packets")),

        "packets_sent":
            convert_int(fields.get("pkts_sent")),

        "packets_received":
            convert_int(fields.get("pkts_received")),


        # Device context
        "virtual_system":
            clean_value(fields.get("vsys")),

        "device_name":
            clean_value(fields.get("device_name")),

        "serial_number":
            clean_value(fields.get("serial")),

        "sequence_number":
            clean_value(fields.get("seqno"))
    }


    # Remove null values from normalized details.
    return {
        key: value
        for key, value in details.items()
        if value is not None
    }


# ============================================================
# NORMALIZATION
# ============================================================

def normalize(
    raw_log: str,
    raw_id: str,
    u_id: Optional[str] = None
) -> Dict[str, Any]:

    if not detect(raw_log):
        raise ValueError(
            "Input does not appear to be "
            "a PAN-OS Traffic log"
        )

    fields = parse_csv_fields(raw_log)

    classification = classify(fields)

    event = empty_common_event()


    # --------------------------------------------------------
    # IDs
    # --------------------------------------------------------

    event["raw_id"] = raw_id

    event["u_id"] = (
        u_id
        or f"UEV-{uuid.uuid4()}"
    )


    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    # Prefer dataplane-generated time.
    # Fall back to receive time.
    event["timestamp"] = parse_timestamp(
        fields.get("time_generated")
        or fields.get("receive_time")
    )


    # --------------------------------------------------------
    # Vendor identity
    # --------------------------------------------------------

    event["vendor"] = "Palo Alto Networks"

    event["product"] = "PAN-OS"


    # --------------------------------------------------------
    # Common semantic taxonomy
    # --------------------------------------------------------

    event["category"] = (
        classification["category"]
    )

    event["type"] = (
        classification["type"]
    )

    event["subtype"] = (
        classification["subtype"]
    )

    event["outcome"] = (
        classification["outcome"]
    )


    # --------------------------------------------------------
    # Traffic logs do not have a general severity field
    # in the standard Traffic schema.
    # --------------------------------------------------------

    event["severity"] = None


    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    event["src_ip"] = clean_value(
        fields.get("src")
    )

    event["dst_ip"] = clean_value(
        fields.get("dst")
    )

    protocol = normalize_protocol(
        fields.get("proto")
    )

    event["protocol"] = protocol

    event["src_port"] = normalize_port(
        fields.get("sport"),
        protocol
    )

    event["dst_port"] = normalize_port(
        fields.get("dport"),
        protocol
    )


    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    event["user"] = clean_value(
        fields.get("srcuser")
    )


    # --------------------------------------------------------
    # Action / Reason
    # --------------------------------------------------------

    event["action"] = clean_value(
        fields.get("action")
    )

    event["reason"] = clean_value(
        fields.get("session_end_reason")
    )


    # --------------------------------------------------------
    # Policy object
    # --------------------------------------------------------

    rule = clean_value(
        fields.get("rule")
    )

    if rule:

        event["object_type"] = "SECURITY_RULE"

        event["object_name"] = rule


    # --------------------------------------------------------
    # Category-specific data
    # --------------------------------------------------------

    event["details"] = build_details(
        fields
    )


    # --------------------------------------------------------
    # Vendor Event ID
    # --------------------------------------------------------
    #
    # PAN-OS Traffic logs do not use a FortiGate-style logid.
    #
    # seqno is a PAN-OS log entry sequence identifier,
    # so we preserve it here as the vendor event identifier.
    # It is NOT an event-class code like FortiGate logid.
    # --------------------------------------------------------

    event["vendor_event_id"] = None


    # --------------------------------------------------------
    # Preserve all parsed PAN-OS fields.
    # --------------------------------------------------------

    event["vendor_fields"] = fields.copy()


    return event

# ============================================================
# NORMALIZE NAT IP
# ============================================================

def normalize_nat_ip(
    value: Optional[str]
) -> Optional[str]:

    value = clean_value(value)

    if value in {
        "0.0.0.0",
        "::",
        "::0"
    }:
        return None

    return value

# ============================================================
# NORMALIZE NAT PORT
# ============================================================

def normalize_nat_port(
    value: Optional[str]
):

    port = convert_port(value)

    if port == 0:
        return None

    return port


# ============================================================
# NORMALIZE PORT
# ============================================================

def normalize_port(
    value: Optional[str],
    protocol: Optional[str]
):
    port = convert_int(value)

    if protocol in {"ICMP", "ICMPV6"}:
        return None

    return port

# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        # ----------------------------------------------------
        # 1. Traffic - Session Start
        # ----------------------------------------------------

        (
            '<14>May 6 15:51:04 '
            '1,2010/05/06 15:51:04,'
            '0006C101167,'
            'TRAFFIC,start,1,'
            '2010/05/06 15:50:58,'
            '192.168.28.21,'
            '172.16.255.78,'
            '::172.16.255.78,'
            '172.16.255.78,'
            'rule3,,,'
            'icmp,'
            'vsys1,'
            'untrust,'
            'untrust,'
            'ethernet1/1,'
            'ethernet1/1,'
            'syslog-172.16.20.152,'
            ','
            '600,'
            '2,'
            '0,'
            '0,'
            '0,'
            '0,'
            '0x40,'
            'icmp,'
            'allow,'
            '196,'
            '196,'
            '0,'
            '2,'
            '2010/05/06 15:50:58,'
            '0,'
            'any,'
            ','
            '1000001'
        ),


        # ----------------------------------------------------
        # 2. Traffic - Session End
        # ----------------------------------------------------

        (
            '<190>Jan 28 01:28:35 PA-VM300-goran1 '
            '1,2014/01/28 01:28:35,'
            '007200001056,'
            'TRAFFIC,end,1,'
            '2014/01/28 01:28:34,'
            '192.168.41.30,'
            '192.168.41.255,'
            '10.193.16.193,'
            '192.168.41.255,'
            'allow-all,,,'
            'netbios-ns,'
            'vsys1,'
            'Trust,'
            'Untrust,'
            'ethernet1/1,'
            'ethernet1/2,'
            'To-Panorama,'
            ','
            '8720,'
            '1,'
            '137,'
            '137,'
            '11637,'
            '137,'
            '0x400000,'
            'udp,'
            'allow,'
            '276,'
            '276,'
            '0,'
            '3,'
            '2014/01/28 01:28:02,'
            '2,'
            'any,'
            ','
            '2076326,'
            '0x0,'
            '192.168.0.0-192.168.255.255,'
            '192.168.0.0-192.168.255.255,'
            ','
            '3,'
            '0,'
            'aged-out'
        ),


        # ----------------------------------------------------
        # 3. Traffic - Drop
        # ----------------------------------------------------

        (
            '<14>Jan 5 12:51:34 PAN1 '
            '1,2015/01/05 12:51:33,'
            '0003C105690,'
            'TRAFFIC,drop,1,'
            '2015/01/05 12:51:33,'
            '10.0.0.219,'
            '10.3.0.21,'
            '0.0.0.0,'
            '0.0.0.0,'
            'catch all deny,,,'
            'not-applicable,'
            'vsys1,'
            'GuestAccess,'
            'trust,'
            'vlan.84,'
            ','
            'LOG-Default,'
            ','
            '0,'
            '1,'
            '62063,'
            '389,'
            '0,'
            '0,'
            '0x0,'
            'tcp,'
            'deny,'
            '70,'
            '70,'
            '0,'
            '1,'
            '2015/01/05 12:51:34,'
            '0,'
            'any,'
            ','
            '956329030,'
            '0x0,'
            '10.0.0.0-10.255.255.255,'
            '10.0.0.0-10.255.255.255,'
            ','
            '1,'
            '0,'
            'policy-deny'
        ),


        # ----------------------------------------------------
        # 4. Traffic - Deny
        # ----------------------------------------------------

        (
            '<14>1 2021-11-30T15:54:05-05:00 '
            'logsourcehost appname - - - '
            '1,2021/10/13 05:47:22,'
            '123456789,'
            'TRAFFIC,deny,2561,'
            '2021/10/13 05:47:22,'
            '10.0.0.2,'
            '10.0.0.3,'
            '10.0.0.4,'
            '10.0.0.5,'
            'OS Blocked Apps,,,'
            'slack-base,'
            'vsys1,'
            'trust,'
            'untrust,'
            'ethernet1/2,'
            'ethernet1/1,'
            'Syslog forwarding,'
            ','
            '12251,'
            '1,'
            '62883,'
            '443,'
            '25341,'
            '443,'
            '0x404400,'
            'tcp,'
            'reset-both,'
            '763,'
            '697,'
            '66,'
            '4,'
            '2021/10/13 05:47:20,'
            '1,'
            'internet-communications-and-telephony,'
            ','
            '4000001,'
            '0x0,'
            '10.0.0.0-10.255.255.255,'
            '10.0.0.0-10.255.255.255,'
            ','
            '2,'
            '2,'
            'policy-deny'
        ),


        # ----------------------------------------------------
        # 5. Unknown Future Traffic Subtype
        # ----------------------------------------------------

        (
            '<14>Aug 24 18:30:00 PA-FW '
            '1,2026/08/24 18:30:00,'
            'PA123456789,'
            'TRAFFIC,future-type,1,'
            '2026/08/24 18:29:59,'
            '10.10.10.10,'
            '10.20.20.20,'
            '0.0.0.0,'
            '0.0.0.0,'
            'test-rule,,,'
            'unknown,'
            'vsys1,'
            'trust,'
            'untrust,'
            'ethernet1/1,'
            'ethernet1/2,'
            'default-log,'
            ','
            '9999,'
            '1,'
            '50000,'
            '443,'
            '0,'
            '0,'
            '0x0,'
            'tcp,'
            'allow,'
            '100,'
            '60,'
            '40,'
            '2,'
            '2026/08/24 18:29:59,'
            '1,'
            'any,'
            ','
            '9999999'
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
                f"RAW-PA-TRAFFIC-{index:06d}"
            ),
            u_id=(
                f"UEV-PA-TRAFFIC-{index:06d}"
            )
        )


        normalized_events.append(
            normalized_event
        )


    # ========================================================
    # SAVE NORMALIZED EVENTS
    # ========================================================

    with open(
        "paloalto_traffic_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )