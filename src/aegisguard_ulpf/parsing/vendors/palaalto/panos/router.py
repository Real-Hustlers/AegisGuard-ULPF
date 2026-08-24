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

        "vendor_fields": {}
    }


# ============================================================
# PAN-OS SYSTEM FIELD ORDER
# ============================================================
#
# Palo Alto routing events are primarily carried inside
# PAN-OS SYSTEM records.
#
# We therefore use the same positional SYSTEM schema as the
# Palo Alto System and VPN parsers.
# ============================================================

SYSTEM_FIELD_NAMES = [
    "future_use_1",          # 0
    "receive_time",          # 1
    "serial",                # 2
    "type",                  # 3
    "subtype",               # 4
    "future_use_2",          # 5
    "time_generated",        # 6
    "vsys",                  # 7
    "eventid",               # 8
    "object",                # 9
    "future_use_3",          # 10
    "future_use_4",          # 11
    "module",                # 12
    "severity",              # 13
    "description",           # 14
    "sequence_number",       # 15
    "action_flags",          # 16
    "dg_hier_level_1",       # 17
    "dg_hier_level_2",       # 18
    "dg_hier_level_3",       # 19
    "dg_hier_level_4",       # 20
    "vsys_name",             # 21
    "device_name",           # 22
    "future_use_5",          # 23
    "future_use_6",          # 24
    "high_res_timestamp"     # 25
]


# ============================================================
# ROUTER-OWNED PAN-OS SYSTEM SUBTYPES
# ============================================================

ROUTER_SYSTEM_SUBTYPES = {
    "routing",
    "pbf",
    "bfd"
}


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_value(
    value: Optional[str]
) -> Optional[str]:

    if value is None:
        return None

    value = str(value).strip()

    if value.lower() in {
        "",
        "n/a",
        "na",
        "none",
        "null",
        "-"
    }:
        return None

    return value


def parse_timestamp(
    value: Optional[str]
) -> Optional[str]:

    value = clean_value(value)

    if value is None:
        return None


    try:

        iso_value = value.replace(
            "Z",
            "+00:00"
        )

        return datetime.fromisoformat(
            iso_value
        ).isoformat()

    except ValueError:
        pass


    formats = [
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
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


    # Preserve unknown/new timestamp format.
    return value


# ============================================================
# GENERIC EXTRACTION HELPERS
# ============================================================

def extract_ipv4(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'\b(?:'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)'
        r'\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)'
        r'\b',
        text
    )

    if match:
        return match.group(0)

    return None


def extract_interface(
    text: str
) -> Optional[str]:

    if not text:
        return None

    # Prefer explicit "on interface <name>"
    # before generic "interface <name>".
    patterns = [
        r'\bon\s+interface\s+([A-Za-z0-9_.:/-]+)',
        r'\bPort\s+([A-Za-z0-9_.:/-]+)',
        r'\binterface\s+([A-Za-z0-9_.:/-]+)'
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            value = (
                match.group(1)
                .rstrip(":,;.")
            )

            # Avoid matching descriptive words such as:
            # "interface state changed..."
            if value.lower() in {
                "state",
                "status",
                "change",
                "changed"
            }:
                continue

            return value

    return None


# ============================================================
# BGP EXTRACTION
# ============================================================

def extract_bgp_peer_name(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'peer\s+name:\s*'
        r'([^,]+)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


def extract_bgp_peer_ip(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'peer\s+IP:\s*'
        r'((?:\d{1,3}\.){3}\d{1,3})',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


# ============================================================
# OSPF EXTRACTION
# ============================================================

def extract_ospf_neighbor(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'\bneighbor\s+'
        r'((?:\d{1,3}\.){3}\d{1,3})',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


# ============================================================
# RIP EXTRACTION
# ============================================================

def extract_rip_peer(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'(?:peer|neighbor)'
        r'(?:\s+IP)?[:\s]+'
        r'((?:\d{1,3}\.){3}\d{1,3})',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


# ============================================================
# BFD EXTRACTION
# ============================================================

def extract_bfd_state(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'BFD state changed to\s+'
        r'([A-Za-z_-]+)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


def extract_bfd_session(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'BFD session\s+'
        r'([A-Za-z0-9_.:/-]+)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


def extract_bfd_neighbor(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'to neighbor\s+'
        r'((?:\d{1,3}\.){3}\d{1,3})',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


def extract_bfd_protocol(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'Protocol:\s*'
        r'([A-Za-z0-9_-]+)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


# ============================================================
# STATIC ROUTE EXTRACTION
# ============================================================

def extract_route_destination(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'(?:route\s+destination|destination)\s+'
        r'('
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r'(?:/\d{1,2})?'
        r')',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


def extract_next_hop(
    text: str
) -> Optional[str]:

    if not text:
        return None

    patterns = [
        r'next\s+hop\s+'
        r'((?:\d{1,3}\.){3}\d{1,3})',

        r'nexthop\s+'
        r'((?:\d{1,3}\.){3}\d{1,3})'
    ]


    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return None


# ============================================================
# PBF EXTRACTION
# ============================================================

def extract_pbf_rule(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'PBF rule\s+'
        r'([^\s]+)',
        text,
        re.IGNORECASE
    )

    if match:

        return (
            match.group(1)
            .rstrip(":,;.")
        )

    return None


# ============================================================
# ECMP EXTRACTION
# ============================================================

def extract_virtual_router(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'virtual router\s+'
        r'([A-Za-z0-9_.:/-]+)',
        text,
        re.IGNORECASE
    )

    if match:

        return (
            match.group(1)
            .rstrip(":,;.")
        )

    return None


# ============================================================
# CSV PAYLOAD EXTRACTION
# ============================================================

def extract_csv_payload(
    raw_log: str
) -> str:

    raw_log = raw_log.strip()


    pattern = re.compile(
        r'(?<!\d)1,'
        r'(?='
        r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}'
        r'|'
        r'\d{4}-\d{2}-\d{2}T'
        r')'
    )


    match = pattern.search(
        raw_log
    )


    if match:

        return raw_log[
            match.start():
        ].strip()


    if raw_log.startswith("1,"):
        return raw_log


    raise ValueError(
        "Could not locate PAN-OS CSV payload"
    )


# ============================================================
# PAN-OS SYSTEM CSV PARSER
# ============================================================

def parse_csv_fields(
    raw_log: str
) -> Dict[str, str]:

    payload = extract_csv_payload(
        raw_log
    )


    reader = csv.reader(
        io.StringIO(payload)
    )


    try:

        values = next(reader)

    except StopIteration:

        raise ValueError(
            "PAN-OS Router/System log is empty"
        )


    if len(values) < 15:

        raise ValueError(
            "PAN-OS Router/System log "
            "has too few fields"
        )


    parsed = {}


    for index, value in enumerate(
        values
    ):

        if index < len(
            SYSTEM_FIELD_NAMES
        ):

            key = (
                SYSTEM_FIELD_NAMES[index]
            )

        else:

            # Preserve future PAN-OS fields.
            key = f"field_{index}"


        parsed[key] = value


    return parsed


# ============================================================
# ROUTER DETECTION
# ============================================================

def detect(
    raw_log: str
) -> bool:
    """
    Detect PAN-OS routing-related SYSTEM events.

    Supported ownership:
      SYSTEM / routing
      SYSTEM / pbf

    Also recognizes strongly routing-specific event IDs/modules
    for forward compatibility.
    """

    try:

        fields = parse_csv_fields(
            raw_log
        )

    except (
        ValueError,
        csv.Error
    ):

        return False


    log_type = (
        fields.get("type", "")
        .strip()
        .upper()
    )

    subtype = (
        fields.get("subtype", "")
        .strip()
        .lower()
    )

    eventid = (
        fields.get("eventid", "")
        .strip()
        .lower()
    )

    module = (
        fields.get("module", "")
        .strip()
        .lower()
    )


    if log_type != "SYSTEM":
        return False


    if subtype in ROUTER_SYSTEM_SUBTYPES:
        return True


    # Strong routing-specific indicators.
    routing_event_prefixes = (
        "routed-",
        "path-monitor-",
        "route-table-"
    )


    if eventid.startswith(
        routing_event_prefixes
    ):
        return True


    if module in {
        "routed",
        "routing",
        "bfd"
    }:
        return True


    return False


# ============================================================
# CLASSIFICATION
# ============================================================

def classify(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    subtype = (
        fields.get("subtype", "")
        .strip()
        .lower()
    )

    eventid = (
        fields.get("eventid", "")
        .strip()
        .lower()
    )

    module = (
        fields.get("module", "")
        .strip()
        .lower()
    )

    description = (
        fields.get("description", "")
        .strip()
        .lower()
    )


    classification = {
        "category": "ROUTER",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


    # ========================================================
    # 1. BGP
    # ========================================================

    if (
        "bgp" in eventid
        and (
            "enter-established" in eventid
            or (
                "established" in description
                and "left" not in description
                and "down" not in description
            )
        )
    ):

        classification.update({
            "type": "BGP",
            "subtype": "PEER_UP",
            "outcome": "SUCCESS"
        })


    elif (
        "bgp" in eventid
        and (
            "left-established" in eventid
            or "peer-down" in eventid
            or "left established" in description
            or "peer session down" in description
        )
    ):

        classification.update({
            "type": "BGP",
            "subtype": "PEER_DOWN",
            "outcome": "FAILURE"
        })


    elif (
        "bgp" in eventid
        and (
            (
                "prefix" in eventid
                and (
                    "limit" in eventid
                    or "exceeded" in eventid
                )
            )
            or (
                "maximum allowed prefixes"
                in description
            )
        )
    ):

        classification.update({
            "type": "BGP",
            "subtype": "PREFIX_LIMIT_EXCEEDED",
            "outcome": "FAILURE"
        })


    elif (
        "bgp" in eventid
        and "graceful" in description
        and "restart" in description
    ):

        classification.update({
            "type": "BGP",
            "subtype": "GRACEFUL_RESTART",
            "outcome": "UNKNOWN"
        })


    elif (
        "bgp" in eventid
        and (
            "route-refresh" in eventid
            or "route refresh" in description
        )
    ):

        classification.update({
            "type": "BGP",
            "subtype": "ROUTE_REFRESH",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 2. OSPF
    # ========================================================

    elif (
        "ospf" in eventid
        and (
            "neighbor-down" in eventid
            or "adjacency" in description
            and "gone down" in description
        )
    ):

        classification.update({
            "type": "OSPF",
            "subtype": "NEIGHBOR_DOWN",
            "outcome": "FAILURE"
        })


    elif (
        "ospf" in eventid
        and (
            "neighbor-up" in eventid
            or "neighbor-full" in eventid
            or (
                "full adjacency established"
                in description
            )
            or (
                "adjacency" in description
                and "up" in description
            )
        )
    ):

        classification.update({
            "type": "OSPF",
            "subtype": "NEIGHBOR_UP",
            "outcome": "SUCCESS"
        })


    elif (
        "ospf" in eventid
        and (
            "md5" in eventid
            or "auth" in eventid
            or "authentication" in description
        )
    ):

        classification.update({
            "type": "OSPF",
            "subtype": "AUTHENTICATION_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        "ospf" in eventid
        and (
            "hello" in eventid
            or "mismatch" in description
        )
    ):

        classification.update({
            "type": "OSPF",
            "subtype": "PARAMETER_MISMATCH",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 3. RIP
    # ========================================================

    elif (
        "rip" in eventid
        and (
            "peer-del" in eventid
            or "peer disappeared" in description
        )
    ):

        classification.update({
            "type": "RIP",
            "subtype": "PEER_DOWN",
            "outcome": "FAILURE"
        })


    elif (
        "rip" in eventid
        and (
            "auth-failed" in eventid
            or "authtype-bad" in eventid
            or "authentication failure" in description
        )
    ):

        classification.update({
            "type": "RIP",
            "subtype": "AUTHENTICATION_FAILURE",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 4. BFD
    # ========================================================

    # --------------------------------------------------------
    # Administrative Down
    #
    # Must be checked BEFORE generic SESSION_DOWN because
    # "administrative down" also contains the word "down".
    # --------------------------------------------------------

    elif (
        module == "bfd"
        or subtype == "bfd"
        or "bfd" in eventid
        or "bfd " in description
    ) and (
        "admin-down" in eventid
        or "administrative down" in description
    ):

        classification.update({
            "type": "BFD",
            "subtype": "ADMIN_DOWN",
            "outcome": "UNKNOWN"
        })


    # --------------------------------------------------------
    # Session Down
    # --------------------------------------------------------

    elif (
        module == "bfd"
        or subtype == "bfd"
        or "bfd" in eventid
        or "bfd " in description
    ) and (
        "changed to down" in description
        or "state down" in description
        or "expired-time" in eventid
        or "neighbor-down" in eventid
    ):

        classification.update({
            "type": "BFD",
            "subtype": "SESSION_DOWN",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # Session Up
    # --------------------------------------------------------

    elif (
        module == "bfd"
        or subtype == "bfd"
        or "bfd" in eventid
        or "bfd " in description
    ) and (
        "changed to up" in description
        or "state up" in description
    ):

        classification.update({
            "type": "BFD",
            "subtype": "SESSION_UP",
            "outcome": "SUCCESS"
        })

    # ========================================================
    # 5. STATIC ROUTE
    # ========================================================

    elif (
        "path-monitor-failure" in eventid
        or (
            "path monitoring failed" in description
            and "route removed" in description
        )
    ):

        classification.update({
            "type": "STATIC_ROUTE",
            "subtype": "ROUTE_REMOVED",
            "outcome": "FAILURE"
        })


    elif (
        "path-monitor-recovery" in eventid
        or (
            "path monitoring" in description
            and "recovered" in description
            and "route restored" in description
        )
    ):

        classification.update({
            "type": "STATIC_ROUTE",
            "subtype": "ROUTE_RESTORED",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 6. POLICY BASED FORWARDING
    # ========================================================

    # --------------------------------------------------------
    # FQDN Resolution Failure
    # --------------------------------------------------------

    elif (
        subtype == "pbf"
        and (
            "pbf-fqdn-down" in eventid
            or (
                "fqdn" in description
                and "unresolved" in description
            )
        )
    ):

        classification.update({
            "type": "PBF",
            "subtype": "FQDN_RESOLUTION_FAILURE",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # Rule Bypassed
    #
    # Must be BEFORE NEXT_HOP_DOWN because PAN-OS can use
    # eventid=nh-down for this state too.
    # --------------------------------------------------------

    elif (
        subtype == "pbf"
        and "bypassed" in description
    ):

        classification.update({
            "type": "PBF",
            "subtype": "RULE_BYPASSED",
            "outcome": "UNKNOWN"
        })


    # --------------------------------------------------------
    # Next Hop Down
    # --------------------------------------------------------

    elif (
        subtype == "pbf"
        and (
            (
                eventid == "nh-down"
                and "nexthop" in description
            )
            or "nexthop is down" in description
        )
    ):

        classification.update({
            "type": "PBF",
            "subtype": "NEXT_HOP_DOWN",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # Next Hop Up
    # --------------------------------------------------------

    elif (
        subtype == "pbf"
        and (
            eventid == "nh-up"
            or "nexthop is up" in description
        )
    ):

        classification.update({
            "type": "PBF",
            "subtype": "NEXT_HOP_UP",
            "outcome": "SUCCESS"
        })

    # ========================================================
    # 7. ECMP
    # ========================================================

    elif (
        "ecmp" in eventid
        and "enabled" in description
    ):

        classification.update({
            "type": "ECMP",
            "subtype": "ECMP_ENABLED",
            "outcome": "SUCCESS"
        })


    elif (
        "ecmp" in eventid
        and (
            "maximum path changed" in description
            or "max path changed" in description
        )
    ):

        classification.update({
            "type": "ECMP",
            "subtype": "MAX_PATH_CHANGED",
            "outcome": "UNKNOWN"
        })


    # ========================================================
    # 8. MULTICAST / PIM
    # ========================================================

    elif (
        "pim" in eventid
        and (
            "interface-state-changed" in eventid
            or "interface state changed" in description
        )
    ):

        classification.update({
            "type": "MULTICAST",
            "subtype": "PIM_INTERFACE_STATE_CHANGE",
            "outcome": "UNKNOWN"
        })


    # ========================================================
    # 9. ROUTE TABLE
    # ========================================================

    elif (
        "route-table-capacity" in eventid
        or "route table capacity reached" in description
    ):

        classification.update({
            "type": "ROUTE_TABLE",
            "subtype": "CAPACITY_REACHED",
            "outcome": "FAILURE"
        })


    elif (
        "rtm-bad-route" in eventid
        or "invalid dynamic route" in description
    ):

        classification.update({
            "type": "ROUTE_TABLE",
            "subtype": "INVALID_ROUTE_REJECTED",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 10. ROUTING ENGINE
    # ========================================================

    elif (
        "routed-config-p1-failed" in eventid
        or (
            "route daemon" in description
            and "configuration" in description
            and "failed" in description
        )
    ):

        classification.update({
            "type": "ROUTING_ENGINE",
            "subtype": "CONFIG_LOAD_FAILURE",
            "outcome": "FAILURE"
        })


    return classification


# ============================================================
# ACTION
# ============================================================

def build_action(
    classification: Dict[str, Any]
) -> Optional[str]:

    subtype = classification[
        "subtype"
    ]


    mapping = {

        "PEER_UP":
            "peer-up",

        "PEER_DOWN":
            "peer-down",

        "PREFIX_LIMIT_EXCEEDED":
            "route-limit",

        "GRACEFUL_RESTART":
            "restart",

        "ROUTE_REFRESH":
            "route-refresh",

        "NEIGHBOR_UP":
            "neighbor-up",

        "NEIGHBOR_DOWN":
            "neighbor-down",

        "AUTHENTICATION_FAILURE":
            "authentication",

        "PARAMETER_MISMATCH":
            "parameter-check",

        "SESSION_UP":
            "session-up",

        "SESSION_DOWN":
            "session-down",

        "ADMIN_DOWN":
            "administrative-down",

        "ROUTE_REMOVED":
            "route-remove",

        "ROUTE_RESTORED":
            "route-restore",

        "NEXT_HOP_UP":
            "next-hop-up",

        "NEXT_HOP_DOWN":
            "next-hop-down",

        "RULE_BYPASSED":
            "rule-bypass",

        "FQDN_RESOLUTION_FAILURE":
            "fqdn-resolution",

        "ECMP_ENABLED":
            "enable",

        "MAX_PATH_CHANGED":
            "configuration-change",

        "PIM_INTERFACE_STATE_CHANGE":
            "state-change",

        "CAPACITY_REACHED":
            "capacity-alert",

        "INVALID_ROUTE_REJECTED":
            "route-reject",

        "CONFIG_LOAD_FAILURE":
            "config-load"
    }


    return mapping.get(
        subtype
    )


# ============================================================
# DETAILS NORMALIZATION
# ============================================================

def build_details(
    fields: Dict[str, str],
    classification: Dict[str, Any]
) -> Dict[str, Any]:

    description = (
        clean_value(
            fields.get("description")
        )
        or ""
    )

    router_type = classification[
        "type"
    ]

    router_subtype = classification[
        "subtype"
    ]


    details = {

        "system_subtype":
            clean_value(
                fields.get("subtype")
            ),

        "module":
            clean_value(
                fields.get("module")
            ),

        "sequence_number":
            clean_value(
                fields.get("sequence_number")
            ),

        "description":
            clean_value(
                fields.get("description")
            ),

        "system_object":
            clean_value(
                fields.get("object")
            ),

        "device_name":
            clean_value(
                fields.get("device_name")
            ),

        "virtual_system":
            clean_value(
                fields.get("vsys")
            ),

        "serial_number":
            clean_value(
                fields.get("serial")
            )
    }


    # --------------------------------------------------------
    # BGP
    # --------------------------------------------------------

    if router_type == "BGP":

        details.update({

            "routing_protocol":
                "BGP",

            "peer_name":
                extract_bgp_peer_name(
                    description
                ),

            "peer_ip":
                extract_bgp_peer_ip(
                    description
                )
        })


    # --------------------------------------------------------
    # OSPF
    # --------------------------------------------------------

    elif router_type == "OSPF":

        details.update({

            "routing_protocol":
                "OSPF",

            "neighbor_ip":
                extract_ospf_neighbor(
                    description
                ),

            "interface_name":
                extract_interface(
                    description
                )
        })


    # --------------------------------------------------------
    # RIP
    # --------------------------------------------------------

    elif router_type == "RIP":

        details.update({

            "routing_protocol":
                "RIP",

            "peer_ip":
                extract_rip_peer(
                    description
                )
        })


    # --------------------------------------------------------
    # BFD
    # --------------------------------------------------------

    elif router_type == "BFD":

        details.update({

            "routing_protocol":
                extract_bfd_protocol(
                    description
                ),

            "bfd_state":
                extract_bfd_state(
                    description
                ),

            "bfd_session":
                extract_bfd_session(
                    description
                ),

            "neighbor_ip":
                extract_bfd_neighbor(
                    description
                ),

            "interface_name":
                extract_interface(
                    description
                )
        })


    # --------------------------------------------------------
    # STATIC ROUTE
    # --------------------------------------------------------

    elif router_type == "STATIC_ROUTE":

        details.update({

            "route_type":
                "STATIC",

            "destination":
                extract_route_destination(
                    description
                ),

            "next_hop":
                extract_next_hop(
                    description
                ),

            "monitor_status":
                (
                    "DOWN"
                    if router_subtype
                    == "ROUTE_REMOVED"
                    else "UP"
                )
        })


    # --------------------------------------------------------
    # PBF
    # --------------------------------------------------------

    elif router_type == "PBF":

        details.update({

            "routing_method":
                "PBF",

            "pbf_rule":
                extract_pbf_rule(
                    description
                ),

            "next_hop":
                extract_next_hop(
                    description
                )
        })


    # --------------------------------------------------------
    # ECMP
    # --------------------------------------------------------

    elif router_type == "ECMP":

        details.update({

            "routing_method":
                "ECMP",

            "virtual_router":
                extract_virtual_router(
                    description
                )
        })


    # --------------------------------------------------------
    # MULTICAST
    # --------------------------------------------------------

    elif router_type == "MULTICAST":

        details.update({

            "routing_protocol":
                "PIM",

            "interface_name":
                extract_interface(
                    description
                )
        })


    # --------------------------------------------------------
    # ROUTE TABLE
    # --------------------------------------------------------

    elif router_type == "ROUTE_TABLE":

        details.update({

            "routing_component":
                "ROUTE_TABLE",

            "route_table_operation":
                router_subtype
        })


    # --------------------------------------------------------
    # ROUTING ENGINE
    # --------------------------------------------------------

    elif router_type == "ROUTING_ENGINE":

        details.update({

            "routing_component":
                "ROUTING_DAEMON",

            "routing_engine_operation":
                router_subtype
        })


    return {
        key: value
        for key, value in details.items()
        if value is not None
    }


# ============================================================
# OBJECT NORMALIZATION
# ============================================================

def build_object(
    fields: Dict[str, str],
    classification: Dict[str, Any]
):

    description = (
        clean_value(
            fields.get("description")
        )
        or ""
    )

    router_type = classification[
        "type"
    ]


    if router_type == "BGP":

        peer_name = (
            extract_bgp_peer_name(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "ROUTING_PEER",
            peer_name
        )


    if router_type == "OSPF":

        neighbor = extract_ospf_neighbor(
            description
        )

        if neighbor is not None:

            return (
                "ROUTING_NEIGHBOR",
                neighbor
            )

        return (
            "ROUTING_PROTOCOL",
            "OSPF"
        )


    if router_type == "RIP":

        peer = extract_rip_peer(
            description
        )

        if peer is not None:

            return (
                "ROUTING_PEER",
                peer
            )

        return (
            "ROUTING_PROTOCOL",
            "RIP"
        )


    if router_type == "BFD":

        session = (
            extract_bfd_session(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "BFD_SESSION",
            session
        )


    if router_type == "STATIC_ROUTE":

        destination = (
            extract_route_destination(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "ROUTE",
            destination
        )


    if router_type == "PBF":

        rule = (
            extract_pbf_rule(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "PBF_RULE",
            rule
        )


    if router_type == "ECMP":

        virtual_router = (
            extract_virtual_router(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "VIRTUAL_ROUTER",
            virtual_router
        )


    if router_type == "MULTICAST":

        interface = (
            extract_interface(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "NETWORK_INTERFACE",
            interface
        )


    if router_type == "ROUTE_TABLE":

        return (
            "ROUTE_TABLE",
            (
                clean_value(
                    fields.get("object")
                )
                or "routing-table"
            )
        )


    if router_type == "ROUTING_ENGINE":

        return (
            "ROUTING_DAEMON",
            (
                clean_value(
                    fields.get("module")
                )
                or "routed"
            )
        )


    # Unknown/future routing event.
    return (
        None,
        clean_value(
            fields.get("object")
        )
    )


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
            "a Palo Alto routing System log"
        )


    fields = parse_csv_fields(
        raw_log
    )


    classification = classify(
        fields
    )


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

    event["timestamp"] = (
        parse_timestamp(
            fields.get("time_generated")
            or fields.get("receive_time")
        )
    )


    # --------------------------------------------------------
    # Vendor
    # --------------------------------------------------------

    event["vendor"] = (
        "Palo Alto Networks"
    )

    event["product"] = "PAN-OS"


    # --------------------------------------------------------
    # Common taxonomy
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
    # Severity
    # --------------------------------------------------------

    event["severity"] = clean_value(
        fields.get("severity")
    )


    description = (
        clean_value(
            fields.get("description")
        )
        or ""
    )


    # --------------------------------------------------------
    # Network fields
    # --------------------------------------------------------
    #
    # Only populate common src/dst fields where the semantic
    # meaning is sufficiently strong.
    #
    # A routing peer is not necessarily a packet src/dst, so
    # we keep peer addresses in details instead of falsely
    # mapping them to src_ip/dst_ip.
    # --------------------------------------------------------

    event["src_ip"] = None
    event["src_port"] = None

    event["dst_ip"] = None
    event["dst_port"] = None

    event["protocol"] = None

    event["user"] = None


    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    event["action"] = build_action(
        classification
    )


    # --------------------------------------------------------
    # Reason
    # --------------------------------------------------------

    if (
        classification["outcome"]
        == "FAILURE"
    ):

        event["reason"] = clean_value(
            description
        )

    else:

        event["reason"] = None


    # --------------------------------------------------------
    # Object
    # --------------------------------------------------------

    (
        object_type,
        object_name
    ) = build_object(
        fields,
        classification
    )


    event["object_type"] = (
        object_type
    )

    event["object_name"] = (
        object_name
    )


    # --------------------------------------------------------
    # Details
    # --------------------------------------------------------

    event["details"] = build_details(
        fields,
        classification
    )


    # --------------------------------------------------------
    # Vendor Event ID
    # --------------------------------------------------------
    #
    # eventid is the PAN-OS event identifier.
    # Sequence number remains metadata only.
    # --------------------------------------------------------

    event["vendor_event_id"] = (
        clean_value(
            fields.get("eventid")
        )
    )


    # --------------------------------------------------------
    # Preserve all parsed PAN-OS fields
    # --------------------------------------------------------

    event["vendor_fields"] = (
        fields.copy()
    )


    return event


# ============================================================
# TEST FIXTURE BUILDER
# ============================================================

def build_router_fixture(
    *,
    receive_time: str,
    generated_time: str,
    subtype: str,
    eventid: str,
    module: str,
    severity: str,
    description: str,
    sequence_number: str,
    object_name: str = "",
    serial: str = "PA123456789",
    vsys: str = "vsys1",
    device_name: str = "PA-FW-01",
    log_type: str = "SYSTEM"
) -> str:

    values = [
        "1",
        receive_time,
        serial,
        log_type,
        subtype,
        "1",
        generated_time,
        vsys,
        eventid,
        object_name,
        "",
        "",
        module,
        severity,
        description,
        sequence_number,
        "0x0",
        "0",
        "0",
        "0",
        "0",
        vsys,
        device_name,
        "",
        "",
        ""
    ]


    output = io.StringIO()


    writer = csv.writer(
        output,
        lineterminator=""
    )


    writer.writerow(
        values
    )


    return output.getvalue()


# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        # ----------------------------------------------------
        # 1. BGP - Peer Established
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:00:01",
            generated_time="2025/01/10 13:00:00",
            subtype="routing",
            eventid="routed-BGP-peer-enter-established",
            module="routed",
            severity="informational",
            description=(
                "BGP peer session enters established "
                "state. peer name: ISP-1, "
                "peer IP: 192.0.2.1."
            ),
            sequence_number="500001",
            object_name="ISP-1"
        ),


        # ----------------------------------------------------
        # 2. OSPF - Neighbor Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:05:01",
            generated_time="2025/01/10 13:05:00",
            subtype="routing",
            eventid="routed-OSPF-neighbor-down",
            module="routed",
            severity="high",
            description=(
                "OSPF adjacency with neighbor "
                "has gone down. "
                "interface ae5.54, "
                "neighbor 10.0.0.2"
            ),
            sequence_number="500002",
            object_name="10.0.0.2"
        ),


        # ----------------------------------------------------
        # 3. RIP - Peer Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:10:01",
            generated_time="2025/01/10 13:10:00",
            subtype="routing",
            eventid="routed-RIP-peer-del",
            module="routed",
            severity="high",
            description=(
                "RIP peer disappeared. "
                "peer IP: 192.0.2.9"
            ),
            sequence_number="500003",
            object_name="192.0.2.9"
        ),


        # ----------------------------------------------------
        # 4. BFD - Session Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:15:01",
            generated_time="2025/01/10 13:15:00",
            subtype="routing",
            eventid="session-state-change",
            module="bfd",
            severity="high",
            description=(
                "BFD state changed to Down "
                "for BFD session BFD-ISP1 "
                "to neighbor 192.0.2.1 "
                "on interface ethernet1/1. "
                "Protocol: BGP"
            ),
            sequence_number="500004",
            object_name="BFD-ISP1"
        ),


        # ----------------------------------------------------
        # 5. Static Route - Removed
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:20:01",
            generated_time="2025/01/10 13:20:00",
            subtype="routing",
            eventid="path-monitor-failure",
            module="routed",
            severity="critical",
            description=(
                "Path monitoring failed for static "
                "route destination 192.168.16.0/24 "
                "with next hop 172.16.130.96. "
                "Route removed."
            ),
            sequence_number="500005",
            object_name="192.168.16.0/24"
        ),


        # ----------------------------------------------------
        # 6. PBF - Next Hop Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:25:01",
            generated_time="2025/01/10 13:25:00",
            subtype="pbf",
            eventid="nh-down",
            module="",
            severity="high",
            description=(
                "Vsys vsys1 PBF rule "
                "Internet-Backup "
                "nexthop is DOWN"
            ),
            sequence_number="500006",
            object_name="Internet-Backup"
        ),


        # ----------------------------------------------------
        # 7. ECMP - Enabled
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:30:01",
            generated_time="2025/01/10 13:30:00",
            subtype="routing",
            eventid="routed-ECMP",
            module="routed",
            severity="informational",
            description=(
                "ECMP enabled in "
                "virtual router default."
            ),
            sequence_number="500007",
            object_name="default"
        ),


        # ----------------------------------------------------
        # 8. Multicast / PIM - Interface State Change
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:35:01",
            generated_time="2025/01/10 13:35:00",
            subtype="routing",
            eventid="routed-PIM-interface-state-changed",
            module="routed",
            severity="informational",
            description=(
                "PIM interface state changed "
                "on interface ethernet1/3"
            ),
            sequence_number="500008",
            object_name="ethernet1/3"
        ),


        # ----------------------------------------------------
        # 9. Route Table - Capacity Reached
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:40:01",
            generated_time="2025/01/10 13:40:00",
            subtype="routing",
            eventid="route-table-capacity",
            module="routed",
            severity="high",
            description="Route table capacity reached.",
            sequence_number="500009",
            object_name="routing-table"
        ),


        # ----------------------------------------------------
        # 10. Routing Engine - Config Failure
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:45:01",
            generated_time="2025/01/10 13:45:00",
            subtype="routing",
            eventid="routed-config-p1-failed",
            module="routed",
            severity="high",
            description=(
                "Route daemon configuration "
                "load phase-1 failed."
            ),
            sequence_number="500010",
            object_name="routed"
        ),


        # ----------------------------------------------------
        # 11. BGP - Peer Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:50:01",
            generated_time="2025/01/10 13:50:00",
            subtype="routing",
            eventid="routed-BGP-peer-left-established",
            module="routed",
            severity="high",
            description=(
                "BGP peer session left established "
                "state. peer name: ISP-1, "
                "peer IP: 192.0.2.1."
            ),
            sequence_number="500011",
            object_name="ISP-1"
        ),


        # ----------------------------------------------------
        # 12. BGP - Prefix Limit Exceeded
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 13:55:01",
            generated_time="2025/01/10 13:55:00",
            subtype="routing",
            eventid="routed-BGP-peer-prefix-exceeded",
            module="routed",
            severity="high",
            description=(
                "BGP peer advertised more than "
                "maximum allowed prefixes. "
                "peer name: ISP-1, "
                "peer IP: 192.0.2.1."
            ),
            sequence_number="500012",
            object_name="ISP-1"
        ),


        # ----------------------------------------------------
        # 13. BGP - Graceful Restart
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:00:01",
            generated_time="2025/01/10 14:00:00",
            subtype="routing",
            eventid="routed-BGP-peer-restarted",
            module="routed",
            severity="high",
            description=(
                "Initiated graceful-restart "
                "with a BGP peer. "
                "peer name: ISP-1, "
                "peer IP: 192.0.2.1."
            ),
            sequence_number="500013",
            object_name="ISP-1"
        ),


        # ----------------------------------------------------
        # 14. BGP - Route Refresh
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:05:01",
            generated_time="2025/01/10 14:05:00",
            subtype="routing",
            eventid="routed-BGP-refresh-sent",
            module="routed",
            severity="informational",
            description=(
                "ROUTE REFRESH message sent "
                "to a BGP peer. "
                "peer name: ISP-1, "
                "peer IP: 192.0.2.1."
            ),
            sequence_number="500014",
            object_name="ISP-1"
        ),


        # ----------------------------------------------------
        # 15. OSPF - Neighbor Up
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:10:01",
            generated_time="2025/01/10 14:10:00",
            subtype="routing",
            eventid="routed-OSPF-neighbor-full",
            module="routed",
            severity="informational",
            description=(
                "OSPF full adjacency established "
                "with neighbor. "
                "interface ethernet1/2, "
                "neighbor 10.0.0.2"
            ),
            sequence_number="500015",
            object_name="10.0.0.2"
        ),


        # ----------------------------------------------------
        # 16. OSPF - Authentication Failure
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:15:01",
            generated_time="2025/01/10 14:15:00",
            subtype="routing",
            eventid="routed-OSPF-md5chksum-bad",
            module="routed",
            severity="low",
            description=(
                "OSPF packet dropped due to "
                "incorrect MD5 checksum."
            ),
            sequence_number="500016",
            object_name="OSPF"
        ),


        # ----------------------------------------------------
        # 17. OSPF - Parameter Mismatch
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:20:01",
            generated_time="2025/01/10 14:20:00",
            subtype="routing",
            eventid="routed-OSPF-hello-hello-intval-bad",
            module="routed",
            severity="low",
            description=(
                "OSPF hello packet dropped due "
                "to hello-interval mismatch."
            ),
            sequence_number="500017",
            object_name="OSPF"
        ),


        # ----------------------------------------------------
        # 18. RIP - Authentication Failure
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:25:01",
            generated_time="2025/01/10 14:25:00",
            subtype="routing",
            eventid="routed-RIP-auth-failed",
            module="routed",
            severity="low",
            description=(
                "RIP packet dropped due to "
                "authentication failure."
            ),
            sequence_number="500018",
            object_name="RIP"
        ),


        # ----------------------------------------------------
        # 19. BFD - Session Up
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:30:01",
            generated_time="2025/01/10 14:30:00",
            subtype="bfd",
            eventid="session-state-change",
            module="bfd",
            severity="informational",
            description=(
                "BFD state changed to Up "
                "for BFD session BFD-ISP1 "
                "to neighbor 192.0.2.1 "
                "on interface ethernet1/1. "
                "Protocol: BGP"
            ),
            sequence_number="500019",
            object_name="BFD-ISP1"
        ),


        # ----------------------------------------------------
        # 20. BFD - Administrative Down
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:35:01",
            generated_time="2025/01/10 14:35:00",
            subtype="bfd",
            eventid="admin-down",
            module="bfd",
            severity="high",
            description=(
                "BFD administrative down for "
                "BFD session BFD-ISP1 "
                "to neighbor 192.0.2.1 "
                "on interface ethernet1/1. "
                "Protocol: BGP"
            ),
            sequence_number="500020",
            object_name="BFD-ISP1"
        ),


        # ----------------------------------------------------
        # 21. Static Route - Restored
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:40:01",
            generated_time="2025/01/10 14:40:00",
            subtype="routing",
            eventid="path-monitor-recovery",
            module="routed",
            severity="critical",
            description=(
                "Path monitoring for static route "
                "destination 192.168.16.0/24 "
                "with next hop 172.16.130.96 "
                "recovered. Route restored."
            ),
            sequence_number="500021",
            object_name="192.168.16.0/24"
        ),


        # ----------------------------------------------------
        # 22. PBF - Next Hop Up
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:45:01",
            generated_time="2025/01/10 14:45:00",
            subtype="pbf",
            eventid="nh-up",
            module="",
            severity="informational",
            description=(
                "Vsys vsys1 PBF rule "
                "Internet-Backup "
                "nexthop is UP"
            ),
            sequence_number="500022",
            object_name="Internet-Backup"
        ),


        # ----------------------------------------------------
        # 23. PBF - Rule Bypassed
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:50:01",
            generated_time="2025/01/10 14:50:00",
            subtype="pbf",
            eventid="nh-down",
            module="",
            severity="informational",
            description=(
                "Vsys vsys1 PBF rule "
                "Internet-Backup is Bypassed"
            ),
            sequence_number="500023",
            object_name="Internet-Backup"
        ),


        # ----------------------------------------------------
        # 24. PBF - FQDN Resolution Failure
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 14:55:01",
            generated_time="2025/01/10 14:55:00",
            subtype="pbf",
            eventid="pbf-fqdn-down",
            module="",
            severity="critical",
            description=(
                "Vsys vsys1 PBF rule "
                "Cloud-PBF nexthop FQDN "
                "gateway.example.test "
                "is unresolved for IPv4"
            ),
            sequence_number="500024",
            object_name="Cloud-PBF"
        ),


        # ----------------------------------------------------
        # 25. ECMP - Maximum Path Changed
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 15:00:01",
            generated_time="2025/01/10 15:00:00",
            subtype="routing",
            eventid="routed-ECMP",
            module="routed",
            severity="informational",
            description=(
                "ECMP maximum path changed to 4 "
                "in virtual router default."
            ),
            sequence_number="500025",
            object_name="default"
        ),


        # ----------------------------------------------------
        # 26. Route Table - Invalid Route Rejected
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2025/01/10 15:05:01",
            generated_time="2025/01/10 15:05:00",
            subtype="routing",
            eventid="routed-RTM-bad-route",
            module="routed",
            severity="low",
            description=(
                "An invalid dynamic route "
                "has been rejected: "
                "203.0.113.0/24"
            ),
            sequence_number="500026",
            object_name="203.0.113.0/24"
        ),


        # ----------------------------------------------------
        # 27. Unknown Future Routing Event
        # ----------------------------------------------------

        build_router_fixture(
            receive_time="2026/08/24 20:10:01",
            generated_time="2026/08/24 20:10:00",
            subtype="routing",
            eventid="routed-future-feature-event",
            module="routed",
            severity="informational",
            description=(
                "Future PAN-OS routing "
                "functionality event"
            ),
            sequence_number="999999",
            object_name="future-routing-object"
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
                f"RAW-PA-ROUTER-{index:06d}"
            ),
            u_id=(
                f"UEV-PA-ROUTER-{index:06d}"
            )
        )


        normalized_events.append(
            normalized_event
        )


    # ========================================================
    # SAVE NORMALIZED EVENTS
    # ========================================================

    with open(
        "paloalto_router_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )