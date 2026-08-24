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

        # Every parsed vendor field is preserved.
        "vendor_fields": {}
    }


# ============================================================
# PAN-OS GLOBALPROTECT FIELD ORDER
# ============================================================
#
# Based on Palo Alto's documented GlobalProtect Syslog
# default field order.
#
# Newer versions may append additional fields.
# Unknown trailing fields are preserved as field_N.
# ============================================================

GLOBALPROTECT_FIELD_NAMES = [
    "future_use_1",          # 0
    "receive_time",          # 1
    "serial",                # 2
    "type",                  # 3
    "subtype",               # 4
    "config_version",        # 5
    "time_generated",        # 6
    "vsys",                  # 7
    "eventid",               # 8
    "stage",                 # 9
    "auth_method",           # 10
    "tunnel_type",           # 11
    "srcuser",               # 12
    "srcregion",             # 13
    "machinename",           # 14
    "public_ip",             # 15
    "public_ipv6",           # 16
    "private_ip",            # 17
    "private_ipv6",          # 18
    "hostid",                # 19
    "endpoint_serial",       # 20
    "client_version",        # 21
    "client_os",             # 22
    "client_os_version",     # 23
    "repeat_count",          # 24
    "reason",                # 25
    "error",                 # 26
    "description",           # 27
    "status",                # 28
    "location",              # 29
    "login_duration",        # 30
    "connect_method",        # 31
    "error_code",            # 32
    "portal",                # 33
    "sequence_number",       # 34
    "action_flags",          # 35
    "high_res_timestamp",    # 36
    "selection_type",        # 37
    "response_time",         # 38
    "priority",              # 39
    "attempted_gateways",    # 40
    "gateway",               # 41
    "dg_hier_level_1",       # 42
    "dg_hier_level_2",       # 43
    "dg_hier_level_3",       # 44
    "dg_hier_level_4",       # 45
    "vsys_name",             # 46
    "device_name",           # 47
    "vsys_id",               # 48
    "cluster_name"           # 49
]


# ============================================================
# PAN-OS SYSTEM FIELD ORDER
# ============================================================

SYSTEM_FIELD_NAMES = [
    "future_use_1",          # 0
    "receive_time",          # 1
    "serial",                # 2
    "type",                  # 3
    "subtype",               # 4
    "config_version",        # 5
    "time_generated",        # 6
    "vsys",                  # 7
    "eventid",               # 8
    "object",                # 9
    "future_use_2",          # 10
    "future_use_3",          # 11
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
    "device_group",          # 23
    "template",              # 24
    "high_res_timestamp"     # 25
]


VPN_SYSTEM_SUBTYPES = {
    "vpn",
    "sslvpn",
    "global-protect",
    "crypto"
}


# ============================================================
# HELPERS
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


def convert_int(
    value: Optional[str]
):

    value = clean_value(value)

    if value is None:
        return None

    try:
        return int(value)

    except (ValueError, TypeError):
        return value


def parse_timestamp(
    value: Optional[str]
) -> Optional[str]:

    value = clean_value(value)

    if not value:
        return None

    # ISO-8601 PAN-OS timestamps
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

    # Older PAN-OS timestamps
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

    return value


def status_to_outcome(
    status: Optional[str]
) -> str:

    status = (
        clean_value(status)
        or ""
    ).lower()

    if status in {
        "success",
        "succeeded",
        "connected",
        "complete",
        "completed"
    }:
        return "SUCCESS"

    if status in {
        "failure",
        "failed",
        "error",
        "denied"
    }:
        return "FAILURE"

    return "UNKNOWN"


# ============================================================
# EXTRACT PAN-OS CSV PAYLOAD
# ============================================================

def extract_csv_payload(
    raw_log: str
) -> str:

    raw_log = raw_log.strip()

    # Supports old:
    #   1,2024/01/01 12:00:00,...
    #
    # and newer:
    #   1,2024-01-01T12:00:00.000000Z,...

    pattern = re.compile(
        r'(?<!\d)1,'
        r'(?='
        r'\d{4}[/-]\d{2}[/-]\d{2}'
        r'|'
        r'\d{4}-\d{2}-\d{2}T'
        r')'
    )

    match = pattern.search(raw_log)

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
# GENERIC PAN-OS CSV PARSER
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
            "PAN-OS log is empty"
        )

    if len(values) < 5:
        raise ValueError(
            "PAN-OS log has too few fields"
        )

    log_type = values[3].strip().upper()

    if log_type == "GLOBALPROTECT":
        field_names = GLOBALPROTECT_FIELD_NAMES

    elif log_type == "SYSTEM":
        field_names = SYSTEM_FIELD_NAMES

    else:
        field_names = []

    parsed = {}

    for index, value in enumerate(values):

        if index < len(field_names):
            key = field_names[index]

        else:
            key = f"field_{index}"

        parsed[key] = value

    return parsed


# ============================================================
# VPN DETECTION
# ============================================================

def detect(
    raw_log: str
) -> bool:
    """
    Detect both:

        GLOBALPROTECT logs

    and VPN-related:

        SYSTEM / vpn
        SYSTEM / sslvpn
        SYSTEM / global-protect
        SYSTEM / crypto

    Detection is intentionally broader than classification.
    Unknown VPN semantics must still be preserved.
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

    log_type = fields.get(
        "type",
        ""
    ).strip().upper()

    subtype = fields.get(
        "subtype",
        ""
    ).strip().lower()

    if log_type == "GLOBALPROTECT":
        return True

    if (
        log_type == "SYSTEM"
        and subtype in VPN_SYSTEM_SUBTYPES
    ):
        return True

    return False


# ============================================================
# GLOBALPROTECT CLASSIFICATION
# ============================================================

def classify_globalprotect(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    eventid = (
        fields.get("eventid", "")
        .strip()
        .lower()
    )

    stage = (
        fields.get("stage", "")
        .strip()
        .lower()
    )

    status = (
        fields.get("status", "")
        .strip()
        .lower()
    )

    description = (
        fields.get("description", "")
        .strip()
        .lower()
    )

    error = (
        fields.get("error", "")
        .strip()
        .lower()
    )

    reason = (
        fields.get("reason", "")
        .strip()
        .lower()
    )

    text = " ".join([
        eventid,
        stage,
        status,
        description,
        error,
        reason
    ])


    classification = {
        "category": "VPN",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


    # --------------------------------------------------------
    # AUTHENTICATION FAILURE
    # --------------------------------------------------------

    if (
        "auth-fail" in eventid
        or (
            stage == "login"
            and status in {
                "failure",
                "failed"
            }
        )
        or "authentication failed" in text
    ):

        classification.update({
            "type": "AUTHENTICATION",
            "subtype": "LOGIN_FAILURE",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # AUTHENTICATION SUCCESS
    # --------------------------------------------------------

    elif (
        "auth-succ" in eventid
        or (
            stage == "login"
            and status in {
                "success",
                "succeeded"
            }
        )
        or "authentication succeeded" in text
    ):

        classification.update({
            "type": "AUTHENTICATION",
            "subtype": "LOGIN_SUCCESS",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # CONFIGURATION RELEASE
    # --------------------------------------------------------

    elif (
        "config-release" in eventid
        or "configuration released" in text
    ):

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "CONFIG_RELEASED",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # CONFIGURATION RECEIVED / GENERATED
    # --------------------------------------------------------

    elif (
        "config-succ" in eventid
        or (
            stage == "configuration"
            and status in {
                "success",
                "succeeded"
            }
        )
        or "configuration generated" in text
    ):

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "CONFIG_RECEIVED",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # USER LOGOUT
    # --------------------------------------------------------

    elif (
        "logout-succ" in eventid
        or stage == "logout"
        or "logout succeeded" in text
    ):

        classification.update({
            "type": "CONNECTION",
            "subtype": "USER_LOGOUT",
            "outcome": (
                status_to_outcome(status)
                if status
                else "SUCCESS"
            )
        })


    # --------------------------------------------------------
    # TUNNEL DOWN
    # --------------------------------------------------------

    elif (
        "tunnel is down" in text
        or "tunnel down" in text
        or "tunnel-down" in eventid
    ):

        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_DOWN",
            "outcome": (
                "FAILURE"
                if any(
                    keyword in text
                    for keyword in {
                        "timeout",
                        "failed",
                        "failure",
                        "error",
                        "dpd"
                    }
                )
                else "UNKNOWN"
            )
        })


    # --------------------------------------------------------
    # TUNNEL UP
    # --------------------------------------------------------

    elif (
        "tunnel creation finished" in text
        or "tunnel-up" in eventid
        or (
            stage == "tunnel"
            and status in {
                "success",
                "succeeded"
            }
        )
    ):

        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_UP",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # HOST POSTURE / HIP
    # --------------------------------------------------------

    elif (
        stage == "host-info"
        or "hip report" in text
        or "hip check" in text
    ):

        classification.update({
            "type": "HOST_POSTURE",
            "subtype": "HIP_CHECK_COMPLETED",
            "outcome": (
                status_to_outcome(status)
                if status
                else "SUCCESS"
            )
        })


    # --------------------------------------------------------
    # PRELOGIN
    # --------------------------------------------------------

    elif (
        stage == "before-login"
        or "prelogin" in eventid
        or "pre-login" in eventid
    ):

        classification.update({
            "type": "CONNECTION",
            "subtype": "PRELOGIN",

            # Pre-login is a stage, not necessarily a
            # successful authenticated VPN session.
            "outcome": "UNKNOWN"
        })


    # --------------------------------------------------------
    # CONNECTION ESTABLISHED
    # --------------------------------------------------------

    elif (
        "regist-succ" in eventid
        or (
            stage == "connected"
            and status in {
                "success",
                "succeeded",
                "connected"
            }
        )
        or "user login succeeded" in text
    ):

        classification.update({
            "type": "CONNECTION",
            "subtype": "CONNECTION_ESTABLISHED",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # GENERIC VPN ERROR
    # --------------------------------------------------------

    elif (
        status in {
            "failure",
            "failed",
            "error"
        }
        or error
        or "could not connect" in text
        or "connection failed" in text
    ):

        classification.update({
            "type": "ERROR",
            "subtype": "VPN_ERROR",
            "outcome": "FAILURE"
        })


    return classification


# ============================================================
# SYSTEM VPN CLASSIFICATION
# ============================================================

def classify_system_vpn(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    eventid = (
        fields.get("eventid", "")
        .strip()
        .lower()
    )

    description = (
        fields.get("description", "")
        .strip()
        .lower()
    )

    subtype = (
        fields.get("subtype", "")
        .strip()
        .lower()
    )

    text = " ".join([
        eventid,
        subtype,
        description
    ])


    classification = {
        "category": "VPN",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


    # --------------------------------------------------------
    # IPSEC / IKE NEGOTIATION SUCCESS
    # --------------------------------------------------------

    if (
        "negotiation is succeeded" in text
        or "negotiation succeeded" in text
        or "established sa" in text
    ):

        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_SUCCESS",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # IPSEC / IKE NEGOTIATION FAILURE
    # --------------------------------------------------------

    elif (
        "negotiation failed" in text
        or "negotiation failure" in text
        or "no proposal chosen" in text
        or "proposal mismatch" in text
        or "proposal does not match" in text
    ):

        classification.update({
            "type": "NEGOTIATION",
            "subtype": "NEGOTIATION_FAILURE",
            "outcome": "FAILURE"
        })


    # --------------------------------------------------------
    # TUNNEL UP
    # --------------------------------------------------------

    elif (
        eventid == "tunnel-status-up"
        or (
            "tunnel" in text
            and " is up" in text
        )
    ):

        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_UP",
            "outcome": "SUCCESS"
        })


    # --------------------------------------------------------
    # TUNNEL DOWN
    # --------------------------------------------------------

    elif (
        eventid == "tunnel-status-down"
        or "ike sa is down" in text
        or (
            "tunnel" in text
            and " is down" in text
        )
    ):

        classification.update({
            "type": "TUNNEL",
            "subtype": "TUNNEL_DOWN",
            "outcome": (
                "FAILURE"
                if any(
                    keyword in text
                    for keyword in {
                        "dpd",
                        "timeout",
                        "failed",
                        "failure",
                        "error"
                    }
                )
                else "UNKNOWN"
            )
        })


    # --------------------------------------------------------
    # GENERIC VPN ERROR
    # --------------------------------------------------------

    elif (
        "error" in text
        or "failed" in text
        or "failure" in text
    ):

        classification.update({
            "type": "ERROR",
            "subtype": "VPN_ERROR",
            "outcome": "FAILURE"
        })


    return classification


# ============================================================
# CLASSIFY ANY PALO ALTO VPN LOG
# ============================================================

def classify(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    log_type = fields.get(
        "type",
        ""
    ).strip().upper()

    if log_type == "GLOBALPROTECT":
        return classify_globalprotect(
            fields
        )

    if log_type == "SYSTEM":
        return classify_system_vpn(
            fields
        )

    return {
        "category": "VPN",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


# ============================================================
# VPN TYPE
# ============================================================

def identify_vpn_type(
    fields: Dict[str, str]
) -> Optional[str]:

    log_type = fields.get(
        "type",
        ""
    ).upper()

    subtype = fields.get(
        "subtype",
        ""
    ).lower()

    tunnel_type = (
        fields.get("tunnel_type", "")
        .lower()
    )

    description = (
        fields.get("description", "")
        .lower()
    )

    text = " ".join([
        subtype,
        tunnel_type,
        description
    ])

    if log_type == "GLOBALPROTECT":
        return "GLOBALPROTECT"

    if (
        "ipsec" in text
        or "ike" in text
        or subtype in {
            "vpn",
            "crypto"
        }
    ):
        return "IPSEC"

    if (
        "ssl" in text
        or subtype == "sslvpn"
    ):
        return "SSL_VPN"

    return None


# ============================================================
# CATEGORY-SPECIFIC DETAILS
# ============================================================

def build_details(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    log_type = fields.get(
        "type",
        ""
    ).upper()


    if log_type == "GLOBALPROTECT":

        details = {
            "vpn_type":
                identify_vpn_type(fields),

            "stage":
                clean_value(
                    fields.get("stage")
                ),

            "authentication_method":
                clean_value(
                    fields.get("auth_method")
                ),

            "tunnel_type":
                clean_value(
                    fields.get("tunnel_type")
                ),

            "source_region":
                clean_value(
                    fields.get("srcregion")
                ),

            "machine_name":
                clean_value(
                    fields.get("machinename")
                ),

            "public_ip":
                clean_value(
                    fields.get("public_ip")
                ),

            "public_ipv6":
                clean_value(
                    fields.get("public_ipv6")
                ),

            "private_ip":
                clean_value(
                    fields.get("private_ip")
                ),

            "private_ipv6":
                clean_value(
                    fields.get("private_ipv6")
                ),

            "host_id":
                clean_value(
                    fields.get("hostid")
                ),

            "endpoint_serial":
                clean_value(
                    fields.get("endpoint_serial")
                ),

            "client_version":
                clean_value(
                    fields.get("client_version")
                ),

            "client_os":
                clean_value(
                    fields.get("client_os")
                ),

            "client_os_version":
                clean_value(
                    fields.get("client_os_version")
                ),

            "repeat_count":
                convert_int(
                    fields.get("repeat_count")
                ),

            "status":
                clean_value(
                    fields.get("status")
                ),

            "location":
                clean_value(
                    fields.get("location")
                ),

            "login_duration":
                convert_int(
                    fields.get("login_duration")
                ),

            "connect_method":
                clean_value(
                    fields.get("connect_method")
                ),

            "error":
                clean_value(
                    fields.get("error")
                ),

            "error_code":
                clean_value(
                    fields.get("error_code")
                ),

            "portal":
                clean_value(
                    fields.get("portal")
                ),

            "gateway":
                clean_value(
                    fields.get("gateway")
                ),

            "sequence_number":
                clean_value(
                    fields.get("sequence_number")
                ),

            "description":
                clean_value(
                    fields.get("description")
                ),

            "device_name":
                clean_value(
                    fields.get("device_name")
                ),

            "virtual_system":
                clean_value(
                    fields.get("vsys")
                )
        }


    else:

        details = {
            "vpn_type":
                identify_vpn_type(fields),

            "system_subtype":
                clean_value(
                    fields.get("subtype")
                ),

            "system_object":
                clean_value(
                    fields.get("object")
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

            "device_name":
                clean_value(
                    fields.get("device_name")
                ),

            "virtual_system":
                clean_value(
                    fields.get("vsys")
                )
        }


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
            "a Palo Alto VPN log"
        )


    fields = parse_csv_fields(
        raw_log
    )

    classification = classify(
        fields
    )

    event = empty_common_event()


    # IDs
    event["raw_id"] = raw_id

    event["u_id"] = (
        u_id
        or f"UEV-{uuid.uuid4()}"
    )


    # Timestamp
    event["timestamp"] = parse_timestamp(
        fields.get("time_generated")
        or fields.get("receive_time")
    )


    # Vendor
    event["vendor"] = (
        "Palo Alto Networks"
    )

    event["product"] = "PAN-OS"


    # Taxonomy
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


    # Severity only exists directly in
    # SYSTEM logs.
    event["severity"] = clean_value(
        fields.get("severity")
    )


    # --------------------------------------------------------
    # Network / identity
    # --------------------------------------------------------

    log_type = fields.get(
        "type",
        ""
    ).upper()

    if log_type == "GLOBALPROTECT":

        # Public client IP is the clearest common
        # source address for a remote VPN connection.
        event["src_ip"] = clean_value(
            fields.get("public_ip")
        )

        event["user"] = clean_value(
            fields.get("srcuser")
        )

    else:

        event["src_ip"] = None
        event["user"] = None


    event["src_port"] = None
    event["dst_ip"] = None
    event["dst_port"] = None
    event["protocol"] = None


    # --------------------------------------------------------
    # Action / Reason
    # --------------------------------------------------------

    # PAN-OS VPN logs don't contain a universal action
    # column equivalent to PAN-OS Traffic logs.
    event["action"] = None

    if classification["outcome"] == "FAILURE":

        event["reason"] = clean_value(
            fields.get("error")
            or fields.get("reason")
            or fields.get("description")
        )

    else:

        event["reason"] = clean_value(
            fields.get("reason")
        )


    # --------------------------------------------------------
    # Object
    # --------------------------------------------------------

    if log_type == "GLOBALPROTECT":

        gateway = clean_value(
            fields.get("gateway")
        )

        portal = clean_value(
            fields.get("portal")
        )

        if gateway:

            event["object_type"] = (
                "VPN_GATEWAY"
            )

            event["object_name"] = (
                gateway
            )

        elif portal:

            event["object_type"] = (
                "VPN_PORTAL"
            )

            event["object_name"] = (
                portal
            )

    else:

        system_object = clean_value(
            fields.get("object")
        )

        if system_object:

            event["object_type"] = (
                "VPN_TUNNEL"
            )

            event["object_name"] = (
                system_object
            )


    # Details
    event["details"] = build_details(
        fields
    )


    # Palo Alto Event ID is an actual named event.
    event["vendor_event_id"] = (
        clean_value(
            fields.get("eventid")
        )
    )


    # Preserve all parsed vendor fields.
    event["vendor_fields"] = (
        fields.copy()
    )


    return event


# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        # ----------------------------------------------------
        # 1. GlobalProtect - Gateway Registration
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:00:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:00:00,'
            'vsys1,'
            'globalprotectgateway-regist-succ,'
            'connected,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'GlobalProtect gateway user login succeeded,'
            'success,'
            'India,'
            '3,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100001,'
            '0x0,'
            ','
            'manual,'
            '100,'
            '1,'
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 2. GlobalProtect - Authentication Failure
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:05:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:05:00,'
            'vsys1,'
            'globalprotectportal-auth-fail,'
            'login,'
            'SAML,'
            'SSLVPN,'
            'bob,'
            'IN,'
            'LAPTOP-02,'
            '203.0.113.20,'
            ','
            ','
            ','
            'HOST-002,'
            'ENDPOINT-002,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            'Authentication rejected,'
            'Authentication failed,'
            'GlobalProtect portal user authentication failed,'
            'failure,'
            'India,'
            '0,'
            'on-demand,'
            '1001,'
            'gp-portal,'
            '100002,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            ','
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 3. GlobalProtect - Configuration Received
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:10:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:10:00,'
            'vsys1,'
            'globalprotectportal-config-succ,'
            'configuration,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'GlobalProtect portal client configuration generated,'
            'success,'
            'India,'
            '1,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100003,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            ','
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 4. GlobalProtect - SSL Tunnel Up
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:15:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:15:00,'
            'vsys1,'
            'globalprotect-tunnel-event,'
            'tunnel,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'SSL tunnel creation finished with Gateway gp-gateway,'
            'success,'
            'India,'
            '2,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100004,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 5. SYSTEM VPN - IKEv2 Negotiation Success
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:20:01,'
            'PA123456789,'
            'SYSTEM,vpn,1,'
            '2024/04/10 10:20:00,'
            'vsys1,'
            'ikev2-n,'
            'Branch-IPSec,'
            ','
            ','
            ','
            'informational,'
            'IKEv2 child SA negotiation is succeeded '
            'as responder non-rekey. Established SA,'
            '200001,'
            '0x0,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01'
        ),


        # ----------------------------------------------------
        # 6. GlobalProtect - HIP Check
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:25:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:25:00,'
            'vsys1,'
            'globalprotect-hip-report,'
            'host-info,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'Completed HIP Report check with Gateway gp-gateway,'
            'success,'
            'India,'
            '1,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100005,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 7. GlobalProtect - Gateway Connection Failure
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:30:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:30:00,'
            'vsys1,'
            'globalprotect-gateway-error,'
            'connected,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            ','
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            'Gateway unavailable,'
            'Could not connect to the GlobalProtect gateway,'
            'Gateway connection failed,'
            'failure,'
            'India,'
            '0,'
            'on-demand,'
            '2001,'
            'gp-portal,'
            '100006,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 8. GlobalProtect - Prelogin
        # ----------------------------------------------------

        (
            '1,2024/04/10 09:55:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 09:55:00,'
            'vsys1,'
            'portal-prelogin,'
            'before-login,'
            'certificate,'
            'SSLVPN,'
            'pre-logon,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            ','
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'GlobalProtect portal pre-login check started,'
            'pending,'
            'India,'
            '0,'
            'pre-logon,'
            '0,'
            'gp-portal,'
            '100007,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            ','
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 9. GlobalProtect - User Logout
        # ----------------------------------------------------

        (
            '1,2024/04/10 11:00:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 11:00:00,'
            'vsys1,'
            'globalprotectgateway-logout-succ,'
            'logout,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            'User initiated logout,'
            ','
            'GlobalProtect gateway user logout succeeded,'
            'success,'
            'India,'
            '3600,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100008,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 10. GlobalProtect - Login Success
        # ----------------------------------------------------

        (
            '1,2024/04/10 10:04:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:04:00,'
            'vsys1,'
            'globalprotectportal-auth-succ,'
            'login,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            ','
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'GlobalProtect portal user authentication succeeded,'
            'success,'
            'India,'
            '1,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100009,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            ','
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 11. GlobalProtect - Configuration Released
        # ----------------------------------------------------

        (
            '1,2024/04/10 11:00:00,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 10:59:59,'
            'vsys1,'
            'globalprotectgateway-config-release,'
            'configuration,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'GlobalProtect gateway client configuration released,'
            'success,'
            'India,'
            '3599,'
            'on-demand,'
            '0,'
            'gp-portal,'
            '100010,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 12. GlobalProtect - Tunnel Down
        # ----------------------------------------------------

        (
            '1,2024/04/10 11:10:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2024/04/10 11:10:00,'
            'vsys1,'
            'globalprotect-tunnel-down,'
            'tunnel,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '6.2.0,'
            'Windows,'
            '11,'
            '1,'
            'Keep-alive timeout,'
            'Keep-alive timeout,'
            'Tunnel is down due to keep-alive timeout,'
            'failure,'
            'India,'
            '3610,'
            'on-demand,'
            '3001,'
            'gp-portal,'
            '100011,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1'
        ),


        # ----------------------------------------------------
        # 13. SYSTEM VPN - IKEv2 Negotiation Failure
        # ----------------------------------------------------

        (
            '1,2024/04/10 11:20:01,'
            'PA123456789,'
            'SYSTEM,vpn,1,'
            '2024/04/10 11:20:00,'
            'vsys1,'
            'ikev2-neg-fail,'
            'Branch-IPSec,'
            ','
            ','
            'ikemgr,'
            'error,'
            'IKEv2 proposal does not match. '
            'NO_PROPOSAL_CHOSEN received. '
            'Negotiation failed,'
            '200002,'
            '0x0,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01'
        ),


        # ----------------------------------------------------
        # 14. Unknown Future GlobalProtect Event
        # ----------------------------------------------------

        (
            '1,2026/08/24 18:45:01,'
            'PA123456789,'
            'GLOBALPROTECT,globalprotect,1,'
            '2026/08/24 18:45:00,'
            'vsys1,'
            'globalprotect-future-event,'
            'future-stage,'
            'SAML,'
            'SSLVPN,'
            'alice,'
            'IN,'
            'LAPTOP-01,'
            '203.0.113.10,'
            ','
            '10.10.10.25,'
            ','
            'HOST-001,'
            'ENDPOINT-001,'
            '9.0.0,'
            'Windows,'
            '11,'
            '1,'
            ','
            ','
            'Future GlobalProtect functionality event,'
            'pending,'
            'India,'
            '0,'
            'future-method,'
            '0,'
            'gp-portal,'
            '999999,'
            '0x0,'
            ','
            ','
            ','
            ','
            ','
            'gp-gateway,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01,'
            '1,'
            ','
            'FUTURE_VENDOR_FIELD'
        ),


        # ----------------------------------------------------
        # 15. Unknown Future SYSTEM VPN Event
        # ----------------------------------------------------

        (
            '1,2026/08/24 19:00:01,'
            'PA123456789,'
            'SYSTEM,vpn,1,'
            '2026/08/24 19:00:00,'
            'vsys1,'
            'future-vpn-event,'
            'Future-IPSec-Tunnel,'
            ','
            ','
            'future-module,'
            'informational,'
            'Future PAN-OS VPN functionality event,'
            '999999,'
            '0x0,'
            '0,0,0,0,'
            'vsys1,'
            'PA-FW-01'
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
                f"RAW-PA-VPN-{index:06d}"
            ),
            u_id=(
                f"UEV-PA-VPN-{index:06d}"
            )
        )


        normalized_events.append(
            normalized_event
        )


    # ========================================================
    # SAVE NORMALIZED EVENTS
    # ========================================================

    with open(
        "paloalto_vpn_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )