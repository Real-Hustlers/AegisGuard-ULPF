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

        # Preserve every parsed PAN-OS vendor field.
        "vendor_fields": {}
    }


# ============================================================
# PAN-OS SYSTEM FIELD ORDER
# ============================================================
#
# Official PAN-OS System Syslog order:
#
# FUTURE_USE
# Receive Time
# Serial Number
# Type
# Subtype
# FUTURE_USE
# Generated Time
# Virtual System
# Event ID
# Object
# FUTURE_USE
# FUTURE_USE
# Module
# Severity
# Description
# Sequence Number
# Action Flags
# DG Hierarchy 1
# DG Hierarchy 2
# DG Hierarchy 3
# DG Hierarchy 4
# Vsys Name
# Device Name
# FUTURE_USE
# FUTURE_USE
# High Resolution Timestamp
#
# Unknown fields appended by newer PAN-OS versions are
# retained as field_N.
# ============================================================

SYSTEM_FIELD_NAMES = [
    "future_use_1",              # 0
    "receive_time",              # 1
    "serial",                    # 2
    "type",                      # 3
    "subtype",                   # 4
    "future_use_2",              # 5
    "time_generated",            # 6
    "vsys",                      # 7
    "eventid",                   # 8
    "object",                    # 9
    "future_use_3",              # 10
    "future_use_4",              # 11
    "module",                    # 12
    "severity",                  # 13
    "description",               # 14
    "sequence_number",           # 15
    "action_flags",              # 16
    "dg_hier_level_1",           # 17
    "dg_hier_level_2",           # 18
    "dg_hier_level_3",           # 19
    "dg_hier_level_4",           # 20
    "vsys_name",                 # 21
    "device_name",               # 22
    "future_use_5",              # 23
    "future_use_6",              # 24
    "high_res_timestamp"         # 25
]


# ============================================================
# SYSTEM EVENTS OWNED BY OTHER PARSERS
# ============================================================
#
# These are still PAN-OS SYSTEM logs, but they are intentionally
# handled elsewhere in the AegisGuard ULPF architecture.
# ============================================================

VPN_SYSTEM_SUBTYPES = {
    "vpn",
    "sslvpn",
    "global-protect",
    "crypto"
}

ROUTER_SYSTEM_SUBTYPES = {
    "routing",
    "pbf"
}


# Operational-service subtypes that may be handled by the
# System parser.
SERVICE_SUBTYPES = {
    "dhcp",
    "dnsproxy",
    "ntpd",
    "pppoe",
    "userid",
    "url-filtering",
    "satd",
    "sslmgr",
    "syslog"
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

    if value is None:
        return None

    # Newer ISO-like timestamps
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


    # Never silently discard a timestamp simply because
    # a newer format was encountered.
    return value


def extract_user(
    text: str
) -> Optional[str]:

    if not text:
        return None

    patterns = [
        r"User\s+'([^']+)'",
        r'User\s+"([^"]+)"',
        r"\bfor user\s+([A-Za-z0-9_.\\@-]+)",
        r"\bUser\s+([A-Za-z0-9_.\\@-]+)\s+logged"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:
            return clean_value(
                match.group(1)
            )

    return None


def extract_source_ip(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'\bFrom:\s*'
        r'((?:\d{1,3}\.){3}\d{1,3})',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


def extract_reason(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'Reason:\s*(.+?)(?:\s+From:|$)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1).rstrip(".")
        )

    return None


def extract_interface(
    text: str
) -> Optional[str]:

    if not text:
        return None

    patterns = [
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
            return match.group(1).rstrip(":,;")

    return None


def extract_ha_states(
    text: str
):

    if not text:
        return None, None

    match = re.search(
        r'Moved from state\s+'
        r'(.+?)\s+'
        r'to state\s+'
        r'(.+?)'
        r'(?:\.|$)',
        text,
        re.IGNORECASE
    )

    if not match:
        return None, None

    return (
        clean_value(match.group(1)),
        clean_value(match.group(2))
    )


def extract_ha_group(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'\bHA Group\s+(\d+)',
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


def extract_process_id(
    text: str
):

    if not text:
        return None

    match = re.search(
        r'\b(?:process|pid)\s+(\d+)',
        text,
        re.IGNORECASE
    )

    if match:
        return int(
            match.group(1)
        )

    return None


def extract_software_version(
    text: str
) -> Optional[str]:

    if not text:
        return None

    patterns = [
        r'\bversion\s+([0-9][A-Za-z0-9_.-]+)',
        r'\bsoftware\s+([0-9][A-Za-z0-9_.-]+)'
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


def extract_power_supply(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'(Power Supply\s+#?\d+'
        r'(?:\s*\([^)]+\))?)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


def extract_fan(
    text: str
) -> Optional[str]:

    if not text:
        return None

    match = re.search(
        r'(Fan\s+#?\d+)',
        text,
        re.IGNORECASE
    )

    if match:
        return clean_value(
            match.group(1)
        )

    return None


# ============================================================
# EXTRACT PAN-OS CSV PAYLOAD
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
# PARSE SYSTEM CSV
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
            "PAN-OS System log is empty"
        )


    if len(values) < 15:

        raise ValueError(
            "PAN-OS System log has too few fields"
        )


    parsed = {}

    for index, value in enumerate(values):

        if index < len(SYSTEM_FIELD_NAMES):

            key = SYSTEM_FIELD_NAMES[
                index
            ]

        else:

            # Preserve fields added by future PAN-OS versions.
            key = f"field_{index}"


        parsed[key] = value


    return parsed


# ============================================================
# DETECTION
# ============================================================

def detect(
    raw_log: str
) -> bool:
    """
    Detect operational PAN-OS SYSTEM events.

    VPN and routing System subtypes are intentionally excluded
    because they belong to their dedicated parsers.
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


    if log_type != "SYSTEM":
        return False


    if subtype in VPN_SYSTEM_SUBTYPES:
        return False


    if subtype in ROUTER_SYSTEM_SUBTYPES:
        return False


    # Unknown operational SYSTEM subtypes are still accepted.
    # Their semantics will become UNKNOWN rather than being lost.
    return True


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

    severity = (
        fields.get("severity", "")
        .strip()
        .lower()
    )

    description = (
        fields.get("description", "")
        .strip()
        .lower()
    )


    text = " ".join([
        subtype,
        eventid,
        module,
        severity,
        description
    ])


    classification = {
        "category": "SYSTEM",
        "type": "UNKNOWN",
        "subtype": "UNKNOWN",
        "outcome": "UNKNOWN"
    }


    # ========================================================
    # 1. ADMINISTRATION
    # ========================================================

    if (
        "auth-fail" in eventid
        or "failed authentication" in description
        or "authentication failed" in description
    ):

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        "auth-su" in eventid
        or "auth-succ" in eventid
        or "authenticated" in description
        or "login succeeded" in description
    ):

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_SUCCESS",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 2. CONFIGURATION
    # ========================================================

    elif (
        "commit job succeeded" in description
        or "commit succeeded" in description
    ):

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "COMMIT_SUCCESS",
            "outcome": "SUCCESS"
        })


    elif (
        "config installed" in description
        or "configuration installed" in description
    ):

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "CONFIG_INSTALL",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 3. DEVICE
    # ========================================================

    elif (
        "rebooting system" in description
        or "restarts exhausted" in description
    ):

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_RESTART",
            "outcome": "FAILURE"
        })


    elif (
        "system started" in description
        or "system startup" in description
        or "device started" in description
    ):

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_START",
            "outcome": "SUCCESS"
        })


    elif (
        "system shutdown" in description
        or "shutting down" in description
        or "device shutdown" in description
    ):

        abnormal = any(
            keyword in description
            for keyword in {
                "unexpected",
                "failure",
                "failed",
                "error",
                "power loss"
            }
        )

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_SHUTDOWN",
            "outcome": (
                "FAILURE"
                if abnormal
                else "UNKNOWN"
            )
        })


    # ========================================================
    # 4. INTERFACE
    # ========================================================

    elif (
        subtype in {
            "port",
            "lacp"
        }
        and (
            " down " in f" {description} "
            or "link down" in description
            or "moved out of" in description
        )
    ):

        classification.update({
            "type": "INTERFACE",
            "subtype": "INTERFACE_DOWN",
            "outcome": "UNKNOWN"
        })


    elif (
        subtype in {
            "port",
            "lacp"
        }
        and (
            " up " in f" {description} "
            or "link up" in description
            or "moved into" in description
        )
    ):

        classification.update({
            "type": "INTERFACE",
            "subtype": "INTERFACE_UP",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 5. HIGH AVAILABILITY
    # ========================================================

    elif (
        subtype == "ha"
        or module == "ha"
    ) and (
        "moved from state" in description
        or "non-functional" in description
    ):

        if "non-functional" in description:

            classification.update({
                "type": "HIGH_AVAILABILITY",
                "subtype": "HA_NON_FUNCTIONAL",
                "outcome": "FAILURE"
            })

        else:

            classification.update({
                "type": "HIGH_AVAILABILITY",
                "subtype": "HA_STATE_CHANGE",
                "outcome": "UNKNOWN"
            })


    # ========================================================
    # 6. RESOURCE
    # ========================================================

    elif (
        "out of memory" in description
        or "memory exhaustion" in description
        or "not enough memory" in description
    ):

        classification.update({
            "type": "RESOURCE",
            "subtype": "MEMORY_EXHAUSTION",
            "outcome": "FAILURE"
        })


    elif (
        "not enough space" in description
        or "disk full" in description
        or "storage exhausted" in description
        or "no space left" in description
    ):

        classification.update({
            "type": "RESOURCE",
            "subtype": "STORAGE_EXHAUSTION",
            "outcome": "FAILURE"
        })


    elif (
        "high cpu" in description
        or "high load" in description
        or "resource utilization" in description
    ):

        classification.update({
            "type": "RESOURCE",
            "subtype": "HIGH_LOAD",
            "outcome": "UNKNOWN"
        })


    # ========================================================
    # 7. HARDWARE
    # ========================================================

    elif (
        subtype == "hw"
        and (
            "power supply" in description
            or "ps-fail" in eventid
        )
    ):

        classification.update({
            "type": "HARDWARE",
            "subtype": "POWER_SUPPLY_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        subtype == "hw"
        and (
            "fan" in description
            or "fan-fai" in eventid
            or "fan-fail" in eventid
        )
    ):

        classification.update({
            "type": "HARDWARE",
            "subtype": "FAN_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        subtype == "hw"
        and (
            "thermal" in description
            or "temperature" in description
        )
    ):

        classification.update({
            "type": "HARDWARE",
            "subtype": "THERMAL_FAILURE",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 8. CERTIFICATE
    # ========================================================

    elif (
        "certificate" in description
        and (
            "failed to renew" in description
            or "renewal failed" in description
        )
    ):

        classification.update({
            "type": "CERTIFICATE",
            "subtype": "CERTIFICATE_RENEWAL_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        "certificate" in description
        and (
            "expires" in description
            or "expiring" in description
        )
    ):

        classification.update({
            "type": "CERTIFICATE",
            "subtype": "CERTIFICATE_EXPIRING",
            "outcome": "UNKNOWN"
        })


    elif (
        "certificate" in description
        and (
            "renewed" in description
            or "renewal succeeded" in description
        )
    ):

        classification.update({
            "type": "CERTIFICATE",
            "subtype": "CERTIFICATE_RENEWED",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 9. FIRMWARE / SOFTWARE
    # ========================================================

    elif (
        "system software upgrade" in description
        and "failed" in description
    ) or (
        "failed to install software" in description
    ):

        classification.update({
            "type": "FIRMWARE",
            "subtype": "SOFTWARE_UPDATE_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        "software" in description
        and "installed" in description
    ) or (
        "plugin" in description
        and "installed" in description
    ):

        classification.update({
            "type": "FIRMWARE",
            "subtype": "SOFTWARE_INSTALL",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 10. SERVICE
    # ========================================================

    elif (
        subtype in SERVICE_SUBTYPES
        and (
            "restart" in eventid
            or "restart" in description
        )
    ):

        classification.update({
            "type": "SERVICE",
            "subtype": "SERVICE_RESTART",
            "outcome": "SUCCESS"
        })


    elif (
        subtype in SERVICE_SUBTYPES
        and (
            "connection established" in description
            or "connected" in description
        )
    ):

        classification.update({
            "type": "SERVICE",
            "subtype": "SERVICE_CONNECTED",
            "outcome": "SUCCESS"
        })


    elif (
        subtype in SERVICE_SUBTYPES
        and (
            "failed" in description
            or "failure" in description
            or "error" in description
        )
    ):

        classification.update({
            "type": "SERVICE",
            "subtype": "SERVICE_ERROR",
            "outcome": "FAILURE"
        })


    elif (
        subtype in SERVICE_SUBTYPES
        and (
            "started" in description
            or "start" in eventid
        )
    ):

        classification.update({
            "type": "SERVICE",
            "subtype": "SERVICE_START",
            "outcome": "SUCCESS"
        })


    return classification


# ============================================================
# NORMALIZED ACTION
# ============================================================

def build_action(
    classification: Dict[str, Any]
) -> Optional[str]:

    subtype = classification[
        "subtype"
    ]


    mapping = {
        "ADMIN_LOGIN_SUCCESS":
            "login",

        "ADMIN_LOGIN_FAILURE":
            "login",

        "COMMIT_SUCCESS":
            "commit",

        "CONFIG_INSTALL":
            "install",

        "DEVICE_START":
            "start",

        "DEVICE_RESTART":
            "restart",

        "DEVICE_SHUTDOWN":
            "shutdown",

        "INTERFACE_UP":
            "interface-up",

        "INTERFACE_DOWN":
            "interface-down",

        "HA_STATE_CHANGE":
            "state-change",

        "HA_NON_FUNCTIONAL":
            "state-change",

        "MEMORY_EXHAUSTION":
            "resource-alert",

        "STORAGE_EXHAUSTION":
            "resource-alert",

        "HIGH_LOAD":
            "resource-alert",

        "SERVICE_START":
            "start",

        "SERVICE_RESTART":
            "restart",

        "SERVICE_CONNECTED":
            "connect",

        "SERVICE_ERROR":
            "error",

        "POWER_SUPPLY_FAILURE":
            "hardware-alert",

        "FAN_FAILURE":
            "hardware-alert",

        "THERMAL_FAILURE":
            "hardware-alert",

        "CERTIFICATE_EXPIRING":
            "certificate-check",

        "CERTIFICATE_RENEWED":
            "certificate-renew",

        "CERTIFICATE_RENEWAL_FAILURE":
            "certificate-renew",

        "SOFTWARE_INSTALL":
            "install",

        "SOFTWARE_UPDATE_FAILURE":
            "update"
    }


    return mapping.get(
        subtype
    )


# ============================================================
# DETAILS
# ============================================================

def build_details(
    fields: Dict[str, str],
    classification: Dict[str, Any]
) -> Dict[str, Any]:

    description = clean_value(
        fields.get("description")
    ) or ""

    system_type = classification[
        "type"
    ]

    system_subtype = classification[
        "subtype"
    ]


    # Common System metadata
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
    # Administration
    # --------------------------------------------------------

    if system_type == "ADMINISTRATION":

        details.update({
            "authentication_user":
                extract_user(
                    description
                ),

            "authentication_source_ip":
                extract_source_ip(
                    description
                ),

            "authentication_reason":
                extract_reason(
                    description
                )
        })


    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    elif system_type == "CONFIGURATION":

        details.update({
            "configuration_user":
                extract_user(
                    description
                )
        })


    # --------------------------------------------------------
    # Device
    # --------------------------------------------------------

    elif system_type == "DEVICE":

        details.update({
            "device_operation":
                system_subtype
        })


    # --------------------------------------------------------
    # Interface
    # --------------------------------------------------------

    elif system_type == "INTERFACE":

        details.update({
            "interface_name":
                extract_interface(
                    description
                ),

            "interface_status":
                (
                    "UP"
                    if system_subtype
                    == "INTERFACE_UP"
                    else "DOWN"
                )
        })


    # --------------------------------------------------------
    # High Availability
    # --------------------------------------------------------

    elif system_type == "HIGH_AVAILABILITY":

        previous_state, new_state = (
            extract_ha_states(
                description
            )
        )

        details.update({
            "ha_group":
                extract_ha_group(
                    description
                ),

            "previous_state":
                previous_state,

            "new_state":
                new_state
        })


    # --------------------------------------------------------
    # Resource
    # --------------------------------------------------------

    elif system_type == "RESOURCE":

        resource_type = None

        if system_subtype == "MEMORY_EXHAUSTION":
            resource_type = "MEMORY"

        elif system_subtype == "STORAGE_EXHAUSTION":
            resource_type = "STORAGE"

        elif system_subtype == "HIGH_LOAD":
            resource_type = "SYSTEM_LOAD"


        details.update({
            "resource_type":
                resource_type,

            "process_id":
                extract_process_id(
                    description
                )
        })


    # --------------------------------------------------------
    # Service
    # --------------------------------------------------------

    elif system_type == "SERVICE":

        service_name = clean_value(
            fields.get("subtype")
        )

        details.update({
            "service_name":
                (
                    service_name.upper()
                    if service_name
                    else None
                ),

            "service_operation":
                system_subtype
        })


    # --------------------------------------------------------
    # Hardware
    # --------------------------------------------------------

    elif system_type == "HARDWARE":

        hardware_type = None
        hardware_name = None

        if system_subtype == "POWER_SUPPLY_FAILURE":

            hardware_type = "POWER_SUPPLY"

            hardware_name = (
                extract_power_supply(
                    description
                )
            )

        elif system_subtype == "FAN_FAILURE":

            hardware_type = "FAN"

            hardware_name = (
                extract_fan(
                    description
                )
            )

        elif system_subtype == "THERMAL_FAILURE":

            hardware_type = "THERMAL_SENSOR"


        details.update({
            "hardware_type":
                hardware_type,

            "hardware_name":
                hardware_name
        })


    # --------------------------------------------------------
    # Certificate
    # --------------------------------------------------------

    elif system_type == "CERTIFICATE":

        details.update({
            "certificate_type":
                "DEVICE_CERTIFICATE",

            "certificate_operation":
                system_subtype
        })


    # --------------------------------------------------------
    # Firmware / Software
    # --------------------------------------------------------

    elif system_type == "FIRMWARE":

        details.update({
            "software_version":
                extract_software_version(
                    description
                ),

            "software_operation":
                system_subtype
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

    description = clean_value(
        fields.get("description")
    ) or ""

    system_type = classification[
        "type"
    ]


    if system_type == "ADMINISTRATION":

        user = extract_user(
            description
        )

        return (
            "ADMIN_USER",
            user
        )


    if system_type == "CONFIGURATION":

        return (
            "CONFIGURATION",
            clean_value(
                fields.get("object")
            )
        )


    if system_type == "DEVICE":

        return (
            "DEVICE",
            clean_value(
                fields.get("device_name")
            )
        )


    if system_type == "INTERFACE":

        return (
            "NETWORK_INTERFACE",
            extract_interface(
                description
            )
        )


    if system_type == "HIGH_AVAILABILITY":

        ha_group = extract_ha_group(
            description
        )

        return (
            "HA_GROUP",
            (
                f"HA Group {ha_group}"
                if ha_group
                else None
            )
        )


    if system_type == "RESOURCE":

        return (
            "SYSTEM_RESOURCE",
            classification[
                "subtype"
            ]
        )


    if system_type == "SERVICE":

        service = clean_value(
            fields.get("subtype")
        )

        return (
            "SERVICE",
            (
                service.upper()
                if service
                else None
            )
        )


    if system_type == "HARDWARE":

        if (
            classification["subtype"]
            == "POWER_SUPPLY_FAILURE"
        ):

            return (
                "POWER_SUPPLY",
                extract_power_supply(
                    description
                )
            )

        if (
            classification["subtype"]
            == "FAN_FAILURE"
        ):

            return (
                "FAN",
                extract_fan(
                    description
                )
            )

        return (
            "HARDWARE_COMPONENT",
            clean_value(
                fields.get("object")
            )
        )


    if system_type == "CERTIFICATE":

        return (
            "CERTIFICATE",
            "device-certificate"
        )


    if system_type == "FIRMWARE":

        software_name = (
            extract_software_version(
                description
            )
            or clean_value(
                fields.get("object")
            )
        )

        return (
            "SOFTWARE",
            software_name
        )

    # --------------------------------------------------------
    # Unknown / fallback
    # --------------------------------------------------------

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
            "an operational Palo Alto System log"
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

    event["timestamp"] = parse_timestamp(
        fields.get("time_generated")
        or fields.get("receive_time")
    )


    # --------------------------------------------------------
    # Vendor
    # --------------------------------------------------------

    event["vendor"] = (
        "Palo Alto Networks"
    )

    event["product"] = "PAN-OS"


    # --------------------------------------------------------
    # Taxonomy
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


    # --------------------------------------------------------
    # Description
    # --------------------------------------------------------

    description = clean_value(
        fields.get("description")
    ) or ""


    # --------------------------------------------------------
    # User / Source IP
    # --------------------------------------------------------

    event["user"] = extract_user(
        description
    )


    event["src_ip"] = extract_source_ip(
        description
    )


    event["src_port"] = None
    event["dst_ip"] = None
    event["dst_port"] = None
    event["protocol"] = None


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

        event["reason"] = (
            extract_reason(
                description
            )
            or clean_value(
                description
            )
        )

    else:

        event["reason"] = (
            extract_reason(
                description
            )
        )


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
    # PAN-OS eventid names the event.
    #
    # Sequence Number is NOT used here.
    # --------------------------------------------------------

    event["vendor_event_id"] = (
        clean_value(
            fields.get("eventid")
        )
    )


    # --------------------------------------------------------
    # Preserve complete parsed vendor representation
    # --------------------------------------------------------

    event["vendor_fields"] = (
        fields.copy()
    )


    return event


# ============================================================
# TEST FIXTURE BUILDER
# ============================================================
#
# We use csv.writer so descriptions containing commas are
# correctly quoted and do not destroy positional parsing.
# ============================================================

def build_system_fixture(
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
    device_name: str = "PA-FW-01"
) -> str:

    values = [
        "1",                    # future_use_1
        receive_time,
        serial,
        "SYSTEM",
        subtype,
        "1",                    # future_use_2
        generated_time,
        vsys,
        eventid,
        object_name,
        "",                     # future_use_3
        "",                     # future_use_4
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

    writer.writerow(values)

    return output.getvalue()


# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        # ----------------------------------------------------
        # 1. Administration - Login Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:00:01",
            generated_time="2025/01/10 10:00:00",
            subtype="general",
            eventid="auth-fail",
            module="auth",
            severity="medium",
            description=(
                "User 'TESTCORP\\admin' "
                "failed authentication. "
                "Reason: Invalid username/password "
                "From:192.0.2.33."
            ),
            sequence_number="300001"
        ),


        # ----------------------------------------------------
        # 2. Configuration - Commit Success
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:05:01",
            generated_time="2025/01/10 10:05:00",
            subtype="general",
            eventid="general",
            module="general",
            severity="informational",
            description=(
                "Commit job succeeded "
                "for user omer"
            ),
            sequence_number="300002"
        ),


        # ----------------------------------------------------
        # 3. Device - Abnormal Restart
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:10:01",
            generated_time="2025/01/10 10:10:00",
            subtype="general",
            eventid="general",
            module="general",
            severity="critical",
            description=(
                "data_plane: restarts exhausted, "
                "rebooting system"
            ),
            sequence_number="300003"
        ),


        # ----------------------------------------------------
        # 4. Interface - Down
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:15:01",
            generated_time="2025/01/10 10:15:00",
            subtype="port",
            eventid="link-change",
            module="",
            severity="informational",
            description=(
                "Port ethernet1/4: "
                "Down 1Gb/s-full duplex"
            ),
            sequence_number="300004",
            object_name="ethernet1/4"
        ),


        # ----------------------------------------------------
        # 5. High Availability - State Change
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:20:01",
            generated_time="2025/01/10 10:20:00",
            subtype="ha",
            eventid="state-change",
            module="ha",
            severity="informational",
            description=(
                "HA Group 1: "
                "Moved from state Active "
                "to state Suspended"
            ),
            sequence_number="300005",
            object_name="HA Group 1"
        ),


        # ----------------------------------------------------
        # 6. Resource - Memory Exhaustion
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/02/11 16:26:31",
            generated_time="2025/02/11 16:26:30",
            subtype="general",
            eventid="general",
            module="general",
            severity="critical",
            description=(
                "Out of memory condition detected, "
                "kill process 9045"
            ),
            sequence_number="300006"
        ),


        # ----------------------------------------------------
        # 7. Service - NTP Restart
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:30:01",
            generated_time="2025/01/10 10:30:00",
            subtype="ntpd",
            eventid="restart",
            module="",
            severity="informational",
            description=(
                "NTP restart "
                "synchronization performed"
            ),
            sequence_number="300007",
            object_name="NTP"
        ),


        # ----------------------------------------------------
        # 8. Hardware - Power Supply Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:35:01",
            generated_time="2025/01/10 10:35:00",
            subtype="hw",
            eventid="ps-fail",
            module="",
            severity="critical",
            description=(
                "Alarm on "
                "Power Supply #2 (right)"
            ),
            sequence_number="300008",
            object_name="Power Supply #2 (right)"
        ),


        # ----------------------------------------------------
        # 9. Certificate - Renewal Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:40:01",
            generated_time="2025/01/10 10:40:00",
            subtype="general",
            eventid="general",
            module="management",
            severity="high",
            description=(
                "Failed to renew device certificate. "
                "Application Error occurred. "
                "Please contact support!"
            ),
            sequence_number="300009",
            object_name="device-certificate"
        ),


        # ----------------------------------------------------
        # 10. Firmware - Software Upgrade Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:45:01",
            generated_time="2025/01/10 10:45:00",
            subtype="general",
            eventid="general",
            module="upgrade",
            severity="critical",
            description=(
                "System software upgrade "
                "with version 10.2.4-h4 failed"
            ),
            sequence_number="300010",
            object_name="10.2.4-h4"
        ),


        # ----------------------------------------------------
        # 11. Administration - Login Success
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:50:01",
            generated_time="2025/01/10 10:50:00",
            subtype="general",
            eventid="auth-su",
            module="auth",
            severity="informational",
            description=(
                "User 'admin' authenticated. "
                "From: 10.0.0.143."
            ),
            sequence_number="300011",
            object_name="admin"
        ),


        # ----------------------------------------------------
        # 12. Configuration - Config Install
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 10:55:01",
            generated_time="2025/01/10 10:55:00",
            subtype="general",
            eventid="general",
            module="general",
            severity="informational",
            description="Config installed",
            sequence_number="300012",
            object_name="running-configuration"
        ),


        # ----------------------------------------------------
        # 13. Device - Start
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:00:01",
            generated_time="2025/01/10 11:00:00",
            subtype="general",
            eventid="system-start",
            module="general",
            severity="informational",
            description=(
                "System started successfully"
            ),
            sequence_number="300013",
            object_name="PA-FW-01"
        ),


        # ----------------------------------------------------
        # 14. Device - Normal Shutdown
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:05:01",
            generated_time="2025/01/10 11:05:00",
            subtype="general",
            eventid="shutdown",
            module="management",
            severity="informational",
            description=(
                "System shutdown initiated "
                "by administrator"
            ),
            sequence_number="300014",
            object_name="PA-FW-01"
        ),


        # ----------------------------------------------------
        # 15. Interface - Up
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:10:01",
            generated_time="2025/01/10 11:10:00",
            subtype="port",
            eventid="link-change",
            module="ethernet",
            severity="informational",
            description=(
                "Port ethernet1/24: "
                "Up 10Gb/s-full duplex"
            ),
            sequence_number="300015",
            object_name="ethernet1/24"
        ),


        # ----------------------------------------------------
        # 16. High Availability - Non Functional
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:15:01",
            generated_time="2025/01/10 11:15:00",
            subtype="ha",
            eventid="state-change",
            module="ha",
            severity="critical",
            description=(
                "HA Group 1: "
                "Moved from state Active "
                "to state Non-Functional"
            ),
            sequence_number="300016",
            object_name="HA Group 1"
        ),


        # ----------------------------------------------------
        # 17. Resource - Storage Exhaustion
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:20:01",
            generated_time="2025/01/10 11:20:00",
            subtype="general",
            eventid="storage-alert",
            module="management",
            severity="critical",
            description=(
                "No space left on device "
                "while writing system logs"
            ),
            sequence_number="300017",
            object_name="system-storage"
        ),


        # ----------------------------------------------------
        # 18. Resource - High CPU Load
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:25:01",
            generated_time="2025/01/10 11:25:00",
            subtype="general",
            eventid="resource-alert",
            module="management",
            severity="high",
            description=(
                "High CPU utilization detected "
                "on management plane"
            ),
            sequence_number="300018",
            object_name="management-plane"
        ),


        # ----------------------------------------------------
        # 19. Service - Start
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:30:01",
            generated_time="2025/01/10 11:30:00",
            subtype="ntpd",
            eventid="start",
            module="",
            severity="informational",
            description=(
                "NTP service started successfully"
            ),
            sequence_number="300019",
            object_name="NTP"
        ),


        # ----------------------------------------------------
        # 20. Service - Connected
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:35:01",
            generated_time="2025/01/10 11:35:00",
            subtype="syslog",
            eventid="syslog-connect",
            module="",
            severity="informational",
            description=(
                "Syslog connection established to "
                "server['AF_INET.10.0.0.2:514.']"
            ),
            sequence_number="300020",
            object_name="10.0.0.2:514"
        ),


        # ----------------------------------------------------
        # 21. Service - Connection Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:40:01",
            generated_time="2025/01/10 11:40:00",
            subtype="syslog",
            eventid="syslog-connect-fail",
            module="",
            severity="high",
            description=(
                "Syslog connection failed to "
                "server['AF_INET.10.230.240.173:1514.']"
            ),
            sequence_number="300021",
            object_name="10.230.240.173:1514"
        ),


        # ----------------------------------------------------
        # 22. Hardware - Fan Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:45:01",
            generated_time="2025/01/10 11:45:00",
            subtype="hw",
            eventid="fan-fai",
            module="",
            severity="critical",
            description="Alarm on Fan #4 RPM",
            sequence_number="300022",
            object_name="Fan #4"
        ),


        # ----------------------------------------------------
        # 23. Hardware - Thermal Failure
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:50:01",
            generated_time="2025/01/10 11:50:00",
            subtype="hw",
            eventid="thermal-alarm",
            module="",
            severity="critical",
            description=(
                "Chassis temperature alarm detected"
            ),
            sequence_number="300023",
            object_name="Chassis Temperature"
        ),


        # ----------------------------------------------------
        # 24. Certificate - Expiring
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 11:55:01",
            generated_time="2025/01/10 11:55:00",
            subtype="general",
            eventid="general",
            module="management",
            severity="informational",
            description=(
                "Device certificate expires "
                "in 15 or less days"
            ),
            sequence_number="300024",
            object_name="device-certificate"
        ),


        # ----------------------------------------------------
        # 25. Certificate - Renewed
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 12:00:01",
            generated_time="2025/01/10 12:00:00",
            subtype="general",
            eventid="certificate-renew",
            module="management",
            severity="informational",
            description=(
                "Device certificate renewed successfully"
            ),
            sequence_number="300025",
            object_name="device-certificate"
        ),


        # ----------------------------------------------------
        # 26. Firmware - Plugin Installed
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2025/01/10 12:05:01",
            generated_time="2025/01/10 12:05:00",
            subtype="general",
            eventid="general",
            module="upgrade",
            severity="informational",
            description=(
                "Plugin vm_series-2.1.4 installed."
            ),
            sequence_number="300026",
            object_name="vm_series-2.1.4"
        ),


        # ----------------------------------------------------
        # 27. Unknown Future System Event
        # ----------------------------------------------------

        build_system_fixture(
            receive_time="2026/08/24 19:30:01",
            generated_time="2026/08/24 19:30:00",
            subtype="future-system",
            eventid="future-system-event",
            module="future-module",
            severity="informational",
            description=(
                "Future PAN-OS operational "
                "system functionality event"
            ),
            sequence_number="999999",
            object_name="future-object"
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
                f"RAW-PA-SYSTEM-{index:06d}"
            ),
            u_id=(
                f"UEV-PA-SYSTEM-{index:06d}"
            )
        )


        normalized_events.append(
            normalized_event
        )


    # ========================================================
    # SAVE NORMALIZED EVENTS
    # ========================================================

    with open(
        "paloalto_system_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )