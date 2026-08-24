import csv
import io
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

        # Preserve every parsed FortiGate field here.
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
    Parse FortiGate key=value formatted logs.

    Examples:
        user="admin"
        status="failed"
        cpu=6
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
# HELPERS
# ============================================================

def clean_value(value: Optional[str]) -> Optional[str]:

    if value is None:
        return None

    value = str(value).strip()

    if value.lower() in {
        "",
        "n/a",
        "na",
        "none",
        "null",
        "-",
        "unknown"
    }:
        return None

    return value


def convert_int(value: Optional[str]):

    if value is None:
        return None

    try:
        return int(value)

    except (ValueError, TypeError):
        return value


def short_log_id(logid: Optional[str]) -> Optional[str]:
    """
    FortiGate full ID:

        0100032002

    Semantic message ID:

        32002
    """

    if not logid:
        return None

    digits = "".join(
        char for char in str(logid)
        if char.isdigit()
    )

    if len(digits) >= 5:
        return digits[-5:]

    return digits or None


def build_timestamp(
    fields: Dict[str, str]
) -> Optional[str]:

    date = fields.get("date")
    time = fields.get("time")
    timezone = fields.get("tz")

    if not date or not time:
        return None

    timestamp = f"{date}T{time}"

    if timezone:
        timestamp += timezone

    return timestamp


def convert_port(value: Optional[str]):

    if value is None:
        return None

    try:
        return int(value)

    except (ValueError, TypeError):
        return value


def normalize_protocol(
    value: Optional[str]
) -> Optional[str]:

    if value is None:
        return None

    mapping = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPV6"
    }

    return mapping.get(
        str(value),
        str(value).upper()
    )


# ============================================================
# SYSTEM LOG DETECTION
# ============================================================

SYSTEM_EVENT_IDS = {
    # Administration
    "32001",
    "32002",
    "32003",

    # Configuration
    "32099",
    "32102",
    "32104",
    "44544",
    "44545",

    # Device
    "32009",
    "32545",

    # Interface
    "20099",

    # Service / daemon
    "20204",

    # Resources
    "40704",
    "22011",

    # Firmware
    "32103",
    "22081"
}


def detect(raw_log: str) -> bool:
    """
    Detect FortiGate System events.

    Primary detection:
        subtype="system"

    Known System event IDs are also accepted.
    """

    fields = parse_key_values(raw_log)

    subtype = fields.get(
        "subtype",
        ""
    ).lower()

    event_id = short_log_id(
        fields.get("logid")
    )

    if subtype == "system":
        return True

    if event_id in SYSTEM_EVENT_IDS:
        return True

    return False


# ============================================================
# SYSTEM EVENT CLASSIFICATION
# ============================================================

def classify(
    fields: Dict[str, str]
) -> Dict[str, Any]:

    event_id = short_log_id(
        fields.get("logid")
    )

    action = fields.get(
        "action",
        ""
    ).lower()

    status = fields.get(
        "status",
        ""
    ).lower()

    logdesc = fields.get(
        "logdesc",
        ""
    ).lower()

    msg = fields.get(
        "msg",
        ""
    ).lower()

    reason = fields.get(
        "reason",
        ""
    ).lower()

    combined_text = " ".join([
        action,
        status,
        logdesc,
        msg,
        reason
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

    if event_id == "32001":

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_SUCCESS",
            "outcome": "SUCCESS"
        })


    elif event_id == "32002":

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_FAILURE",
            "outcome": "FAILURE"
        })


    elif event_id == "32003":

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGOUT",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 2. CONFIGURATION
    # ========================================================

    elif event_id in {
        "32099",
        "32102",
        "32104",
        "44544",
        "44545"
    }:

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "CONFIG_CHANGE",
            "outcome": "SUCCESS"
        })


    elif (
        "configuration changed" in combined_text
        or "config changed" in combined_text
    ):

        classification.update({
            "type": "CONFIGURATION",
            "subtype": "CONFIG_CHANGE",
            "outcome": "SUCCESS"
        })


    # ========================================================
    # 3. DEVICE
    # ========================================================

    elif event_id == "32009":

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_START",
            "outcome": "SUCCESS"
        })


    elif event_id == "32545":

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_RESTART",
            "outcome": "SUCCESS"
        })


    elif (
        action == "shutdown"
        or "device shutdown" in combined_text
        or "system shutdown" in combined_text
    ):

        abnormal_keywords = {
            "unexpected",
            "power failure",
            "power loss",
            "integrity check failed",
            "error",
            "failure"
        }

        abnormal = any(
            keyword in combined_text
            for keyword in abnormal_keywords
        )

        classification.update({
            "type": "DEVICE",
            "subtype": "DEVICE_SHUTDOWN",

            # Do not assume every intentional shutdown is failure.
            "outcome": (
                "FAILURE"
                if abnormal
                else "UNKNOWN"
            )
        })


    # ========================================================
    # 4. INTERFACE
    # ========================================================

    elif event_id == "20099":

        if status == "up":

            classification.update({
                "type": "INTERFACE",
                "subtype": "INTERFACE_UP",
                "outcome": "SUCCESS"
            })


        elif status == "down":

            classification.update({
                "type": "INTERFACE",
                "subtype": "INTERFACE_DOWN",

                # DOWN may be intentional.
                "outcome": "UNKNOWN"
            })


        else:

            classification.update({
                "type": "INTERFACE",
                "subtype": "INTERFACE_STATUS_CHANGE",
                "outcome": "UNKNOWN"
            })


    # ========================================================
    # 5. SERVICE / DAEMON
    # ========================================================

    elif event_id == "20204":

        classification.update({
            "type": "SERVICE",
            "subtype": "DAEMON_START",
            "outcome": "SUCCESS"
        })


    elif (
        "daemon" in combined_text
        and (
            "error" in combined_text
            or "failed" in combined_text
        )
    ):

        classification.update({
            "type": "SERVICE",
            "subtype": "DAEMON_ERROR",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 6. RESOURCE
    # ========================================================

    elif event_id == "40704":

        classification.update({
            "type": "RESOURCE",
            "subtype": "PERFORMANCE_STATISTICS",

            # A metric snapshot is neither success nor failure.
            "outcome": "UNKNOWN"
        })


    elif event_id == "22011":

        classification.update({
            "type": "RESOURCE",
            "subtype": "MEMORY_CONSERVE_ENTERED",
            "outcome": "FAILURE"
        })


    # ========================================================
    # 7. FIRMWARE
    # ========================================================

    elif event_id == "32103":

        classification.update({
            "type": "FIRMWARE",
            "subtype": "FIRMWARE_AVAILABLE",

            # Availability itself is not success/failure.
            "outcome": "UNKNOWN"
        })


    elif event_id == "22081":

        classification.update({
            "type": "FIRMWARE",
            "subtype": "FIRMWARE_UPDATE_FAILURE",
            "outcome": "FAILURE"
        })


    # ========================================================
    # FALLBACK SEMANTIC RULES
    # ========================================================

    elif (
        action == "login"
        and status in {
            "success",
            "successful"
        }
    ):

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_SUCCESS",
            "outcome": "SUCCESS"
        })


    elif (
        action == "login"
        and status in {
            "failed",
            "failure",
            "denied"
        }
    ):

        classification.update({
            "type": "ADMINISTRATION",
            "subtype": "ADMIN_LOGIN_FAILURE",
            "outcome": "FAILURE"
        })


    elif (
        "memory conserve" in combined_text
        or (
            fields.get(
                "conserve",
                ""
            ).lower() == "on"
            and fields.get(
                "service",
                ""
            ).lower() == "kernel"
        )
    ):

        classification.update({
            "type": "RESOURCE",
            "subtype": "MEMORY_CONSERVE_ENTERED",
            "outcome": "FAILURE"
        })


    return classification


# ============================================================
# CATEGORY-SPECIFIC DETAILS
# ============================================================

def build_details(
    fields: Dict[str, str],
    classification: Dict[str, Any]
) -> Dict[str, Any]:

    system_type = classification["type"]

    details = {}


    # --------------------------------------------------------
    # Administration
    # --------------------------------------------------------

    if system_type == "ADMINISTRATION":

        details = {
            "admin_method":
                clean_value(fields.get("method")),

            "interface":
                clean_value(fields.get("ui")),

            "admin_profile":
                clean_value(fields.get("profile")),

            "session_serial":
                clean_value(fields.get("sn"))
        }


    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    elif system_type == "CONFIGURATION":

        details = {
            "configuration_path":
                clean_value(
                    fields.get("cfgpath")
                    or fields.get("path")
                ),

            "configuration_object":
                clean_value(
                    fields.get("cfgobj")
                    or fields.get("object")
                ),

            "transaction_id":
                clean_value(fields.get("cfgtid")),

            "management_interface":
                clean_value(fields.get("ui")),

            "module":
                clean_value(fields.get("module")),

            "submodule":
                clean_value(fields.get("submodule"))
        }


    # --------------------------------------------------------
    # Device
    # --------------------------------------------------------

    elif system_type == "DEVICE":

        details = {
            "device_id":
                clean_value(fields.get("devid")),

            "virtual_domain":
                clean_value(fields.get("vd")),

            "device_name":
                clean_value(
                    fields.get("devname")
                    or fields.get("hostname")
                )
        }


    # --------------------------------------------------------
    # Interface
    # --------------------------------------------------------

    elif system_type == "INTERFACE":

        details = {
            "interface_name":
                extract_interface_name(fields),

            "interface_status":
                clean_value(fields.get("status"))
        }


    # --------------------------------------------------------
    # Service
    # --------------------------------------------------------

    elif system_type == "SERVICE":

        details = {
            "service_name":
                clean_value(
                    fields.get("daemon")
                    or fields.get("service")
                ),

            "process_id":
                convert_int(fields.get("pid"))
        }


    # --------------------------------------------------------
    # Resource
    # --------------------------------------------------------

    elif system_type == "RESOURCE":

        details = {
            "cpu_percent":
                convert_int(fields.get("cpu")),

            "memory_percent":
                convert_int(fields.get("mem")),

            "disk_percent":
                convert_int(fields.get("disk")),

            "total_sessions":
                convert_int(fields.get("totalsession")),

            "session_setup_rate":
                convert_int(fields.get("setuprate")),

            "disk_log_rate":
                convert_int(fields.get("disklograte")),

            "fortianalyzer_log_rate":
                convert_int(fields.get("fazlograte")),

            "free_disk_storage":
                convert_int(fields.get("freediskstorage")),

            "system_uptime":
                convert_int(fields.get("sysuptime")),

            "conserve_mode":
                (
                    True
                    if fields.get(
                        "conserve",
                        ""
                    ).lower() == "on"
                    else None
                ),

            "resource_service":
                clean_value(fields.get("service"))
        }


    # --------------------------------------------------------
    # Firmware
    # --------------------------------------------------------

    elif system_type == "FIRMWARE":

        details = {
            "firmware_version":
                clean_value(
                    fields.get("version")
                    or fields.get("firmware")
                ),

            "firmware_status":
                clean_value(fields.get("status"))
        }


    # Remove empty values from details
    return {
        key: value
        for key, value in details.items()
        if value is not None
    }

# ============================================================
# EXTRACT INTERFACE NAME
# ============================================================

def extract_interface_name(
    fields: Dict[str, str]
) -> Optional[str]:

    # Prefer explicit structured fields.
    explicit = (
        fields.get("interface")
        or fields.get("intf")
        or fields.get("dev")
    )

    if explicit:
        return clean_value(explicit)

    # Fallback for messages such as:
    # "Interface port1 turned up"
    # "Interface wan1 turned down"

    msg = fields.get("msg", "")

    match = re.search(
        r'\bInterface\s+([A-Za-z0-9_.:-]+)',
        msg,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None

# ============================================================
# TEST FIXTURE BUILDER
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
        receive_time,           # receive_time
        serial,                 # serial
        "SYSTEM",               # type
        subtype,                # subtype
        "1",                    # future_use_2
        generated_time,         # time_generated
        vsys,                   # vsys
        eventid,                # eventid
        object_name,            # object
        "",                     # future_use_3
        "",                     # future_use_4
        module,                 # module
        severity,               # severity
        description,            # description
        sequence_number,        # sequence_number
        "0x0",                  # action_flags
        "0",                    # dg_hier_level_1
        "0",                    # dg_hier_level_2
        "0",                    # dg_hier_level_3
        "0",                    # dg_hier_level_4
        vsys,                   # vsys_name
        device_name,            # device_name
        "",                     # future_use_5
        "",                     # future_use_6
        ""                      # high_res_timestamp
    ]

    output = io.StringIO()

    writer = csv.writer(
        output,
        lineterminator=""
    )

    writer.writerow(values)

    return output.getvalue()

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
            "Input does not appear to be a "
            "FortiGate System log"
        )


    fields = parse_key_values(raw_log)

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

    event["timestamp"] = build_timestamp(fields)


    # --------------------------------------------------------
    # Vendor identity
    # --------------------------------------------------------

    event["vendor"] = "Fortinet"

    event["product"] = "FortiGate"


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
    # Severity
    # --------------------------------------------------------

    event["severity"] = clean_value(
        fields.get("level")
    )


    # --------------------------------------------------------
    # Network fields
    # --------------------------------------------------------

    event["src_ip"] = clean_value(
        fields.get("srcip")
        or fields.get("remip")
    )

    event["src_port"] = convert_port(
        fields.get("srcport")
        or fields.get("remport")
    )

    event["dst_ip"] = clean_value(
        fields.get("dstip")
        or fields.get("locip")
    )

    event["dst_port"] = convert_port(
        fields.get("dstport")
        or fields.get("locport")
    )

    event["protocol"] = normalize_protocol(
        fields.get("proto")
        or fields.get("protocol")
    )


    # --------------------------------------------------------
    # User
    # --------------------------------------------------------

    event["user"] = clean_value(
        fields.get("user")
    )


    # --------------------------------------------------------
    # Action / Reason
    # --------------------------------------------------------

    event["action"] = clean_value(
        fields.get("action")
    )

    event["reason"] = clean_value(
        fields.get("reason")
        or fields.get("error_reason")
    )


    # --------------------------------------------------------
    # Object fields
    # --------------------------------------------------------

    if classification["type"] == "INTERFACE":

        event["object_type"] = "NETWORK_INTERFACE"

        event["object_name"] = extract_interface_name(
            fields
        )


    elif classification["type"] == "SERVICE":

        event["object_type"] = "SYSTEM_SERVICE"

        event["object_name"] = clean_value(
            fields.get("daemon")
            or fields.get("service")
        )


    elif classification["type"] == "FIRMWARE":

        event["object_type"] = "FIRMWARE"

        event["object_name"] = clean_value(
            fields.get("version")
            or fields.get("firmware")
        )


    # --------------------------------------------------------
    # Category-specific normalized data
    # --------------------------------------------------------

    event["details"] = build_details(
        fields,
        classification
    )


    # --------------------------------------------------------
    # Vendor Event ID
    # --------------------------------------------------------

    event["vendor_event_id"] = (
        fields.get("logid")
    )


    # --------------------------------------------------------
    # Preserve ALL parsed vendor fields
    # --------------------------------------------------------

    event["vendor_fields"] = fields.copy()


    return event


# ============================================================
# RAW LOG INGESTION
# ============================================================

if __name__ == "__main__":

    raw_logs = [

        'date=2024-04-01 '
        'time=15:42:08 '
        'logid="0100032002" '
        'type="event" '
        'subtype="system" '
        'level="alert" '
        'user="admin" '
        'method="ssh" '
        'srcip="172.16.200.100" '
        'action="login" '
        'status="failed" '
        'logdesc="Admin login failed"',


        'date=2021-03-12 '
        'time=14:06:09 '
        'logid="0100032102" '
        'type="event" '
        'subtype="system" '
        'level="alert" '
        'logdesc="Configuration changed" '
        'user="admin" '
        'ui="https(192.168.244.133)" '
        'action="config-change"',


        'date=2022-10-26 '
        'time=03:40:12 '
        'logid="0100032009" '
        'type="event" '
        'subtype="system" '
        'level="information" '
        'logdesc="FortiGate started" '
        'msg="Fortigate started"',


        'date=2025-01-07 '
        'time=09:37:32 '
        'logid="0100020099" '
        'type="event" '
        'subtype="system" '
        'level="warning" '
        'logdesc="Interface status changed" '
        'action="interface-stat-change" '
        'status="UP" '
        'msg="Interface port1 turned up"',


        'date=2026-08-24 '
        'time=10:15:20 '
        'logid="0100020204" '
        'type="event" '
        'subtype="system" '
        'level="information" '
        'logdesc="Daemon started" '
        'action="start" '
        'daemon="httpsd" '
        'pid=2451 '
        'msg="Daemon started"',


        'date=2022-11-02 '
        'time=16:58:37 '
        'logid="0100022011" '
        'type="event" '
        'subtype="system" '
        'level="critical" '
        'logdesc="Memory conserve mode entered" '
        'service="kernel" '
        'conserve="on"',


        'date=2026-08-24 '
        'time=11:10:00 '
        'logid="0100032103" '
        'type="event" '
        'subtype="system" '
        'level="notice" '
        'logdesc="New firmware available on FortiGuard" '
        'action="firmware-check" '
        'status="available" '
        'version="7.6.x"',


        'date=2024-04-01 '
        'time=15:40:11 '
        'logid="0100032001" '
        'type="event" '
        'subtype="system" '
        'level="information" '
        'user="admin" '
        'method="https" '
        'srcip="172.16.200.100" '
        'action="login" '
        'status="success" '
        'logdesc="Admin login successful"',


        'date=2024-04-01 '
        'time=16:10:25 '
        'logid="0100032003" '
        'type="event" '
        'subtype="system" '
        'level="information" '
        'user="admin" '
        'method="https" '
        'srcip="172.16.200.100" '
        'action="logout" '
        'status="success" '
        'logdesc="Admin logout successful"',


        'date=2026-08-24 '
        'time=03:00:00 '
        'logid="0100032545" '
        'type="event" '
        'subtype="system" '
        'level="notice" '
        'logdesc="Scheduled daily reboot started" '
        'action="reboot" '
        'msg="Scheduled daily reboot started"',


        'date=2024-06-10 '
        'time=02:18:42 '
        'logid="0100032200" '
        'type="event" '
        'subtype="system" '
        'level="critical" '
        'logdesc="Device shutdown" '
        'action="shutdown" '
        'reason="Unexpected power failure" '
        'msg="Device shutdown due to unexpected power failure"',


        'date=2025-01-07 '
        'time=09:37:42 '
        'logid="0100020099" '
        'type="event" '
        'subtype="system" '
        'level="warning" '
        'logdesc="Interface status changed" '
        'action="interface-stat-change" '
        'status="DOWN" '
        'msg="Interface port1 turned down"',


        'date=2024-05-15 '
        'time=10:20:30 '
        'logid="0100040704" '
        'type="event" '
        'subtype="system" '
        'level="notice" '
        'logdesc="System performance statistics" '
        'action="perf-stats" '
        'cpu=6 '
        'mem=28 '
        'disk=3 '
        'totalsession=20977 '
        'setuprate=45 '
        'disklograte=2 '
        'fazlograte=15 '
        'freediskstorage=91 '
        'sysuptime=86400',


        'date=2026-08-24 '
        'time=11:20:00 '
        'logid="0100022081" '
        'type="event" '
        'subtype="system" '
        'level="error" '
        'logdesc="Provisioning of latest firmware failed" '
        'action="firmware-update" '
        'status="failed" '
        'reason="Firmware provisioning failed" '
        'version="7.6.x"',


        'date=2026-08-24 '
        'time=12:00:00 '
        'logid="0100099999" '
        'type="event" '
        'subtype="system" '
        'level="warning" '
        'logdesc="Future FortiGate system feature event" '
        'action="future-special-action" '
        'user="admin" '
        'customfield="FORTINET_FUTURE_VALUE" '
        'anotherfield="12345"'
    ]


    normalized_events = []


    for index, raw_log in enumerate(
        raw_logs,
        start=1
    ):

        if not detect(raw_log):
            continue


        event = normalize(
            raw_log=raw_log,
            raw_id=f"RAW-FG-SYSTEM-{index:06d}",
            u_id=f"UEV-FG-SYSTEM-{index:06d}"
        )


        normalized_events.append(event)

    with open(
        "fortigate_system_normalized.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=2
        )