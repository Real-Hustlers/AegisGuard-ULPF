"""Small registry of OCSF 1.9.0 facts verified for AegisGuard-ULPF."""

from enum import IntEnum


BASE_EVENT_CLASS_UID = 0
BASE_EVENT_CATEGORY_UID = 0

FILE_SYSTEM_ACTIVITY_CLASS_UID = 1001
FILE_SYSTEM_ACTIVITY_CATEGORY_UID = 1

PROCESS_ACTIVITY_CLASS_UID = 1007
PROCESS_ACTIVITY_CATEGORY_UID = 1

DETECTION_FINDING_CLASS_UID = 2004
DETECTION_FINDING_CATEGORY_UID = 2

AUTHENTICATION_CLASS_UID = 3002
AUTHENTICATION_CATEGORY_UID = 3

NETWORK_ACTIVITY_CLASS_UID = 4001
NETWORK_ACTIVITY_CATEGORY_UID = 4

TUNNEL_ACTIVITY_CLASS_UID = 4014
TUNNEL_ACTIVITY_CATEGORY_UID = 4


class NetworkActivityID(IntEnum):
    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RESET = 3
    FAIL = 4
    REFUSE = 5
    TRAFFIC = 6
    LISTEN = 7
    OTHER = 99


class AuthenticationActivityID(IntEnum):
    UNKNOWN = 0
    LOGON = 1
    LOGOFF = 2
    OTHER = 99


class ProcessActivityID(IntEnum):
    UNKNOWN = 0
    LAUNCH = 1
    TERMINATE = 2
    OTHER = 99


class TunnelActivityID(IntEnum):
    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RENEW = 3
    OTHER = 99


class DetectionFindingActivityID(IntEnum):
    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class StatusID(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class SeverityID(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


VERIFIED_CLASSES = {
    BASE_EVENT_CLASS_UID: {
        "category_uid": BASE_EVENT_CATEGORY_UID,
        "category_name": "Uncategorized",
        "class_name": "Base Event",
    },
    FILE_SYSTEM_ACTIVITY_CLASS_UID: {
        "category_uid": FILE_SYSTEM_ACTIVITY_CATEGORY_UID,
        "category_name": "System Activity",
        "class_name": "File System Activity",
    },
    PROCESS_ACTIVITY_CLASS_UID: {
        "category_uid": PROCESS_ACTIVITY_CATEGORY_UID,
        "category_name": "System Activity",
        "class_name": "Process Activity",
    },
    DETECTION_FINDING_CLASS_UID: {
        "category_uid": DETECTION_FINDING_CATEGORY_UID,
        "category_name": "Findings",
        "class_name": "Detection Finding",
    },
    AUTHENTICATION_CLASS_UID: {
        "category_uid": AUTHENTICATION_CATEGORY_UID,
        "category_name": "Identity & Access Management",
        "class_name": "Authentication",
    },
    NETWORK_ACTIVITY_CLASS_UID: {
        "category_uid": NETWORK_ACTIVITY_CATEGORY_UID,
        "category_name": "Network Activity",
        "class_name": "Network Activity",
    },
    TUNNEL_ACTIVITY_CLASS_UID: {
        "category_uid": TUNNEL_ACTIVITY_CATEGORY_UID,
        "category_name": "Network Activity",
        "class_name": "Tunnel Activity",
    },
}


VERIFIED_ACTIVITY_NAMES = {
    NETWORK_ACTIVITY_CLASS_UID: {
        0: "Unknown",
        1: "Open",
        2: "Close",
        3: "Reset",
        4: "Fail",
        5: "Refuse",
        6: "Traffic",
        7: "Listen",
        99: "Other",
    },
    PROCESS_ACTIVITY_CLASS_UID: {
        0: "Unknown",
        1: "Launch",
        2: "Terminate",
        99: "Other",
    },
    AUTHENTICATION_CLASS_UID: {
        0: "Unknown",
        1: "Logon",
        2: "Logoff",
        99: "Other",
    },
    TUNNEL_ACTIVITY_CLASS_UID: {
        0: "Unknown",
        1: "Open",
        2: "Close",
        3: "Renew",
        99: "Other",
    },
    DETECTION_FINDING_CLASS_UID: {
        0: "Unknown",
        1: "Create",
        2: "Update",
        3: "Close",
        99: "Other",
    },
}


def make_type_uid(class_uid: int, activity_id: int) -> int:
    """Return the OCSF type UID for a class/activity pair."""

    for name, value in (("class_uid", class_uid), ("activity_id", activity_id)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        if value < 0:
            raise ValueError(f"{name} must be non-negative")

    return class_uid * 100 + activity_id
