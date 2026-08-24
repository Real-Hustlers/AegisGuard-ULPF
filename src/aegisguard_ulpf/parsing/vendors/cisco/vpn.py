import json
import os
import re
from datetime import datetime


INPUT_FILE = r"C:\Users\rish2\ULPF\datasets\corpus_v1\cisco_vpn\cisco_vpn_samples.log"

OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_vpn_common.jsonl"

RAW_OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_vpn_raw.jsonl"


SEVERITY_MAP = {
    "0": "emergency",
    "1": "alert",
    "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "notice",
    "6": "informational",
    "7": "debug"
}


def empty_taxonomy():
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


def parse_timestamp_prefix(raw):
    match = re.match(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<year>\d{4})\s+"
        r"(?P<clock>\d{2}:\d{2}:\d{2}):\s+",
        raw
    )

    if not match:
        return None, raw

    try:
        dt = datetime.strptime(
            f"{match.group('month')} "
            f"{match.group('day')} "
            f"{match.group('year')} "
            f"{match.group('clock')}",
            "%b %d %Y %H:%M:%S"
        )

        timestamp = dt.isoformat()

    except ValueError:
        timestamp = None

    return timestamp, raw[match.end():]


def parse_asa_header(raw):
    timestamp, remaining = parse_timestamp_prefix(raw)

    match = re.search(
        r"%ASA-(?P<severity>\d)-(?P<event_id>\d+):\s*(?P<message>.*)$",
        remaining
    )

    if not match:
        return None

    return {
        "timestamp": timestamp,
        "severity": match.group("severity"),
        "event_id": match.group("event_id"),
        "message": match.group("message")
    }


def parse_group_user_ip(message):
    match = re.search(
        r"Group\s*[=<]\s*(?P<group>[^>,]+)>?"
        r".*?"
        r"User(?:name)?\s*[=<]\s*(?P<user>[^>,]+)>?"
        r".*?"
        r"IP\s*[=<]\s*(?P<ip>[^>,\s]+)>?",
        message,
        re.IGNORECASE
    )

    if not match:
        return None

    return {
        "group": match.group("group").strip(),
        "user": match.group("user").strip(),
        "ip": match.group("ip").strip()
    }


def parse_716001(message, event):
    info = parse_group_user_ip(message)

    if not info:
        return False

    event["category"] = "authentication"
    event["subtype"] = "session_start"
    event["outcome"] = "success"

    event["src_ip"] = info["ip"]
    event["user"] = info["user"]

    event["action"] = "login_success"

    event["object_type"] = "vpn_session"
    event["object_name"] = info["user"]

    event["details"]["group"] = info["group"]
    event["details"]["vpn_type"] = "WebVPN"

    return True


def parse_716002(message, event):
    info = parse_group_user_ip(message)

    if not info:
        return False

    event["category"] = "authentication"
    event["subtype"] = "session_end"
    event["outcome"] = "success"

    event["src_ip"] = info["ip"]
    event["user"] = info["user"]

    event["action"] = "logout"

    event["object_type"] = "vpn_session"
    event["object_name"] = info["user"]

    event["details"]["group"] = info["group"]
    event["details"]["vpn_type"] = "WebVPN"

    return True


def parse_722051(message, event):
    match = re.search(
        r"Group\s+<(?P<group>[^>]+)>\s+"
        r"User\s+<(?P<user>[^>]+)>\s+"
        r"IP\s+<(?P<src_ip>[^>]+)>\s+"
        r"IPv4 Address\s+<(?P<assigned_ip>[^>]+)>\s+"
        r"IPv6 address\s+<(?P<ipv6>[^>]+)>\s+"
        r"assigned to session",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "address_assignment"
    event["outcome"] = "success"

    event["src_ip"] = match.group("src_ip")
    event["user"] = match.group("user")

    event["action"] = "address_assigned"

    event["object_type"] = "vpn_session"
    event["object_name"] = match.group("user")

    event["details"] = {
        "group": match.group("group"),
        "assigned_ipv4": match.group("assigned_ip"),
        "assigned_ipv6": match.group("ipv6")
    }

    return True


def parse_113019(message, event):
    match = re.search(
        r"Group\s*=\s*(?P<group>[^,]+),\s*"
        r"Username\s*=\s*(?P<user>[^,]+),\s*"
        r"IP\s*=\s*(?P<src_ip>[^,]+),\s*"
        r"Session disconnected\.\s*"
        r"Session Type:\s*(?P<session_type>[^,]+),\s*"
        r"Duration:\s*(?P<duration>[^,]+),\s*"
        r"Bytes xmt:\s*(?P<bytes_sent>\d+),\s*"
        r"Bytes rcv:\s*(?P<bytes_received>\d+),\s*"
        r"Reason:\s*(?P<reason>.*)$",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "session_end"
    event["outcome"] = "success"

    event["src_ip"] = match.group("src_ip").strip()
    event["user"] = match.group("user").strip()

    event["protocol"] = match.group("session_type").strip().upper()

    event["action"] = "session_disconnected"
    event["reason"] = match.group("reason").strip()

    event["object_type"] = "vpn_session"
    event["object_name"] = match.group("user").strip()

    event["details"] = {
        "group": match.group("group").strip(),
        "session_type": match.group("session_type").strip(),
        "duration": match.group("duration").strip(),
        "bytes_sent": int(match.group("bytes_sent")),
        "bytes_received": int(match.group("bytes_received"))
    }

    return True


def parse_725003(message, event):
    match = re.search(
        r"SSL client\s+"
        r"(?P<interface>[^:]+):"
        r"(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+"
        r"request to resume previous session",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "session_resume"
    event["outcome"] = "success"

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))

    event["protocol"] = "SSL"

    event["action"] = "resume_session"

    event["object_type"] = "vpn_session"

    event["details"] = {
        "interface": match.group("interface"),
        "vpn_type": "SSL"
    }

    return True


def parse_722050(message, event):
    info = parse_group_user_ip(message)

    if not info:
        return False

    reason_match = re.search(
        r"Session terminated:\s*(?P<reason>.*)$",
        message,
        re.IGNORECASE
    )

    event["category"] = "authentication"
    event["subtype"] = "session_end"
    event["outcome"] = "failure"

    event["src_ip"] = info["ip"]
    event["user"] = info["user"]

    event["action"] = "session_terminated"

    if reason_match:
        event["reason"] = reason_match.group("reason").strip()

    event["object_type"] = "vpn_session"
    event["object_name"] = info["user"]

    event["details"]["group"] = info["group"]

    return True


def parse_722053(message, event):
    info = parse_group_user_ip(message)

    if not info:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "client_connection"
    event["outcome"] = "failure"

    event["src_ip"] = info["ip"]
    event["user"] = info["user"]

    event["action"] = "unsupported_client"
    event["reason"] = "unknown client user-agent"

    event["object_type"] = "vpn_client"
    event["object_name"] = info["user"]

    event["details"]["group"] = info["group"]

    return True


def parse_746012(message, event):
    match = re.search(
        r"Add IP-User mapping\s+"
        r"(?P<ip>\S+)\s+-\s+"
        r"(?P<user>\S+)\s+"
        r"(?P<result>Succeeded|Failed)\s+-\s+VPN user",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    success = match.group("result").lower() == "succeeded"

    event["category"] = "authentication"
    event["subtype"] = "identity_mapping"
    event["outcome"] = "success" if success else "failure"

    event["user"] = match.group("user")

    event["action"] = (
        "ip_user_mapping_added"
        if success
        else "ip_user_mapping_failed"
    )

    event["object_type"] = "ip_user_mapping"
    event["object_name"] = match.group("ip")

    event["details"] = {
        "assigned_ip": match.group("ip")
    }

    return True


def convert(raw, number):
    event = empty_taxonomy()

    event["u_id"] = f"ULPF-CISCO-VPN-{number:09d}"
    event["raw_id"] = f"RAW-CISCO-VPN-{number:09d}"

    event["vendor"] = "Cisco"
    event["product"] = "ASA"

    event["type"] = "vpn"

    header = parse_asa_header(raw)

    if not header:
        event["outcome"] = "unknown"
        event["action"] = "unparsed"

        event["vendor_fields"]["parse_error"] = (
            "ASA VPN header not recognized"
        )

        return event

    event["timestamp"] = header["timestamp"]

    event["severity"] = SEVERITY_MAP.get(
        header["severity"]
    )

    event["vendor_event_id"] = header["event_id"]

    event_id = header["event_id"]
    message = header["message"]

    handlers = {
        "716001": parse_716001,
        "716002": parse_716002,
        "722051": parse_722051,
        "113019": parse_113019,
        "725003": parse_725003,
        "722050": parse_722050,
        "722053": parse_722053,
        "746012": parse_746012
    }

    parser = handlers.get(event_id)

    parsed = False

    if parser:
        parsed = parser(message, event)

    if not parsed:
        event["outcome"] = "unknown"
        event["action"] = "unparsed"
        event["vendor_fields"]["message"] = message

    return event


def main():
    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    processed = 0
    parsed = 0
    unparsed = 0

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as infile, open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as outfile, open(
        RAW_OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as rawfile:

        for line in infile:
            raw = line.strip()

            if not raw:
                continue

            if raw.startswith("#"):
                continue

            processed += 1

            event = convert(raw, processed)

            rawfile.write(
                json.dumps(
                    {
                        "raw_id": event["raw_id"],
                        "u_id": event["u_id"],
                        "raw_event": raw
                    },
                    ensure_ascii=False
                )
                + "\n"
            )

            outfile.write(
                json.dumps(
                    event,
                    ensure_ascii=False
                )
                + "\n"
            )

            if event["action"] == "unparsed":
                unparsed += 1
            else:
                parsed += 1

    print()
    print("Cisco VPN conversion complete")
    print(f"Records processed : {processed}")
    print(f"Parsed            : {parsed}")
    print(f"Unparsed          : {unparsed}")
    print(f"Common taxonomy   : {OUTPUT_FILE}")
    print(f"Raw store         : {RAW_OUTPUT_FILE}")


if __name__ == "__main__":
    main()