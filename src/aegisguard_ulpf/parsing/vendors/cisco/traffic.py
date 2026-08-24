import json
import os
import re


INPUT_FILE = r"C:\Users\rish2\ULPF\datasets\corpus_v1\cisco_asa\cisco_asa_traffic_samples.log"
OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_asa_traffic_common.jsonl"
RAW_OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_asa_traffic_raw.jsonl"


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


def parse_header(raw):
    timestamp = None

    ts_match = re.match(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}):\s+",
        raw
    )

    if ts_match:
        timestamp = ts_match.group("timestamp")
        raw = raw[ts_match.end():]

    asa_match = re.search(
        r"%ASA-(?P<severity>\d)-(?P<event_id>\d+):\s*(?P<message>.*)$",
        raw
    )

    if not asa_match:
        return None

    return {
        "timestamp": timestamp,
        "severity": asa_match.group("severity"),
        "event_id": asa_match.group("event_id"),
        "message": asa_match.group("message")
    }


def parse_connection_start(event_id, message, event):
    match = re.match(
        r"Built\s+(?P<direction>inbound|outbound)\s+"
        r"(?P<protocol>TCP|UDP)\s+connection\s+"
        r"(?P<connection_id>\d+)\s+for\s+"
        r"(?P<dst_interface>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>\d+)"
        r"(?:\s+\([^)]+\))?\s+to\s+"
        r"(?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)"
        r"(?:\s+\([^)]+\))?",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "session_start"
    event["outcome"] = "success"
    event["protocol"] = match.group("protocol").upper()
    event["action"] = "connection_built"

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))
    event["dst_ip"] = match.group("dst_ip")
    event["dst_port"] = int(match.group("dst_port"))

    event["object_type"] = "network_session"
    event["object_name"] = match.group("connection_id")

    event["details"] = {
        "connection_id": match.group("connection_id"),
        "direction": match.group("direction").lower(),
        "source_interface": match.group("src_interface"),
        "destination_interface": match.group("dst_interface")
    }

    return True


def parse_connection_end(event_id, message, event):
    match = re.match(
        r"Teardown\s+(?P<protocol>TCP|UDP)\s+connection\s+"
        r"(?P<connection_id>\d+)\s+for\s+"
        r"(?P<dst_interface>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>\d+)\s+to\s+"
        r"(?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)"
        r"(?:\s+duration\s+(?P<duration>\S+))?"
        r"(?:\s+bytes\s+(?P<bytes>\d+))?"
        r"(?:\s+(?P<reason>.*))?",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "session_end"
    event["outcome"] = "success"
    event["protocol"] = match.group("protocol").upper()
    event["action"] = "connection_teardown"

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))
    event["dst_ip"] = match.group("dst_ip")
    event["dst_port"] = int(match.group("dst_port"))

    event["object_type"] = "network_session"
    event["object_name"] = match.group("connection_id")

    details = {
        "connection_id": match.group("connection_id"),
        "source_interface": match.group("src_interface"),
        "destination_interface": match.group("dst_interface")
    }

    if match.group("duration"):
        details["duration"] = match.group("duration")

    if match.group("bytes"):
        details["bytes"] = int(match.group("bytes"))

    if match.group("reason"):
        event["reason"] = match.group("reason").strip()

    event["details"] = details

    return True


def parse_acl_deny(message, event):
    match = re.match(
        r"Deny\s+(?P<protocol>\w+)\s+"
        r"src\s+(?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+"
        r"dst\s+(?P<dst_interface>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>\d+)"
        r"\s+by access-group\s+\"(?P<acl>[^\"]+)\"",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "acl_decision"
    event["outcome"] = "failure"
    event["protocol"] = match.group("protocol").upper()
    event["action"] = "deny"

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))
    event["dst_ip"] = match.group("dst_ip")
    event["dst_port"] = int(match.group("dst_port"))

    event["object_type"] = "access_control_rule"
    event["object_name"] = match.group("acl")

    event["details"] = {
        "source_interface": match.group("src_interface"),
        "destination_interface": match.group("dst_interface"),
        "access_group": match.group("acl")
    }

    return True


def parse_acl_106100(message, event):
    match = re.match(
        r"access-list\s+(?P<acl>\S+)\s+"
        r"(?P<decision>permitted|denied)\s+"
        r"(?P<protocol>\w+)\s+"
        r"(?P<src_interface>[^/]+)/(?P<src_ip>[^(]+)\((?P<src_port>\d+)\)\s+->\s+"
        r"(?P<dst_interface>[^/]+)/(?P<dst_ip>[^(]+)\((?P<dst_port>\d+)\)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    permitted = match.group("decision").lower() == "permitted"

    event["subtype"] = "acl_decision"
    event["outcome"] = "success" if permitted else "failure"
    event["protocol"] = match.group("protocol").upper()
    event["action"] = "allow" if permitted else "deny"

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))
    event["dst_ip"] = match.group("dst_ip")
    event["dst_port"] = int(match.group("dst_port"))

    event["object_type"] = "access_control_rule"
    event["object_name"] = match.group("acl")

    event["details"] = {
        "source_interface": match.group("src_interface"),
        "destination_interface": match.group("dst_interface"),
        "access_group": match.group("acl")
    }

    return True


def parse_nat(message, event):
    built = re.match(
        r"Built\s+(?P<nat_type>\w+)\s+"
        r"(?P<protocol>TCP|UDP)\s+translation from\s+"
        r"(?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+"
        r"to\s+(?P<dst_interface>[^:]+):(?P<translated_ip>[^/]+)/(?P<translated_port>\d+)",
        message,
        re.IGNORECASE
    )

    teardown = re.match(
        r"Teardown\s+(?P<nat_type>\w+)\s+"
        r"(?P<protocol>TCP|UDP)\s+translation from\s+"
        r"(?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+"
        r"to\s+(?P<dst_interface>[^:]+):(?P<translated_ip>[^/]+)/(?P<translated_port>\d+)"
        r"(?:\s+duration\s+(?P<duration>\S+))?",
        message,
        re.IGNORECASE
    )

    match = built or teardown

    if not match:
        return False

    event["subtype"] = "nat_translation"
    event["outcome"] = "success"
    event["protocol"] = match.group("protocol").upper()

    event["src_ip"] = match.group("src_ip")
    event["src_port"] = int(match.group("src_port"))

    event["action"] = (
        "translation_built" if built
        else "translation_teardown"
    )

    event["object_type"] = "nat_translation"
    event["object_name"] = match.group("translated_ip")

    details = {
        "nat_type": match.group("nat_type").lower(),
        "source_interface": match.group("src_interface"),
        "translated_interface": match.group("dst_interface"),
        "translated_ip": match.group("translated_ip"),
        "translated_port": int(match.group("translated_port"))
    }

    if teardown and match.group("duration"):
        details["duration"] = match.group("duration")

    event["details"] = details

    return True


def parse_icmp(message, event, start):
    match = re.match(
        r"(?:Built|Teardown)\s+"
        r"(?:(?P<direction>inbound|outbound)\s+)?"
        r"ICMP connection(?:\s+for)?\s+"
        r"faddr\s+(?P<foreign_ip>[^/]+)/\d+\s+"
        r"gaddr\s+(?P<global_ip>[^/]+)/\d+\s+"
        r"laddr\s+(?P<local_ip>[^/]+)/\d+",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = (
        "session_start" if start else "session_end"
    )

    event["outcome"] = "success"
    event["protocol"] = "ICMP"

    event["action"] = (
        "connection_built"
        if start
        else "connection_teardown"
    )

    event["src_ip"] = match.group("local_ip")
    event["dst_ip"] = match.group("foreign_ip")

    event["object_type"] = "network_session"

    event["details"] = {
        "global_ip": match.group("global_ip")
    }

    if match.group("direction"):
        event["details"]["direction"] = (
            match.group("direction").lower()
        )

    return True

def parse_gre(message, event, start):
    match = re.match(
        r"(?:Built|Teardown)\s+(?P<direction>inbound|outbound)\s+GRE connection from\s+"
        r"(?P<src_interface>[^:]+):(?P<src_ip>\S+)\s+to\s+"
        r"(?P<dst_interface>[^:]+):(?P<dst_ip>\S+)"
        r"(?:\s+duration\s+(?P<duration>\S+))?",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "session_start" if start else "session_end"
    event["outcome"] = "success"
    event["protocol"] = "GRE"
    event["action"] = "connection_built" if start else "connection_teardown"

    event["src_ip"] = match.group("src_ip")
    event["dst_ip"] = match.group("dst_ip")

    event["details"] = {
        "direction": match.group("direction").lower(),
        "source_interface": match.group("src_interface"),
        "destination_interface": match.group("dst_interface")
    }

    if match.group("duration"):
        event["details"]["duration"] = match.group("duration")

    return True


def convert(raw, number):
    event = empty_taxonomy()

    event["u_id"] = f"ULPF-CISCO-{number:09d}"
    event["raw_id"] = f"RAW-CISCO-{number:09d}"

    event["vendor"] = "Cisco"
    event["product"] = "ASA"

    event["category"] = "network_activity"
    event["type"] = "traffic"

    header = parse_header(raw)

    if not header:
        event["action"] = "unparsed"
        event["outcome"] = "unknown"
        event["vendor_fields"]["parse_error"] = "ASA header not recognized"
        return event

    event["timestamp"] = header["timestamp"]
    event["severity"] = SEVERITY_MAP.get(header["severity"])
    event["vendor_event_id"] = header["event_id"]

    event_id = header["event_id"]
    message = header["message"]

    parsed = False

    if event_id in {"302013", "302015"}:
        parsed = parse_connection_start(event_id, message, event)

    elif event_id in {"302014", "302016"}:
        parsed = parse_connection_end(event_id, message, event)

    elif event_id == "106023":
        parsed = parse_acl_deny(message, event)

    elif event_id == "106100":
        parsed = parse_acl_106100(message, event)

    elif event_id in {"305011", "305012"}:
        parsed = parse_nat(message, event)

    elif event_id == "302020":
        parsed = parse_icmp(message, event, True)

    elif event_id == "302021":
        parsed = parse_icmp(message, event, False)

    elif event_id == "302017":
        parsed = parse_gre(message, event, True)

    elif event_id == "302018":
        parsed = parse_gre(message, event, False)

    if not parsed:
        event["action"] = "unparsed"
        event["outcome"] = "unknown"
        event["vendor_fields"]["message"] = message

    return event


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    processed = 0
    parsed = 0
    unparsed = 0

    with open(INPUT_FILE, "r", encoding="utf-8") as infile, \
         open(OUTPUT_FILE, "w", encoding="utf-8") as outfile, \
         open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as rawfile:

        for line in infile:
            raw = line.strip()

            if not raw:
                continue

            if raw.startswith("#"):
                continue

            processed += 1

            event = convert(raw, processed)

            rawfile.write(
                json.dumps({
                    "raw_id": event["raw_id"],
                    "u_id": event["u_id"],
                    "raw_event": raw
                }, ensure_ascii=False) + "\n"
            )

            outfile.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

            if event["action"] == "unparsed":
                unparsed += 1
            else:
                parsed += 1

    print()
    print("Cisco ASA conversion complete")
    print(f"Records processed : {processed}")
    print(f"Parsed            : {parsed}")
    print(f"Unparsed          : {unparsed}")
    print(f"Common taxonomy   : {OUTPUT_FILE}")
    print(f"Raw store         : {RAW_OUTPUT_FILE}")


if __name__ == "__main__":
    main()