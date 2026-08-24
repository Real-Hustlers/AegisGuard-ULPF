import json
import os
import re
from datetime import datetime


INPUT_FILE = (
    r"C:\Users\rish2\ULPF\datasets\corpus_v1"
    r"\routing\routing_test.log"
)

OUTPUT_FILE = (
    r"C:\Users\rish2\ULPF\output"
    r"\routing_common.jsonl"
)

RAW_OUTPUT_FILE = (
    r"C:\Users\rish2\ULPF\output"
    r"\routing_raw.jsonl"
)


# Cisco-style syslog timestamps normally omit the year.
# For this test corpus, use 2026.
DEFAULT_YEAR = 2026


SEVERITY_MAP = {
    "0": "emergency",
    "1": "alert",
    "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "notice",
    "6": "informational",
    "7": "debug",
}


HEADER_REGEX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+"
    r"%(?P<facility>[A-Z]+)-"
    r"(?P<severity>\d)-"
    r"(?P<message_id>[A-Z0-9_]+):\s*"
    r"(?P<message>.*)$"
)


def make_empty_taxonomy():
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


def build_timestamp(month, day, clock):
    value = f"{DEFAULT_YEAR} {month} {day} {clock}"

    try:
        dt = datetime.strptime(
            value,
            "%Y %b %d %H:%M:%S"
        )

        return dt.isoformat()

    except ValueError:
        return None


def parse_bgp_neighbor(message, event):
    match = re.match(
        r"neighbor\s+"
        r"(?P<neighbor>\S+)\s+"
        r"(?P<state>Up|Down)"
        r"(?:\s+(?P<reason>.*))?$",
        message,
        re.IGNORECASE,
    )

    if not match:
        return False

    neighbor = match.group("neighbor")
    state = match.group("state").lower()
    reason = match.group("reason")

    event["subtype"] = "bgp_neighbor_state"
    event["protocol"] = "BGP"

    event["dst_ip"] = neighbor

    event["object_type"] = "routing_neighbor"
    event["object_name"] = neighbor

    event["details"]["neighbor_ip"] = neighbor
    event["details"]["new_state"] = state

    if state == "up":
        event["action"] = "neighbor_up"
        event["outcome"] = "success"
    else:
        event["action"] = "neighbor_down"
        event["outcome"] = "failure"

    if reason:
        event["reason"] = reason.strip()

    return True


def parse_bgp_route(message, event):
    advertised = re.match(
        r"Advertised prefix "
        r"(?P<prefix>\S+) "
        r"to neighbor "
        r"(?P<neighbor>\S+)",
        message,
        re.IGNORECASE,
    )

    withdrawn = re.match(
        r"Withdrawn prefix "
        r"(?P<prefix>\S+) "
        r"from neighbor "
        r"(?P<neighbor>\S+)",
        message,
        re.IGNORECASE,
    )

    match = advertised or withdrawn

    if not match:
        return False

    prefix = match.group("prefix")
    neighbor = match.group("neighbor")

    event["subtype"] = "bgp_route_update"
    event["protocol"] = "BGP"
    event["outcome"] = "success"

    event["dst_ip"] = neighbor

    event["object_type"] = "network_prefix"
    event["object_name"] = prefix

    event["details"]["prefix"] = prefix
    event["details"]["neighbor_ip"] = neighbor

    if advertised:
        event["action"] = "route_advertised"
    else:
        event["action"] = "route_withdrawn"

    return True


def parse_ospf_adjacency(message, event):
    match = re.match(
        r"Process\s+(?P<process>\d+),\s*"
        r"Nbr\s+(?P<neighbor>\S+)\s+"
        r"on\s+(?P<interface>\S+)\s+"
        r"from\s+(?P<old_state>\S+)\s+"
        r"to\s+(?P<new_state>[A-Za-z0-9_-]+)"
        r"(?:,\s*(?P<reason>.*))?$",
        message,
        re.IGNORECASE,
    )

    if not match:
        return False

    process_id = int(match.group("process"))
    neighbor = match.group("neighbor")
    interface = match.group("interface")

    old_state = match.group("old_state").upper()
    new_state = match.group("new_state").upper()

    reason = match.group("reason")

    event["protocol"] = "OSPF"

    event["dst_ip"] = neighbor

    event["object_type"] = "routing_neighbor"
    event["object_name"] = neighbor

    event["details"]["neighbor_ip"] = neighbor
    event["details"]["process_id"] = process_id
    event["details"]["interface"] = interface
    event["details"]["previous_state"] = old_state
    event["details"]["new_state"] = new_state

    if new_state == "FULL":
        event["subtype"] = "ospf_neighbor_state"
        event["action"] = "neighbor_up"
        event["outcome"] = "success"

    elif new_state == "DOWN":
        event["subtype"] = "ospf_neighbor_state"
        event["action"] = "neighbor_down"
        event["outcome"] = "failure"

    else:
        event["subtype"] = "ospf_adjacency_change"
        event["action"] = "adjacency_state_change"
        event["outcome"] = "success"

    if reason:
        cleaned_reason = reason.strip()

        if cleaned_reason.lower().startswith(
            "neighbor down:"
        ):
            cleaned_reason = cleaned_reason.split(
                ":",
                1
            )[1].strip()

        event["reason"] = cleaned_reason

    return True


def parse_ospf_route(message, event):
    learned = re.match(
        r"Route\s+"
        r"(?P<prefix>\S+)\s+"
        r"learned via\s+"
        r"(?P<next_hop>\S+),\s*"
        r"metric\s+"
        r"(?P<metric>\d+)",
        message,
        re.IGNORECASE,
    )

    removed = re.match(
        r"Route\s+"
        r"(?P<prefix>\S+)\s+"
        r"removed from routing table",
        message,
        re.IGNORECASE,
    )

    if learned:
        prefix = learned.group("prefix")
        next_hop = learned.group("next_hop")
        metric = int(learned.group("metric"))

        event["subtype"] = "ospf_route_update"
        event["protocol"] = "OSPF"
        event["outcome"] = "success"

        event["action"] = "route_learned"

        event["dst_ip"] = next_hop

        event["object_type"] = "network_prefix"
        event["object_name"] = prefix

        event["details"]["prefix"] = prefix
        event["details"]["next_hop"] = next_hop
        event["details"]["metric"] = metric

        return True

    if removed:
        prefix = removed.group("prefix")

        event["subtype"] = "ospf_route_update"
        event["protocol"] = "OSPF"
        event["outcome"] = "success"

        event["action"] = "route_removed"

        event["object_type"] = "network_prefix"
        event["object_name"] = prefix

        event["details"]["prefix"] = prefix

        return True

    return False


def parse_static_route(message, event):
    added = re.match(
        r"Route\s+"
        r"(?P<prefix>\S+)\s+"
        r"added via\s+"
        r"(?P<next_hop>\S+)",
        message,
        re.IGNORECASE,
    )

    removed = re.match(
        r"Route\s+"
        r"(?P<prefix>\S+)\s+"
        r"removed$",
        message,
        re.IGNORECASE,
    )

    next_hop_change = re.match(
        r"Route\s+"
        r"(?P<prefix>\S+)\s+"
        r"next-hop changed from\s+"
        r"(?P<old_next_hop>\S+)\s+"
        r"to\s+"
        r"(?P<new_next_hop>\S+)",
        message,
        re.IGNORECASE,
    )

    event["subtype"] = "routing_table_change"
    event["outcome"] = "success"
    event["object_type"] = "network_prefix"

    if added:
        prefix = added.group("prefix")
        next_hop = added.group("next_hop")

        event["action"] = "route_added"
        event["object_name"] = prefix

        event["details"]["prefix"] = prefix
        event["details"]["next_hop"] = next_hop

        return True

    if removed:
        prefix = removed.group("prefix")

        event["action"] = "route_removed"
        event["object_name"] = prefix

        event["details"]["prefix"] = prefix

        return True

    if next_hop_change:
        prefix = next_hop_change.group("prefix")
        old_next_hop = next_hop_change.group(
            "old_next_hop"
        )
        new_next_hop = next_hop_change.group(
            "new_next_hop"
        )

        event["action"] = "next_hop_changed"
        event["object_name"] = prefix

        event["details"]["prefix"] = prefix
        event["details"]["old_next_hop"] = (
            old_next_hop
        )
        event["details"]["new_next_hop"] = (
            new_next_hop
        )

        return True

    return False


def convert_log(raw_log, record_number):
    event = make_empty_taxonomy()

    event["u_id"] = (
        f"ULPF-ROUTE-{record_number:09d}"
    )

    event["raw_id"] = (
        f"RAW-ROUTE-{record_number:09d}"
    )

    event["vendor"] = "Cisco"
    event["product"] = "IOS"

    event["category"] = "network_activity"
    event["type"] = "routing"

    header = HEADER_REGEX.match(raw_log)

    if not header:
        event["outcome"] = "unknown"
        event["action"] = "unparsed"

        event["vendor_fields"]["parse_error"] = (
            "Cisco syslog header not recognized"
        )

        return event

    timestamp = build_timestamp(
        header.group("month"),
        header.group("day"),
        header.group("clock"),
    )

    facility = header.group("facility")
    severity_number = header.group("severity")
    message_id = header.group("message_id")
    message = header.group("message")
    device = header.group("device")

    event["timestamp"] = timestamp

    event["severity"] = SEVERITY_MAP.get(
        severity_number,
        "unknown"
    )

    event["vendor_event_id"] = (
        f"{facility}-{severity_number}-{message_id}"
    )

    event["details"]["device"] = device

    parsed = False

    if facility == "BGP":
        if message_id == "ADJCHANGE":
            parsed = parse_bgp_neighbor(
                message,
                event
            )

        elif message_id == "UPDATE":
            parsed = parse_bgp_route(
                message,
                event
            )

    elif facility == "OSPF":
        if message_id == "ADJCHG":
            parsed = parse_ospf_adjacency(
                message,
                event
            )

        elif message_id == "ROUTE":
            parsed = parse_ospf_route(
                message,
                event
            )

    elif facility == "ROUTING":
        parsed = parse_static_route(
            message,
            event
        )

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
    ) as normalized_file, open(
        RAW_OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as raw_file:

        for record_number, line in enumerate(
            infile,
            start=1
        ):
            raw_log = line.strip()

            if not raw_log:
                continue

            normalized = convert_log(
                raw_log,
                record_number
            )

            raw_record = {
                "raw_id": normalized["raw_id"],
                "u_id": normalized["u_id"],
                "raw_event": raw_log
            }

            raw_file.write(
                json.dumps(
                    raw_record,
                    ensure_ascii=False
                )
                + "\n"
            )

            normalized_file.write(
                json.dumps(
                    normalized,
                    ensure_ascii=False
                )
                + "\n"
            )

            processed += 1

            if normalized["action"] == "unparsed":
                unparsed += 1
            else:
                parsed += 1

    print()
    print("Routing conversion complete")
    print(f"Records processed : {processed:,}")
    print(f"Parsed            : {parsed:,}")
    print(f"Unparsed          : {unparsed:,}")
    print(f"Common taxonomy   : {OUTPUT_FILE}")
    print(f"Raw store         : {RAW_OUTPUT_FILE}")


if __name__ == "__main__":
    main()  