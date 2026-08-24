import json
import os
import re
from datetime import datetime


INPUT_FILE = r"C:\Users\rish2\ULPF\datasets\corpus_v1\cisco_router\cisco_router_samples.log"
OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_router_common.jsonl"
RAW_OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_router_raw.jsonl"

DEFAULT_YEAR = 2026


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


def parse_timestamp(raw):
    # Aug 24 16:10:11:
    m = re.match(
        r"^\*?(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<clock>\d{2}:\d{2}:\d{2}):\s*",
        raw
    )

    if m:
        try:
            dt = datetime.strptime(
                f"{DEFAULT_YEAR} {m.group('month')} {m.group('day')} {m.group('clock')}",
                "%Y %b %d %H:%M:%S"
            )
            return dt.isoformat(), raw[m.end():]
        except ValueError:
            pass

    # 00:00:46:
    m = re.match(
        r"^(?P<clock>\d{2}:\d{2}:\d{2}):\s*",
        raw
    )

    if m:
        return None, raw[m.end():]

    # *Mar 1 18:46:11:
    m = re.match(
        r"^\*(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<clock>\d{2}:\d{2}:\d{2}):\s*",
        raw
    )

    if m:
        try:
            dt = datetime.strptime(
                f"{DEFAULT_YEAR} {m.group('month')} {m.group('day')} {m.group('clock')}",
                "%Y %b %d %H:%M:%S"
            )
            return dt.isoformat(), raw[m.end():]
        except ValueError:
            pass

    return None, raw


def parse_header(raw):
    timestamp, remaining = parse_timestamp(raw)

    m = re.search(
        r"%(?P<facility>[A-Z0-9_]+)-"
        r"(?P<severity>\d)-"
        r"(?P<event_id>[A-Z0-9_]+):\s*"
        r"(?P<message>.*)$",
        remaining
    )

    if not m:
        return None

    return {
        "timestamp": timestamp,
        "facility": m.group("facility"),
        "severity": m.group("severity"),
        "event_id": m.group("event_id"),
        "message": m.group("message")
    }


def parse_link(message, event):
    m = re.match(
        r"Interface\s+(?P<interface>[^,]+),\s*"
        r"changed state to\s+(?P<state>up|down)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    state = m.group("state").lower()
    interface = m.group("interface").strip()

    event["category"] = "network_activity"
    event["subtype"] = "interface_state"
    event["outcome"] = "success" if state == "up" else "failure"

    event["action"] = f"interface_{state}"

    event["object_type"] = "network_interface"
    event["object_name"] = interface

    event["details"] = {
        "interface": interface,
        "new_state": state
    }

    return True


def parse_lineproto(message, event):
    m = re.match(
        r"Line protocol on Interface\s+(?P<interface>[^,]+),\s*"
        r"changed state to\s+(?P<state>up|down)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    state = m.group("state").lower()
    interface = m.group("interface").strip()

    event["category"] = "network_activity"
    event["subtype"] = "line_protocol_state"
    event["outcome"] = "success" if state == "up" else "failure"

    event["action"] = f"line_protocol_{state}"

    event["object_type"] = "network_interface"
    event["object_name"] = interface

    event["details"] = {
        "interface": interface,
        "new_state": state
    }

    return True


def parse_bgp(message, event):
    m = re.match(
        r"neighbor\s+(?P<neighbor>\S+)\s+"
        r"(?P<state>Up|Down)"
        r"(?:\s+(?P<reason>.*))?$",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    state = m.group("state").lower()
    neighbor = m.group("neighbor")

    event["category"] = "network_activity"
    event["subtype"] = "bgp_neighbor_state"
    event["protocol"] = "BGP"

    event["dst_ip"] = neighbor

    event["action"] = f"neighbor_{state}"
    event["outcome"] = "success" if state == "up" else "failure"

    event["object_type"] = "routing_neighbor"
    event["object_name"] = neighbor

    event["details"] = {
        "neighbor_ip": neighbor,
        "new_state": state
    }

    if m.group("reason"):
        event["reason"] = m.group("reason").strip()

    return True


def parse_ospf(message, event):
    m = re.match(
        r"Process\s+(?P<process>\d+),\s*"
        r"Nbr\s+(?P<neighbor>\S+)\s+"
        r"on\s+(?P<interface>\S+)\s+"
        r"from\s+(?P<old>\S+)\s+to\s+(?P<new>[A-Za-z0-9_-]+)"
        r"(?:,\s*(?P<reason>.*))?$",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    old_state = m.group("old").upper()
    new_state = m.group("new").upper()
    neighbor = m.group("neighbor")

    event["category"] = "network_activity"
    event["protocol"] = "OSPF"
    event["dst_ip"] = neighbor

    event["object_type"] = "routing_neighbor"
    event["object_name"] = neighbor

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

    event["details"] = {
        "process_id": int(m.group("process")),
        "neighbor_ip": neighbor,
        "interface": m.group("interface"),
        "previous_state": old_state,
        "new_state": new_state
    }

    if m.group("reason"):
        reason = m.group("reason").strip()
        if ":" in reason:
            reason = reason.split(":", 1)[1].strip()
        event["reason"] = reason

    return True


def parse_eigrp(message, event):
    m = re.match(
        r"EIGRP-IPv4\s+(?P<asn>\d+):\s*"
        r"Neighbor\s+(?P<neighbor>\S+)\s+"
        r"\((?P<interface>[^)]+)\)\s+"
        r"is\s+(?P<state>up|down):\s*(?P<reason>.*)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    state = m.group("state").lower()
    neighbor = m.group("neighbor")

    event["category"] = "network_activity"
    event["subtype"] = "eigrp_neighbor_state"
    event["protocol"] = "EIGRP"
    event["dst_ip"] = neighbor

    event["action"] = f"neighbor_{state}"
    event["outcome"] = "success" if state == "up" else "failure"

    event["object_type"] = "routing_neighbor"
    event["object_name"] = neighbor

    event["reason"] = m.group("reason").strip()

    event["details"] = {
        "autonomous_system": int(m.group("asn")),
        "neighbor_ip": neighbor,
        "interface": m.group("interface"),
        "new_state": state
    }

    return True


def parse_isis(message, event):
    m = re.match(
        r"ISIS:\s+Adjacency to\s+(?P<neighbor>\S+)\s+"
        r"\((?P<interface>[^)]+)\)\s+"
        r"(?P<state>Up|Down)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    state = m.group("state").lower()

    event["category"] = "network_activity"
    event["subtype"] = "isis_adjacency_state"
    event["protocol"] = "ISIS"

    event["action"] = f"adjacency_{state}"
    event["outcome"] = "success" if state == "up" else "failure"

    event["object_type"] = "routing_neighbor"
    event["object_name"] = m.group("neighbor")

    event["details"] = {
        "neighbor": m.group("neighbor"),
        "interface": m.group("interface"),
        "new_state": state
    }

    return True


def parse_config(message, event):
    m = re.match(
        r"Configured from console by\s+(?P<user>\S+)"
        r"(?:\s+\((?P<src_ip>[^)]+)\))?",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    event["category"] = "configuration"
    event["subtype"] = "configuration_change"
    event["outcome"] = "success"

    event["user"] = m.group("user")
    event["src_ip"] = m.group("src_ip")

    event["action"] = "configuration_changed"

    event["object_type"] = "network_device"

    return True


def parse_login(message, event, success):
    pattern = (
        r"Login Success \[user:\s*(?P<user>[^\]]+)\]\s*"
        if success else
        r"Login failed \[user:\s*(?P<user>[^\]]+)\]\s*"
    )

    pattern += (
        r"\[Source:\s*(?P<src_ip>[^\]]+)\]\s*"
        r"\[localport:\s*(?P<port>\d+)\]"
    )

    m = re.match(pattern, message, re.IGNORECASE)

    if not m:
        return False

    event["category"] = "authentication"
    event["subtype"] = "login"

    event["outcome"] = "success" if success else "failure"
    event["action"] = "login_success" if success else "login_failure"

    event["user"] = m.group("user").strip()
    event["src_ip"] = m.group("src_ip").strip()
    event["dst_port"] = int(m.group("port"))

    event["object_type"] = "network_device"

    return True


def parse_acl(message, event):
    m = re.match(
        r"list\s+(?P<acl>\S+)\s+"
        r"(?P<decision>denied|permitted)\s+"
        r"(?P<protocol>\w+)\s+"
        r"(?P<src_ip>[^(]+)\((?P<src_port>\d+)\)\s*->\s*"
        r"(?P<dst_ip>[^(]+)\((?P<dst_port>\d+)\),\s*"
        r"(?P<packets>\d+)\s+packet",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    allowed = m.group("decision").lower() == "permitted"

    event["category"] = "network_activity"
    event["subtype"] = "acl_decision"
    event["outcome"] = "success" if allowed else "failure"

    event["src_ip"] = m.group("src_ip").strip()
    event["src_port"] = int(m.group("src_port"))
    event["dst_ip"] = m.group("dst_ip").strip()
    event["dst_port"] = int(m.group("dst_port"))
    event["protocol"] = m.group("protocol").upper()

    event["action"] = "allow" if allowed else "deny"

    event["object_type"] = "access_control_rule"
    event["object_name"] = m.group("acl")

    event["details"] = {
        "access_list": m.group("acl"),
        "packet_count": int(m.group("packets"))
    }

    return True


def parse_nat(message, event, created):
    verb = "Created" if created else "Deleted"

    m = re.match(
        rf"{verb}\s+(?P<protocol>\w+)\s+translation\s+"
        r"(?P<original_ip>[^:]+):(?P<original_port>\d+)\s*->\s*"
        r"(?P<translated_ip>[^:]+):(?P<translated_port>\d+)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "nat_translation"
    event["outcome"] = "success"

    event["src_ip"] = m.group("original_ip")
    event["src_port"] = int(m.group("original_port"))
    event["protocol"] = m.group("protocol").upper()

    event["action"] = (
        "translation_created"
        if created
        else "translation_deleted"
    )

    event["object_type"] = "nat_translation"
    event["object_name"] = m.group("translated_ip")

    event["details"] = {
        "translated_ip": m.group("translated_ip"),
        "translated_port": int(m.group("translated_port"))
    }

    return True


def parse_dhcp(message, event, assigned):
    verb = "Assigned" if assigned else "Released"
    connector = "to" if assigned else "from"

    m = re.match(
        rf"{verb}\s+(?P<ip>\S+)\s+{connector}\s+client\s+(?P<mac>\S+)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    event["category"] = "network_activity"
    event["subtype"] = "dhcp"
    event["outcome"] = "success"

    event["action"] = (
        "address_assigned"
        if assigned
        else "address_released"
    )

    event["object_type"] = "ip_address"
    event["object_name"] = m.group("ip")

    event["details"] = {
        "ip_address": m.group("ip"),
        "client_mac": m.group("mac")
    }

    return True


def parse_reload(message, event):
    m = re.match(
        r"Reload requested by\s+(?P<user>\S+)\s+"
        r"on\s+(?P<source>[^.]+)\.\s*"
        r"Reload Reason:\s*(?P<reason>.*)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    event["category"] = "system"
    event["subtype"] = "device_reload"
    event["outcome"] = "success"

    event["user"] = m.group("user")
    event["action"] = "device_reload"
    event["reason"] = m.group("reason").strip().rstrip(".")

    event["object_type"] = "network_device"

    event["details"] = {
        "request_source": m.group("source")
    }

    return True


def parse_cpuhog(message, event):
    m = re.match(
        r"Task ran for\s+(?P<msec>\d+)\s+msec,\s*"
        r"process\s*=\s*(?P<process>.*)",
        message,
        re.IGNORECASE
    )

    if not m:
        return False

    event["category"] = "system"
    event["subtype"] = "resource_usage"
    event["outcome"] = "failure"

    event["action"] = "cpu_hog_detected"

    event["object_type"] = "process"
    event["object_name"] = m.group("process").strip()

    event["details"] = {
        "runtime_ms": int(m.group("msec"))
    }

    return True


def convert(raw, number):
    event = empty_taxonomy()

    event["u_id"] = f"ULPF-CISCO-ROUTER-{number:09d}"
    event["raw_id"] = f"RAW-CISCO-ROUTER-{number:09d}"

    event["vendor"] = "Cisco"
    event["product"] = "IOS"

    event["type"] = "router"

    header = parse_header(raw)

    if not header:
        event["outcome"] = "unknown"
        event["action"] = "unparsed"
        event["vendor_fields"]["parse_error"] = "Cisco IOS header not recognized"
        return event

    event["timestamp"] = header["timestamp"]
    event["severity"] = SEVERITY_MAP.get(header["severity"])

    facility = header["facility"]
    event_id = header["event_id"]
    message = header["message"]

    event["vendor_event_id"] = (
        f"{facility}-{header['severity']}-{event_id}"
    )

    parsed = False

    if facility == "LINK" and event_id == "UPDOWN":
        parsed = parse_link(message, event)

    elif facility == "LINEPROTO" and event_id == "UPDOWN":
        parsed = parse_lineproto(message, event)

    elif facility == "BGP" and event_id == "ADJCHANGE":
        parsed = parse_bgp(message, event)

    elif facility == "OSPF" and event_id == "ADJCHG":
        parsed = parse_ospf(message, event)

    elif facility == "DUAL" and event_id == "NBRCHANGE":
        parsed = parse_eigrp(message, event)

    elif facility == "CLNS" and event_id == "ADJCHANGE":
        parsed = parse_isis(message, event)

    elif facility == "SYS" and event_id == "CONFIG_I":
        parsed = parse_config(message, event)

    elif facility == "SEC_LOGIN" and event_id == "LOGIN_SUCCESS":
        parsed = parse_login(message, event, True)

    elif facility == "SEC_LOGIN" and event_id == "LOGIN_FAILED":
        parsed = parse_login(message, event, False)

    elif facility == "SEC" and event_id == "IPACCESSLOGP":
        parsed = parse_acl(message, event)

    elif facility == "NAT" and event_id == "TRANSLATION_CREATE":
        parsed = parse_nat(message, event, True)

    elif facility == "NAT" and event_id == "TRANSLATION_DELETE":
        parsed = parse_nat(message, event, False)

    elif facility == "DHCPD" and event_id == "ADDRESS_ASSIGN":
        parsed = parse_dhcp(message, event, True)

    elif facility == "DHCPD" and event_id == "ADDRESS_RELEASE":
        parsed = parse_dhcp(message, event, False)

    elif facility == "SYS" and event_id == "RELOAD":
        parsed = parse_reload(message, event)

    elif facility == "SYS" and event_id == "CPUHOG":
        parsed = parse_cpuhog(message, event)

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
    parsed_count = 0
    unparsed_count = 0

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
                unparsed_count += 1
            else:
                parsed_count += 1

    print()
    print("Cisco router conversion complete")
    print(f"Records processed : {processed}")
    print(f"Parsed            : {parsed_count}")
    print(f"Unparsed          : {unparsed_count}")
    print(f"Common taxonomy   : {OUTPUT_FILE}")
    print(f"Raw store         : {RAW_OUTPUT_FILE}")


if __name__ == "__main__":
    main()