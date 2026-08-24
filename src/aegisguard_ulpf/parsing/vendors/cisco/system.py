import json
import os
import re
from datetime import datetime


INPUT_FILE = r"C:\Users\rish2\ULPF\datasets\corpus_v1\cisco_system\cisco_system_samples.log"

OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_system_common.jsonl"

RAW_OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\cisco_system_raw.jsonl"

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
    match = re.match(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<clock>\d{2}:\d{2}:\d{2}):\s*",
        raw
    )

    if not match:
        return None, raw

    try:
        dt = datetime.strptime(
            f"{DEFAULT_YEAR} "
            f"{match.group('month')} "
            f"{match.group('day')} "
            f"{match.group('clock')}",
            "%Y %b %d %H:%M:%S"
        )

        timestamp = dt.isoformat()

    except ValueError:
        timestamp = None

    return timestamp, raw[match.end():]


def parse_header(raw):
    timestamp, remaining = parse_timestamp(raw)

    match = re.search(
        r"%(?P<facility>[A-Z0-9_]+)-"
        r"(?P<severity>\d)-"
        r"(?P<event_id>[A-Z0-9_]+):\s*"
        r"(?P<message>.*)$",
        remaining
    )

    if not match:
        return None

    return {
        "timestamp": timestamp,
        "facility": match.group("facility"),
        "severity": match.group("severity"),
        "event_id": match.group("event_id"),
        "message": match.group("message")
    }


def parse_reload(message, event):
    match = re.match(
        r"Reload requested by\s+(?P<user>\S+)\s+"
        r"on\s+(?P<source>[^.]+)\.\s*"
        r"Reload Reason:\s*(?P<reason>.*)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "device_reload"
    event["outcome"] = "success"

    event["user"] = match.group("user")
    event["action"] = "device_reload"
    event["reason"] = match.group("reason").strip().rstrip(".")

    event["object_type"] = "network_device"

    event["details"] = {
        "request_source": match.group("source").strip()
    }

    return True


def parse_restart(message, event):
    match = re.match(
        r"System restarted\s+--\s*(?P<software>.*)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "device_restart"
    event["outcome"] = "success"

    event["action"] = "system_restarted"

    event["object_type"] = "network_device"

    event["details"] = {
        "software": match.group("software").strip()
    }

    return True


def parse_cpuhog(message, event):
    match = re.match(
        r"Task ran for\s+(?P<msec>\d+)\s+msec,\s*"
        r"process\s*=\s*(?P<process>.*)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "resource_usage"
    event["outcome"] = "failure"

    event["action"] = "cpu_hog_detected"

    event["object_type"] = "process"
    event["object_name"] = match.group("process").strip()

    event["details"] = {
        "runtime_ms": int(match.group("msec"))
    }

    return True


def parse_mallocfail(message, event):
    match = re.match(
        r"Memory allocation of\s+(?P<bytes>\d+)\s+bytes failed"
        r"(?:\s+from\s+(?P<address>[^,\s]+))?"
        r"(?:,\s*alignment\s+(?P<alignment>\d+))?",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "memory_error"
    event["outcome"] = "failure"

    event["action"] = "memory_allocation_failed"

    event["object_type"] = "memory"

    event["details"]["requested_bytes"] = int(
        match.group("bytes")
    )

    if match.group("address"):
        event["details"]["address"] = match.group("address")

    if match.group("alignment"):
        event["details"]["alignment"] = int(
            match.group("alignment")
        )

    return True


def parse_power_failure(message, event):
    match = re.match(
        r"Power supply\s+(?P<id>\S+)\s+failed",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "hardware"
    event["outcome"] = "failure"

    event["action"] = "power_supply_failed"

    event["object_type"] = "power_supply"
    event["object_name"] = match.group("id")

    return True


def parse_fan_failure(message, event):
    match = re.match(
        r"Fan\s+(?P<id>\S+)\s+failed",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "hardware"
    event["outcome"] = "failure"

    event["action"] = "fan_failed"

    event["object_type"] = "fan"
    event["object_name"] = match.group("id")

    return True


def parse_temperature(message, event):
    match = re.match(
        r"Temperature threshold exceeded on sensor\s+(?P<id>\S+)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "hardware"
    event["outcome"] = "failure"

    event["action"] = "temperature_threshold_exceeded"

    event["object_type"] = "temperature_sensor"
    event["object_name"] = match.group("id")

    return True


def parse_crash(message, event):
    match = re.match(
        r'Process\s+"(?P<process>[^"]+)"\s+crashed unexpectedly',
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "process_failure"
    event["outcome"] = "failure"

    event["action"] = "process_crashed"

    event["object_type"] = "process"
    event["object_name"] = match.group("process")

    return True


def parse_interface_error(message, event):
    match = re.match(
        r"Interface\s+(?P<interface>\S+)\s+hardware error detected",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "hardware"
    event["outcome"] = "failure"

    event["action"] = "interface_hardware_error"

    event["object_type"] = "network_interface"
    event["object_name"] = match.group("interface")

    return True


def parse_clock_update(message, event):
    match = re.match(
        r"System clock changed from\s+(?P<old>\S+)\s+to\s+(?P<new>\S+)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "clock_change"
    event["outcome"] = "success"

    event["action"] = "clock_changed"

    event["object_type"] = "system_clock"

    event["details"] = {
        "old_time": match.group("old"),
        "new_time": match.group("new")
    }

    return True


def parse_config_save(message, event):
    match = re.match(
        r"Configuration saved to\s+(?P<destination>\S+)\s+by\s+(?P<user>\S+)",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "configuration_save"
    event["outcome"] = "success"

    event["user"] = match.group("user")
    event["action"] = "configuration_saved"

    event["object_type"] = "configuration"
    event["object_name"] = match.group("destination")

    event["details"] = {
        "destination": match.group("destination")
    }

    return True


def parse_module_failure(message, event):
    match = re.match(
        r"Module\s+(?P<id>\S+)\s+failed diagnostic test",
        message,
        re.IGNORECASE
    )

    if not match:
        return False

    event["subtype"] = "module_failure"
    event["outcome"] = "failure"

    event["action"] = "module_failure"

    event["object_type"] = "hardware_module"
    event["object_name"] = match.group("id")

    return True


def convert(raw, number):
    event = empty_taxonomy()

    event["u_id"] = f"ULPF-CISCO-SYSTEM-{number:09d}"
    event["raw_id"] = f"RAW-CISCO-SYSTEM-{number:09d}"

    event["vendor"] = "Cisco"
    event["product"] = "IOS"

    event["category"] = "system"
    event["type"] = "system"

    header = parse_header(raw)

    if not header:
        event["outcome"] = "unknown"
        event["action"] = "unparsed"

        event["vendor_fields"]["parse_error"] = (
            "Cisco system header not recognized"
        )

        return event

    event["timestamp"] = header["timestamp"]

    event["severity"] = SEVERITY_MAP.get(
        header["severity"]
    )

    facility = header["facility"]
    event_id = header["event_id"]
    message = header["message"]

    event["vendor_event_id"] = (
        f"{facility}-{header['severity']}-{event_id}"
    )

    parsed = False

    if facility == "SYS" and event_id == "RELOAD":
        parsed = parse_reload(message, event)

    elif facility == "SYS" and event_id == "RESTART":
        parsed = parse_restart(message, event)

    elif facility == "SYS" and event_id == "CPUHOG":
        parsed = parse_cpuhog(message, event)

    elif facility == "SYS" and event_id == "MALLOCFAIL":
        parsed = parse_mallocfail(message, event)

    elif facility == "PLATFORM_ENV" and event_id == "PWRFAIL":
        parsed = parse_power_failure(message, event)

    elif facility == "PLATFORM_ENV" and event_id == "FANFAIL":
        parsed = parse_fan_failure(message, event)

    elif facility == "PLATFORM_ENV" and event_id == "TEMP":
        parsed = parse_temperature(message, event)

    elif facility == "SYS" and event_id == "CRASH":
        parsed = parse_crash(message, event)

    elif facility == "LINK" and event_id == "ERROR":
        parsed = parse_interface_error(message, event)

    elif facility == "SYS" and event_id == "CLOCKUPDATE":
        parsed = parse_clock_update(message, event)

    elif facility == "SYS" and event_id == "CONFIG_SAVE":
        parsed = parse_config_save(message, event)

    elif facility == "MODULE" and event_id == "FAILURE":
        parsed = parse_module_failure(message, event)

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
    print("Cisco system conversion complete")
    print(f"Records processed : {processed}")
    print(f"Parsed            : {parsed_count}")
    print(f"Unparsed          : {unparsed_count}")
    print(f"Common taxonomy   : {OUTPUT_FILE}")
    print(f"Raw store         : {RAW_OUTPUT_FILE}")


if __name__ == "__main__":
    main()