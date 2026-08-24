import csv
import json
import uuid
from datetime import datetime

INPUT_FILE = r"C:\Users\rish2\ULPF\datasets\corpus_v1\fortigate\fortigate_real.csv"

OUTPUT_FILE = r"C:\Users\rish2\ULPF\output\fortigate_traffic_common.jsonl"


def empty_to_none(value):
    if value is None:
        return None

    value = str(value).strip()

    if value == "":
        return None

    return value


def to_int(value):
    value = empty_to_none(value)

    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def normalize_protocol(proto):
    proto = empty_to_none(proto)

    if proto is None:
        return None

    protocol_map = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "58": "ICMPv6"
    }

    return protocol_map.get(proto, proto.upper())


def normalize_action(action):
    action = empty_to_none(action)

    if action is None:
        return None

    action = action.lower()

    action_map = {
        "accept": "allow",
        "allow": "allow",
        "permit": "allow",

        "deny": "deny",
        "drop": "deny",
        "reject": "deny",

        "close": "close",
        "start": "start"
    }

    return action_map.get(action, action)


def derive_outcome(action):
    if action is None:
        return None

    if action == "allow":
        return "success"

    if action == "deny":
        return "failure"

    if action == "close":
        return "success"

    if action == "start":
        return "success"

    return None


def build_timestamp(row):
    date = empty_to_none(row.get("date"))
    time = empty_to_none(row.get("time"))
    timezone = empty_to_none(row.get("tz"))

    if not date or not time:
        return None

    timestamp = f"{date}T{time}"

    if timezone:
        if len(timezone) == 5:
            timestamp += timezone[:3] + ":" + timezone[3:]
        else:
            timestamp += timezone

    return timestamp


def convert_row(row, record_number):
    action = normalize_action(row.get("action"))

    details = {}

    detail_mapping = {
        "service": "service",
        "sessionid": "session_id",
        "duration": "duration",
        "sentbyte": "bytes_sent",
        "rcvdbyte": "bytes_received",
        "sentpkt": "packets_sent",
        "rcvdpkt": "packets_received",
        "srcintf": "source_interface",
        "dstintf": "destination_interface",
        "srcintfrole": "source_interface_role",
        "dstintfrole": "destination_interface_role",
        "policyid": "policy_id",
        "policyname": "policy_name",
        "trandisp": "nat_disposition",
        "transip": "translated_ip",
        "transport": "translated_port",
        "vd": "virtual_domain",
        "app": "application",
        "appcat": "application_category",
        "appid": "application_id",
        "apprisk": "application_risk"
    }

    integer_detail_fields = {
        "duration",
        "sentbyte",
        "rcvdbyte",
        "sentpkt",
        "rcvdpkt",
        "policyid",
        "transport",
        "appid"
    }

    mapped_raw_fields = {
        "date",
        "time",
        "tz",
        "type",
        "subtype",
        "level",
        "srcip",
        "srcport",
        "dstip",
        "dstport",
        "proto",
        "action",
        "logid"
    }

    for raw_key, common_key in detail_mapping.items():
        value = row.get(raw_key)

        if raw_key in integer_detail_fields:
            value = to_int(value)
        else:
            value = empty_to_none(value)

        if value is not None:
            details[common_key] = value

        mapped_raw_fields.add(raw_key)

    vendor_fields = {}

    for key, value in row.items():
        if key in mapped_raw_fields:
            continue

        value = empty_to_none(value)

        if value is not None:
            vendor_fields[key] = value

    common = {
        "u_id": f"ULPF-{record_number:09d}",
        "raw_id": f"RAW-{record_number:09d}",

        "timestamp": build_timestamp(row),

        "vendor": "Fortinet",
        "product": "FortiGate",

        "category": "network_activity",
        "type": empty_to_none(row.get("type")),
        "subtype": empty_to_none(row.get("subtype")),
        "outcome": derive_outcome(action),

        "severity": empty_to_none(row.get("level")),

        "src_ip": empty_to_none(row.get("srcip")),
        "src_port": to_int(row.get("srcport")),
        "dst_ip": empty_to_none(row.get("dstip")),
        "dst_port": to_int(row.get("dstport")),
        "protocol": normalize_protocol(row.get("proto")),

        "user": None,

        "action": action,
        "reason": None,

        "object_type": None,
        "object_name": None,

        "details": details,

        "vendor_event_id": empty_to_none(row.get("logid")),

        "vendor_fields": vendor_fields
    }

    return common


def main():
    import os

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    processed = 0

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as infile, open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as outfile:

        reader = csv.DictReader(infile)

        for record_number, row in enumerate(reader, start=1):

            normalized = convert_row(row, record_number)

            outfile.write(
                json.dumps(
                    normalized,
                    ensure_ascii=False,
                    separators=(",", ":")
                )
                + "\n"
            )

            processed += 1

            if processed % 100000 == 0:
                print(f"Processed {processed:,} records")

    print()
    print("Conversion complete")
    print(f"Records processed : {processed:,}")
    print(f"Output file       : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()