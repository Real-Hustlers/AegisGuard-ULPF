"""Translate validated ULPF OCSF records to the old SIEM merged-log contract."""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any, Iterable

from aegisguard_ulpf.integration.siem_adapter import (
    SIEM_MERGED_LOGS_FILENAME,
    map_ocsf_event_to_siem,
    read_ocsf_jsonl,
    write_merged_logs,
)
from aegisguard_ulpf.normalization.ocsf.registry import (
    AUTHENTICATION_CLASS_UID,
    PROCESS_ACTIVITY_CLASS_UID,
    AuthenticationActivityID,
    ProcessActivityID,
    StatusID,
)


SIEM_MERGED_LOG_FIELDS = (
    "log_id",
    "machine_id",
    "hostname",
    "os",
    "timestamp",
    "event_type",
    "user",
    "source_ip",
    "destination_ip",
    "process",
    "file_path",
    "severity",
    "raw_log",
)

SIEM_INGESTION_LOG_FIELDS = (
    "timestamp",
    "event_type",
    "user",
    "source_ip",
    "destination_ip",
    "process",
    "file_path",
    "severity",
    "raw_log",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text_or_empty(value: Any, *, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"SIEM field {field} must be a string when present")
    return value


def _required_text(value: Any, *, field: str) -> str:
    text = _text_or_empty(value, field=field)
    if not text:
        raise ValueError(f"OCSF event requires {field} for SIEM translation")
    return text


def _event_type(ocsf_event: dict[str, Any]) -> str:
    class_uid = ocsf_event.get("class_uid")
    activity_id = ocsf_event.get("activity_id")
    status_id = ocsf_event.get("status_id")

    if (
        class_uid == AUTHENTICATION_CLASS_UID
        and activity_id == AuthenticationActivityID.LOGON
    ):
        if status_id == StatusID.SUCCESS:
            return "SUCCESSFUL_LOGIN"
        if status_id == StatusID.FAILURE:
            return "FAILED_LOGIN"
        raise ValueError(
            "Authentication OCSF event requires success or failure status_id"
        )

    if (
        class_uid == PROCESS_ACTIVITY_CLASS_UID
        and activity_id == ProcessActivityID.LAUNCH
    ):
        return "PROCESS_CREATED"

    raise ValueError(
        "Unsupported OCSF class/activity for SIEM contract translation: "
        f"{class_uid!r}/{activity_id!r}"
    )


def _raw_log(ocsf_event: dict[str, Any]) -> str:
    raw_data = ocsf_event.get("raw_data")
    if isinstance(raw_data, str):
        return raw_data
    if isinstance(raw_data, dict):
        try:
            return json.dumps(
                raw_data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("OCSF raw_data is not JSON-safe") from exc
    raise ValueError("OCSF event requires raw_data for SIEM raw_log")


def _process_name(ocsf_event: dict[str, Any], event_type: str) -> str:
    process = _mapping(ocsf_event.get("process"))
    name = _text_or_empty(process.get("name"), field="process.name")
    if event_type == "PROCESS_CREATED" and not name:
        raise ValueError("Process Activity OCSF event requires process.name")
    return name


def _file_path(ocsf_event: dict[str, Any]) -> str:
    file_object = _mapping(ocsf_event.get("file"))
    return _text_or_empty(file_object.get("path"), field="file.path")


def _inferred_os(legacy_event: dict[str, Any]) -> str:
    vendor = legacy_event.get("vendor")
    product = legacy_event.get("product")
    if (
        isinstance(vendor, str)
        and vendor.casefold() == "microsoft"
        and isinstance(product, str)
        and product.casefold().startswith("windows")
    ):
        return "Windows"
    return "UNKNOWN"


def map_ocsf_event_to_siem_contract(
    ocsf_event: dict[str, Any],
    *,
    sequence: int,
    machine_id: str | None = None,
    os_name: str | None = None,
) -> dict[str, Any]:
    """Return one SIEM ``merged_logs.json`` record plus ULPF traceability.

    Existing adapter fields remain present. The additional SIEM fields are the
    fields consumed by the old analyzer's classifier and correlation engine.
    """

    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("sequence must be a positive integer")

    legacy_event = map_ocsf_event_to_siem(ocsf_event)
    event_type = _event_type(ocsf_event)
    timestamp = _required_text(legacy_event.get("timestamp"), field="time")
    hostname = _text_or_empty(legacy_event.get("hostname"), field="hostname")
    resolved_machine_id = _text_or_empty(machine_id, field="machine_id") or hostname or "UNKNOWN"
    resolved_os = _text_or_empty(os_name, field="os") or _inferred_os(legacy_event)

    return {
        **legacy_event,
        "log_id": f"LOG-{sequence:06d}",
        "machine_id": resolved_machine_id,
        "hostname": hostname or "UNKNOWN",
        "os": resolved_os,
        "timestamp": timestamp,
        "event_type": event_type,
        "user": _text_or_empty(legacy_event.get("user"), field="user"),
        "source_ip": _text_or_empty(
            legacy_event.get("source_ip"),
            field="source_ip",
        ),
        "destination_ip": _text_or_empty(
            legacy_event.get("destination_ip"),
            field="destination_ip",
        ),
        "process": _process_name(ocsf_event, event_type),
        "file_path": _file_path(ocsf_event),
        "severity": _required_text(
            legacy_event.get("severity"),
            field="severity",
        ).upper(),
        "raw_log": _raw_log(ocsf_event),
    }


def translate_ocsf_events_to_siem_contract(
    ocsf_events: Iterable[dict[str, Any]],
    *,
    machine_id: str | None = None,
    os_name: str | None = None,
) -> list[dict[str, Any]]:
    """Translate OCSF records to deterministic SIEM merged-log records."""

    return [
        map_ocsf_event_to_siem_contract(
            event,
            sequence=sequence,
            machine_id=machine_id,
            os_name=os_name,
        )
        for sequence, event in enumerate(ocsf_events, start=1)
    ]


def translate_ocsf_jsonl_to_siem_merged_logs(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    machine_id: str | None = None,
    os_name: str | None = None,
) -> Path:
    """Read ULPF OCSF JSONL and write old-SIEM compatible ``merged_logs``."""

    source_path = Path(input_path)
    target_path = (
        Path(output_path)
        if output_path is not None
        else source_path.with_name(SIEM_MERGED_LOGS_FILENAME)
    )
    translated_events = translate_ocsf_events_to_siem_contract(
        read_ocsf_jsonl(source_path),
        machine_id=machine_id,
        os_name=os_name,
    )
    return write_merged_logs(translated_events, target_path)


def _uniform_value(
    events: list[dict[str, Any]],
    field: str,
    override: str | None,
) -> str:
    if override is not None:
        return _required_text(override, field=field)

    values = {event[field] for event in events}
    if len(values) != 1:
        raise ValueError(
            f"SIEM ingestion envelope requires one {field}; "
            "group events by source machine before translation"
        )
    return _required_text(values.pop(), field=field)


def translate_ocsf_events_to_siem_ingestion_envelope(
    ocsf_events: Iterable[dict[str, Any]],
    *,
    machine_id: str | None = None,
    hostname: str | None = None,
    os_name: str | None = None,
) -> dict[str, Any]:
    """Build the old SIEM's ``/api/upload_logs`` machine-envelope payload.

    The SIEM merger deliberately projects the envelope's logs to the
    post-merge fields. Use ``translate_ocsf_events_to_siem_contract`` when
    the caller must retain the additional ULPF traceability fields in the
    output file itself.
    """

    translated_events = translate_ocsf_events_to_siem_contract(
        ocsf_events,
        machine_id=machine_id,
        os_name=os_name,
    )
    if not translated_events:
        raise ValueError("SIEM ingestion envelope requires at least one OCSF event")

    resolved_machine_id = _uniform_value(
        translated_events,
        "machine_id",
        machine_id,
    )
    resolved_hostname = _uniform_value(
        translated_events,
        "hostname",
        hostname,
    )
    resolved_os = _uniform_value(
        translated_events, "os", os_name)

    logs: list[dict[str, Any]] = []
    for event in translated_events:
        record_id = event.get("event_id") or event.get("raw_id") or event["log_id"]
        logs.append(
            {
                "record_id": _required_text(record_id, field="record_id"),
                **{
                    field: event[field]
                    for field in SIEM_INGESTION_LOG_FIELDS
                },
            }
        )

    return {
        "machine_id": resolved_machine_id,
        "hostname": resolved_hostname,
        "os": resolved_os,
        "logs": logs,
    }


def translate_ocsf_jsonl_to_siem_ingestion_envelope(
    input_path: str | Path,
    output_path: str | Path,
    *,
    machine_id: str | None = None,
    hostname: str | None = None,
    os_name: str | None = None,
) -> Path:
    """Read OCSF JSONL and write an old-SIEM upload payload JSON file."""

    envelope = translate_ocsf_events_to_siem_ingestion_envelope(
        read_ocsf_jsonl(input_path),
        machine_id=machine_id,
        hostname=hostname,
        os_name=os_name,
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(envelope, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    return path
