"""Adapt ULPF OCSF JSONL output to the old AegisGuard SIEM file contract."""

from __future__ import annotations

import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SIEM_MERGED_LOGS_FILENAME = "merged_logs.json"


OCSF_SEVERITY_TO_SIEM = {
    0: "unknown",
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "fatal",
    99: "other",
}


def read_ocsf_jsonl(
    input_path: str | Path,
) -> list[dict[str, Any]]:
    """Load JSON objects from a ULPF OCSF JSONL file."""

    path = Path(input_path)
    events: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            payload = line.strip()
            if not payload:
                continue

            try:
                event = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid OCSF JSONL record at line {line_number}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"OCSF JSONL record at line {line_number} must be an object"
                )

            events.append(event)

    return events


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _timestamp_from_millis(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None

    return (
        datetime.fromtimestamp(value / 1_000, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _actor_user(actor: dict[str, Any]) -> str | None:
    user = actor.get("user")
    if isinstance(user, dict):
        return _string_or_none(user.get("name"))
    return _string_or_none(user)


def _ocsf_user(
    ocsf_event: dict[str, Any],
    actor: dict[str, Any],
) -> str | None:
    """Return the user identity for both OCSF IAM and actor-based events."""

    user = _mapping(ocsf_event.get("user"))
    user_name = _string_or_none(user.get("name"))
    return user_name if user_name is not None else _actor_user(actor)


def map_ocsf_event_to_siem(
    ocsf_event: dict[str, Any],
) -> dict[str, Any]:
    """Map one OCSF event to the old AegisGuard SIEM event envelope."""

    if not isinstance(ocsf_event, dict):
        raise TypeError("OCSF event must be a dictionary")

    metadata = _mapping(ocsf_event.get("metadata"))
    product = _mapping(metadata.get("product"))
    raw_data = _mapping(ocsf_event.get("raw_data"))
    src_endpoint = _mapping(ocsf_event.get("src_endpoint"))
    dst_endpoint = _mapping(ocsf_event.get("dst_endpoint"))
    actor = _mapping(ocsf_event.get("actor"))
    device = _mapping(ocsf_event.get("device"))

    hostname = _string_or_none(device.get("hostname"))
    if hostname is None:
        hostname = _string_or_none(device.get("name"))

    severity_id = ocsf_event.get("severity_id")
    severity = (
        OCSF_SEVERITY_TO_SIEM.get(severity_id, "unknown")
        if isinstance(severity_id, int) and not isinstance(severity_id, bool)
        else "unknown"
    )

    return {
        "timestamp": _timestamp_from_millis(ocsf_event.get("time")),
        "severity": severity,
        "vendor": _string_or_none(product.get("vendor_name")),
        "product": _string_or_none(product.get("name")),
        "event_id": _string_or_none(raw_data.get("u_id")),
        "source_ip": _string_or_none(src_endpoint.get("ip")),
        "destination_ip": _string_or_none(dst_endpoint.get("ip")),
        "user": _ocsf_user(ocsf_event, actor),
        "hostname": hostname,
        "raw_id": _string_or_none(raw_data.get("raw_id")),
        "ulpf_original_event": ocsf_event,
    }


def write_merged_logs(
    events: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Write adapter output as the SIEM-compatible JSON array format."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            events,
            handle,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        handle.write("\n")

    return path


def adapt_ocsf_jsonl_to_siem(
    input_path: str | Path,
    output_path: str | Path | None = None,
) -> Path:
    """Convert an OCSF JSONL file into a SIEM ``merged_logs.json`` array."""

    source_path = Path(input_path)
    target_path = (
        Path(output_path)
        if output_path is not None
        else source_path.with_name(SIEM_MERGED_LOGS_FILENAME)
    )

    siem_events = [
        map_ocsf_event_to_siem(event)
        for event in read_ocsf_jsonl(source_path)
    ]

    return write_merged_logs(siem_events, target_path)
