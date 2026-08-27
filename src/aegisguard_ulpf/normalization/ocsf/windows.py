"""Windows Security Event Log mappings for pinned OCSF 1.9.0."""

from __future__ import annotations

import copy

from datetime import datetime, timezone
from pathlib import PureWindowsPath
from collections.abc import Mapping
from typing import Any

from aegisguard_ulpf.core.models import (
    Actor,
    CommonEvent,
    Device,
    Endpoint,
    EventClassification,
    EventResource,
    EventTimestamps,
    TraceabilityReferences,
    VendorInformation,
)
from aegisguard_ulpf.ingestion.windows import adapt_windows_security_event
from aegisguard_ulpf.normalization.ocsf.base_event import build_base_event
from aegisguard_ulpf.normalization.ocsf.registry import (
    AUTHENTICATION_CATEGORY_UID,
    AUTHENTICATION_CLASS_UID,
    PROCESS_ACTIVITY_CATEGORY_UID,
    PROCESS_ACTIVITY_CLASS_UID,
    AuthenticationActivityID,
    ProcessActivityID,
    SeverityID,
    StatusID,
)
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator


WINDOWS_AUTHENTICATION_EVENT_IDS = frozenset({4624, 4625})
WINDOWS_PROCESS_CREATION_EVENT_ID = 4688

_TIME_FIELDS = (
    "TimeCreated",
    "TimeCreatedUtc",
    "SystemTime",
)
_USER_FIELDS = (
    "TargetUserName",
    "User",
    "SubjectUserName",
)
_SOURCE_IP_FIELDS = (
    "IpAddress",
    "SourceIP",
    "IP",
)
_HOST_FIELDS = (
    "Computer",
    "WorkstationName",
)


def map_windows_security_event_to_common_event(
    event: Mapping[str, Any] | str,
    *,
    observed_time: datetime | None = None,
    processed_time: datetime | None = None,
) -> CommonEvent:
    """Adapt one Windows event and map it to the ULPF CommonEvent contract."""

    raw_event = adapt_windows_security_event(event)
    return map_windows_security_raw_event_to_common_event(
        raw_event,
        observed_time=observed_time,
        processed_time=processed_time,
    )


def map_windows_security_raw_event_to_common_event(
    raw_event,
    *,
    observed_time: datetime | None = None,
    processed_time: datetime | None = None,
) -> CommonEvent:
    """Map an adapted Windows ``RawEvent`` to a ULPF CommonEvent."""

    event = _structured_windows_event(raw_event)
    event_id = _windows_event_id(event)
    observed = observed_time or datetime.now(timezone.utc)
    processed = processed_time or observed
    event_time = _event_time(event, observed)
    user = _first_text(event, _USER_FIELDS)
    source_ip = _first_text(event, _SOURCE_IP_FIELDS)
    hostname = _first_text(event, _HOST_FIELDS)

    common_fields: dict[str, Any] = {
        "mapping_status": "incomplete" if _unmapped_fields(event, event_id) else "mapped",
        "classification": _classification(event_id),
        "timestamps": EventTimestamps(
            event_time=event_time,
            observed_time=observed,
            processed_time=processed,
        ),
        "vendor": VendorInformation(
            vendor="Microsoft",
            product="Windows Security",
            vendor_event_id=str(event_id),
        ),
        "traceability": TraceabilityReferences(
            u_id=str(raw_event.event_id),
            raw_id=raw_event.raw_id,
        ),
        "details": _common_details(event, event_id),
        "vendor_fields": copy.deepcopy(event),
    }

    if user is not None:
        common_fields["actor"] = Actor(user=user)
    if source_ip is not None:
        common_fields["src_endpoint"] = Endpoint(ip=source_ip)
    if hostname is not None:
        common_fields["device"] = Device(hostname=hostname)

    if event_id == WINDOWS_PROCESS_CREATION_EVENT_ID:
        process_name = _process_name(event)
        common_fields["resource"] = EventResource(
            type="process",
            name=process_name,
        )

    return CommonEvent(**common_fields)


def map_windows_security_event_to_ocsf(
    event: Mapping[str, Any] | str,
    *,
    observed_time: datetime | None = None,
    processed_time: datetime | None = None,
) -> dict[str, Any]:
    """Map one supported Windows Security event through CommonEvent to OCSF."""

    raw_event = adapt_windows_security_event(event)
    common_event = map_windows_security_raw_event_to_common_event(
        raw_event,
        observed_time=observed_time,
        processed_time=processed_time,
    )
    return map_windows_security_raw_event_to_ocsf(raw_event, common_event)


def map_windows_security_raw_event_to_ocsf(
    raw_event,
    common_event: CommonEvent | None = None,
) -> dict[str, Any]:
    """Map an adapted Windows event and its CommonEvent representation to OCSF."""

    event = _structured_windows_event(raw_event)
    event_id = _windows_event_id(event)
    common = common_event or map_windows_security_raw_event_to_common_event(raw_event)

    if event_id in WINDOWS_AUTHENTICATION_EVENT_IDS:
        ocsf_event = _authentication_ocsf_event(event, common, event_id)
    elif event_id == WINDOWS_PROCESS_CREATION_EVENT_ID:
        ocsf_event = _process_ocsf_event(event, common)
    else:
        raise ValueError(f"Unsupported Windows Security EventID: {event_id}")

    ocsf_event["raw_data"] = raw_event.raw
    ocsf_event["observables"] = _observables(common)
    ocsf_event["unmapped"] = {
        "windows_security": _unmapped_fields(event, event_id),
    }

    validation = OCSFValidator().validate(ocsf_event)
    if not validation.valid:
        raise ValueError(
            "Generated Windows OCSF event failed validation: "
            + "; ".join(validation.errors)
        )

    return ocsf_event


def _structured_windows_event(raw_event) -> dict[str, Any]:
    event = raw_event.metadata.get("raw_event")
    if not isinstance(event, dict):
        raise ValueError("RawEvent does not contain Windows event metadata")
    return copy.deepcopy(event)


def _windows_event_id(event: dict[str, Any]) -> int:
    value = event.get("EventID")
    if isinstance(value, bool):
        raise ValueError("Windows Security EventID must be an integer")
    try:
        event_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Windows Security EventID must be an integer") from exc

    if event_id not in {
        *WINDOWS_AUTHENTICATION_EVENT_IDS,
        WINDOWS_PROCESS_CREATION_EVENT_ID,
    }:
        raise ValueError(f"Unsupported Windows Security EventID: {event_id}")
    return event_id


def _event_time(event: dict[str, Any], fallback: datetime) -> datetime:
    value = _first_text(event, _TIME_FIELDS)
    if value is None:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Windows event timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_text(event: dict[str, Any], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = event.get(name)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned and cleaned != "-":
                return cleaned
    return None


def _process_name(event: dict[str, Any]) -> str:
    value = _first_text(event, ("NewProcessName", "ProcessName"))
    if value is None:
        raise ValueError("Windows Event ID 4688 requires NewProcessName or ProcessName")
    return PureWindowsPath(value).name or value


def _integer_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _classification(event_id: int) -> EventClassification:
    if event_id == 4624:
        return EventClassification(
            category="authentication",
            type="LOGON",
            outcome="SUCCESS",
            severity="INFORMATIONAL",
        )
    if event_id == 4625:
        return EventClassification(
            category="authentication",
            type="LOGON",
            outcome="FAILURE",
            severity="LOW",
        )
    return EventClassification(
        category="system_activity",
        type="PROCESS_LAUNCH",
        outcome="SUCCESS",
        severity="INFORMATIONAL",
    )


def _common_details(event: dict[str, Any], event_id: int) -> dict[str, Any]:
    details: dict[str, Any] = {"windows_event_id": event_id}
    for source, target in (
        ("LogonType", "logon_type"),
        ("WorkstationName", "workstation_name"),
        ("CommandLine", "command_line"),
        ("ParentProcessName", "parent_process_name"),
    ):
        value = event.get(source)
        if value is not None:
            details[target] = copy.deepcopy(value)
    return details


def _unmapped_fields(event: dict[str, Any], event_id: int) -> dict[str, Any]:
    mapped = {
        "EventID",
        *_TIME_FIELDS,
        *_USER_FIELDS,
        *_SOURCE_IP_FIELDS,
        *_HOST_FIELDS,
        "LogonType",
        "CommandLine",
        "ParentProcessName",
    }
    if event_id == WINDOWS_PROCESS_CREATION_EVENT_ID:
        mapped.update({"NewProcessName", "ProcessName", "NewProcessId"})

    return {
        key: copy.deepcopy(value)
        for key, value in event.items()
        if key not in mapped
    }


def _authentication_ocsf_event(
    event: dict[str, Any],
    common: CommonEvent,
    event_id: int,
) -> dict[str, Any]:
    user = common.actor.user if common.actor is not None else None
    if user is None:
        raise ValueError(f"Windows Event ID {event_id} requires a user identity")

    ocsf_event = build_base_event(
        class_uid=AUTHENTICATION_CLASS_UID,
        category_uid=AUTHENTICATION_CATEGORY_UID,
        activity_id=AuthenticationActivityID.LOGON,
        time=_event_time_millis(common),
        severity_id=(
            SeverityID.INFORMATIONAL
            if event_id == 4624
            else SeverityID.LOW
        ),
        product_vendor="Microsoft",
        product_name="Windows Security",
    )
    ocsf_event["status_id"] = (
        StatusID.SUCCESS if event_id == 4624 else StatusID.FAILURE
    )
    ocsf_event["user"] = {"name": user}
    ocsf_event["service"] = {"name": "Windows Security"}

    if common.src_endpoint is not None and common.src_endpoint.ip is not None:
        ocsf_event["src_endpoint"] = {"ip": common.src_endpoint.ip}
    if common.device is not None and common.device.hostname is not None:
        ocsf_event["device"] = {"hostname": common.device.hostname}
    if "LogonType" in event:
        ocsf_event["logon_type"] = str(event["LogonType"])
    return ocsf_event


def _process_ocsf_event(
    event: dict[str, Any],
    common: CommonEvent,
) -> dict[str, Any]:
    process_name = _process_name(event)
    ocsf_event = build_base_event(
        class_uid=PROCESS_ACTIVITY_CLASS_UID,
        category_uid=PROCESS_ACTIVITY_CATEGORY_UID,
        activity_id=ProcessActivityID.LAUNCH,
        time=_event_time_millis(common),
        severity_id=SeverityID.INFORMATIONAL,
        product_vendor="Microsoft",
        product_name="Windows Security",
    )
    ocsf_event["status_id"] = StatusID.SUCCESS
    ocsf_event["process"] = {"name": process_name}

    pid = _integer_or_none(event.get("NewProcessId"))
    if pid is not None:
        ocsf_event["process"]["pid"] = pid
    command_line = _first_text(event, ("CommandLine",))
    if command_line is not None:
        ocsf_event["process"]["cmd_line"] = command_line
    if common.actor is not None and common.actor.user is not None:
        ocsf_event["actor"] = {"user": {"name": common.actor.user}}
    if common.device is not None and common.device.hostname is not None:
        ocsf_event["device"] = {"hostname": common.device.hostname}
    return ocsf_event


def _event_time_millis(event: CommonEvent) -> int:
    event_time = event.timestamps.event_time
    if event_time is None:
        raise ValueError("Windows OCSF mapping requires an event timestamp")
    return int(event_time.timestamp() * 1_000)


def _observables(event: CommonEvent) -> list[dict[str, Any]]:
    if event.src_endpoint is None or event.src_endpoint.ip is None:
        return []
    return [
        {
            "name": "src_endpoint.ip",
            "type_id": 2,
            "value": event.src_endpoint.ip,
        },
    ]
