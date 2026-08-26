"""Declarative CommonEvent to pinned OCSF binding."""

from datetime import datetime, timezone

from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.normalization.ocsf.base_event import build_base_event
from aegisguard_ulpf.normalization.ocsf.registry import VERIFIED_CLASSES
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator
from aegisguard_ulpf.parsing.semantic_packs.models import OcsfBinding


def _event_time_millis(event_time: datetime | None) -> int:
    if event_time is None:
        raise ValueError(
            "OCSF binding requires CommonEvent.timestamps.event_time"
        )

    if event_time.tzinfo is None or event_time.utcoffset() is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    utc_time = event_time.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc_time - epoch
    return (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )


def _mapped_id(
    mapping: dict[str, int],
    semantic_value: str,
    *,
    name: str,
) -> int:
    try:
        return mapping[semantic_value]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported CommonEvent {name} for OCSF binding: "
            f"{semantic_value!r}"
        ) from exc


def _endpoint_payload(endpoint) -> dict | None:
    if endpoint is None or endpoint.ip is None:
        return None
    return {"ip": endpoint.ip}


def map_common_event_to_ocsf(
    event: CommonEvent,
    binding: OcsfBinding,
) -> dict | None:
    """Map one CommonEvent through a validated Semantic Pack binding.

    Deferred bindings deliberately return no OCSF event. Bound bindings only
    use semantic values explicitly configured by the pack.
    """

    if binding.status == "deferred":
        return None

    class_uid = binding.class_uid
    if class_uid is None:
        raise ValueError("Bound OCSF binding requires class_uid")

    event_type = event.classification.type
    if event_type is None:
        raise ValueError("OCSF binding requires CommonEvent.classification.type")

    activity_id = _mapped_id(
        binding.activity_mappings,
        event_type,
        name="classification.type",
    )

    severity = event.classification.severity
    severity_id = (
        binding.default_severity_id
        if severity is None
        else _mapped_id(
            binding.severity_mappings,
            severity,
            name="classification.severity",
        )
    )

    ocsf_event = build_base_event(
        class_uid=class_uid,
        category_uid=VERIFIED_CLASSES[class_uid]["category_uid"],
        activity_id=activity_id,
        time=_event_time_millis(event.timestamps.event_time),
        severity_id=severity_id,
        product_vendor=event.vendor.vendor,
        product_name=event.vendor.product,
        activity_name=(
            event_type
            if activity_id == 99
            else None
        ),
    )

    outcome = event.classification.outcome
    if outcome is not None:
        ocsf_event["status_id"] = _mapped_id(
            binding.status_mappings,
            outcome,
            name="classification.outcome",
        )

    src_endpoint = _endpoint_payload(event.src_endpoint)
    if src_endpoint is not None:
        ocsf_event["src_endpoint"] = src_endpoint

    dst_endpoint = _endpoint_payload(event.dst_endpoint)
    if dst_endpoint is not None:
        ocsf_event["dst_endpoint"] = dst_endpoint

    if event.network is not None and event.network.protocol is not None:
        ocsf_event["network"] = {"protocol": event.network.protocol}

    ocsf_event["raw_data"] = {
        "u_id": event.traceability.u_id,
        "raw_id": event.traceability.raw_id,
    }

    validation = OCSFValidator().validate(ocsf_event)
    if not validation.valid:
        raise ValueError(
            "Generated OCSF event failed validation: "
            + "; ".join(validation.errors)
        )

    return ocsf_event
