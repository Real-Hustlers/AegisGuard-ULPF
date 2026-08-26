from collections.abc import Mapping
from datetime import datetime
from typing import Any

from aegisguard_ulpf.core.models import (
    Actor,
    CommonEvent,
    Device,
    Endpoint,
    EventClassification,
    EventResource,
    EventTimestamps,
    MappingStatus,
    Nat,
    Network,
    Policy,
    TraceabilityReferences,
    VendorInformation,
)


_KNOWN_LEGACY_FIELDS = frozenset({
    "u_id",
    "raw_id",
    "timestamp",
    "vendor",
    "product",
    "category",
    "type",
    "subtype",
    "outcome",
    "severity",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "user",
    "action",
    "reason",
    "object_type",
    "object_name",
    "details",
    "vendor_event_id",
    "vendor_fields",
})

_ROUTING_OBJECT_TYPES = frozenset({
    "bfd_session",
    "network_prefix",
    "pbf_rule",
    "route",
    "route_table",
    "routing_daemon",
    "routing_neighbor",
    "routing_peer",
    "routing_protocol",
    "virtual_router",
})

_ROUTING_SUBTYPES = frozenset({
    "bgp_neighbor_state",
    "bgp_route_update",
    "eigrp_neighbor_state",
    "isis_adjacency_state",
    "ospf_adjacency_change",
    "ospf_neighbor_state",
    "ospf_route_update",
    "routing_table_change",
})


def _copy_optional_mapping(
    value: Any,
    *,
    field_name: str,
) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise TypeError(
            f"{field_name} must be a mapping or None"
        )

    return dict(value)


def _has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    return True


def _normalized_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    return value.casefold() if value else None


def _text_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _identifier_value(value: Any) -> str | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return str(value)

    return _text_value(value)


def _convert_integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        try:
            return int(value)
        except ValueError:
            return None

    return None


def _is_vendor_product(
    fields: Mapping[str, Any],
    *,
    vendor: str,
    product: str,
) -> bool:
    return (
        _normalized_text(fields.get("vendor"))
        == vendor.casefold()
        and _normalized_text(fields.get("product"))
        == product.casefold()
    )


def _is_traffic_event(
    fields: Mapping[str, Any],
) -> bool:
    return (
        _normalized_text(fields.get("category"))
        == "traffic"
        or _normalized_text(fields.get("type"))
        == "traffic"
    )


def _is_routing_semantic_event(
    fields: Mapping[str, Any],
) -> bool:
    category = _normalized_text(
        fields.get("category")
    )
    event_type = _normalized_text(fields.get("type"))
    subtype = _normalized_text(fields.get("subtype"))
    object_type = _normalized_text(
        fields.get("object_type")
    )

    return (
        category == "router"
        or event_type == "routing"
        or subtype in _ROUTING_SUBTYPES
        or object_type in _ROUTING_OBJECT_TYPES
    )


def _collision_safe_key(
    values: Mapping[str, Any],
    key: str,
) -> str:
    if key not in values:
        return key

    candidate = f"legacy_{key}"

    if candidate not in values:
        return candidate

    suffix = 2

    while f"{candidate}_{suffix}" in values:
        suffix += 1

    return f"{candidate}_{suffix}"


def _get_unmapped_fields(
    details: dict[str, Any],
) -> dict[str, Any]:
    existing = details.get("unmapped_fields")

    if existing is None:
        unmapped_fields: dict[str, Any] = {}
    elif isinstance(existing, Mapping):
        unmapped_fields = dict(existing)
    else:
        unmapped_fields = {
            "legacy_unmapped_fields": existing,
        }

    details["unmapped_fields"] = unmapped_fields

    return unmapped_fields


def _preserve_unmapped(
    details: dict[str, Any],
    key: str,
    value: Any,
) -> None:
    unmapped_fields = _get_unmapped_fields(details)
    preserved_key = _collision_safe_key(
        unmapped_fields,
        key,
    )
    unmapped_fields[preserved_key] = value


def _convert_timestamp(
    value: Any,
    details: dict[str, Any],
) -> datetime | None:
    if isinstance(value, datetime):
        return value

    if value is None:
        return None

    if isinstance(value, str):
        timestamp = value.strip()

        if not timestamp:
            return None

        if timestamp.endswith("Z"):
            timestamp = f"{timestamp[:-1]}+00:00"

        try:
            return datetime.fromisoformat(timestamp)
        except ValueError:
            pass

    _preserve_unmapped(
        details,
        "timestamp",
        value,
    )

    return None


def _convert_port(
    value: Any,
    *,
    field_name: str,
    details: dict[str, Any],
) -> int | None:
    converted = _convert_integer(value)

    if converted is not None:
        return converted

    if value is None or (
        isinstance(value, str)
        and not value.strip()
    ):
        return None

    _preserve_unmapped(
        details,
        field_name,
        value,
    )

    return None


def map_legacy_common_event(
    fields: Mapping[str, Any],
    *,
    observed_time: datetime,
    processed_time: datetime,
    mapping_status: MappingStatus = "mapped",
) -> CommonEvent:
    details = _copy_optional_mapping(
        fields.get("details"),
        field_name="details",
    )

    vendor_fields = _copy_optional_mapping(
        fields.get("vendor_fields"),
        field_name="vendor_fields",
    )

    event_time = _convert_timestamp(
        fields.get("timestamp"),
        details,
    )

    is_traffic = _is_traffic_event(fields)
    is_routing = _is_routing_semantic_event(fields)
    is_fortigate = _is_vendor_product(
        fields,
        vendor="Fortinet",
        product="FortiGate",
    )
    is_cisco_asa = _is_vendor_product(
        fields,
        vendor="Cisco",
        product="ASA",
    )
    is_cisco_ios = _is_vendor_product(
        fields,
        vendor="Cisco",
        product="IOS",
    )
    is_panos = _is_vendor_product(
        fields,
        vendor="Palo Alto Networks",
        product="PAN-OS",
    )

    src_ip = None
    src_port = None
    dst_ip = None
    dst_port = None

    if is_routing:
        for endpoint_key in (
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
        ):
            endpoint_value = fields.get(endpoint_key)

            if _has_meaningful_value(endpoint_value):
                _preserve_unmapped(
                    details,
                    endpoint_key,
                    endpoint_value,
                )
    else:
        src_ip = fields.get("src_ip")
        src_port = _convert_port(
            fields.get("src_port"),
            field_name="src_port",
            details=details,
        )
        dst_ip = fields.get("dst_ip")
        dst_port = _convert_port(
            fields.get("dst_port"),
            field_name="dst_port",
            details=details,
        )

        if not _has_meaningful_value(src_ip):
            src_ip = None

        if not _has_meaningful_value(dst_ip):
            dst_ip = None

    src_interface = None
    dst_interface = None
    src_zone = None
    dst_zone = None

    if is_traffic:
        if is_fortigate or is_cisco_asa:
            src_interface = _text_value(
                details.get("source_interface")
            )
            dst_interface = _text_value(
                details.get("destination_interface")
            )
        elif is_panos:
            src_interface = _text_value(
                details.get("inbound_interface")
            )
            dst_interface = _text_value(
                details.get("outbound_interface")
            )
            src_zone = _text_value(
                details.get("source_zone")
            )
            dst_zone = _text_value(
                details.get("destination_zone")
            )

    src_endpoint = None

    if any((
        src_ip is not None,
        src_port is not None,
        src_interface is not None,
        src_zone is not None,
    )):
        src_endpoint = Endpoint(
            ip=src_ip,
            port=src_port,
            interface=src_interface,
            zone=src_zone,
        )

    dst_endpoint = None

    if any((
        dst_ip is not None,
        dst_port is not None,
        dst_interface is not None,
        dst_zone is not None,
    )):
        dst_endpoint = Endpoint(
            ip=dst_ip,
            port=dst_port,
            interface=dst_interface,
            zone=dst_zone,
        )

    protocol = fields.get("protocol")

    if not _has_meaningful_value(protocol):
        protocol = None

    session_id = None
    bytes_total = None
    packets_total = None
    duration_seconds = None

    if is_traffic:
        if is_fortigate:
            session_id = _identifier_value(
                details.get("session_id")
            )
        elif is_cisco_asa:
            session_id = _identifier_value(
                details.get("connection_id")
            )
            bytes_total = _convert_integer(
                details.get("bytes")
            )
        elif is_panos:
            session_id = _identifier_value(
                details.get("session_id")
            )
            bytes_total = _convert_integer(
                details.get("bytes_total")
            )
            packets_total = _convert_integer(
                details.get("packets_total")
            )
            duration_seconds = _convert_integer(
                details.get("elapsed_seconds")
            )

    network = None

    if any((
        protocol is not None,
        session_id is not None,
        bytes_total is not None,
        packets_total is not None,
        duration_seconds is not None,
    )):
        network = Network(
            protocol=protocol,
            bytes_total=bytes_total,
            packets_total=packets_total,
            session_id=session_id,
            duration_seconds=duration_seconds,
        )

    user = fields.get("user")

    if not _has_meaningful_value(user):
        user = None

    actor = (
        Actor(user=user)
        if user is not None
        else None
    )

    object_type = fields.get("object_type")
    object_name = fields.get("object_name")

    if not _has_meaningful_value(object_type):
        object_type = None

    if not _has_meaningful_value(object_name):
        object_name = None

    resource = None

    if object_type is not None or object_name is not None:
        resource = EventResource(
            type=object_type,
            name=object_name,
        )

    device_id = None
    device_name = None
    serial_number = None
    virtual_domain = None
    virtual_system = None

    category = _normalized_text(fields.get("category"))
    event_type = _normalized_text(fields.get("type"))

    if is_fortigate:
        if is_traffic:
            virtual_domain = _text_value(
                details.get("virtual_domain")
            )
        elif category == "system" and event_type == "device":
            device_id = _identifier_value(
                details.get("device_id")
            )
            device_name = _text_value(
                details.get("device_name")
            )
            virtual_domain = _text_value(
                details.get("virtual_domain")
            )
    elif is_panos and category in {
        "traffic",
        "router",
        "system",
    }:
        device_name = _text_value(
            details.get("device_name")
        )
        serial_number = _text_value(
            details.get("serial_number")
        )
        virtual_system = _text_value(
            details.get("virtual_system")
        )

    device = None

    if any((
        device_id is not None,
        device_name is not None,
        serial_number is not None,
        virtual_domain is not None,
        virtual_system is not None,
    )):
        device = Device(
            id=device_id,
            name=device_name,
            serial_number=serial_number,
            virtual_domain=virtual_domain,
            virtual_system=virtual_system,
        )

    policy_id = None
    policy_name = None
    policy_uuid = None

    if is_traffic and is_fortigate:
        policy_id = _identifier_value(
            details.get("policy_id")
        )
        policy_name = _text_value(
            details.get("policy_name")
        )
    elif is_traffic and is_panos:
        policy_id = _identifier_value(
            details.get("policy_id")
        )
        policy_name = _text_value(
            details.get("rule")
        )
        policy_uuid = _text_value(
            details.get("rule_uuid")
        )

    policy = None

    if any((
        policy_id is not None,
        policy_name is not None,
        policy_uuid is not None,
    )):
        policy = Policy(
            id=policy_id,
            name=policy_name,
            uuid=policy_uuid,
        )

    translated_src_ip = None
    translated_src_port = None
    translated_dst_ip = None
    translated_dst_port = None
    nat_type = None
    nat_disposition = None

    is_cisco_nat = (
        (is_cisco_asa or is_cisco_ios)
        and _normalized_text(fields.get("subtype"))
        == "nat_translation"
        and _normalized_text(fields.get("object_type"))
        == "nat_translation"
    )

    if is_cisco_nat:
        translated_src_ip = _text_value(
            details.get("translated_ip")
        )
        translated_src_port = _convert_integer(
            details.get("translated_port")
        )

        if is_cisco_asa and is_traffic:
            nat_type = _text_value(
                details.get("nat_type")
            )
    elif is_traffic and is_panos:
        translated_src_ip = _text_value(
            details.get("nat_src_ip")
        )
        translated_src_port = _convert_integer(
            details.get("nat_src_port")
        )
        translated_dst_ip = _text_value(
            details.get("nat_dst_ip")
        )
        translated_dst_port = _convert_integer(
            details.get("nat_dst_port")
        )
    elif is_traffic and is_fortigate:
        nat_disposition = _text_value(
            details.get("nat_disposition")
        )

    nat = None

    if any((
        translated_src_ip is not None,
        translated_src_port is not None,
        translated_dst_ip is not None,
        translated_dst_port is not None,
        nat_type is not None,
        nat_disposition is not None,
    )):
        nat = Nat(
            translated_src_ip=translated_src_ip,
            translated_src_port=translated_src_port,
            translated_dst_ip=translated_dst_ip,
            translated_dst_port=translated_dst_port,
            type=nat_type,
            disposition=nat_disposition,
        )

    for key, value in fields.items():
        if key not in _KNOWN_LEGACY_FIELDS:
            _preserve_unmapped(
                details,
                key,
                value,
            )

    return CommonEvent(
        mapping_status=mapping_status,
        classification=EventClassification(
            category=fields.get("category"),
            type=fields.get("type"),
            subtype=fields.get("subtype"),
            outcome=fields.get("outcome"),
            severity=fields.get("severity"),
            action=fields.get("action"),
            reason=fields.get("reason"),
        ),
        timestamps=EventTimestamps(
            event_time=event_time,
            observed_time=observed_time,
            processed_time=processed_time,
        ),
        vendor=VendorInformation(
            vendor=fields.get("vendor"),
            product=fields.get("product"),
            vendor_event_id=fields.get(
                "vendor_event_id"
            ),
        ),
        traceability=TraceabilityReferences(
            u_id=fields.get("u_id"),
            raw_id=fields.get("raw_id"),
        ),
        device=device,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        network=network,
        actor=actor,
        policy=policy,
        nat=nat,
        resource=resource,
        details=details,
        vendor_fields=vendor_fields,
    )
