from copy import deepcopy
from datetime import datetime, timezone
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.normalization.mapper import (
    map_legacy_common_event,
)


OBSERVED_TIME = datetime(
    2026,
    8,
    26,
    10,
    0,
    tzinfo=timezone.utc,
)

PROCESSED_TIME = datetime(
    2026,
    8,
    26,
    10,
    0,
    1,
    tzinfo=timezone.utc,
)

EVENT_TIME = datetime(
    2026,
    8,
    26,
    9,
    59,
    58,
    tzinfo=timezone.utc,
)


def legacy_event(**overrides):
    fields = {
        "u_id": "UEV-000001",
        "raw_id": "RAW-000001",
        "timestamp": "2026-08-26T09:59:58+00:00",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "category": "network_activity",
        "type": "traffic",
        "subtype": "session_end",
        "outcome": "success",
        "severity": "informational",
        "src_ip": "10.0.0.10",
        "src_port": 51514,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "user": "alice",
        "action": "allow",
        "reason": "session complete",
        "object_type": "network_session",
        "object_name": "123456",
        "details": {
            "application": "dns",
        },
        "vendor_event_id": "0000000013",
        "vendor_fields": {
            "vd": "root",
        },
    }
    fields.update(overrides)
    return fields


def map_event(fields):
    return map_legacy_common_event(
        fields,
        observed_time=OBSERVED_TIME,
        processed_time=PROCESSED_TIME,
    )


def test_complete_legacy_event_maps_to_common_event():
    event = map_event(
        MappingProxyType(legacy_event())
    )

    assert isinstance(event, CommonEvent)
    assert event.mapping_status == "mapped"
    assert event.classification.category == (
        "network_activity"
    )
    assert event.classification.type == "traffic"
    assert event.classification.subtype == "session_end"
    assert event.classification.outcome == "success"
    assert event.classification.severity == (
        "informational"
    )
    assert event.classification.action == "allow"
    assert event.classification.reason == (
        "session complete"
    )

    assert event.timestamps.event_time == EVENT_TIME
    assert event.timestamps.observed_time == OBSERVED_TIME
    assert event.timestamps.processed_time == PROCESSED_TIME

    assert event.vendor.vendor == "Fortinet"
    assert event.vendor.product == "FortiGate"
    assert event.vendor.vendor_event_id == "0000000013"
    assert event.traceability.u_id == "UEV-000001"
    assert event.traceability.raw_id == "RAW-000001"

    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "10.0.0.10"
    assert event.src_endpoint.port == 51514
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "8.8.8.8"
    assert event.dst_endpoint.port == 53
    assert event.network is not None
    assert event.network.protocol == "UDP"
    assert event.actor is not None
    assert event.actor.user == "alice"
    assert event.resource is not None
    assert event.resource.type == "network_session"
    assert event.resource.name == "123456"

    assert event.details == {
        "application": "dns",
    }
    assert event.vendor_fields == {
        "vd": "root",
    }
    assert event.device is None
    assert event.policy is None
    assert event.nat is None


def test_iso_timestamp_with_z_suffix_maps_to_datetime():
    event = map_event(
        legacy_event(
            timestamp="2026-08-26T09:59:58Z"
        )
    )

    assert event.timestamps.event_time == EVENT_TIME


def test_datetime_timestamp_is_preserved():
    event = map_event(
        legacy_event(timestamp=EVENT_TIME)
    )

    assert event.timestamps.event_time is EVENT_TIME


@pytest.mark.parametrize("timestamp", [None, "", "   "])
def test_empty_timestamp_becomes_none(timestamp):
    event = map_event(
        legacy_event(timestamp=timestamp)
    )

    assert event.timestamps.event_time is None


def test_invalid_timestamp_is_preserved_as_unmapped():
    event = map_event(
        legacy_event(timestamp="not-a-timestamp")
    )

    assert event.timestamps.event_time is None
    assert event.details["unmapped_fields"] == {
        "timestamp": "not-a-timestamp",
    }


@pytest.mark.parametrize(
    ("src_ip", "src_port", "expected_ip", "expected_port"),
    [
        ("10.0.0.10", None, "10.0.0.10", None),
        (None, 443, None, 443),
    ],
)
def test_source_endpoint_is_created_from_either_source_field(
    src_ip,
    src_port,
    expected_ip,
    expected_port,
):
    event = map_event(
        legacy_event(
            src_ip=src_ip,
            src_port=src_port,
        )
    )

    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == expected_ip
    assert event.src_endpoint.port == expected_port


@pytest.mark.parametrize(
    ("dst_ip", "dst_port", "expected_ip", "expected_port"),
    [
        ("8.8.8.8", None, "8.8.8.8", None),
        (None, 53, None, 53),
    ],
)
def test_destination_endpoint_is_created_from_either_field(
    dst_ip,
    dst_port,
    expected_ip,
    expected_port,
):
    event = map_event(
        legacy_event(
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
    )

    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == expected_ip
    assert event.dst_endpoint.port == expected_port


def test_empty_endpoint_fields_do_not_create_containers():
    event = map_event(
        legacy_event(
            src_ip=None,
            src_port=None,
            dst_ip="   ",
            dst_port="",
        )
    )

    assert event.src_endpoint is None
    assert event.dst_endpoint is None


def test_numeric_string_ports_become_integers():
    event = map_event(
        legacy_event(
            src_port="51514",
            dst_port=" 53 ",
        )
    )

    assert event.src_endpoint is not None
    assert event.src_endpoint.port == 51514
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.port == 53


def test_invalid_ports_are_preserved_without_guessing():
    event = map_event(
        legacy_event(
            src_ip=None,
            src_port="ephemeral",
            dst_ip=None,
            dst_port=53.5,
        )
    )

    assert event.src_endpoint is None
    assert event.dst_endpoint is None
    assert event.details["unmapped_fields"] == {
        "src_port": "ephemeral",
        "dst_port": 53.5,
    }


def test_protocol_controls_network_container():
    with_protocol = map_event(
        legacy_event(protocol="TCP")
    )
    without_protocol = map_event(
        legacy_event(protocol=None)
    )

    assert with_protocol.network is not None
    assert with_protocol.network.protocol == "TCP"
    assert without_protocol.network is None


def test_user_controls_actor_container():
    with_user = map_event(
        legacy_event(user="alice")
    )
    without_user = map_event(
        legacy_event(user=None)
    )

    assert with_user.actor is not None
    assert with_user.actor.user == "alice"
    assert without_user.actor is None


def test_object_fields_control_resource_container():
    with_type = map_event(
        legacy_event(
            object_type="network_interface",
            object_name=None,
        )
    )
    with_name = map_event(
        legacy_event(
            object_type=None,
            object_name="port1",
        )
    )
    without_object = map_event(
        legacy_event(
            object_type=None,
            object_name=None,
        )
    )

    assert with_type.resource is not None
    assert with_type.resource.type == "network_interface"
    assert with_name.resource is not None
    assert with_name.resource.name == "port1"
    assert without_object.resource is None


def test_details_and_vendor_fields_are_copied():
    details = {
        "application": "dns",
    }
    vendor_fields = {
        "vd": "root",
    }
    fields = legacy_event(
        details=details,
        vendor_fields=vendor_fields,
    )

    event = map_event(fields)

    assert event.details == details
    assert event.details is not details
    assert event.vendor_fields == vendor_fields
    assert event.vendor_fields is not vendor_fields

    event.details["new_detail"] = True
    event.vendor_fields["new_vendor_field"] = True

    assert "new_detail" not in details
    assert "new_vendor_field" not in vendor_fields


@pytest.mark.parametrize(
    "field_name",
    [
        "details",
        "vendor_fields",
    ],
)
def test_non_mapping_extension_container_fails_clearly(
    field_name,
):
    with pytest.raises(
        TypeError,
        match=rf"{field_name} must be a mapping or None",
    ):
        map_event(
            legacy_event(**{field_name: ["invalid"]})
        )


def test_unknown_top_level_field_is_preserved():
    event = map_event(
        legacy_event(custom_vendor_value="preserve-me")
    )

    assert event.details["unmapped_fields"] == {
        "custom_vendor_value": "preserve-me",
    }


def test_existing_unmapped_fields_survive():
    event = map_event(
        legacy_event(
            details={
                "unmapped_fields": {
                    "existing": "keep-me",
                },
            },
            another_unknown="also-keep-me",
        )
    )

    assert event.details["unmapped_fields"] == {
        "existing": "keep-me",
        "another_unknown": "also-keep-me",
    }


def test_unmapped_collision_preserves_both_values():
    event = map_event(
        legacy_event(
            timestamp="invalid-new-timestamp",
            details={
                "unmapped_fields": {
                    "timestamp": "existing-timestamp",
                    "legacy_timestamp": "older-timestamp",
                    "custom": "existing-custom",
                },
            },
            custom="new-custom",
        )
    )

    assert event.details["unmapped_fields"] == {
        "timestamp": "existing-timestamp",
        "legacy_timestamp": "older-timestamp",
        "legacy_timestamp_2": "invalid-new-timestamp",
        "custom": "existing-custom",
        "legacy_custom": "new-custom",
    }


@pytest.mark.parametrize(
    "missing_field",
    [
        "u_id",
        "raw_id",
        "vendor",
        "product",
    ],
)
def test_required_identity_fields_are_not_fabricated(
    missing_field,
):
    fields = legacy_event()
    fields.pop(missing_field)

    with pytest.raises(ValidationError):
        map_event(fields)


def test_input_mapping_is_unchanged_after_mapping():
    fields = legacy_event(
        timestamp="invalid-timestamp",
        src_port="invalid-port",
        details={
            "unmapped_fields": {
                "existing": "value",
            },
        },
        unknown={
            "nested": True,
        },
    )
    before = deepcopy(fields)

    map_event(fields)

    assert fields == before


def test_fortigate_traffic_interfaces_merge_with_endpoint():
    event = map_event(
        legacy_event(
            details={
                "source_interface": "port1",
                "destination_interface": "wan1",
            },
        )
    )

    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "10.0.0.10"
    assert event.src_endpoint.port == 51514
    assert event.src_endpoint.interface == "port1"
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "8.8.8.8"
    assert event.dst_endpoint.port == 53
    assert event.dst_endpoint.interface == "wan1"


def test_cisco_traffic_interfaces_are_promoted():
    event = map_event(
        legacy_event(
            vendor="Cisco",
            product="ASA",
            details={
                "source_interface": "inside",
                "destination_interface": "outside",
            },
        )
    )

    assert event.src_endpoint is not None
    assert event.src_endpoint.interface == "inside"
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.interface == "outside"


def test_panos_traffic_interfaces_and_zones_are_promoted():
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="TRAFFIC",
            type="SESSION",
            details={
                "inbound_interface": "ethernet1/1",
                "outbound_interface": "ethernet1/2",
                "source_zone": "trust",
                "destination_zone": "untrust",
            },
        )
    )

    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "10.0.0.10"
    assert event.src_endpoint.interface == "ethernet1/1"
    assert event.src_endpoint.zone == "trust"
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "8.8.8.8"
    assert event.dst_endpoint.interface == "ethernet1/2"
    assert event.dst_endpoint.zone == "untrust"


@pytest.mark.parametrize(
    (
        "vendor",
        "product",
        "category",
        "event_type",
        "detail_key",
        "value",
        "expected",
    ),
    [
        (
            "Fortinet",
            "FortiGate",
            "network_activity",
            "traffic",
            "session_id",
            12345,
            "12345",
        ),
        (
            "Cisco",
            "ASA",
            "network_activity",
            "traffic",
            "connection_id",
            "67890",
            "67890",
        ),
        (
            "Palo Alto Networks",
            "PAN-OS",
            "TRAFFIC",
            "SESSION",
            "session_id",
            24680,
            "24680",
        ),
    ],
)
def test_traffic_session_identifiers_are_promoted(
    vendor,
    product,
    category,
    event_type,
    detail_key,
    value,
    expected,
):
    event = map_event(
        legacy_event(
            vendor=vendor,
            product=product,
            category=category,
            type=event_type,
            details={detail_key: value},
        )
    )

    assert event.network is not None
    assert event.network.session_id == expected
    assert event.details[detail_key] == value


def test_cisco_traffic_bytes_total_is_promoted():
    event = map_event(
        legacy_event(
            vendor="Cisco",
            product="ASA",
            details={"bytes": "4096"},
        )
    )

    assert event.network is not None
    assert event.network.bytes_total == 4096
    assert event.details["bytes"] == "4096"


def test_panos_traffic_totals_and_duration_are_promoted():
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="TRAFFIC",
            type="SESSION",
            details={
                "bytes_total": "8192",
                "packets_total": 64,
                "elapsed_seconds": "120",
            },
        )
    )

    assert event.network is not None
    assert event.network.bytes_total == 8192
    assert event.network.packets_total == 64
    assert event.network.duration_seconds == 120


def test_invalid_numeric_promotions_remain_only_in_details():
    details = {
        "bytes_total": "12.5",
        "packets_total": "many",
        "elapsed_seconds": 1.5,
        "nat_src_port": "ephemeral",
    }
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="TRAFFIC",
            type="SESSION",
            details=details,
        )
    )

    assert event.network is not None
    assert event.network.bytes_total is None
    assert event.network.packets_total is None
    assert event.network.duration_seconds is None
    assert event.nat is None
    assert event.details == details


def test_fortigate_reporting_device_fields_are_promoted():
    details = {
        "device_id": 101,
        "device_name": "branch-fw",
        "virtual_domain": "root",
    }
    event = map_event(
        legacy_event(
            category="SYSTEM",
            type="DEVICE",
            details=details,
        )
    )

    assert event.device is not None
    assert event.device.id == "101"
    assert event.device.name == "branch-fw"
    assert event.device.virtual_domain == "root"
    assert event.device.hostname is None
    assert event.details == details


def test_panos_reporting_device_fields_are_promoted():
    details = {
        "device_name": "PA-FW-01",
        "serial_number": "PA123456789",
        "virtual_system": "vsys1",
    }
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="ROUTER",
            type="BGP",
            src_ip=None,
            src_port=None,
            dst_ip=None,
            dst_port=None,
            details=details,
        )
    )

    assert event.device is not None
    assert event.device.name == "PA-FW-01"
    assert event.device.serial_number == "PA123456789"
    assert event.device.virtual_system == "vsys1"
    assert event.device.hostname is None


def test_vpn_client_identity_is_not_reporting_device_identity():
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="VPN",
            type="TUNNEL",
            details={
                "machine_name": "client-laptop",
                "endpoint_serial": "CLIENT-123",
                "device_name": "PA-FW-01",
            },
        )
    )

    assert event.device is None
    assert event.src_endpoint is not None
    assert event.src_endpoint.hostname is None


def test_fortigate_traffic_policy_is_promoted_additively():
    details = {
        "policy_id": 10,
        "policy_name": "Internet-Allow",
    }
    event = map_event(legacy_event(details=details))

    assert event.policy is not None
    assert event.policy.id == "10"
    assert event.policy.name == "Internet-Allow"
    assert event.details == details


def test_panos_traffic_policy_is_promoted():
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="TRAFFIC",
            type="POLICY",
            details={
                "policy_id": 20,
                "rule": "Allow-DNS",
                "rule_uuid": "rule-uuid-20",
            },
        )
    )

    assert event.policy is not None
    assert event.policy.id == "20"
    assert event.policy.name == "Allow-DNS"
    assert event.policy.uuid == "rule-uuid-20"


@pytest.mark.parametrize(
    ("product", "event_type"),
    [
        ("ASA", "traffic"),
        ("IOS", "router"),
    ],
)
def test_cisco_nat_source_translation_is_promoted(
    product,
    event_type,
):
    details = {
        "translated_ip": "203.0.113.10",
        "translated_port": "40000",
        "nat_type": "dynamic",
    }
    event = map_event(
        legacy_event(
            vendor="Cisco",
            product=product,
            type=event_type,
            subtype="nat_translation",
            object_type="nat_translation",
            details=details,
        )
    )

    assert event.nat is not None
    assert event.nat.translated_src_ip == "203.0.113.10"
    assert event.nat.translated_src_port == 40000
    assert event.nat.type == (
        "dynamic" if product == "ASA" else None
    )
    assert event.details == details


def test_panos_source_and_destination_nat_are_promoted():
    event = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="TRAFFIC",
            type="SESSION",
            details={
                "nat_src_ip": "203.0.113.10",
                "nat_src_port": "40000",
                "nat_dst_ip": "192.0.2.20",
                "nat_dst_port": 8443,
            },
        )
    )

    assert event.nat is not None
    assert event.nat.translated_src_ip == "203.0.113.10"
    assert event.nat.translated_src_port == 40000
    assert event.nat.translated_dst_ip == "192.0.2.20"
    assert event.nat.translated_dst_port == 8443


def test_fortigate_nat_disposition_is_promoted_without_direction_guess():
    details = {
        "nat_disposition": "snat",
        "translated_ip": "203.0.113.10",
        "translated_port": 40000,
    }
    event = map_event(legacy_event(details=details))

    assert event.nat is not None
    assert event.nat.disposition == "snat"
    assert event.nat.translated_src_ip is None
    assert event.nat.translated_src_port is None
    assert event.nat.translated_dst_ip is None
    assert event.nat.translated_dst_port is None
    assert event.details == details


def test_directional_counters_and_interface_roles_are_not_promoted():
    event = map_event(
        legacy_event(
            details={
                "bytes_sent": 100,
                "bytes_received": 200,
                "packets_sent": 10,
                "packets_received": 20,
                "source_interface_role": "lan",
                "destination_interface_role": "wan",
            },
        )
    )

    assert event.network is not None
    assert event.network.bytes_in is None
    assert event.network.bytes_out is None
    assert event.network.bytes_total is None
    assert event.network.packets_in is None
    assert event.network.packets_out is None
    assert event.network.packets_total is None
    assert event.src_endpoint is not None
    assert event.src_endpoint.zone is None
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.zone is None


def test_routing_peer_flat_endpoint_is_suppressed_and_preserved():
    event = map_event(
        legacy_event(
            vendor="Cisco",
            product="IOS",
            category="network_activity",
            type="router",
            subtype="bgp_neighbor_state",
            src_ip=None,
            src_port=None,
            dst_ip="192.0.2.1",
            dst_port=None,
            object_type="routing_neighbor",
            object_name="192.0.2.1",
            details={"neighbor_ip": "192.0.2.1"},
        )
    )

    assert event.src_endpoint is None
    assert event.dst_endpoint is None
    assert event.details["neighbor_ip"] == "192.0.2.1"
    assert event.details["unmapped_fields"]["dst_ip"] == (
        "192.0.2.1"
    )


def test_ordinary_traffic_destination_endpoint_is_not_suppressed():
    event = map_event(
        legacy_event(
            vendor="Cisco",
            product="ASA",
            category="network_activity",
            type="traffic",
            subtype="session_end",
            object_type="network_session",
        )
    )

    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "8.8.8.8"
    assert event.dst_endpoint.port == 53


def test_deferred_policy_sources_are_not_promoted():
    cisco_acl = map_event(
        legacy_event(
            vendor="Cisco",
            product="ASA",
            object_type="access_control_rule",
            details={"access_group": "outside_access_in"},
        )
    )
    panos_pbf = map_event(
        legacy_event(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            category="ROUTER",
            type="PBF",
            object_type="PBF_RULE",
            details={"pbf_rule": "Internet-Backup"},
        )
    )

    assert cisco_acl.policy is None
    assert panos_pbf.policy is None


def test_empty_promotion_candidates_do_not_create_containers():
    event = map_event(
        legacy_event(
            details={
                "device_id": None,
                "device_name": "   ",
                "policy_id": None,
                "policy_name": "",
                "nat_disposition": None,
                "translated_port": "invalid",
            },
        )
    )

    assert event.device is None
    assert event.policy is None
    assert event.nat is None


def test_promotions_do_not_mutate_input_or_extension_dictionaries():
    details = {
        "source_interface": "port1",
        "session_id": 123,
        "policy_id": 10,
        "policy_name": "Internet-Allow",
        "nat_disposition": "snat",
    }
    vendor_fields = {"vd": "root"}
    fields = legacy_event(
        details=details,
        vendor_fields=vendor_fields,
    )
    before = deepcopy(fields)

    event = map_event(fields)

    assert fields == before
    assert event.details == details
    assert event.vendor_fields == vendor_fields
    assert event.details is not details
    assert event.vendor_fields is not vendor_fields


def test_explicit_incomplete_mapping_status_is_preserved():
    event = map_legacy_common_event(
        legacy_event(),
        observed_time=OBSERVED_TIME,
        processed_time=PROCESSED_TIME,
        mapping_status="incomplete",
    )

    assert event.mapping_status == "incomplete"


def test_invalid_mapping_status_is_rejected():
    with pytest.raises(ValidationError):
        map_legacy_common_event(
            legacy_event(),
            observed_time=OBSERVED_TIME,
            processed_time=PROCESSED_TIME,
            mapping_status="unknown",
        )
