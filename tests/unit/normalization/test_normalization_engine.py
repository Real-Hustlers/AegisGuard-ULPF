from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.normalization.engine import (
    NormalizationEngine,
)


OBSERVED_TIME = datetime(
    2026,
    8,
    26,
    10,
    0,
    tzinfo=timezone.utc,
)
PROCESSED_TIME = OBSERVED_TIME + timedelta(seconds=1)


def legacy_fields(**overrides):
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
        "reason": None,
        "object_type": "network_session",
        "object_name": "123456",
        "details": {
            "source_interface": "port1",
            "session_id": 123456,
        },
        "vendor_event_id": "0000000013",
        "vendor_fields": {
            "vd": "root",
        },
    }
    fields.update(overrides)
    return fields


def normalize(fields, **overrides):
    return NormalizationEngine().normalize(
        fields,
        observed_time=OBSERVED_TIME,
        processed_time=PROCESSED_TIME,
        **overrides,
    )


def test_engine_returns_mapped_common_event():
    event = normalize(legacy_fields())

    assert isinstance(event, CommonEvent)
    assert event.mapping_status == "mapped"
    assert event.classification.type == "traffic"
    assert event.vendor.vendor == "Fortinet"
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "10.0.0.10"
    assert event.src_endpoint.interface == "port1"
    assert event.network is not None
    assert event.network.protocol == "UDP"
    assert event.network.session_id == "123456"


def test_explicit_engine_timestamps_are_preserved():
    event = normalize(legacy_fields())

    assert event.timestamps.observed_time is OBSERVED_TIME
    assert event.timestamps.processed_time is PROCESSED_TIME


def test_engine_generates_aware_utc_processed_time():
    before = datetime.now(timezone.utc)
    event = NormalizationEngine().normalize(
        legacy_fields(),
        observed_time=before,
    )
    after = datetime.now(timezone.utc)

    generated = event.timestamps.processed_time
    assert generated.tzinfo is not None
    assert generated.utcoffset() == timedelta(0)
    assert before <= generated <= after


def test_explicit_incomplete_mapping_status_survives_engine():
    event = normalize(
        legacy_fields(),
        mapping_status="incomplete",
    )

    assert event.mapping_status == "incomplete"


def test_engine_rejects_invalid_semantic_input():
    with pytest.raises(ValueError, match="src_endpoint.port"):
        normalize(legacy_fields(src_port=-1))


def test_mapper_preservation_survives_engine():
    event = normalize(
        legacy_fields(custom_top_level="preserve-me")
    )

    assert event.details["unmapped_fields"] == {
        "custom_top_level": "preserve-me",
    }
    assert event.vendor_fields == {"vd": "root"}


def test_engine_does_not_mutate_input_mapping():
    fields = legacy_fields(
        custom_top_level={"nested": True}
    )
    before = deepcopy(fields)

    normalize(fields)

    assert fields == before


@pytest.mark.parametrize(
    "missing_field",
    [
        "u_id",
        "raw_id",
        "vendor",
        "product",
    ],
)
def test_engine_does_not_generate_required_identity(
    missing_field,
):
    fields = legacy_fields()
    fields.pop(missing_field)

    with pytest.raises(ValidationError):
        normalize(fields)


def test_routing_peer_guard_applies_through_engine():
    event = normalize(
        legacy_fields(
            vendor="Cisco",
            product="IOS",
            type="router",
            subtype="bgp_neighbor_state",
            src_ip=None,
            src_port=None,
            dst_ip="192.0.2.1",
            dst_port=None,
            protocol="BGP",
            object_type="routing_neighbor",
            object_name="192.0.2.1",
            details={"neighbor_ip": "192.0.2.1"},
        )
    )

    assert event.src_endpoint is None
    assert event.dst_endpoint is None
    assert event.details["unmapped_fields"]["dst_ip"] == (
        "192.0.2.1"
    )
