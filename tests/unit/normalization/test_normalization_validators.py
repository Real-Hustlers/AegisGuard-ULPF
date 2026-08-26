from datetime import datetime, timedelta, timezone

import pytest

from aegisguard_ulpf.core.models import (
    CommonEvent,
    Endpoint,
    EventClassification,
    EventTimestamps,
    Nat,
    Network,
    TraceabilityReferences,
    VendorInformation,
)
from aegisguard_ulpf.normalization.validators import (
    validate_common_event,
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


def make_event(
    *,
    mapping_status="mapped",
    observed_time=OBSERVED_TIME,
    processed_time=PROCESSED_TIME,
    event_time=None,
    traceability=None,
    vendor=None,
    **sections,
):
    return CommonEvent(
        mapping_status=mapping_status,
        classification=EventClassification(
            category="network_activity",
            type="traffic",
        ),
        timestamps=EventTimestamps(
            event_time=event_time,
            observed_time=observed_time,
            processed_time=processed_time,
        ),
        vendor=(
            vendor
            or VendorInformation(
                vendor="Fortinet",
                product="FortiGate",
            )
        ),
        traceability=(
            traceability
            or TraceabilityReferences(
                u_id="UEV-000001",
                raw_id="RAW-000001",
            )
        ),
        **sections,
    )


def test_valid_event_is_returned_unchanged():
    event = make_event()

    assert validate_common_event(event) is event


@pytest.mark.parametrize(
    ("field_name", "value", "expected_reason"),
    [
        ("u_id", "", "traceability.u_id"),
        ("raw_id", "   ", "traceability.raw_id"),
    ],
)
def test_empty_traceability_identifier_is_rejected(
    field_name,
    value,
    expected_reason,
):
    identifiers = {
        "u_id": "UEV-000001",
        "raw_id": "RAW-000001",
    }
    identifiers[field_name] = value
    event = make_event(
        traceability=TraceabilityReferences(**identifiers)
    )

    with pytest.raises(ValueError, match=expected_reason):
        validate_common_event(event)


@pytest.mark.parametrize(
    ("field_name", "value", "expected_reason"),
    [
        ("vendor", "", "vendor.vendor"),
        ("product", "   ", "vendor.product"),
    ],
)
def test_empty_vendor_text_is_rejected(
    field_name,
    value,
    expected_reason,
):
    identity = {
        "vendor": "Fortinet",
        "product": "FortiGate",
    }
    identity[field_name] = value
    event = make_event(
        vendor=VendorInformation(**identity)
    )

    with pytest.raises(ValueError, match=expected_reason):
        validate_common_event(event)


@pytest.mark.parametrize("port", [-1, 65536])
def test_invalid_source_port_is_rejected(port):
    event = make_event(
        src_endpoint=Endpoint(port=port)
    )

    with pytest.raises(ValueError, match="src_endpoint.port"):
        validate_common_event(event)


def test_invalid_destination_port_is_rejected():
    event = make_event(
        dst_endpoint=Endpoint(port=70000)
    )

    with pytest.raises(ValueError, match="dst_endpoint.port"):
        validate_common_event(event)


@pytest.mark.parametrize("port", [0, 65535])
def test_endpoint_port_boundaries_are_accepted(port):
    event = make_event(
        src_endpoint=Endpoint(port=port),
        dst_endpoint=Endpoint(port=port),
    )

    assert validate_common_event(event) is event


@pytest.mark.parametrize(
    ("field_name", "port"),
    [
        ("translated_src_port", -1),
        ("translated_dst_port", 65536),
    ],
)
def test_invalid_nat_port_is_rejected(field_name, port):
    event = make_event(
        nat=Nat(**{field_name: port})
    )

    with pytest.raises(
        ValueError,
        match=rf"nat\.{field_name}",
    ):
        validate_common_event(event)


@pytest.mark.parametrize(
    "field_name",
    [
        "bytes_in",
        "bytes_out",
        "bytes_total",
        "packets_in",
        "packets_out",
        "packets_total",
        "duration_seconds",
    ],
)
def test_negative_network_numeric_value_is_rejected(
    field_name,
):
    event = make_event(
        network=Network(**{field_name: -1})
    )

    with pytest.raises(
        ValueError,
        match=rf"network\.{field_name}",
    ):
        validate_common_event(event)


def test_processed_time_before_observed_time_is_rejected():
    event = make_event(
        processed_time=OBSERVED_TIME - timedelta(seconds=1)
    )

    with pytest.raises(
        ValueError,
        match="must not be earlier",
    ):
        validate_common_event(event)


@pytest.mark.parametrize(
    "event_time",
    [
        OBSERVED_TIME - timedelta(days=365),
        OBSERVED_TIME + timedelta(days=365),
    ],
)
def test_event_time_relative_to_observed_time_is_not_rejected(
    event_time,
):
    event = make_event(event_time=event_time)

    assert validate_common_event(event) is event


def test_incomplete_mapping_status_is_valid():
    event = make_event(mapping_status="incomplete")

    assert validate_common_event(event) is event


def test_preservation_containers_do_not_cause_rejection():
    event = make_event(
        details={
            "unmapped_fields": {
                "custom": "preserved",
            },
        },
        vendor_fields={
            "vendor_extension": True,
        },
    )

    assert validate_common_event(event) is event
