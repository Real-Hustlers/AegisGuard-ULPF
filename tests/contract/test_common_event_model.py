from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, ValidationError

from aegisguard_ulpf.core.models import (
    Actor,
    CommonEvent,
    DetectionResult,
    Device,
    Endpoint,
    EventClassification,
    EventResource,
    EventTimestamps,
    Nat,
    Network,
    ParsedEvent,
    ParserMetadata,
    Policy,
    ProcessingResult,
    RawEvent,
    TraceabilityReferences,
    VendorInformation,
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


def required_common_event_fields():
    return {
        "mapping_status": "mapped",
        "classification": EventClassification(
            category="network_activity",
            type="traffic",
            subtype="session_end",
            outcome="success",
            severity="informational",
            action="allow",
        ),
        "timestamps": EventTimestamps(
            event_time=EVENT_TIME,
            observed_time=OBSERVED_TIME,
            processed_time=PROCESSED_TIME,
        ),
        "vendor": VendorInformation(
            vendor="Fortinet",
            product="FortiGate",
            vendor_event_id="0000000013",
        ),
        "traceability": TraceabilityReferences(
            u_id="UEV-000001",
            raw_id="RAW-000001",
        ),
    }


def test_valid_common_event_can_be_constructed():
    event = CommonEvent(
        **required_common_event_fields(),
        device=Device(
            id="FGT60FTK12345678",
            name="FGT-01",
            hostname="branch-firewall",
            virtual_domain="root",
        ),
        src_endpoint=Endpoint(
            ip="10.0.0.10",
            port=51514,
            hostname="workstation-01",
            interface="port2",
            zone="internal",
        ),
        dst_endpoint=Endpoint(
            ip="8.8.8.8",
            port=53,
            interface="wan1",
            zone="external",
        ),
        network=Network(
            protocol="UDP",
            bytes_in=512,
            bytes_out=256,
            bytes_total=768,
            packets_in=4,
            packets_out=2,
            packets_total=6,
            session_id="123456",
            duration_seconds=5,
        ),
        actor=Actor(
            user="alice",
        ),
        policy=Policy(
            id="42",
            name="Allow-DNS",
            uuid="policy-uuid-42",
        ),
        nat=Nat(
            translated_src_ip="192.0.2.10",
            translated_src_port=40000,
            translated_dst_ip="8.8.8.8",
            translated_dst_port=53,
            type="source_nat",
            disposition="translated",
        ),
        resource=EventResource(
            type="network_session",
            name="123456",
        ),
        details={
            "application": "dns",
        },
        vendor_fields={
            "vd": "root",
        },
    )

    assert event.src_endpoint is not None
    assert event.mapping_status == "mapped"
    assert event.src_endpoint.ip == "10.0.0.10"
    assert event.src_endpoint.port == 51514
    assert event.src_endpoint.hostname == "workstation-01"
    assert event.src_endpoint.interface == "port2"
    assert event.src_endpoint.zone == "internal"

    assert event.network is not None
    assert event.network.protocol == "UDP"
    assert event.network.bytes_total == 768
    assert event.network.packets_total == 6
    assert event.network.session_id == "123456"
    assert event.network.duration_seconds == 5

    assert event.policy is not None
    assert event.policy.id == "42"
    assert event.nat is not None
    assert event.nat.translated_src_port == 40000
    assert event.resource is not None
    assert event.resource.type == "network_session"


@pytest.mark.parametrize(
    "missing_field",
    [
        "classification",
        "timestamps",
        "vendor",
        "traceability",
        "mapping_status",
    ],
)
def test_common_event_required_fields(missing_field):
    fields = required_common_event_fields()
    fields.pop(missing_field)

    with pytest.raises(ValidationError):
        CommonEvent(**fields)


@pytest.mark.parametrize(
    "mapping_status",
    [
        "mapped",
        "incomplete",
    ],
)
def test_common_event_accepts_mapping_status_values(
    mapping_status,
):
    event = CommonEvent(
        **{
            **required_common_event_fields(),
            "mapping_status": mapping_status,
        }
    )

    assert event.mapping_status == mapping_status


def test_common_event_rejects_invalid_mapping_status():
    with pytest.raises(ValidationError):
        CommonEvent(
            **{
                **required_common_event_fields(),
                "mapping_status": "unknown",
            }
        )


def test_event_timestamps_require_observed_and_processed_time():
    with pytest.raises(ValidationError):
        EventTimestamps(
            processed_time=PROCESSED_TIME,
        )

    with pytest.raises(ValidationError):
        EventTimestamps(
            observed_time=OBSERVED_TIME,
        )

    timestamps = EventTimestamps(
        observed_time=OBSERVED_TIME,
        processed_time=PROCESSED_TIME,
    )

    assert timestamps.event_time is None


def test_optional_sections_and_extension_maps_have_safe_defaults():
    first = CommonEvent(
        **required_common_event_fields()
    )

    second = CommonEvent(
        **required_common_event_fields()
    )

    assert first.device is None
    assert first.src_endpoint is None
    assert first.dst_endpoint is None
    assert first.network is None
    assert first.actor is None
    assert first.policy is None
    assert first.nat is None
    assert first.resource is None
    assert first.details == {}
    assert first.vendor_fields == {}

    first.details["normalized"] = True

    assert first.vendor_fields == {}
    assert second.details == {}
    assert second.vendor_fields == {}

    first.vendor_fields["vendor_key"] = "vendor_value"

    assert "vendor_key" not in first.details
    assert second.vendor_fields == {}


@pytest.mark.parametrize(
    ("model", "required_fields"),
    [
        (EventClassification, {}),
        (
            EventTimestamps,
            {
                "observed_time": OBSERVED_TIME,
                "processed_time": PROCESSED_TIME,
            },
        ),
        (
            VendorInformation,
            {
                "vendor": "Cisco",
                "product": "ASA",
            },
        ),
        (Device, {}),
        (Endpoint, {}),
        (Network, {}),
        (Actor, {}),
        (Policy, {}),
        (Nat, {}),
        (EventResource, {}),
        (
            TraceabilityReferences,
            {
                "u_id": "UEV-1",
                "raw_id": "RAW-1",
            },
        ),
        (CommonEvent, required_common_event_fields()),
    ],
)
def test_new_common_event_models_reject_unknown_fields(
    model: type[BaseModel],
    required_fields,
):
    with pytest.raises(ValidationError):
        model(
            **required_fields,
            unknown_field="not-allowed",
        )


def test_common_event_model_dump_is_nested():
    event = CommonEvent(
        **required_common_event_fields(),
        src_endpoint=Endpoint(
            ip="10.0.0.10",
            port=12345,
        ),
        network=Network(
            protocol="TCP",
            packets_total=3,
        ),
    )

    dumped = event.model_dump()

    assert "src_ip" not in dumped
    assert "protocol" not in dumped
    assert dumped["src_endpoint"] == {
        "ip": "10.0.0.10",
        "port": 12345,
        "hostname": None,
        "interface": None,
        "zone": None,
    }
    assert dumped["network"]["protocol"] == "TCP"
    assert dumped["classification"]["type"] == "traffic"
    assert dumped["vendor"]["vendor"] == "Fortinet"
    assert dumped["traceability"]["raw_id"] == "RAW-000001"


def test_common_event_datetime_json_serialization():
    event = CommonEvent(
        **required_common_event_fields()
    )

    dumped = event.model_dump(mode="json")
    timestamps = dumped["timestamps"]

    assert datetime.fromisoformat(
        timestamps["event_time"].replace("Z", "+00:00")
    ) == EVENT_TIME

    assert datetime.fromisoformat(
        timestamps["observed_time"].replace("Z", "+00:00")
    ) == OBSERVED_TIME

    assert datetime.fromisoformat(
        timestamps["processed_time"].replace("Z", "+00:00")
    ) == PROCESSED_TIME


def test_existing_models_remain_compatible():
    raw = RawEvent(
        raw="hello world",
        transport="file",
        metadata={
            "source": "contract-test",
        },
    )

    parser = ParserMetadata(
        parser_id="test.dummy",
        parser_version="1.0.0",
        vendor="TestVendor",
        product="TestProduct",
        supported_formats=["text"],
    )

    parsed = ParsedEvent(
        raw_event=raw,
        parser=parser,
        fields={
            "arbitrary": {
                "nested": True,
            },
        },
        warnings=["test warning"],
    )

    detection = DetectionResult(
        vendor="TestVendor",
        product="TestProduct",
        event_family="system",
        format="text",
        parser_id="test.dummy",
        confidence=0.75,
        evidence=["contract test"],
    )

    result = ProcessingResult(
        raw_event=raw,
        detection=detection,
        parsed_event=parsed,
    )

    assert raw.raw_id == f"RAW-{raw.event_id}"
    assert raw.ingested_at.tzinfo is not None
    assert parsed.fields["arbitrary"]["nested"] is True
    assert parsed.warnings == ["test warning"]
    assert detection.confidence == 0.75
    assert result.raw_event is raw
    assert result.detection is detection
    assert result.parsed_event is parsed
