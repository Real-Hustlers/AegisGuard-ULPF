from datetime import datetime, timezone

import pytest

from pydantic import ValidationError

from aegisguard_ulpf.core.models import (
    CommonEvent,
    EventClassification,
    EventTimestamps,
    TraceabilityReferences,
    VendorInformation,
)
from aegisguard_ulpf.normalization.ocsf.mapper import (
    map_common_event_to_ocsf,
)
from aegisguard_ulpf.parsing.semantic_packs.models import OcsfBinding


def bound_payload(**updates):
    payload = {
        "status": "bound",
        "class_uid": 4001,
        "activity_mappings": {"SESSION": 6},
        "status_mappings": {"SUCCESS": 1},
        "severity_mappings": {"LOW": 2},
        "default_severity_id": 0,
    }
    payload.update(updates)
    return payload


def common_event(**classification_updates) -> CommonEvent:
    classification = {
        "type": "SESSION",
        "outcome": "SUCCESS",
        "severity": None,
    }
    classification.update(classification_updates)
    return CommonEvent(
        mapping_status="mapped",
        classification=EventClassification(**classification),
        timestamps=EventTimestamps(
            event_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
            observed_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
            processed_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
        ),
        vendor=VendorInformation(vendor="Example", product="Firewall"),
        traceability=TraceabilityReferences(u_id="UEV-1", raw_id="RAW-1"),
    )


def test_valid_bound_binding_loads():
    binding = OcsfBinding.model_validate(bound_payload())

    assert binding.class_uid == 4001
    assert binding.activity_mappings == {"SESSION": 6}


def test_unsupported_class_uid_is_rejected():
    with pytest.raises(ValidationError, match="class_uid"):
        OcsfBinding.model_validate(bound_payload(class_uid=9999))


def test_illegal_activity_mapping_is_rejected():
    with pytest.raises(ValidationError, match="activity_id"):
        OcsfBinding.model_validate(
            bound_payload(activity_mappings={"SESSION": 88})
        )


def test_deferred_binding_remains_valid_and_produces_no_ocsf_event():
    binding = OcsfBinding.model_validate({"status": "deferred"})

    assert map_common_event_to_ocsf(common_event(), binding) is None


def test_unmapped_semantic_value_is_not_guessed():
    binding = OcsfBinding.model_validate(bound_payload())

    with pytest.raises(ValidationError):
        OcsfBinding.model_validate(
            bound_payload(activity_mappings={"UNKNOWN": 77})
        )

    with pytest.raises(ValueError, match="classification.type"):
        map_common_event_to_ocsf(
            common_event(type="UNKNOWN"),
            binding,
        )

    explicit_unknown = OcsfBinding.model_validate(
        bound_payload(activity_mappings={"SESSION": 6, "UNKNOWN": 0})
    )
    event = map_common_event_to_ocsf(
        common_event(type="UNKNOWN"),
        explicit_unknown,
    )

    assert event["activity_id"] == 0
    assert event["type_uid"] == 400100
