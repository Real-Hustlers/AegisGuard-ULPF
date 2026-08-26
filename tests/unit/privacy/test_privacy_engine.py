from datetime import datetime, timezone

import pytest

from pydantic import ValidationError

from aegisguard_ulpf.core.models import (
    Actor,
    CommonEvent,
    Endpoint,
    EventClassification,
    EventTimestamps,
    RawEvent,
    TraceabilityReferences,
    VendorInformation,
)
from aegisguard_ulpf.normalization.fidelity import evaluate_mapping_fidelity
from aegisguard_ulpf.parsing.semantic_packs.models import (
    SensitivityField,
    SensitivityMetadata,
)
from aegisguard_ulpf.privacy import apply_privacy_policy


def make_event() -> CommonEvent:
    now = datetime(2026, 8, 26, tzinfo=timezone.utc)
    return CommonEvent(
        mapping_status="mapped",
        classification=EventClassification(type="SESSION"),
        timestamps=EventTimestamps(
            event_time=now,
            observed_time=now,
            processed_time=now,
        ),
        vendor=VendorInformation(vendor="Example", product="Firewall"),
        traceability=TraceabilityReferences(u_id="UEV-1", raw_id="RAW-1"),
        src_endpoint=Endpoint(ip="10.0.0.1"),
        dst_endpoint=Endpoint(ip="198.51.100.10"),
        actor=Actor(user="alice"),
        details={
            "dst_user": "bob",
            "credential": "password-value",
            "secret": "token-value",
            "note": "private-note",
        },
    )


def sensitivity() -> SensitivityMetadata:
    return SensitivityMetadata(
        fields=(
            SensitivityField(
                field_path="src_endpoint.ip",
                semantic_role="source_network_address",
                classification="network_identifier",
            ),
            SensitivityField(
                field_path="dst_endpoint.ip",
                semantic_role="destination_network_address",
                classification="network_identifier",
            ),
            SensitivityField(
                field_path="actor.user",
                semantic_role="source_user",
                classification="personal_identifier",
            ),
            SensitivityField(
                field_path="details.dst_user",
                semantic_role="destination_user",
                classification="personal_identifier",
            ),
            SensitivityField(
                field_path="details.credential",
                semantic_role="credential_material",
                classification="credential",
            ),
            SensitivityField(
                field_path="details.secret",
                semantic_role="secret_material",
                classification="secret",
            ),
            SensitivityField(
                field_path="details.note",
                semantic_role="free_text",
                classification="potentially_sensitive",
            ),
        )
    )


def test_valid_sensitivity_metadata_is_typed():
    assert len(sensitivity().fields) == 7


@pytest.mark.parametrize(
    "payload",
    [
        {
            "field_path": "details.value",
            "semantic_role": "test",
            "classification": "unknown",
        },
        {
            "field_path": " ",
            "semantic_role": "test",
            "classification": "normal",
        },
        {
            "field_path": "details..value",
            "semantic_role": "test",
            "classification": "normal",
        },
    ],
)
def test_invalid_sensitivity_field_is_rejected(payload):
    with pytest.raises(ValidationError):
        SensitivityField.model_validate(payload)


def test_duplicate_sensitivity_field_path_is_rejected():
    field = SensitivityField(
        field_path="details.value",
        semantic_role="test",
        classification="normal",
    )
    with pytest.raises(ValidationError, match="unique"):
        SensitivityMetadata(fields=(field, field))


def test_soc_policy_retains_identifiers_drops_credentials_and_masks_text():
    transformed, report = apply_privacy_policy(
        make_event(), sensitivity(), "SOC"
    )

    assert transformed.src_endpoint.ip == "10.0.0.1"
    assert transformed.actor.user == "alice"
    assert "credential" not in transformed.details
    assert "secret" not in transformed.details
    assert transformed.details["note"] == "[MASKED]"
    assert report.fields_retained == (
        "src_endpoint.ip",
        "dst_endpoint.ip",
        "actor.user",
        "details.dst_user",
    )
    assert report.fields_dropped == ("details.credential", "details.secret")
    assert report.fields_masked == ("details.note",)


def test_data_lake_pseudonymizes_identifiers_and_applies_other_actions():
    transformed, report = apply_privacy_policy(
        make_event(), sensitivity(), "Data Lake", pseudonymization_key="key-a"
    )

    assert transformed.src_endpoint.ip.startswith("[PSEUDONYMIZED:")
    assert transformed.src_endpoint.ip != "10.0.0.1"
    assert transformed.actor.user.startswith("[PSEUDONYMIZED:")
    assert "credential" not in transformed.details
    assert "secret" not in transformed.details
    assert transformed.details["note"] == "[MASKED]"
    assert "key-a" not in report.model_dump_json()
    assert report.fields_pseudonymized == (
        "src_endpoint.ip",
        "dst_endpoint.ip",
        "actor.user",
        "details.dst_user",
    )


def test_pseudonymization_is_deterministic_and_input_distinct():
    first, _ = apply_privacy_policy(
        make_event(), sensitivity(), "Data Lake", pseudonymization_key=b"key-a"
    )
    second, _ = apply_privacy_policy(
        make_event(), sensitivity(), "Data Lake", pseudonymization_key=b"key-a"
    )

    assert first.src_endpoint.ip == second.src_endpoint.ip
    assert first.src_endpoint.ip != first.dst_endpoint.ip


def test_missing_pseudonymization_key_fails():
    with pytest.raises(ValueError, match="key is required"):
        apply_privacy_policy(make_event(), sensitivity(), "Data Lake")


def test_invalid_sink_profile_is_rejected():
    with pytest.raises(ValueError, match="Unsupported sink profile"):
        apply_privacy_policy(make_event(), sensitivity(), "Archive")


def test_original_traceability_and_raw_evidence_remain_unchanged():
    original = make_event()
    raw_event = RawEvent(raw="original raw evidence")
    transformed, _ = apply_privacy_policy(
        original, sensitivity(), "Data Lake", pseudonymization_key="key-a"
    )

    assert original.src_endpoint.ip == "10.0.0.1"
    assert original.details["credential"] == "password-value"
    assert transformed.traceability.u_id == original.traceability.u_id
    assert transformed.traceability.raw_id == original.traceability.raw_id
    assert "key-a" not in transformed.model_dump_json()
    assert raw_event.raw == "original raw evidence"

    with pytest.raises(TypeError, match="normalized CommonEvent"):
        apply_privacy_policy(raw_event, sensitivity(), "SOC")


def test_protected_targets_are_rejected_by_metadata_and_policy_engine():
    with pytest.raises(ValidationError, match="protected"):
        SensitivityField(
            field_path="traceability.u_id",
            semantic_role="forensic_identifier",
            classification="personal_identifier",
        )

    unsafe = SensitivityMetadata.model_construct(
        fields=(
            SensitivityField.model_construct(
                field_path="mapping_status",
                semantic_role="unsafe",
                classification="potentially_sensitive",
            ),
        )
    )
    with pytest.raises(ValueError, match="protected"):
        apply_privacy_policy(make_event(), unsafe, "SOC")


def test_tier0_absence_of_metadata_is_an_explicit_no_op():
    original = make_event()
    transformed, report = apply_privacy_policy(original, None, "Data Lake")

    assert transformed.model_dump() == original.model_dump()
    assert report.fields_classified == ()
    assert report.affected_field_paths == ()


def test_policy_drops_do_not_change_mapping_fidelity():
    original = make_event()
    fidelity = evaluate_mapping_fidelity(
        {"details": {"credential": "password-value"}},
        original,
    )
    _, privacy_report = apply_privacy_policy(original, sensitivity(), "SOC")

    assert fidelity.fields_dropped == 0
    assert privacy_report.fields_dropped == ("details.credential", "details.secret")
