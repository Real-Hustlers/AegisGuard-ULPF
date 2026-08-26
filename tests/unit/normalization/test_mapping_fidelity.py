from datetime import (
    datetime,
    timezone,
)

import pytest

from aegisguard_ulpf.normalization.engine import (
    NormalizationEngine,
)

from aegisguard_ulpf.normalization.fidelity import (
    evaluate_mapping_fidelity,
)


NOW = datetime(
    2026,
    8,
    26,
    16,
    0,
    tzinfo=timezone.utc,
)


def base_fields():
    return {
        "u_id": "EVT-001",
        "raw_id": "RAW-001",

        "timestamp":
            "2026-08-26T15:59:00Z",

        "vendor": "Fortinet",
        "product": "FortiGate",

        "category":
            "network_activity",

        "type":
            "traffic",

        "subtype":
            "forward",

        "outcome":
            "success",

        "severity":
            None,

        "src_ip":
            "10.0.0.1",

        "src_port":
            54321,

        "dst_ip":
            "8.8.8.8",

        "dst_port":
            53,

        "protocol":
            "UDP",

        "user":
            None,

        "action":
            "allow",

        "reason":
            None,

        "object_type":
            None,

        "object_name":
            None,

        "details": {
            "session_id":
                "12345",
        },

        "vendor_event_id":
            "0000000013",

        "vendor_fields": {},
    }


def test_fidelity_counts_mapped_unmapped_and_absent_separately():

    fields = base_fields()

    fields[
        "vendor_fields"
    ] = {
        "custom_vendor_flag":
            "abc",
    }

    engine = NormalizationEngine()

    event, report = (
        engine.normalize_with_fidelity(
            fields,
            observed_time=NOW,
        )
    )

    assert (
        report.fields_semantically_mapped
        > 0
    )

    assert (
        report.fields_unmapped
        == 1
    )

    assert (
        report.fields_dropped
        == 0
    )

    assert (
        "vendor:custom_vendor_flag"
        in report.unmapped_fields
    )

    # severity=None is absent, not unmapped.
    assert (
        "field:severity"
        not in report.unmapped_fields
    )

    assert (
        "field:severity"
        not in report.mapped_fields
    )

    assert (
        event.mapping_status
        == "incomplete"
    )


def test_invalid_timestamp_is_unmapped_not_mapped():

    fields = base_fields()

    fields[
        "timestamp"
    ] = "not-a-timestamp"

    engine = NormalizationEngine()

    event, report = (
        engine.normalize_with_fidelity(
            fields,
            observed_time=NOW,
        )
    )

    assert (
        "field:timestamp"
        not in report.mapped_fields
    )

    assert any(
        item.endswith(
            ":timestamp"
        )
        for item
        in report.unmapped_fields
    )

    assert (
        event.mapping_status
        == "incomplete"
    )


def test_dropped_fields_are_explicit_and_not_unmapped():

    fields = base_fields()

    fields[
        "debug_blob"
    ] = "temporary-value"

    engine = NormalizationEngine()

    event, report = (
        engine.normalize_with_fidelity(
            fields,
            observed_time=NOW,
            dropped_fields=[
                "debug_blob",
            ],
        )
    )

    assert (
        report.fields_dropped
        == 1
    )

    assert (
        "field:debug_blob"
        in report.dropped_fields
    )

    assert (
        "field:debug_blob"
        not in report.unmapped_fields
    )

    assert (
        report.mapping_status
        == "incomplete"
    )

    assert (
        event.mapping_status
        == "incomplete"
    )


def test_no_fake_extraction_coverage_when_source_count_unknown():

    engine = NormalizationEngine()

    _, report = (
        engine.normalize_with_fidelity(
            base_fields(),
            observed_time=NOW,
        )
    )

    assert (
        report.extraction_coverage
        is None
    )

    assert (
        report.extraction_coverage_reason
        == "source_field_count_not_provided"
    )

    assert (
        report.semantic_coverage
        is not None
    )


def test_known_source_count_can_produce_extraction_coverage():

    engine = NormalizationEngine()

    _, first_report = (
        engine.normalize_with_fidelity(
            base_fields(),
            observed_time=NOW,
        )
    )

    extracted = (
        first_report.fields_extracted
    )

    _, report = (
        engine.normalize_with_fidelity(
            base_fields(),
            observed_time=NOW,
            source_field_count=(
                extracted + 2
            ),
        )
    )

    assert (
        report.extraction_coverage
        == round(
            extracted
            / (extracted + 2),
            6,
        )
    )


def test_integrity_verified_requires_raw_preservation():

    engine = NormalizationEngine()

    with pytest.raises(
        ValueError,
        match="raw_preserved",
    ):
        engine.normalize_with_fidelity(
            base_fields(),
            observed_time=NOW,
            raw_preserved=False,
            integrity_verified=True,
        )


def test_raw_and_integrity_flags_are_reported_independently():

    engine = NormalizationEngine()

    _, report = (
        engine.normalize_with_fidelity(
            base_fields(),
            observed_time=NOW,
            raw_preserved=True,
            integrity_verified=True,
        )
    )

    assert (
        report.raw_preserved
        is True
    )

    assert (
        report.integrity_verified
        is True
    )


def test_tier0_style_event_has_zero_semantic_coverage():

    fields = {
        "u_id": "EVT-TIER0",
        "raw_id": "RAW-TIER0",

        "timestamp": None,

        "vendor": None,
        "product": None,

        "category": None,
        "type": None,
        "subtype": None,
        "outcome": None,
        "severity": None,

        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,

        "user": None,
        "action": None,
        "reason": None,

        "object_type": None,
        "object_name": None,

        "details": {
            "tier0": {
                "mapping_status":
                    "incomplete",
                "fallback_reason":
                    "no_supported_parser",
            }
        },

        "vendor_event_id": None,

        "vendor_fields": {
            "foo": "bar",
            "answer": 42,
        },

        "mapping_status":
            "incomplete",
    }

    report = evaluate_mapping_fidelity(
        fields,
        None,
        mapping_status="incomplete",
    )

    assert (
        report.fields_semantically_mapped
        == 0
    )

    assert (
        report.fields_unmapped
        == 2
    )

    assert (
        report.semantic_coverage
        == 0.0
    )

    assert (
        report.mapping_status
        == "incomplete"
    )

    assert set(
        report.unmapped_fields
    ) == {
        "vendor:foo",
        "vendor:answer",
    }