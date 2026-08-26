import json

from datetime import datetime, timezone

import pytest

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
from aegisguard_ulpf.normalization.ocsf.base_event import build_base_event
from aegisguard_ulpf.normalization.ocsf.registry import (
    NETWORK_ACTIVITY_CATEGORY_UID,
    NETWORK_ACTIVITY_CLASS_UID,
    NetworkActivityID,
    SeverityID,
)
from aegisguard_ulpf.outputs import (
    NORMALIZED_EVENTS_FILENAME,
    OCSF_EVENTS_FILENAME,
    RAW_EVENTS_FILENAME,
    JsonlOutputWriter,
)
from aegisguard_ulpf.privacy import apply_privacy_policy
from aegisguard_ulpf.parsing.semantic_packs.models import (
    SensitivityField,
    SensitivityMetadata,
)


def make_raw_event() -> RawEvent:
    return RawEvent(
        event_id="EVT-OUTPUT-1",
        raw="raw payload, unchanged",
        transport="syslog_udp",
        metadata={"source": "test"},
        evidence_raw_id="RAW-OUTPUT-1",
        raw_sha256="a" * 64,
    )


def make_common_event() -> CommonEvent:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
    return CommonEvent(
        mapping_status="mapped",
        classification=EventClassification(type="SESSION"),
        timestamps=EventTimestamps(
            event_time=now,
            observed_time=now,
            processed_time=now,
        ),
        vendor=VendorInformation(vendor="Example", product="Firewall"),
        traceability=TraceabilityReferences(
            u_id="EVT-OUTPUT-1",
            raw_id="RAW-OUTPUT-1",
        ),
        src_endpoint=Endpoint(ip="10.0.0.1"),
        actor=Actor(user="alice"),
        details={"note": "private"},
    )


def make_ocsf_event() -> dict:
    event = build_base_event(
        class_uid=NETWORK_ACTIVITY_CLASS_UID,
        category_uid=NETWORK_ACTIVITY_CATEGORY_UID,
        activity_id=NetworkActivityID.TRAFFIC,
        time=1_777_000_000_000,
        severity_id=SeverityID.INFORMATIONAL,
        product_vendor="Example",
        product_name="Firewall",
    )
    event["raw_data"] = {
        "u_id": "EVT-OUTPUT-1",
        "raw_id": "RAW-OUTPUT-1",
    }
    return event


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_raw_output_appends_pure_records_and_preserves_traceability(tmp_path):
    writer = JsonlOutputWriter(tmp_path / "nested" / "outputs")
    raw_event = make_raw_event()

    first = writer.write_raw(raw_event)
    second = writer.write_raw(raw_event)

    assert first.written and second.written
    assert first.path.name == RAW_EVENTS_FILENAME
    assert first.path.read_bytes().endswith(b"\n")
    lines = read_jsonl(first.path)
    assert len(lines) == 2
    assert lines[0]["raw"] == raw_event.raw
    assert lines[0]["event_id"] == "EVT-OUTPUT-1"
    assert lines[0]["raw_id"] == "RAW-OUTPUT-1"
    assert lines[0]["raw_sha256"] == "a" * 64


def test_normalized_output_is_a_pure_common_event_and_does_not_mutate(tmp_path):
    writer = JsonlOutputWriter(tmp_path)
    event = make_common_event()
    before = event.model_dump(mode="json")

    result = writer.write_normalized(event)

    payload = read_jsonl(result.path)[0]
    assert result.path.name == NORMALIZED_EVENTS_FILENAME
    assert not {"normalized", "event", "ulpf", "ocsf"} & set(payload)
    assert CommonEvent.model_validate(payload).model_dump(mode="json") == before
    assert payload["traceability"] == {
        "u_id": "EVT-OUTPUT-1",
        "raw_id": "RAW-OUTPUT-1",
    }
    assert payload["timestamps"]["event_time"].endswith(("Z", "+00:00"))
    assert event.model_dump(mode="json") == before


def test_ocsf_output_is_pure_and_deferred_none_writes_nothing(tmp_path):
    writer = JsonlOutputWriter(tmp_path)

    deferred = writer.write_ocsf(None)
    assert not deferred.written
    assert not deferred.path.exists()

    result = writer.write_ocsf(make_ocsf_event())
    payload = read_jsonl(result.path)[0]
    assert result.path.name == OCSF_EVENTS_FILENAME
    assert "ocsf" not in payload
    assert payload["class_uid"] == NETWORK_ACTIVITY_CLASS_UID
    assert payload["raw_data"] == {
        "u_id": "EVT-OUTPUT-1",
        "raw_id": "RAW-OUTPUT-1",
    }


def test_ocsf_output_rejects_non_dictionary_input(tmp_path):
    with pytest.raises(TypeError, match="dictionary"):
        JsonlOutputWriter(tmp_path).write_ocsf(["not", "ocsf"])


def test_three_streams_are_independent_and_linkable(tmp_path):
    writer = JsonlOutputWriter(tmp_path)

    writer.write_raw(make_raw_event())
    writer.write_normalized(make_common_event())
    writer.write_ocsf(make_ocsf_event())

    raw = read_jsonl(tmp_path / RAW_EVENTS_FILENAME)[0]
    normalized = read_jsonl(tmp_path / NORMALIZED_EVENTS_FILENAME)[0]
    ocsf = read_jsonl(tmp_path / OCSF_EVENTS_FILENAME)[0]
    assert {path.name for path in tmp_path.iterdir()} == {
        RAW_EVENTS_FILENAME,
        NORMALIZED_EVENTS_FILENAME,
        OCSF_EVENTS_FILENAME,
    }
    assert "classification" in normalized and "class_uid" not in normalized
    assert "class_uid" in ocsf and "classification" not in ocsf
    assert raw["raw_id"] == normalized["traceability"]["raw_id"]
    assert raw["raw_id"] == ocsf["raw_data"]["raw_id"]


def test_json_safety_rejects_nan_and_unsupported_types(tmp_path):
    writer = JsonlOutputWriter(tmp_path)

    with pytest.raises(ValueError):
        writer.write_ocsf({"value": float("nan")})
    with pytest.raises(TypeError, match="Unsupported JSON"):
        writer.write_ocsf({"value": object()})


def test_writer_serializes_privacy_transformed_event_without_a_report(tmp_path):
    event = make_common_event()
    sensitivity = SensitivityMetadata(
        fields=(
            SensitivityField(
                field_path="actor.user",
                semantic_role="source_user",
                classification="personal_identifier",
            ),
        )
    )
    transformed, report = apply_privacy_policy(
        event,
        sensitivity,
        "Data Lake",
        pseudonymization_key="output-test-key",
    )

    path = JsonlOutputWriter(tmp_path).write_normalized(transformed).path
    payload = read_jsonl(path)[0]
    assert payload["actor"]["user"].startswith("[PSEUDONYMIZED:")
    assert "fields_pseudonymized" not in payload
    assert report.fields_pseudonymized == ("actor.user",)
