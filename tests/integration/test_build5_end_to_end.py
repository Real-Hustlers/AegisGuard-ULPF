"""Black-box Build 5 coverage for the Windows-to-SIEM integration boundary."""

from __future__ import annotations

import copy
import json

from pathlib import Path

import pytest

from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.ingestion.windows import adapt_windows_security_event
from aegisguard_ulpf.integration.siem_contract_mapper import (
    translate_ocsf_events_to_siem_ingestion_envelope,
)
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator
from aegisguard_ulpf.normalization.ocsf.windows import (
    map_windows_security_raw_event_to_common_event,
    map_windows_security_raw_event_to_ocsf,
)
from aegisguard_ulpf.outputs.json_file import JsonlOutputWriter
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads(
    (ROOT / "examples" / "build5_windows_integration_cases.json").read_text(
        encoding="utf-8"
    )
)


def _evidence_backed_raw_event(
    event: dict,
    *,
    sequence: int,
    store: RawEvidenceStore,
) -> RawEvent:
    adapted = adapt_windows_security_event(event)
    evidence = store.store(
        adapted.raw.encode("utf-8"),
        identity_context={"test": "build5", "sequence": sequence},
        transport=adapted.transport,
        metadata=adapted.metadata,
    )
    return adapted.model_copy(
        update={
            "event_id": evidence.event_id,
            "evidence_raw_id": evidence.raw_id,
            "raw_sha256": evidence.raw_sha256,
        }
    )


def _map_windows_events(events: list[dict], tmp_path: Path) -> list[dict]:
    store = RawEvidenceStore(tmp_path / "evidence")
    writer = JsonlOutputWriter(tmp_path / "output")
    ocsf_events: list[dict] = []

    for sequence, event in enumerate(events, start=1):
        raw_event = _evidence_backed_raw_event(
            copy.deepcopy(event), sequence=sequence, store=store
        )
        common_event = map_windows_security_raw_event_to_common_event(raw_event)
        ocsf_event = map_windows_security_raw_event_to_ocsf(raw_event, common_event)
        writer.write_raw(raw_event)
        writer.write_normalized(common_event)
        writer.write_ocsf(ocsf_event)
        assert store.verify(str(raw_event.event_id))["integrity"] == "PASS"
        ocsf_events.append(ocsf_event)

    assert len(writer.raw_path.read_text(encoding="utf-8").splitlines()) == len(events)
    assert len(writer.normalized_path.read_text(encoding="utf-8").splitlines()) == len(events)
    assert len(writer.ocsf_path.read_text(encoding="utf-8").splitlines()) == len(events)
    return ocsf_events


def test_1_windows_login_success_reaches_siem_envelope(tmp_path: Path):
    events = _map_windows_events([CASES["login_success"]], tmp_path)

    envelope = translate_ocsf_events_to_siem_ingestion_envelope(
        events,
        machine_id="BUILD5-WIN-01",
        hostname="BUILD5-WIN-01",
        os_name="Windows",
    )

    assert events[0]["status_id"] == 1
    assert envelope["logs"][0]["event_type"] == "SUCCESSFUL_LOGIN"
    assert envelope["logs"][0]["user"] == "build5-user"


def test_2_failed_login_sequence_preserves_all_events(tmp_path: Path):
    events = _map_windows_events(CASES["failed_login_sequence"], tmp_path)

    envelope = translate_ocsf_events_to_siem_ingestion_envelope(
        events,
        machine_id="BUILD5-WIN-01",
        hostname="BUILD5-WIN-01",
        os_name="Windows",
    )

    assert len(events) == 3
    assert [event["status_id"] for event in events] == [2, 2, 2]
    assert [log["event_type"] for log in envelope["logs"]] == [
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "FAILED_LOGIN",
    ]


def test_4_process_creation_reaches_process_activity_contract(tmp_path: Path):
    events = _map_windows_events([CASES["process_creation"]], tmp_path)

    envelope = translate_ocsf_events_to_siem_ingestion_envelope(
        events,
        machine_id="BUILD5-WIN-01",
        hostname="BUILD5-WIN-01",
        os_name="Windows",
    )

    assert events[0]["class_uid"] == 1007
    assert events[0]["process"]["name"] == "cmd.exe"
    assert envelope["logs"][0]["event_type"] == "PROCESS_CREATED"


@pytest.mark.parametrize(
    "case_name",
    ["missing_class_uid", "missing_timestamp"],
)
def test_6_adapter_rejects_missing_required_ocsf_fields(case_name: str):
    event = CASES["invalid_ocsf"][case_name]

    assert not OCSFValidator().validate(event).valid
    with pytest.raises(ValueError):
        translate_ocsf_events_to_siem_ingestion_envelope(
            [event],
            machine_id="BUILD5-WIN-01",
            hostname="BUILD5-WIN-01",
            os_name="Windows",
        )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "The OCSF SIEM translator does not call OCSFValidator, so an invalid "
        "severity_id is converted to UNKNOWN instead of being rejected."
    ),
)
def test_6_adapter_rejects_invalid_ocsf_severity():
    event = CASES["invalid_ocsf"]["invalid_severity"]

    assert not OCSFValidator().validate(event).valid
    with pytest.raises(ValueError):
        translate_ocsf_events_to_siem_ingestion_envelope(
            [event],
            machine_id="BUILD5-WIN-01",
            hostname="BUILD5-WIN-01",
            os_name="Windows",
        )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "The Windows adapter rejects malformed input before RawEvidenceStore "
        "and provides no validation-failure record."
    ),
)
def test_5_malformed_windows_input_is_preserved_with_failure_record(tmp_path: Path):
    store = RawEvidenceStore(tmp_path / "evidence")
    malformed = CASES["invalid_windows"]["malformed_json"]

    raw_event = adapt_windows_security_event(malformed)
    store.store(
        raw_event.raw.encode("utf-8"),
        identity_context={"test": "build5", "sequence": 1},
        transport=raw_event.transport,
        metadata=raw_event.metadata,
    )
    assert len(store.records) == 1


def test_5_missing_event_id_and_corrupted_fields_are_rejected_safely(tmp_path: Path):
    store = RawEvidenceStore(tmp_path / "evidence")

    for sequence, case_name in enumerate(
        ["missing_event_id", "corrupted_fields"], start=1
    ):
        event = CASES["invalid_windows"][case_name]
        adapted = adapt_windows_security_event(event)
        store.store(
            adapted.raw.encode("utf-8"),
            identity_context={"test": "build5", "sequence": sequence},
            transport=adapted.transport,
            metadata=adapted.metadata,
        )
        with pytest.raises(ValueError):
            map_windows_security_raw_event_to_common_event(adapted)

    assert len(store.records) == 2


@pytest.mark.xfail(
    strict=True,
    reason=(
        "A missing Windows timestamp is replaced with observed time; no "
        "validation failure is emitted."
    ),
)
def test_5_missing_timestamp_is_rejected_and_recorded():
    event = CASES["invalid_windows"]["missing_timestamp"]

    with pytest.raises(ValueError):
        map_windows_security_raw_event_to_common_event(
            adapt_windows_security_event(event)
        )
