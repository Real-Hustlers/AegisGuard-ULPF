"""Validation tests for Windows Security Event Log OCSF mappings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisguard_ulpf.normalization.ocsf.registry import (
    AUTHENTICATION_CATEGORY_UID,
    AUTHENTICATION_CLASS_UID,
    PROCESS_ACTIVITY_CATEGORY_UID,
    PROCESS_ACTIVITY_CLASS_UID,
)
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator
from aegisguard_ulpf.normalization.ocsf.version import OCSF_VERSION
from aegisguard_ulpf.normalization.ocsf.windows import (
    map_windows_security_event_to_common_event,
    map_windows_security_event_to_ocsf,
)


WINDOWS_4624 = {
    "EventID": 4624,
    "TimeCreated": "2026-08-27T09:30:00Z",
    "TargetUserName": "alice",
    "IpAddress": "10.0.0.4",
    "Computer": "WORKSTATION-01",
    "LogonType": 3,
    "AuthenticationPackageName": "Negotiate",
}

WINDOWS_4625 = {
    "EventID": 4625,
    "TimeCreated": "2026-08-27T09:31:00Z",
    "User": "test",
    "SourceIP": "10.0.0.5",
    "Computer": "SERVER-01",
    "LogonType": 3,
    "FailureReason": "Unknown user name or bad password.",
}

WINDOWS_4688 = {
    "EventID": 4688,
    "TimeCreated": "2026-08-27T09:32:00Z",
    "SubjectUserName": "administrator",
    "Computer": "WORKSTATION-02",
    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
    "NewProcessId": "1234",
    "CommandLine": "cmd.exe /c whoami",
    "TokenElevationType": "%%1936",
}


def assert_valid(event: dict) -> None:
    result = OCSFValidator().validate(event)
    assert result.valid, result.errors


def test_4624_maps_to_successful_authentication_and_preserves_data():
    common = map_windows_security_event_to_common_event(WINDOWS_4624)
    event = map_windows_security_event_to_ocsf(WINDOWS_4624)

    assert common.classification.type == "LOGON"
    assert common.classification.outcome == "SUCCESS"
    assert common.vendor.vendor == "Microsoft"
    assert common.vendor_fields == WINDOWS_4624
    assert event["class_uid"] == AUTHENTICATION_CLASS_UID
    assert event["category_uid"] == AUTHENTICATION_CATEGORY_UID
    assert event["activity_id"] == 1
    assert event["type_uid"] == 300201
    assert event["status_id"] == 1
    assert event["severity_id"] == 1
    assert event["metadata"]["version"] == OCSF_VERSION
    assert event["metadata"]["product"] == {
        "vendor_name": "Microsoft",
        "name": "Windows Security",
    }
    assert event["user"] == {"name": "alice"}
    assert event["src_endpoint"] == {"ip": "10.0.0.4"}
    assert event["observables"] == [
        {"name": "src_endpoint.ip", "type_id": 2, "value": "10.0.0.4"}
    ]
    assert event["unmapped"]["windows_security"] == {
        "AuthenticationPackageName": "Negotiate"
    }
    assert json.loads(event["raw_data"]) == WINDOWS_4624
    assert_valid(event)


def test_4625_maps_to_failed_authentication_and_keeps_unmapped_fields():
    event = map_windows_security_event_to_ocsf(WINDOWS_4625)

    assert event["class_uid"] == AUTHENTICATION_CLASS_UID
    assert event["category_uid"] == AUTHENTICATION_CATEGORY_UID
    assert event["activity_id"] == 1
    assert event["type_uid"] == 300201
    assert event["status_id"] == 2
    assert event["severity_id"] == 2
    assert event["user"] == {"name": "test"}
    assert event["src_endpoint"] == {"ip": "10.0.0.5"}
    assert event["unmapped"]["windows_security"] == {
        "FailureReason": "Unknown user name or bad password."
    }
    assert json.loads(event["raw_data"]) == WINDOWS_4625
    assert_valid(event)


def test_4688_maps_to_process_activity_and_preserves_data():
    common = map_windows_security_event_to_common_event(WINDOWS_4688)
    event = map_windows_security_event_to_ocsf(WINDOWS_4688)

    assert common.classification.type == "PROCESS_LAUNCH"
    assert common.classification.outcome == "SUCCESS"
    assert common.resource is not None
    assert common.resource.name == "cmd.exe"
    assert event["class_uid"] == PROCESS_ACTIVITY_CLASS_UID
    assert event["category_uid"] == PROCESS_ACTIVITY_CATEGORY_UID
    assert event["activity_id"] == 1
    assert event["type_uid"] == 100701
    assert event["status_id"] == 1
    assert event["severity_id"] == 1
    assert event["process"] == {
        "name": "cmd.exe",
        "pid": 1234,
        "cmd_line": "cmd.exe /c whoami",
    }
    assert event["actor"] == {"user": {"name": "administrator"}}
    assert event["unmapped"]["windows_security"] == {
        "TokenElevationType": "%%1936"
    }
    assert event["observables"] == []
    assert json.loads(event["raw_data"]) == WINDOWS_4688
    assert_valid(event)


def test_unsupported_windows_event_id_is_rejected():
    with pytest.raises(ValueError, match="Unsupported Windows Security EventID: 4634"):
        map_windows_security_event_to_ocsf({"EventID": 4634})


def test_validator_rejects_invalid_observable_shape():
    event = map_windows_security_event_to_ocsf(WINDOWS_4625)
    event["observables"] = [
        {"name": "src_endpoint.ip", "type_id": "2", "value": "10.0.0.5"}
    ]

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert "observable at index 0 requires integer type_id" in result.errors


@pytest.mark.parametrize(
    "sample_name",
    [
        "windows_ocsf_4624.json",
        "windows_ocsf_4625.json",
        "windows_ocsf_4688.json",
    ],
)
def test_documented_ocsf_samples_are_valid(sample_name: str):
    repository_root = Path(__file__).resolve().parents[4]
    event = json.loads(
        (repository_root / "examples" / sample_name).read_text(encoding="utf-8")
    )

    assert_valid(event)
