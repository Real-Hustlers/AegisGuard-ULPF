import json

import pytest

from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.ingestion.windows import (
    WINDOWS_SECURITY_SOURCE,
    WindowsSecurityEventAdapter,
    adapt_windows_security_event,
)


def windows_security_event() -> dict:
    return {
        "EventID": 4625,
        "TimeCreated": "2026-08-27T09:30:00Z",
        "Computer": "WIN-SEC-01",
        "User": "admin",
        "IP": "10.0.0.5",
        "Channel": "Security",
        "EventData": {
            "FailureReason": "Unknown user name or bad password.",
            "LogonType": 3,
        },
    }


def test_adapter_creates_a_raw_event_with_windows_source_metadata():
    event = windows_security_event()

    adapted = adapt_windows_security_event(event)

    assert isinstance(adapted, RawEvent)
    assert adapted.transport == "windows_event_log"
    assert adapted.metadata["source"] == WINDOWS_SECURITY_SOURCE
    assert adapted.metadata["raw_event"] == event


def test_adapter_preserves_the_complete_event_in_raw_payload_and_metadata():
    event = windows_security_event()

    adapted = WindowsSecurityEventAdapter().adapt(event)

    assert json.loads(adapted.raw) == event
    assert adapted.metadata["raw_event"] == event

    event["EventData"]["LogonType"] = 10
    assert adapted.metadata["raw_event"]["EventData"]["LogonType"] == 3


def test_adapter_preserves_a_json_input_string_without_reformatting():
    raw = '{"EventID":4625,"User":"admin","IP":"10.0.0.5"}'

    adapted = adapt_windows_security_event(raw)

    assert adapted.raw == raw
    assert adapted.metadata["raw_event"] == {
        "EventID": 4625,
        "User": "admin",
        "IP": "10.0.0.5",
    }


@pytest.mark.parametrize(
    "event,exception",
    [
        ("not-json", ValueError),
        ("[]", ValueError),
        ([{"EventID": 4625}], TypeError),
    ],
)
def test_adapter_rejects_invalid_windows_event_inputs(event, exception):
    with pytest.raises(exception):
        adapt_windows_security_event(event)
