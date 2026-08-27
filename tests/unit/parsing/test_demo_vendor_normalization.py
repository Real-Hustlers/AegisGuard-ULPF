"""Regression coverage for the vendor records used by the SIH demo."""

from __future__ import annotations

from pathlib import Path

from aegisguard_ulpf.parsing.vendors.fortinet.fortigate import traffic as fortigate
from aegisguard_ulpf.parsing.vendors.palaalto.panos import traffic as paloalto


ROOT = Path(__file__).resolve().parents[3]
INPUT_DIR = ROOT / "demo" / "input" / "multivendor"


def _fortigate_demo_fields() -> dict[str, str]:
    return {
        key: value
        for key, value in (
            item.split("=", 1)
            for item in (INPUT_DIR / "fortigate.log").read_text(
                encoding="utf-8"
            ).split()
        )
    }


def test_fortigate_demo_event_has_type_and_severity():
    event = fortigate.convert_row(_fortigate_demo_fields(), 1)

    assert event["type"] is not None
    assert event["severity"] is not None


def test_paloalto_demo_event_has_action_and_severity():
    event = paloalto.normalize(
        (INPUT_DIR / "paloalto.log").read_text(encoding="utf-8"),
        "RAW-DEMO-PA-001",
        "UEV-DEMO-PA-001",
    )

    assert event["action"] is not None
    assert event["severity"] is not None
