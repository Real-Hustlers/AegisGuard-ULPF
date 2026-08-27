"""CLI coverage for the tamper-evident raw-evidence verifier."""

from __future__ import annotations

import sys

from aegisguard_ulpf.cli.main import main
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


def test_verify_command_reports_complete_integrity_status(tmp_path, monkeypatch, capsys):
    store = RawEvidenceStore(tmp_path / "evidence")
    record = store.store(
        b"forensic test event",
        identity_context={"source": "verify-cli.log", "sequence": 1},
        transport="file",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ulpf", "verify", record.event_id, "--store", str(store.root)],
    )

    assert main() == 0

    output = capsys.readouterr().out
    assert "Original event found: YES" in output
    assert "Raw SHA-256 verified: PASS" in output
    assert "Hash chain verified: PASS" in output
    assert "Integrity: PASS" in output


def test_verify_command_returns_failure_for_unknown_event(tmp_path, monkeypatch, capsys):
    store = RawEvidenceStore(tmp_path / "evidence")
    monkeypatch.setattr(
        sys,
        "argv",
        ["ulpf", "verify", "EVT-does-not-exist", "--store", str(store.root)],
    )

    assert main() == 1
    assert "Original event found: NO" in capsys.readouterr().out
