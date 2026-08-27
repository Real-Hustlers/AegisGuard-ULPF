"""Tests for the isolated, evidence-backed unknown-log handling layer."""

from __future__ import annotations

from aegisguard_ulpf.fallback import handle_unknown_log
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


def _handle(raw: bytes | str, tmp_path, *, sequence: int = 1):
    store = RawEvidenceStore(tmp_path / "evidence")
    event = handle_unknown_log(
        raw,
        evidence_store=store,
        identity_context={"source": "unknown.log", "sequence": sequence},
        transport="file",
    )
    return event, store


def test_unknown_vendor_syslog_is_preserved_with_unknown_hints(tmp_path):
    raw = b"<165>Sep 1 10:00:00 host nebula-agent: telemetry value=42"

    event, store = _handle(raw, tmp_path)

    assert event.status == "unknown_format"
    assert event.detected_format == "syslog"
    assert event.possible_vendor == "unknown"
    assert event.possible_product == "unknown"
    assert event.raw_preserved is True
    assert event.fidelity_available is True
    assert store.read_raw(event.event_id) == raw


def test_malformed_log_does_not_crash_or_discard_raw_evidence(tmp_path):
    raw = '{"event":"unterminated"'

    event, store = _handle(raw, tmp_path)

    assert event.status == "unknown_format"
    assert event.detected_format == "plain_text"
    assert event.raw_preserved is True
    assert store.read_raw(event.event_id) == raw.encode("utf-8")


def test_raw_bytes_are_preserved_without_decode_loss(tmp_path):
    raw = b"unsupported\xffbinary\x00event"

    event, store = _handle(raw, tmp_path)

    assert event.raw_preserved is True
    assert store.read_raw(event.event_id) == raw
    assert store.verify(event.event_id)["integrity"] == "PASS"


def test_partial_json_metadata_is_extracted_without_semantic_guessing(tmp_path):
    raw = '{"vendor":"Acme Security","message":"unrecognized telemetry"}'

    event, _ = _handle(raw, tmp_path)

    assert event.detected_format == "json"
    assert event.possible_vendor == "Acme Security"
    assert event.possible_product == "unknown"
    assert event.status == "unknown_format"
