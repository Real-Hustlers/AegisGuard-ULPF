import base64
import json
import sys
from datetime import datetime, timezone

from aegisguard_ulpf.cli.main import main
from aegisguard_ulpf.core.models import CommonEvent, EventClassification, EventTimestamps, TraceabilityReferences, VendorInformation
from aegisguard_ulpf.traceability import RawEvidenceStore, TraceabilityJsonlWriter


def test_raw_envelope_and_trace_mapping(tmp_path, monkeypatch, capsys):
    store = RawEvidenceStore(tmp_path / "evidence")
    record = store.store(b"raw\xffcontent", identity_context={"source": "fortigate.log", "sequence": 1})
    writer = TraceabilityJsonlWriter(tmp_path / "output")
    raw = json.loads(writer.write_raw_event(store, record.event_id).read_text(encoding="utf-8"))
    assert base64.b64decode(raw["raw_content"]) == b"raw\xffcontent"
    assert {"raw_id", "timestamp", "source", "sha256", "previous_hash", "chain_hash"} <= raw.keys()
    now = datetime.now(timezone.utc)
    event = CommonEvent(mapping_status="mapped", classification=EventClassification(), timestamps=EventTimestamps(observed_time=now, processed_time=now), vendor=VendorInformation(vendor="Fortinet", product="FortiGate"), traceability=TraceabilityReferences(u_id=record.event_id, raw_id=record.raw_id))
    trace = json.loads(writer.write_trace(event, store).read_text(encoding="utf-8"))
    assert trace["hash_verified"] is True
    monkeypatch.setattr(sys, "argv", ["ulpf", "trace", record.event_id, "--store", str(store.root)])
    assert main() == 0
    assert "Trace completed: PASS" in capsys.readouterr().out
