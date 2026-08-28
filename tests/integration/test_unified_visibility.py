import json
from datetime import datetime, timedelta, timezone
from aegisguard_ulpf.core.models import Actor, CommonEvent, Endpoint, EventClassification, EventTimestamps, TraceabilityReferences, VendorInformation
from aegisguard_ulpf.visibility import build_unified_timeline, write_unified_timeline

def make_event(product, number):
    now = datetime(2026, 8, 27, tzinfo=timezone.utc) + timedelta(minutes=number)
    return CommonEvent(mapping_status="mapped", classification=EventClassification(type="AUTHENTICATION", subtype="AUTH_FAILURE", severity="medium"), timestamps=EventTimestamps(event_time=now, observed_time=now, processed_time=now), vendor=VendorInformation(vendor=product, product=product), traceability=TraceabilityReferences(u_id=f"EVT-{number}", raw_id=f"RAW-{number}"), actor=Actor(user="admin"), src_endpoint=Endpoint(ip=f"10.0.0.{number}"))

def test_multi_source_timeline_is_consistent_and_sorted(tmp_path):
    events = [make_event("Linux", 3), make_event("FortiGate", 1), make_event("Windows", 2)]
    timeline = build_unified_timeline(events)
    assert [item["source"] for item in timeline] == ["FortiGate", "Windows", "Linux"]
    assert all({"source", "event_type", "timestamp", "raw_id", "u_id"} <= item.keys() for item in timeline)
    path = write_unified_timeline(events, tmp_path / "unified_events.jsonl")
    assert len([json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]) == 3
