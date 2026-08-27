"""Demonstrate FortiGate, Windows, and Linux CommonEvents on one timeline."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from aegisguard_ulpf.core.models import Actor, CommonEvent, Endpoint, EventClassification, EventTimestamps, TraceabilityReferences, VendorInformation
from aegisguard_ulpf.visibility import write_unified_timeline

def event(source, offset):
    now = datetime(2026, 8, 27, tzinfo=timezone.utc) + timedelta(minutes=offset)
    return CommonEvent(mapping_status="mapped", classification=EventClassification(type="AUTHENTICATION", subtype="AUTH_FAILURE", severity="medium"), timestamps=EventTimestamps(event_time=now, observed_time=now, processed_time=now), vendor=VendorInformation(vendor=source, product=source), traceability=TraceabilityReferences(u_id=f"EVT-{source}", raw_id=f"RAW-{source}"), actor=Actor(user="admin"), src_endpoint=Endpoint(ip="10.0.0.5"))

def main():
    output = write_unified_timeline([event("FortiGate", 1), event("Windows", 2), event("Linux", 3)], Path("demo/output/unified-events/unified_events.jsonl"))
    print("\nMultiple Raw Sources\n->\nAegisGuard-ULPF\n->\nUnified Timeline Output\n")
    print("PASS")
    print(output)
if __name__ == "__main__": main()
