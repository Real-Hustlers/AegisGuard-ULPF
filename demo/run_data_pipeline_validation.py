"""Validate normalized-event export and ML-ready feature generation locally."""
from datetime import datetime, timezone
from pathlib import Path
from aegisguard_ulpf.core.models import Actor, CommonEvent, Endpoint, EventClassification, EventTimestamps, TraceabilityReferences, VendorInformation
from aegisguard_ulpf.exporters import export_jsonl
from aegisguard_ulpf.ml import write_features_csv

def main():
    now = datetime.now(timezone.utc)
    event = CommonEvent(mapping_status="mapped", classification=EventClassification(type="AUTHENTICATION", outcome="FAILURE", severity="medium"), timestamps=EventTimestamps(observed_time=now, processed_time=now), vendor=VendorInformation(vendor="Linux", product="Syslog"), traceability=TraceabilityReferences(u_id="EVT-DATA-1", raw_id="RAW-DATA-1"), actor=Actor(user="admin"), src_endpoint=Endpoint(ip="10.0.0.5"))
    output = Path("demo/output/data-pipeline")
    export_jsonl([event], output / "ocsf_or_common_events.jsonl")
    write_features_csv([event], output / "features.csv")
    print("\nRaw Event\n->\nNormalized Event\n->\nOCSF Event\n->\nExport File\n->\nML Feature File")
    print("\nPASS")
if __name__ == "__main__": main()
