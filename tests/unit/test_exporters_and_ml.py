import csv
import json
import pytest
from datetime import datetime, timezone
from aegisguard_ulpf.core.models import Actor, CommonEvent, Endpoint, EventClassification, EventTimestamps, TraceabilityReferences, VendorInformation
from aegisguard_ulpf.exporters import export_csv, export_jsonl, export_parquet
from aegisguard_ulpf.ml import extract_features, write_features_csv
from aegisguard_ulpf.outputs.unified import write_unified_events

def event():
    now = datetime.now(timezone.utc)
    return CommonEvent(mapping_status="mapped", classification=EventClassification(type="AUTHENTICATION", outcome="FAILURE", severity="medium"), timestamps=EventTimestamps(observed_time=now, processed_time=now), vendor=VendorInformation(vendor="Linux", product="Syslog"), traceability=TraceabilityReferences(u_id="EVT-1", raw_id="RAW-1"), actor=Actor(user="admin"), src_endpoint=Endpoint(ip="10.0.0.5"))

def test_exports_features_and_unified_output(tmp_path):
    events = [event()]
    assert json.loads(export_jsonl(events, tmp_path / "events.jsonl").read_text())["traceability"]["raw_id"] == "RAW-1"
    assert "classification.type" in export_csv(events, tmp_path / "events.csv").read_text()
    assert extract_features(events)[0]["failed_login_count"] == 1
    assert list(csv.DictReader(write_features_csv(events, tmp_path / "features.csv").open()))[0]["unique_users"] == "1"
    assert (tmp_path / "unified_events.jsonl") == write_unified_events(events, tmp_path / "unified_events.jsonl")

def test_parquet_requires_explicit_optional_dependency(tmp_path):
    with pytest.raises(RuntimeError, match="pyarrow"):
        export_parquet([event()], tmp_path / "events.parquet")
