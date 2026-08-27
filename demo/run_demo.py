from pathlib import Path
from datetime import datetime, timezone

from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.normalization.ocsf.mapper import (
    map_common_event_to_ocsf,
)
from aegisguard_ulpf.outputs.json_file import JsonlOutputWriter
from aegisguard_ulpf.parsing.semantic_packs.loader import (
    load_semantic_pack,
)


BASE = Path("demo")

INPUT_FILE = BASE / "input" / "fortigate.log"
EVIDENCE_DIR = BASE / "evidence"
OUTPUT_DIR = BASE / "output"

PANOS_TRAFFIC_PACK_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aegisguard_ulpf"
    / "parsing"
    / "semantic_packs"
    / "packs"
    / "paloalto_panos_traffic_v1.json"
)


# ---------------------------------
# 1. Read raw log
# ---------------------------------

raw_bytes = INPUT_FILE.read_bytes()


# ---------------------------------
# 2. Store raw evidence
# ---------------------------------

store = RawEvidenceStore(EVIDENCE_DIR)

raw_record = store.store(
    raw_bytes,
    identity_context={
        "source": "fortigate.log",
        "sequence": 1,
    },
    transport="file",
)


print("\n=== RAW EVIDENCE ===")
print("Event ID:", raw_record.event_id)
print("Raw ID:", raw_record.raw_id)
print("SHA256:", raw_record.raw_sha256)


raw_event = RawEvent(
    event_id=raw_record.event_id,
    raw=raw_bytes.decode("utf-8"),
    transport="file",
    metadata={
        "source": "fortigate.log",
        "sequence": 1,
    },
    evidence_raw_id=raw_record.raw_id,
    raw_sha256=raw_record.raw_sha256,
)


# ---------------------------------
# 3. Simulated parser output
# ---------------------------------

fields = {
    "u_id": raw_record.event_id,
    "raw_id": raw_record.raw_id,

    "timestamp": "2026-08-27T09:30:00Z",

    "vendor": "Fortinet",
    "product": "FortiGate",

    "category": "network_activity",
    "type": "SESSION",
    "subtype": "SESSION_START",

    "outcome": "SUCCESS",
    "action": "allow",

    "src_ip": "10.0.0.10",
    "src_port": 50000,

    "dst_ip": "8.8.8.8",
    "dst_port": 53,

    "protocol": "UDP",

    "details": {
        "device_name": "FGT01",
        "session_id": "123456",
    },

    "vendor_fields": {
        "original_vendor": "Fortinet",
    },
}


# ---------------------------------
# 4. Normalize
# ---------------------------------

engine = NormalizationEngine()

event, report = engine.normalize_with_fidelity(
    fields,
    observed_time=datetime.now(timezone.utc),
    raw_preserved=True,
    integrity_verified=True,
)


print("\n=== NORMALIZATION ===")
print("Mapping:", report.mapping_status)
print("Mapped fields:", report.fields_semantically_mapped)
print("Unmapped fields:", report.fields_unmapped)


# ---------------------------------
# 5. JSONL Outputs
# ---------------------------------

writer = JsonlOutputWriter(OUTPUT_DIR)

writer.write_raw(
    raw_event
)

writer.write_normalized(
    event
)


# ---------------------------------
# 6. OCSF Mapping
# ---------------------------------

semantic_pack = load_semantic_pack(
    PANOS_TRAFFIC_PACK_PATH
)

ocsf_binding = semantic_pack.ocsf_binding


ocsf_event = map_common_event_to_ocsf(
    event,
    ocsf_binding,
)


writer.write_ocsf(
    ocsf_event
)


# ---------------------------------
# 7. Result
# ---------------------------------

print("\n=== OUTPUT FILES ===")

print("Raw:")
print(writer.raw_path)

print("Normalized:")
print(writer.normalized_path)

print("OCSF:")
print(writer.ocsf_path)


print("\nDemo completed successfully")