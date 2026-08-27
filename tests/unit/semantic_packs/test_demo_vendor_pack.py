"""The demonstration vendor is onboarded by data, not a Python parser."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.parsing.semantic_packs import (
    SemanticPackRuntime,
    load_semantic_pack,
)


PACK_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "semantic_packs"
    / "demo_vendor"
    / "semantic_pack.json"
)


def test_demo_vendor_json_pack_loads_with_a_valid_mapping_contract():
    pack = load_semantic_pack(PACK_PATH)

    assert pack.manifest.vendor == "DemoVendor"
    assert pack.manifest.product == "DemoFirewall"
    assert pack.ocsf_binding.status == "deferred"
    assert pack.ocsf_binding.class_uid is None


def test_demo_vendor_requires_no_python_parser_module():
    pack = load_semantic_pack(PACK_PATH)
    runtime = SemanticPackRuntime(pack)

    fields = runtime.run(
        "DEMO,traffic,allow,192.0.2.10,198.51.100.20",
        raw_id="RAW-DEMO-PACK-001",
        u_id="UEV-DEMO-PACK-001",
    )

    assert PACK_PATH.suffix == ".json"
    assert fields["vendor"] == "DemoVendor"
    assert fields["type"] == "SESSION"
    assert fields["vendor_fields"]["source_ip"] == "192.0.2.10"


def test_demo_vendor_pack_normalizes_through_the_existing_engine():
    pack = load_semantic_pack(PACK_PATH)
    fields = SemanticPackRuntime(pack).run(
        "DEMO,traffic,allow,192.0.2.10,198.51.100.20",
        raw_id="RAW-DEMO-PACK-001",
        u_id="UEV-DEMO-PACK-001",
    )
    now = datetime(2026, 9, 2, tzinfo=timezone.utc)

    event = NormalizationEngine().normalize(
        fields,
        observed_time=now,
        processed_time=now,
    )

    assert event.vendor.vendor == "DemoVendor"
    assert event.vendor.product == "DemoFirewall"
    assert event.mapping_status == "mapped"
