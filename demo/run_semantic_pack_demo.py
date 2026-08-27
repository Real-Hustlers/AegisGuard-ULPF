"""Demonstrate adding a vendor through a signed declarative Semantic Pack."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.parsing.semantic_packs import (
    SemanticPackRuntime,
    load_semantic_pack,
)


ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = ROOT / "examples" / "semantic_packs" / "demo_vendor" / "semantic_pack.json"


def main() -> None:
    pack = load_semantic_pack(PACK_PATH)
    fields = SemanticPackRuntime(pack).run(
        "DEMO,traffic,allow,192.0.2.10,198.51.100.20",
        raw_id="RAW-DEMO-PACK-001",
        u_id="UEV-DEMO-PACK-001",
    )
    now = datetime.now(timezone.utc)
    event = NormalizationEngine().normalize(
        fields,
        observed_time=now,
        processed_time=now,
    )
    if event.vendor.vendor != "DemoVendor":
        raise RuntimeError("The DemoVendor Semantic Pack was not normalized")

    print("\n=== Semantic Pack Loading Demo ===\n")
    print("Pack loaded:")
    print(pack.manifest.vendor)
    print("\nEngine modification:")
    print("NONE")
    print("\nParser engine:")
    print("UNCHANGED")
    print("\nNormalization:")
    print("SUCCESS")


if __name__ == "__main__":
    main()
