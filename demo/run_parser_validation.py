"""Validate an existing vendor parser through CommonEvent normalization."""
from __future__ import annotations
from datetime import datetime, timezone
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.parsing.vendors.fortinet.fortigate.traffic import convert_row

def main() -> None:
    fields = convert_row({"date": "2026-08-27", "time": "10:00:00", "type": "traffic", "srcip": "10.0.0.5", "dstip": "8.8.8.8", "action": "deny", "proto": "6"}, 1)
    now = datetime.now(timezone.utc)
    event = NormalizationEngine().normalize(fields, observed_time=now, processed_time=now)
    if event.vendor.vendor != "Fortinet":
        raise RuntimeError("FortiGate normalization failed")
    print("\nSource detected:")
    print("Fortigate")
    print("\nParser:")
    print("FortiGate traffic normalizer (convert_row)")
    print("\nNormalized Event:")
    print("PASS")

if __name__ == "__main__":
    main()
