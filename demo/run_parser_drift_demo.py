"""Demonstrate local parser-fidelity drift detection."""

from __future__ import annotations

from aegisguard_ulpf.drift import detect_parser_drift


def main() -> None:
    baseline = 95.0
    current = 65.0
    alert = detect_parser_drift(
        previous_coverage=baseline,
        current_coverage=current,
        vendor="Fortigate",
        product="FortiGate",
        event_type="Traffic",
    )
    if alert is None:
        raise RuntimeError("The demonstration coverage regression was not detected")

    print("\n=== Parser Drift Detection ===\n")
    print("Baseline:")
    print("Fortigate Traffic")
    print("\nCoverage:")
    print(f"{baseline:.0f}%")
    print("\nAfter update:\n")
    print("Coverage:")
    print(f"{current:.0f}%")
    print("\nAlert:\n")
    print("PARSER_DRIFT DETECTED")


if __name__ == "__main__":
    main()
