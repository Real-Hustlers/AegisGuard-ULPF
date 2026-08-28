"""Generate parser-drift evidence from measured FortiGate fidelity."""

from __future__ import annotations

import shlex

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisguard_ulpf.drift import (
    build_parser_drift_report,
    write_parser_drift_report,
)
from aegisguard_ulpf.fidelity import calculate_fidelity
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.parsing.vendors.fortinet.fortigate.traffic import (
    convert_row,
)


ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "demo" / "input" / "multivendor" / "fortigate.log"
REPORT_PATH = ROOT / "demo" / "evidence" / "parser_drift" / "drift_report.json"

# Simulate an upstream vendor-format revision. The raw values are retained,
# but five familiar FortiGate keys arrive under new names that the unchanged
# parser does not yet map. Coverage is measured after parsing/normalization.
MODIFIED_FORMAT_ALIASES = {
    "srcip": "source_ip",
    "dstip": "destination_ip",
    "srcport": "source_port",
    "dstport": "destination_port",
    "proto": "protocol_number",
}


def _extract_key_values(raw_log: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in shlex.split(raw_log):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            fields[key] = value
    return fields


def _measure_fidelity(
    row: dict[str, str],
    *,
    record_number: int,
    observed_time: datetime,
):
    parser_fields = convert_row(row, record_number)
    normalized = NormalizationEngine().normalize(
        parser_fields,
        observed_time=observed_time,
        processed_time=observed_time,
    )
    return (
        parser_fields,
        calculate_fidelity(
            parser_fields,
            normalized,
        ),
    )


def generate_drift_report(
    output_path: str | Path = REPORT_PATH,
) -> dict[str, Any]:
    """Measure the existing and modified formats, then write JSON evidence."""

    raw_log = INPUT_PATH.read_text(
        encoding="utf-8",
    ).strip()
    baseline_row = _extract_key_values(raw_log)
    current_row = {
        MODIFIED_FORMAT_ALIASES.get(key, key): value
        for key, value in baseline_row.items()
    }
    observed_time = datetime.now(timezone.utc)

    baseline_fields, baseline_fidelity = _measure_fidelity(
        baseline_row,
        record_number=1,
        observed_time=observed_time,
    )
    _, current_fidelity = _measure_fidelity(
        current_row,
        record_number=2,
        observed_time=observed_time,
    )

    report = build_parser_drift_report(
        baseline_fidelity,
        current_fidelity,
        vendor=str(baseline_fields["vendor"]),
        product=str(baseline_fields["product"]),
        event_family=str(baseline_fields["type"]).title(),
    )
    write_parser_drift_report(
        report,
        output_path,
    )
    return report


def main() -> None:
    report = generate_drift_report()

    print("\n=== Parser Drift Detection ===\n")
    print("Vendor:")
    print(report["vendor"])
    print("\nProduct:")
    print(report["product"])
    print("\nBaseline Coverage:")
    print(f"{report['baseline']['coverage']:g}%")
    print("\nCurrent Coverage:")
    print(f"{report['current']['coverage']:g}%")
    print("\nField Loss:")
    print(report["field_loss"])
    print("\nStatus:")
    print(
        "PARSER DRIFT DETECTED"
        if report["status"] == "DETECTED"
        else "NO PARSER DRIFT DETECTED"
    )
    print("\nEvidence:")
    print(REPORT_PATH.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
