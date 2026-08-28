"""Machine-readable parser-drift evidence derived from fidelity reports."""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any

from aegisguard_ulpf.drift.detector import (
    DEFAULT_COVERAGE_THRESHOLD,
    detect_parser_drift,
)
from aegisguard_ulpf.fidelity.models import FidelityReport


def _coverage(report: FidelityReport) -> float:
    """Calculate mapped/detected coverage from audited fidelity counts."""

    if report.detected_fields < 0 or report.mapped_fields < 0:
        raise ValueError("Fidelity field counts cannot be negative")
    if report.mapped_fields > report.detected_fields:
        raise ValueError("Mapped fields cannot exceed detected fields")
    if report.detected_fields == 0:
        return 0.0
    return round(
        report.mapped_fields
        / report.detected_fields
        * 100,
        1,
    )


def build_parser_drift_report(
    baseline: FidelityReport,
    current: FidelityReport,
    *,
    vendor: str,
    product: str,
    event_family: str,
    threshold: float = DEFAULT_COVERAGE_THRESHOLD,
) -> dict[str, Any]:
    """Build an auditable report from two fidelity measurements."""

    if not isinstance(baseline, FidelityReport):
        raise TypeError("baseline must be a FidelityReport")
    if not isinstance(current, FidelityReport):
        raise TypeError("current must be a FidelityReport")

    baseline_coverage = _coverage(baseline)
    current_coverage = _coverage(current)
    alert = detect_parser_drift(
        previous_coverage=baseline_coverage,
        current_coverage=current_coverage,
        vendor=vendor,
        product=product,
        event_type=event_family,
        threshold=threshold,
    )

    return {
        "type": "PARSER_DRIFT",
        "vendor": vendor,
        "product": product,
        "event_family": event_family,
        "baseline": {
            "coverage": baseline_coverage,
            "mapped_fields": baseline.mapped_fields,
            "total_fields": baseline.detected_fields,
        },
        "current": {
            "coverage": current_coverage,
            "mapped_fields": current.mapped_fields,
            "total_fields": current.detected_fields,
        },
        "field_loss": max(
            baseline.mapped_fields
            - current.mapped_fields,
            0,
        ),
        "status": (
            "DETECTED"
            if alert is not None
            else "STABLE"
        ),
    }


def write_parser_drift_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Persist one report as deterministic, human-readable JSON evidence."""

    if not isinstance(report, dict):
        raise TypeError("report must be a dictionary")

    path = Path(output_path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            report,
            handle,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        handle.write("\n")

    return path
