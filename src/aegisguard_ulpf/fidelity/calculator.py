"""Calculate and write transparent, non-mutating mapping-fidelity reports."""

from __future__ import annotations

import json

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.fidelity.models import FidelityReport
from aegisguard_ulpf.normalization.fidelity import evaluate_mapping_fidelity


def _display_name(label: str) -> str:
    """Translate internal audit labels into stable, readable field paths."""

    prefixes = (
        ("field:", ""),
        ("details:", "details."),
        ("vendor:", "vendor_fields."),
        ("unmapped:", "details.unmapped_fields."),
    )
    for prefix, replacement in prefixes:
        if label.startswith(prefix):
            return replacement + label.removeprefix(prefix)
    return label


class FidelityCalculator:
    """Build a presentation-friendly fidelity report after normalization."""

    def calculate(
        self,
        fields: Mapping[str, Any],
        normalized_event: CommonEvent | None,
        *,
        dropped_fields: Iterable[str] = (),
        mapping_status: str | None = None,
    ) -> FidelityReport:
        """Classify every audited field without changing ``normalized_event``."""

        audit = evaluate_mapping_fidelity(
            fields,
            normalized_event,
            dropped_fields=dropped_fields,
            mapping_status=mapping_status,
        )

        details: dict[str, str] = {}
        for label in audit.mapped_fields:
            details[_display_name(label)] = "mapped"
        for label in audit.unmapped_fields:
            details[_display_name(label)] = "unmapped"
        for label in audit.dropped_fields:
            details[_display_name(label)] = "dropped"

        coverage = (
            round(audit.semantic_coverage * 100, 1)
            if audit.semantic_coverage is not None
            else 0.0
        )

        return FidelityReport(
            detected_fields=audit.fields_extracted,
            mapped_fields=audit.fields_semantically_mapped,
            unmapped_fields=audit.fields_unmapped,
            dropped_fields=audit.fields_dropped,
            coverage=coverage,
            field_details=details,
        )


def calculate_fidelity(
    fields: Mapping[str, Any],
    normalized_event: CommonEvent | None,
    *,
    dropped_fields: Iterable[str] = (),
    mapping_status: str | None = None,
) -> FidelityReport:
    """Convenience wrapper for calculating one post-normalization report."""

    return FidelityCalculator().calculate(
        fields,
        normalized_event,
        dropped_fields=dropped_fields,
        mapping_status=mapping_status,
    )


def write_fidelity_report(
    report: FidelityReport,
    output_path: str | Path,
) -> Path:
    """Write one fidelity report as formatted JSON, for example demo output."""

    if not isinstance(report, FidelityReport):
        raise TypeError("report must be a FidelityReport")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report.to_dict(), handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return path
