"""Detect material parser mapping-fidelity regressions."""

from __future__ import annotations

from aegisguard_ulpf.drift.models import ParserDriftAlert


DEFAULT_COVERAGE_THRESHOLD = 20.0


def _validate_coverage(name: str, value: float) -> float:
    if not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    coverage = float(value)
    if not 0.0 <= coverage <= 100.0:
        raise ValueError(f"{name} must be between 0 and 100")
    return coverage


class ParserDriftDetector:
    """Compare two externally supplied fidelity measurements.

    The detector is deliberately stateless: callers retain their own baseline
    storage while this component makes the comparison transparent and local.
    """

    def __init__(self, threshold: float = DEFAULT_COVERAGE_THRESHOLD) -> None:
        self.threshold = _validate_coverage("threshold", threshold)

    def detect(
        self,
        *,
        previous_coverage: float,
        current_coverage: float,
        vendor: str,
        product: str,
        event_type: str,
    ) -> ParserDriftAlert | None:
        """Return an alert only when coverage falls beyond the threshold."""

        previous = _validate_coverage("previous_coverage", previous_coverage)
        current = _validate_coverage("current_coverage", current_coverage)
        if not all(isinstance(value, str) and value.strip() for value in (vendor, product, event_type)):
            raise ValueError("vendor, product, and event_type are required")

        if current >= previous - self.threshold:
            return None

        return ParserDriftAlert(
            vendor=vendor,
            product=product,
            event_type=event_type,
            previous_coverage=previous,
            current_coverage=current,
            threshold=self.threshold,
        )


def detect_parser_drift(
    *,
    previous_coverage: float,
    current_coverage: float,
    vendor: str,
    product: str,
    event_type: str,
    threshold: float = DEFAULT_COVERAGE_THRESHOLD,
) -> ParserDriftAlert | None:
    """Convenience wrapper for a single coverage comparison."""

    return ParserDriftDetector(threshold).detect(
        previous_coverage=previous_coverage,
        current_coverage=current_coverage,
        vendor=vendor,
        product=product,
        event_type=event_type,
    )
