"""Immutable public models for parser coverage drift alerts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParserDriftAlert:
    """A detected material decrease in parser field coverage."""

    vendor: str
    product: str
    event_type: str
    previous_coverage: float
    current_coverage: float
    threshold: float

    @property
    def change(self) -> float:
        """Return the coverage delta in percentage points."""

        return round(self.current_coverage - self.previous_coverage, 1)

    def to_dict(self) -> dict[str, object]:
        """Return the stable, presentation-safe drift event envelope."""

        return {
            "type": "PARSER_DRIFT",
            "source": self.vendor,
            "product": self.product,
            "event_type": self.event_type,
            "previous": f"{self.previous_coverage:g}%",
            "current": f"{self.current_coverage:g}%",
            "change": f"{self.change:+g}%",
            "threshold": f"{self.threshold:g}%",
        }
