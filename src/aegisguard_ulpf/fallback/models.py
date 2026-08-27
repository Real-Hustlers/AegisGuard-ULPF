"""Models for isolated unknown-log fallback handling."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class FallbackDetection:
    """Structural and non-authoritative identity hints for an unknown log."""

    detected_format: str
    possible_vendor: str = "unknown"
    possible_product: str = "unknown"


@dataclass(frozen=True)
class FallbackEvent:
    """Evidence-backed representation for a log without a dedicated parser."""

    status: str
    detected_format: str
    possible_vendor: str
    possible_product: str
    raw_preserved: bool
    fidelity_available: bool
    event_id: str
    raw_id: str
    raw_sha256: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe fallback event representation."""

        return asdict(self)


UnknownEvent = FallbackEvent
