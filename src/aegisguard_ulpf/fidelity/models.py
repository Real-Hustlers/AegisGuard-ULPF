"""Models for the public mapping-fidelity report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


FieldDisposition = Literal["mapped", "unmapped", "dropped"]


@dataclass(frozen=True)
class FidelityReport:
    """A concise, field-by-field view of normalization fidelity.

    ``detected_fields`` is the number of meaningful parser/extraction fields
    audited by the existing normalization-fidelity rules. Control identifiers
    and absent values are not counted as semantic fields.
    """

    detected_fields: int
    mapped_fields: int
    unmapped_fields: int
    dropped_fields: int
    coverage: float
    field_details: dict[str, FieldDisposition]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation without exposing mutable state."""

        return {
            "detected_fields": self.detected_fields,
            "mapped_fields": self.mapped_fields,
            "unmapped_fields": self.unmapped_fields,
            "dropped_fields": self.dropped_fields,
            "coverage": self.coverage,
            "field_details": dict(self.field_details),
        }
