from __future__ import annotations

from collections.abc import (
    Iterable,
    Mapping,
)
from dataclasses import (
    asdict,
    dataclass,
)
from typing import Any, Literal

from aegisguard_ulpf.core.models import (
    CommonEvent,
)


FidelityMappingStatus = Literal[
    "mapped",
    "incomplete",
]


_CONTROL_FIELDS = frozenset({
    "u_id",
    "raw_id",
    "mapping_status",
})


_CONTAINER_FIELDS = frozenset({
    "details",
    "vendor_fields",
})


_KNOWN_SEMANTIC_FIELDS = frozenset({
    "timestamp",
    "vendor",
    "product",
    "category",
    "type",
    "subtype",
    "outcome",
    "severity",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "user",
    "action",
    "reason",
    "object_type",
    "object_name",
    "vendor_event_id",
})


_RESERVED_DETAIL_FIELDS = frozenset({
    "unmapped_fields",
    "dropped_fields",
    "tier0",
    "fidelity",
})


@dataclass(frozen=True)
class MappingFidelityReport:
    """
    Auditable mapping-fidelity result.

    This deliberately does NOT expose a single
    "accuracy percentage".

    extraction_coverage:
        fields_extracted / source_field_count

        It is None when the original source-field count
        is unknown. We do not fabricate 100% coverage.

    semantic_coverage:
        fields_semantically_mapped / fields_extracted
    """

    mapping_status: FidelityMappingStatus

    fields_extracted: int
    fields_semantically_mapped: int
    fields_unmapped: int
    fields_dropped: int

    mapped_fields: tuple[str, ...]
    unmapped_fields: tuple[str, ...]
    dropped_fields: tuple[str, ...]

    extraction_coverage: float | None
    semantic_coverage: float | None

    raw_preserved: bool
    integrity_verified: bool

    extraction_coverage_reason: str | None = None

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(
            self
        )


def _has_meaningful_value(
    value: Any,
) -> bool:

    if value is None:
        return False

    if isinstance(
        value,
        str,
    ):
        return bool(
            value.strip()
        )

    if isinstance(
        value,
        Mapping,
    ):
        return bool(
            value
        )

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        return bool(
            value
        )

    # False and numeric zero are meaningful values.
    return True


def _field_label(
    name: str,
) -> str:
    return f"field:{name}"


def _detail_label(
    name: str,
) -> str:
    return f"details:{name}"


def _vendor_label(
    name: str,
) -> str:
    return f"vendor:{name}"


def _unmapped_label(
    name: str,
) -> str:
    return f"unmapped:{name}"


def _normalize_dropped_fields(
    dropped_fields: Iterable[str],
) -> set[str]:

    normalized: set[str] = set()

    for value in dropped_fields:

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "dropped_fields entries must be strings"
            )

        value = value.strip()

        if not value:
            continue

        if ":" in value:
            normalized.add(
                value
            )
        else:
            normalized.add(
                _field_label(
                    value
                )
            )

    return normalized


def _normalized_unmapped_fields(
    event: CommonEvent | None,
) -> dict[str, Any]:

    if event is None:
        return {}

    value = event.details.get(
        "unmapped_fields"
    )

    if value is None:
        return {}

    if isinstance(
        value,
        Mapping,
    ):
        return dict(
            value
        )

    return {
        "legacy_unmapped_fields":
            value
    }


def evaluate_mapping_fidelity(
    fields: Mapping[str, Any],
    normalized_event: CommonEvent | None,
    *,
    mapping_status: FidelityMappingStatus | None = None,
    dropped_fields: Iterable[str] = (),
    source_field_count: int | None = None,
    raw_preserved: bool = False,
    integrity_verified: bool = False,
) -> MappingFidelityReport:
    """
    Evaluate normalization fidelity without pretending
    that unresolved fields were semantically mapped.

    Rules:

    - absent values are not counted
    - vendor_fields are unresolved/unmapped
    - details.unmapped_fields are unresolved/unmapped
    - explicitly dropped fields are counted separately
    - ordinary semantic detail fields are mapped context
    - Tier-0 control metadata is not counted as semantics
    - traceability/control IDs are not extraction fields
    """

    if not isinstance(
        fields,
        Mapping,
    ):
        raise TypeError(
            "fields must be a mapping"
        )

    if source_field_count is not None:

        if isinstance(
            source_field_count,
            bool,
        ):
            raise TypeError(
                "source_field_count must be an integer or None"
            )

        if not isinstance(
            source_field_count,
            int,
        ):
            raise TypeError(
                "source_field_count must be an integer or None"
            )

        if source_field_count < 0:
            raise ValueError(
                "source_field_count cannot be negative"
            )

    if (
        integrity_verified
        and not raw_preserved
    ):
        raise ValueError(
            "integrity_verified cannot be True when "
            "raw_preserved is False"
        )

    if mapping_status is not None and mapping_status not in {
        "mapped",
        "incomplete",
    }:
        raise ValueError(
            "mapping_status must be 'mapped', "
            "'incomplete', or None"
        )

    if mapping_status is None:

        if normalized_event is None:
            raise ValueError(
                "mapping_status is required when "
                "normalized_event is None"
            )

        base_mapping_status = (
            normalized_event.mapping_status
        )

    else:
        base_mapping_status = (
            mapping_status
        )

    mapped: set[str] = set()
    unmapped: set[str] = set()

    explicit_dropped = (
        _normalize_dropped_fields(
            dropped_fields
        )
    )

    # -------------------------------------------------
    # Top-level parser/normalization fields
    # -------------------------------------------------

    for key, value in fields.items():

        if key in _CONTROL_FIELDS:
            continue

        if key in _CONTAINER_FIELDS:
            continue

        if not _has_meaningful_value(
            value
        ):
            # Absent != unmapped.
            continue

        label = _field_label(
            key
        )

        if key in _KNOWN_SEMANTIC_FIELDS:
            mapped.add(
                label
            )
        else:
            # Unknown top-level values are not silently
            # counted as semantic mappings.
            unmapped.add(
                label
            )

    # -------------------------------------------------
    # Semantic detail fields
    # -------------------------------------------------

    details = fields.get(
        "details"
    )

    if isinstance(
        details,
        Mapping,
    ):

        for key, value in details.items():

            if key in _RESERVED_DETAIL_FIELDS:
                continue

            if not _has_meaningful_value(
                value
            ):
                continue

            mapped.add(
                _detail_label(
                    str(key)
                )
            )

    # -------------------------------------------------
    # Explicit vendor/unresolved fields
    # -------------------------------------------------

    vendor_fields = fields.get(
        "vendor_fields"
    )

    if isinstance(
        vendor_fields,
        Mapping,
    ):

        for key, value in vendor_fields.items():

            if not _has_meaningful_value(
                value
            ):
                continue

            unmapped.add(
                _vendor_label(
                    str(key)
                )
            )

    # -------------------------------------------------
    # Normalizer-generated unmapped evidence
    # -------------------------------------------------

    normalized_unmapped = (
        _normalized_unmapped_fields(
            normalized_event
        )
    )

    for key, value in normalized_unmapped.items():

        if not _has_meaningful_value(
            value
        ):
            continue

        key = str(
            key
        )

        if key in _CONTROL_FIELDS:
            continue

        top_level_label = (
            _field_label(
                key
            )
        )

        # Conversion failures such as malformed timestamp
        # or port must not remain counted as mapped.
        mapped.discard(
            top_level_label
        )

        # If this value was already classified as an
        # unmapped top-level parser field, keep that
        # disposition instead of counting it twice.
        if top_level_label in unmapped:
            continue

        unmapped.add(
            _unmapped_label(
                key
            )
        )

    # -------------------------------------------------
    # Dropped fields are their own disposition.
    # -------------------------------------------------

    for label in explicit_dropped:

        mapped.discard(
            label
        )

        unmapped.discard(
            label
        )

    mapped -= explicit_dropped
    unmapped -= explicit_dropped

    # Defensive guarantee:
    # one audited field cannot have two dispositions.
    overlap = (
        mapped
        & unmapped
    )

    if overlap:
        raise ValueError(
            "Fidelity classification overlap detected: "
            + ", ".join(
                sorted(
                    overlap
                )
            )
        )

    audited_fields = (
        mapped
        | unmapped
        | explicit_dropped
    )

    fields_extracted = len(
        audited_fields
    )

    mapped_count = len(
        mapped
    )

    unmapped_count = len(
        unmapped
    )

    dropped_count = len(
        explicit_dropped
    )

    # -------------------------------------------------
    # Extraction coverage
    # -------------------------------------------------

    extraction_coverage: (
        float
        | None
    )

    extraction_reason: (
        str
        | None
    )

    if source_field_count is None:

        extraction_coverage = None

        extraction_reason = (
            "source_field_count_not_provided"
        )

    elif source_field_count == 0:

        extraction_coverage = (
            1.0
            if fields_extracted == 0
            else None
        )

        extraction_reason = (
            None
            if fields_extracted == 0
            else
            "extracted_fields_exceed_zero_source_count"
        )

    elif fields_extracted > source_field_count:

        # Parser semantic expansion can produce more
        # normalized audit items than original source fields.
        # Do not fabricate a >100% extraction coverage.
        extraction_coverage = None

        extraction_reason = (
            "audit_items_exceed_source_field_count"
        )

    else:

        extraction_coverage = round(
            fields_extracted
            / source_field_count,
            6,
        )

        extraction_reason = None

    # -------------------------------------------------
    # Semantic coverage
    # -------------------------------------------------

    semantic_coverage = (
        round(
            mapped_count
            / fields_extracted,
            6,
        )
        if fields_extracted
        else None
    )

    result_mapping_status: FidelityMappingStatus = (
        "incomplete"
        if (
            base_mapping_status
            == "incomplete"
            or unmapped_count > 0
            or dropped_count > 0
        )
        else "mapped"
    )

    return MappingFidelityReport(
        mapping_status=result_mapping_status,

        fields_extracted=(
            fields_extracted
        ),

        fields_semantically_mapped=(
            mapped_count
        ),

        fields_unmapped=(
            unmapped_count
        ),

        fields_dropped=(
            dropped_count
        ),

        mapped_fields=tuple(
            sorted(
                mapped
            )
        ),

        unmapped_fields=tuple(
            sorted(
                unmapped
            )
        ),

        dropped_fields=tuple(
            sorted(
                explicit_dropped
            )
        ),

        extraction_coverage=(
            extraction_coverage
        ),

        semantic_coverage=(
            semantic_coverage
        ),

        raw_preserved=(
            raw_preserved
        ),

        integrity_verified=(
            integrity_verified
        ),

        extraction_coverage_reason=(
            extraction_reason
        ),
    )