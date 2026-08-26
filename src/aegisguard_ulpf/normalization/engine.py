from collections.abc import (
    Iterable,
    Mapping,
)
from datetime import datetime, timezone
from typing import Any

from aegisguard_ulpf.core.models import (
    CommonEvent,
    MappingStatus,
)
from aegisguard_ulpf.normalization.fidelity import (
    MappingFidelityReport,
    evaluate_mapping_fidelity,
)
from aegisguard_ulpf.normalization.mapper import (
    map_legacy_common_event,
)
from aegisguard_ulpf.normalization.validators import (
    validate_common_event,
)


class NormalizationEngine:
    def normalize(
        self,
        fields: Mapping[str, Any],
        *,
        observed_time: datetime,
        processed_time: datetime | None = None,
        mapping_status: MappingStatus = "mapped",
    ) -> CommonEvent:

        if processed_time is None:
            processed_time = datetime.now(
                timezone.utc
            )

        event = map_legacy_common_event(
            fields,
            observed_time=observed_time,
            processed_time=processed_time,
            mapping_status=mapping_status,
        )

        return validate_common_event(
            event
        )

    def normalize_with_fidelity(
        self,
        fields: Mapping[str, Any],
        *,
        observed_time: datetime,
        processed_time: datetime | None = None,
        mapping_status: MappingStatus = "mapped",
        dropped_fields: Iterable[str] = (),
        source_field_count: int | None = None,
        raw_preserved: bool = False,
        integrity_verified: bool = False,
    ) -> tuple[
        CommonEvent,
        MappingFidelityReport,
    ]:
        """
        Normalize one event and return a separate
        auditable fidelity report.

        Common Schema v1 remains unchanged.
        """

        event = self.normalize(
            fields,
            observed_time=observed_time,
            processed_time=processed_time,
            mapping_status=mapping_status,
        )

        report = evaluate_mapping_fidelity(
            fields,
            event,
            dropped_fields=dropped_fields,
            source_field_count=source_field_count,
            raw_preserved=raw_preserved,
            integrity_verified=integrity_verified,
        )

        # Fidelity evidence is authoritative for whether
        # mapping is complete. Unmapped/dropped fields must
        # not coexist with mapping_status="mapped".
        if (
            report.mapping_status
            != event.mapping_status
        ):
            event = event.model_copy(
                update={
                    "mapping_status":
                        report.mapping_status
                }
            )

            event = validate_common_event(
                event
            )

        return (
            event,
            report,
        )