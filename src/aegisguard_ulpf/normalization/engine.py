from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from aegisguard_ulpf.core.models import (
    CommonEvent,
    MappingStatus,
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
            processed_time = datetime.now(timezone.utc)

        event = map_legacy_common_event(
            fields,
            observed_time=observed_time,
            processed_time=processed_time,
            mapping_status=mapping_status,
        )

        return validate_common_event(event)
