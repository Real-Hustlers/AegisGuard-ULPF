from aegisguard_ulpf.core.models import (
    DetectionResult,
    RawEvent,
)
from aegisguard_ulpf.detection.event_family_detector import (
    EventFamilyDetector,
)
from aegisguard_ulpf.detection.format_detector import (
    FormatDetector,
)
from aegisguard_ulpf.detection.source_detector import (
    SourceDetector,
)


class DetectionEngine:
    """
    Coordinates AegisGuard ULPF detection stages.

    Pipeline:
        RawEvent
            ->
        FormatDetector
            ->
        SourceDetector
            ->
        EventFamilyDetector
            ->
        DetectionResult
    """

    def __init__(
        self,
        format_detector: FormatDetector | None = None,
        source_detector: SourceDetector | None = None,
        event_family_detector: EventFamilyDetector | None = None,
    ) -> None:

        self.format_detector = (
            format_detector
            or FormatDetector()
        )

        self.source_detector = (
            source_detector
            or SourceDetector()
        )

        self.event_family_detector = (
            event_family_detector
            or EventFamilyDetector()
        )

    def detect(
        self,
        event: RawEvent,
    ) -> DetectionResult:
        """
        Run the complete detection pipeline
        for one RawEvent.
        """

        # -------------------------------------------------
        # STEP 1: FORMAT DETECTION
        # -------------------------------------------------

        format_result = (
            self.format_detector.detect(event)
        )

        # -------------------------------------------------
        # STEP 2: SOURCE DETECTION
        # -------------------------------------------------

        source_result = (
            self.source_detector.detect(
                event,
                format_result,
            )
        )

        # If source cannot be identified,
        # we cannot reliably select a vendor parser.
        if (
            source_result.vendor is None
            or source_result.product is None
        ):
            return source_result

        # -------------------------------------------------
        # STEP 3: EVENT FAMILY DETECTION
        # -------------------------------------------------

        family_result = (
            self.event_family_detector.detect(
                event,
                source_result,
            )
        )

        return family_result