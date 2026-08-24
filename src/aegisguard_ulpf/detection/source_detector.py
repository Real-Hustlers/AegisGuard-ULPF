from aegisguard_ulpf.core.models import (
    DetectionResult,
    RawEvent,
)
from aegisguard_ulpf.detection.fingerprints.cisco import (
    CiscoFingerprint,
)
from aegisguard_ulpf.detection.fingerprints.fortinet import (
    FortinetFingerprint,
)
from aegisguard_ulpf.detection.fingerprints.palo_alto import (
    PaloAltoFingerprint,
)


class SourceDetector:
    """
    Vendor/product detection coordinator.

    Vendor-specific fingerprints are implemented
    independently and evaluated by this detector.
    """

    def __init__(self) -> None:
        self._fingerprints = [
            FortinetFingerprint(),
            CiscoFingerprint(),
            PaloAltoFingerprint(),
        ]

    def detect(
        self,
        event: RawEvent,
        format_result: DetectionResult | None = None,
    ) -> DetectionResult:

        detected_format = (
            format_result.format
            if format_result
            else None
        )

        if not event.raw.strip():
            return DetectionResult(
                format=detected_format,
                confidence=0.0,
                evidence=["empty event"],
            )

        candidates: list[DetectionResult] = []

        for fingerprint in self._fingerprints:

            result = fingerprint.detect(event.raw)

            if result is not None:
                result.format = detected_format
                candidates.append(result)

        if not candidates:
            return DetectionResult(
                format=detected_format,
                confidence=0.0,
                evidence=[
                    "no supported vendor fingerprint matched"
                ],
            )

        # Highest-confidence fingerprint wins.
        return max(
            candidates,
            key=lambda result: result.confidence,
        )