from aegisguard_ulpf.core.exceptions import ParserNotFoundError
from aegisguard_ulpf.core.models import (
    DetectionResult,
    ProcessingResult,
    RawEvent,
)
from aegisguard_ulpf.detection.engine import DetectionEngine
from aegisguard_ulpf.parsing.registry import ParserRegistry


class ProcessingPipeline:
    """
    AegisGuard ULPF processing pipeline v1.

    Pipeline:
        RawEvent
            ->
        DetectionEngine
            ->
        DetectionResult
            ->
        ParserRegistry
            ->
        BaseParser
            ->
        ParsedEvent
            ->
        ProcessingResult
    """

    def __init__(
        self,
        registry: ParserRegistry,
        detection_engine: DetectionEngine | None = None,
    ) -> None:
        self.registry = registry

        self.detection_engine = (
            detection_engine
            or DetectionEngine()
        )

    def detect(
        self,
        event: RawEvent,
    ) -> DetectionResult:
        """
        Detect the source, format, and event family
        without parsing the event.
        """

        return self.detection_engine.detect(event)

    def process(
        self,
        event: RawEvent,
    ) -> ProcessingResult:
        """
        Detect the event, locate the correct parser,
        parse it, and return the complete processing result.
        """

        detection = self.detect(event)

        if detection.parser_id is None:
            raise ParserNotFoundError(
                "Detection completed but no parser_id "
                "could be selected for the event."
            )

        parser = self.registry.get(
            detection.parser_id
        )

        parsed_event = parser.parse(event)

        return ProcessingResult(
            raw_event=event,
            detection=detection,
            parsed_event=parsed_event,
        )