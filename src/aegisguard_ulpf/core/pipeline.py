from __future__ import annotations

from typing import Any

from aegisguard_ulpf.core.exceptions import ParserNotFoundError
from aegisguard_ulpf.core.models import (
    DetectionResult,
    ProcessingResult,
    RawEvent,
)
from aegisguard_ulpf.fallback.tier0 import (
    Tier0Fallback,
)
from aegisguard_ulpf.detection.engine import DetectionEngine
from aegisguard_ulpf.parsing.registry import ParserRegistry
from aegisguard_ulpf.parsing.semantic_packs.resolver import (
    SemanticPackResolver,
)
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


class ProcessingPipeline:
    """
    AegisGuard ULPF processing pipeline v1.

    Standard flow:

        RawEvent
            ->
        DetectionEngine
            ->
        ParserRegistry
            ->
        ParsedEvent
            ->
        ProcessingResult

    For forensic/raw-byte ingestion use process_bytes().
    """

    def __init__(
        self,
        registry: ParserRegistry,
        detection_engine: DetectionEngine | None = None,
        tier0_fallback: Tier0Fallback | None = None,
        semantic_pack_resolver: SemanticPackResolver | None = None,
    ) -> None:
        self.registry = registry

        self.detection_engine = (
            detection_engine
            or DetectionEngine()
        )

        self.tier0_fallback = (
            tier0_fallback
            or Tier0Fallback()
        )

        self.semantic_pack_resolver = (
            semantic_pack_resolver
            or SemanticPackResolver()
        )

    def detect(
        self,
        event: RawEvent,
    ) -> DetectionResult:
        return self.detection_engine.detect(
            event
        )

    def process(
        self,
        event: RawEvent,
    ) -> ProcessingResult:
        detection = self.detect(
            event
        )

        parsed_event = (
            self.semantic_pack_resolver.parse(
                event,
                detection,
            )
        )

        if (
            parsed_event is None
            and detection.parser_id is None
        ):

            parsed_event = (
                self.tier0_fallback.parse(
                    event,
                    detection,
                )
            )

        elif parsed_event is None:

            # If detection explicitly selected a parser but
            # deployment/registry does not contain it, that is
            # a configuration error rather than an unsupported
            # source. Preserve the existing exception behavior.
            parser = self.registry.get(
                detection.parser_id
            )

            parsed_event = parser.parse(
                event
            )

        # Central traceability authority.
        #
        # Parser-generated sequential/random IDs are replaced
        # only when the RawEvent came through the authoritative
        # forensic evidence path.
        if event.is_forensically_traceable:
            parsed_event.fields["u_id"] = str(
                event.event_id
            )

            parsed_event.fields["raw_id"] = (
                event.raw_id
            )

        return ProcessingResult(
            raw_event=event,
            detection=detection,
            parsed_event=parsed_event,
        )

    def process_bytes(
        self,
        raw_bytes: bytes,
        *,
        evidence_store: RawEvidenceStore,
        identity_context: dict[str, Any],
        transport: str = "unknown",
        metadata: dict[str, Any] | None = None,
        encoding: str = "utf-8",
    ) -> ProcessingResult:
        """
        Authoritative forensic ingestion path.

        1. Preserve the original bytes.
        2. Calculate raw SHA-256.
        3. Assign deterministic event/raw IDs.
        4. Add the event to the tamper-evident hash chain.
        5. Decode a processing copy for detection/parsing.

        The authoritative evidence bytes are not mutated.
        """

        if not isinstance(
            raw_bytes,
            bytes,
        ):
            raise TypeError(
                "raw_bytes must be bytes"
            )

        evidence = evidence_store.store(
            raw_bytes,
            identity_context=identity_context,
            transport=transport,
            metadata=metadata,
        )

        try:
            decoded_raw = raw_bytes.decode(
                encoding
            )
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Raw evidence was preserved successfully, "
                f"but could not be decoded using {encoding!r}."
            ) from exc

        event = RawEvent(
            event_id=evidence.event_id,
            raw=decoded_raw,
            transport=transport,
            metadata=dict(
                metadata
                or {}
            ),
            evidence_raw_id=evidence.raw_id,
            raw_sha256=evidence.raw_sha256,
        )

        return self.process(
            event
        )
