"""Evidence-backed adaptive handling for logs without a semantic parser."""

from __future__ import annotations

import json

from collections.abc import Mapping
from typing import Any

from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.detection.format_detector import FormatDetector
from aegisguard_ulpf.detection.source_detector import SourceDetector
from aegisguard_ulpf.fallback.models import FallbackDetection, FallbackEvent
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


def _hint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _json_hints(raw: str) -> tuple[str | None, str | None]:
    """Read explicit JSON identity fields without inferring security semantics."""

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, None

    if not isinstance(payload, Mapping):
        return None, None

    source = payload.get("source")
    source_mapping = source if isinstance(source, Mapping) else {}
    vendor = (
        _hint(payload.get("vendor"))
        or _hint(payload.get("vendor_name"))
        or _hint(source_mapping.get("vendor"))
    )
    product = (
        _hint(payload.get("product"))
        or _hint(payload.get("product_name"))
        or _hint(source_mapping.get("product"))
    )
    return vendor, product


class FallbackDetector:
    """Detect safe structural metadata for an unsupported log source.

    This class reuses the ordinary format and source detectors but does not
    select parsers, classify events, or derive security semantics.
    """

    def __init__(
        self,
        format_detector: FormatDetector | None = None,
        source_detector: SourceDetector | None = None,
    ) -> None:
        self._format_detector = format_detector or FormatDetector()
        self._source_detector = source_detector or SourceDetector()

    def detect(self, raw: str) -> FallbackDetection:
        if not isinstance(raw, str):
            raise TypeError("raw must be a string")

        event = RawEvent(raw=raw)
        format_result = self._format_detector.detect(event)
        source_result = self._source_detector.detect(event, format_result)

        vendor = _hint(source_result.vendor)
        product = _hint(source_result.product)

        if format_result.format == "json" and (vendor is None or product is None):
            json_vendor, json_product = _json_hints(raw)
            vendor = vendor or json_vendor
            product = product or json_product

        return FallbackDetection(
            detected_format=format_result.format or "unknown",
            possible_vendor=vendor or "unknown",
            possible_product=product or "unknown",
        )


class UnknownLogHandler:
    """Store unknown raw bytes and return a non-semantic fallback event."""

    def __init__(self, detector: FallbackDetector | None = None) -> None:
        self._detector = detector or FallbackDetector()

    def handle(
        self,
        raw: bytes | str,
        *,
        evidence_store: RawEvidenceStore,
        identity_context: dict[str, Any],
        transport: str = "unknown",
        metadata: dict[str, Any] | None = None,
        encoding: str = "utf-8",
    ) -> FallbackEvent:
        """Preserve raw evidence before structural detection of an unknown log."""

        if isinstance(raw, bytes):
            raw_bytes = raw
            raw_text = raw.decode(encoding, errors="replace")
        elif isinstance(raw, str):
            raw_text = raw
            raw_bytes = raw.encode(encoding)
        else:
            raise TypeError("raw must be bytes or a string")

        evidence = evidence_store.store(
            raw_bytes,
            identity_context=identity_context,
            transport=transport,
            metadata=metadata,
        )
        detection = self._detector.detect(raw_text)

        return FallbackEvent(
            status="unknown_format",
            detected_format=detection.detected_format,
            possible_vendor=detection.possible_vendor,
            possible_product=detection.possible_product,
            raw_preserved=True,
            fidelity_available=True,
            event_id=evidence.event_id,
            raw_id=evidence.raw_id,
            raw_sha256=evidence.raw_sha256,
        )


def handle_unknown_log(
    raw: bytes | str,
    *,
    evidence_store: RawEvidenceStore,
    identity_context: dict[str, Any],
    transport: str = "unknown",
    metadata: dict[str, Any] | None = None,
    encoding: str = "utf-8",
) -> FallbackEvent:
    """Convenience wrapper for one evidence-backed unknown-log event."""

    return UnknownLogHandler().handle(
        raw,
        evidence_store=evidence_store,
        identity_context=identity_context,
        transport=transport,
        metadata=metadata,
        encoding=encoding,
    )
