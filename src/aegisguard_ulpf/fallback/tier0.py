from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET

from typing import Any

from aegisguard_ulpf.core.models import (
    DetectionResult,
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)


TIER0_PARSER_METADATA = ParserMetadata(
    parser_id="aegisguard.tier0.structural",
    parser_version="1.0.0",
    vendor="AegisGuard",
    product="ULPF",
    supported_formats=[
        "json",
        "xml",
        "csv",
        "text",
    ],
)


class Tier0Fallback:
    """
    Graceful unsupported-source handling.

    Tier 0 performs structural extraction only.

    It must NOT infer:
    - vendor
    - product
    - security category
    - event type
    - subtype
    - outcome
    - severity
    - action
    - network/security semantics

    Existing detector evidence may be preserved, but
    no new security meaning is invented here.
    """

    metadata = TIER0_PARSER_METADATA

    def parse(
        self,
        event: RawEvent,
        detection: DetectionResult,
    ) -> ParsedEvent:

        structural_format, extracted = (
            self.extract_structure(
                event.raw
            )
        )

        fields = {
            # Traceability remains owned centrally by
            # ProcessingPipeline. These are populated there
            # only for authoritative forensic events.
            "u_id": None,
            "raw_id": None,

            "timestamp": None,

            # Preserve only identity established by detection.
            # Do not guess a vendor/product.
            "vendor": detection.vendor,
            "product": detection.product,

            # No guessed security semantics.
            "category": None,
            "type": None,
            "subtype": None,
            "outcome": None,

            "severity": None,

            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,

            "user": None,

            "action": None,
            "reason": None,

            "object_type": None,
            "object_name": None,

            "details": {
                "tier0": {
                    "mapping_status": "incomplete",
                    "detected_format": detection.format,
                    "structural_format": structural_format,
                    "fallback_reason": (
                        "no_supported_parser"
                    ),
                }
            },

            "vendor_event_id": None,

            # All safely extracted unresolved structure
            # remains available for later onboarding.
            "vendor_fields": extracted,

            # Explicit Tier 0 contract marker.
            "mapping_status": "incomplete",
        }

        warning = (
            "Tier 0 fallback used: no supported semantic "
            "parser was selected. Structural data was "
            "preserved without guessed security semantics."
        )

        return ParsedEvent(
            raw_event=event,
            parser=self.metadata,
            fields=fields,
            warnings=[warning],
        )

    def extract_structure(
        self,
        raw: str,
    ) -> tuple[str, dict[str, Any]]:
        """
        Safely extract structure using standard-library
        parsers only.

        Order:
            JSON
            XML
            CSV
            text

        Failure of one structural parser never drops the
        event; the raw text falls through to the next form.
        """

        if not isinstance(
            raw,
            str,
        ):
            raise TypeError(
                "Tier 0 raw input must be a string"
            )

        stripped = raw.strip()

        # -------------------------------------------------
        # JSON
        # -------------------------------------------------

        if stripped:

            try:
                parsed_json = json.loads(
                    stripped
                )

            except (
                json.JSONDecodeError,
                TypeError,
            ):
                pass

            else:
                if isinstance(
                    parsed_json,
                    dict,
                ):
                    return (
                        "json",
                        parsed_json.copy(),
                    )

                return (
                    "json",
                    {
                        "value":
                            parsed_json
                    },
                )

        # -------------------------------------------------
        # XML
        # -------------------------------------------------

        if stripped.startswith("<"):

            try:
                root = ET.fromstring(
                    stripped
                )

            except ET.ParseError:
                pass

            else:
                return (
                    "xml",
                    {
                        "root":
                            self._xml_element(
                                root
                            )
                    },
                )

        # -------------------------------------------------
        # CSV
        # -------------------------------------------------
        #
        # We deliberately do not interpret the first row
        # as a header. Header semantics would be a guess.
        # Preserve positional rows only.
        # -------------------------------------------------

        if stripped:

            try:
                rows = list(
                    csv.reader(
                        io.StringIO(
                            raw
                        )
                    )
                )

            except csv.Error:
                rows = []

            if self._looks_structurally_csv(
                rows
            ):
                return (
                    "csv",
                    {
                        "rows":
                            [
                                list(row)
                                for row
                                in rows
                            ]
                    },
                )

        # -------------------------------------------------
        # Plain text
        # -------------------------------------------------

        return (
            "text",
            {
                "text": raw
            },
        )

    @staticmethod
    def _looks_structurally_csv(
        rows: list[list[str]],
    ) -> bool:

        if not rows:
            return False

        # A single ordinary text field is not enough
        # evidence to call the input CSV.
        if (
            len(rows) == 1
            and len(rows[0]) <= 1
        ):
            return False

        # At least one row must contain multiple columns.
        return any(
            len(row) > 1
            for row
            in rows
        )

    def _xml_element(
        self,
        element: ET.Element,
    ) -> dict[str, Any]:
        """
        Preserve XML structure without assigning security
        semantics to tag names.
        """

        node: dict[str, Any] = {
            "tag": element.tag,
        }

        if element.attrib:
            node["attributes"] = dict(
                element.attrib
            )

        text = (
            element.text.strip()
            if element.text
            else ""
        )

        if text:
            node["text"] = text

        children = [
            self._xml_element(
                child
            )
            for child
            in list(element)
        ]

        if children:
            node["children"] = (
                children
            )

        return node