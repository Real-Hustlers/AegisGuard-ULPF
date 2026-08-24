import pytest

from aegisguard_ulpf.core.exceptions import ParserNotFoundError
from aegisguard_ulpf.core.models import (
    ParsedEvent,
    ParserMetadata,
    ProcessingResult,
    RawEvent,
)
from aegisguard_ulpf.core.pipeline import ProcessingPipeline
from aegisguard_ulpf.parsing.base import BaseParser
from aegisguard_ulpf.parsing.registry import ParserRegistry


class DummyFortiGateSystemParser(BaseParser):

    metadata = ParserMetadata(
        parser_id="fortinet.fortigate.system",
        parser_version="1.0.0",
        vendor="Fortinet",
        product="FortiGate",
        supported_formats=[
            "key_value",
            "syslog",
        ],
    )

    def parse(
        self,
        event: RawEvent,
    ) -> ParsedEvent:

        return ParsedEvent(
            raw_event=event,
            parser=self.metadata,
            fields={
                "test": "parsed",
                "raw_length": len(event.raw),
            },
            warnings=[],
        )


def create_pipeline():
    registry = ParserRegistry()

    registry.register(
        DummyFortiGateSystemParser()
    )

    return ProcessingPipeline(
        registry=registry
    )


def test_pipeline_detects_and_parses_fortigate_system():

    pipeline = create_pipeline()

    event = RawEvent(
        raw=(
            'date=2026-08-24 '
            'time=20:10:00 '
            'devname="FGT-01" '
            'devid="FGT60FTK12345678" '
            'logid="0100032001" '
            'type="event" '
            'subtype="system" '
            'vd="root"'
        ),
        transport="syslog_udp",
    )

    result = pipeline.process(event)

    assert isinstance(
        result,
        ProcessingResult,
    )

    assert (
        result.raw_event.event_id
        == event.event_id
    )

    assert (
        result.detection.vendor
        == "Fortinet"
    )

    assert (
        result.detection.product
        == "FortiGate"
    )

    assert (
        result.detection.event_family
        == "system"
    )

    assert (
        result.detection.parser_id
        == "fortinet.fortigate.system"
    )

    assert (
        result.parsed_event.parser.parser_id
        == "fortinet.fortigate.system"
    )

    assert (
        result.parsed_event.fields["test"]
        == "parsed"
    )

    assert (
        result.parsed_event.raw_event.event_id
        == event.event_id
    )


def test_pipeline_detection_can_be_called_separately():

    pipeline = create_pipeline()

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'devid="FGT12345678" '
            'logid="100" '
            'type="event" '
            'subtype="system" '
            'vd="root"'
        )
    )

    detection = pipeline.detect(event)

    assert (
        detection.vendor
        == "Fortinet"
    )

    assert (
        detection.product
        == "FortiGate"
    )

    assert (
        detection.event_family
        == "system"
    )

    assert (
        detection.parser_id
        == "fortinet.fortigate.system"
    )


def test_pipeline_unknown_source_fails_cleanly():

    pipeline = create_pipeline()

    event = RawEvent(
        raw=(
            "some unknown application "
            "started successfully"
        )
    )

    with pytest.raises(
        ParserNotFoundError
    ):
        pipeline.process(event)


def test_pipeline_detected_parser_missing_from_registry():

    registry = ParserRegistry()

    pipeline = ProcessingPipeline(
        registry=registry
    )

    event = RawEvent(
        raw=(
            'devname="FGT-01" '
            'devid="FGT12345678" '
            'logid="100" '
            'type="event" '
            'subtype="system" '
            'vd="root"'
        )
    )

    with pytest.raises(
        ParserNotFoundError
    ):
        pipeline.process(event)