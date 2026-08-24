from aegisguard_ulpf.core.models import (
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)
from aegisguard_ulpf.parsing.base import BaseParser


class DummyParser(BaseParser):
    metadata = ParserMetadata(
        parser_id="test.dummy",
        parser_version="1.0.0",
        vendor="TestVendor",
        product="TestProduct",
        supported_formats=["text"],
    )

    def parse(self, event: RawEvent) -> ParsedEvent:
        return ParsedEvent(
            raw_event=event,
            parser=self.metadata,
            fields={
                "message": event.raw,
            },
            warnings=[],
        )


def test_parser_contract():
    raw = RawEvent(
        raw="hello world",
        transport="file",
    )

    parser = DummyParser()

    parsed = parser.parse(raw)

    assert isinstance(parsed, ParsedEvent)

    assert parsed.raw_event.event_id == raw.event_id

    assert parsed.raw_event.raw == "hello world"

    assert parsed.raw_event.transport == "file"

    assert parsed.parser.parser_id == "test.dummy"

    assert parsed.parser.vendor == "TestVendor"

    assert parsed.fields["message"] == "hello world"

    assert parsed.warnings == []
import pytest


class InvalidParser(BaseParser):
    metadata = ParserMetadata(
        parser_id="test.invalid",
        parser_version="1.0.0",
        vendor="TestVendor",
        product="TestProduct",
        supported_formats=["text"],
    )

    # parse() intentionally missing


def test_parser_must_implement_parse():
    with pytest.raises(TypeError):
        InvalidParser()