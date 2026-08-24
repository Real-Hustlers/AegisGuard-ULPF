import pytest

from aegisguard_ulpf.core.exceptions import (
    ParserNotFoundError,
    ParserRegistrationError,
)
from aegisguard_ulpf.core.models import (
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)
from aegisguard_ulpf.parsing.base import BaseParser
from aegisguard_ulpf.parsing.registry import ParserRegistry


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
        )


def test_register_parser():
    registry = ParserRegistry()

    parser = DummyParser()

    registry.register(parser)

    assert registry.count() == 1
    assert registry.exists("test.dummy")


def test_get_registered_parser():
    registry = ParserRegistry()

    parser = DummyParser()

    registry.register(parser)

    retrieved = registry.get("test.dummy")

    assert retrieved is parser


def test_duplicate_parser_registration_fails():
    registry = ParserRegistry()

    registry.register(DummyParser())

    with pytest.raises(ParserRegistrationError):
        registry.register(DummyParser())


def test_missing_parser_raises_error():
    registry = ParserRegistry()

    with pytest.raises(ParserNotFoundError):
        registry.get("does.not.exist")


def test_all_returns_registered_parsers():
    registry = ParserRegistry()

    parser = DummyParser()

    registry.register(parser)

    parsers = registry.all()

    assert len(parsers) == 1
    assert parsers[0] is parser