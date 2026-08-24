from abc import ABC, abstractmethod

from aegisguard_ulpf.core.models import (
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)


class BaseParser(ABC):
    """
    Base contract that every AegisGuard ULPF parser must follow.
    """

    metadata: ParserMetadata

    @abstractmethod
    def parse(self, event: RawEvent) -> ParsedEvent:
        """
        Parse one RawEvent and return a ParsedEvent.
        """
        raise NotImplementedError