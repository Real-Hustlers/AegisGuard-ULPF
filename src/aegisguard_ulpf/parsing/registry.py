from aegisguard_ulpf.core.exceptions import (
    ParserNotFoundError,
    ParserRegistrationError,
)
from aegisguard_ulpf.parsing.base import BaseParser


class ParserRegistry:
    """
    Central registry for AegisGuard ULPF parsers.

    Parsers are registered using their unique parser_id.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, BaseParser] = {}

    def register(self, parser: BaseParser) -> None:
        """
        Register a parser with the framework.
        """

        parser_id = parser.metadata.parser_id

        if parser_id in self._parsers:
            raise ParserRegistrationError(
                f"Parser already registered: {parser_id}"
            )

        self._parsers[parser_id] = parser

    def get(self, parser_id: str) -> BaseParser:
        """
        Retrieve a parser by its parser_id.
        """

        try:
            return self._parsers[parser_id]
        except KeyError as exc:
            raise ParserNotFoundError(
                f"Parser not found: {parser_id}"
            ) from exc

    def exists(self, parser_id: str) -> bool:
        """
        Check whether a parser is registered.
        """

        return parser_id in self._parsers

    def all(self) -> list[BaseParser]:
        """
        Return all registered parsers.
        """

        return list(self._parsers.values())

    def count(self) -> int:
        """
        Return the number of registered parsers.
        """

        return len(self._parsers)