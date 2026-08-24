class ParserError(Exception):
    """
    Raised when a parser cannot process
    an event assigned to it.
    """

    def __init__(
        self,
        message: str,
        event_id: str | None = None,
        parser_id: str | None = None,
    ):
        super().__init__(message)

        self.event_id = event_id
        self.parser_id = parser_id