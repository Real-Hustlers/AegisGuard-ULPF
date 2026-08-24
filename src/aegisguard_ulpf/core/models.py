from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)

    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    raw: str

    transport: str = "unknown"

    metadata: dict[str, Any] = Field(default_factory=dict)


class ParserMetadata(BaseModel):
    parser_id: str

    parser_version: str

    vendor: str

    product: str

    supported_formats: list[str] = Field(default_factory=list)


class ParsedEvent(BaseModel):
    raw_event: RawEvent

    parser: ParserMetadata

    fields: dict[str, Any] = Field(default_factory=dict)

    warnings: list[str] = Field(default_factory=list)