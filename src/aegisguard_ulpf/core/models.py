from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


MappingStatus = Literal[
    "mapped",
    "incomplete",
]


class RawEvent(BaseModel):
    event_id: UUID = Field(
        default_factory=uuid4
    )

    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    raw: str

    transport: str = "unknown"

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def raw_id(self) -> str:
        return f"RAW-{self.event_id}"


class ParserMetadata(BaseModel):
    parser_id: str
    parser_version: str
    vendor: str
    product: str

    supported_formats: list[str] = Field(
        default_factory=list
    )


class ParsedEvent(BaseModel):
    raw_event: RawEvent

    parser: ParserMetadata

    fields: dict[str, Any] = Field(
        default_factory=dict
    )

    warnings: list[str] = Field(
        default_factory=list
    )


class DetectionResult(BaseModel):
    """
    Standard result produced by the AegisGuard
    source/format detection stage.
    """

    vendor: str | None = None
    product: str | None = None
    event_family: str | None = None
    format: str | None = None
    parser_id: str | None = None

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0
    )

    evidence: list[str] = Field(
        default_factory=list
    )


class ProcessingResult(BaseModel):
    """
    Complete result produced by the AegisGuard ULPF
    processing pipeline before normalization.
    """

    raw_event: RawEvent
    detection: DetectionResult
    parsed_event: ParsedEvent


class EventClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str | None = None
    type: str | None = None
    subtype: str | None = None
    outcome: str | None = None
    severity: str | None = None
    action: str | None = None
    reason: str | None = None


class EventTimestamps(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_time: datetime | None = None
    observed_time: datetime
    processed_time: datetime


class VendorInformation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str
    product: str
    vendor_event_id: str | None = None


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    name: str | None = None
    hostname: str | None = None
    serial_number: str | None = None
    virtual_domain: str | None = None
    virtual_system: str | None = None


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    port: int | None = None
    hostname: str | None = None
    interface: str | None = None
    zone: str | None = None


class Network(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    bytes_total: int | None = None
    packets_in: int | None = None
    packets_out: int | None = None
    packets_total: int | None = None
    session_id: str | None = None
    duration_seconds: int | None = None


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str | None = None


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    name: str | None = None
    uuid: str | None = None


class Nat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    translated_src_ip: str | None = None
    translated_src_port: int | None = None
    translated_dst_ip: str | None = None
    translated_dst_port: int | None = None
    type: str | None = None
    disposition: str | None = None


class EventResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str | None = None
    name: str | None = None


class TraceabilityReferences(BaseModel):
    model_config = ConfigDict(extra="forbid")

    u_id: str
    raw_id: str


class CommonEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mapping_status: MappingStatus
    classification: EventClassification
    timestamps: EventTimestamps
    vendor: VendorInformation
    traceability: TraceabilityReferences

    device: Device | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    network: Network | None = None
    actor: Actor | None = None
    policy: Policy | None = None
    nat: Nat | None = None
    resource: EventResource | None = None

    details: dict[str, Any] = Field(
        default_factory=dict
    )

    vendor_fields: dict[str, Any] = Field(
        default_factory=dict
    )
