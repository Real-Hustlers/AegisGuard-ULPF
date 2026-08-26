from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


OperationName = Literal[
    "constant",
    "clean",
    "to_int",
    "protocol",
    "port",
    "timestamp",
    "nat_ip",
    "nat_port",
    "constant_if_present",
]


class FrozenPackModel(BaseModel):
    """
    Base model for validated Semantic Pack data.

    Packs are declarative data only.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )


class SignatureMetadata(FrozenPackModel):
    """
    Digital-signature metadata for a Semantic Pack.

    The public key is NOT supplied by the pack itself.
    key_id selects a trusted public key controlled by
    the AegisGuard runtime.
    """

    status: Literal[
        "unsigned",
        "signed",
    ] = "unsigned"

    algorithm: Literal[
        "ed25519",
    ] | None = None

    key_id: str | None = None

    value: str | None = None

    @model_validator(mode="after")
    def validate_signature_state(self):

        if self.status == "signed":

            if self.algorithm != "ed25519":
                raise ValueError(
                    "Signed Semantic Pack must use "
                    "the supported ed25519 algorithm"
                )

            if not self.key_id:
                raise ValueError(
                    "Signed Semantic Pack requires key_id"
                )

            if not self.value:
                raise ValueError(
                    "Signed Semantic Pack requires "
                    "a signature value"
                )

        return self


class PackManifest(FrozenPackModel):
    pack_id: str = Field(min_length=1)
    pack_version: str = Field(min_length=1)

    schema_version: str = Field(
        min_length=1
    )

    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)

    event_family: str = Field(
        min_length=1
    )

    format_version: str = Field(
        min_length=1
    )

    signature: SignatureMetadata = Field(
        default_factory=SignatureMetadata
    )


class SyntaxSpec(FrozenPackModel):
    """
    Restricted structural extraction description.

    Runtime v1 supports CSV only.
    """

    input_format: Literal["csv"]

    payload_marker: str = Field(
        min_length=1
    )

    field_names: tuple[str, ...]

    preserve_extra_fields: bool = True

    required_field: str = Field(
        min_length=1
    )

    required_value: str = Field(
        min_length=1
    )

    null_values: tuple[str, ...] = (
        "",
        "n/a",
        "na",
        "none",
        "null",
        "-",
    )


class OperationSpec(FrozenPackModel):
    """
    One safe declarative semantic operation.

    No operation supplied by a pack can resolve
    Python functions or execute host-language code.
    """

    op: OperationName

    target: str = Field(
        min_length=1
    )

    source: str | None = None

    sources: tuple[str, ...] = ()

    value: Any = None

    mapping: dict[str, str] = Field(
        default_factory=dict
    )

    protocol_source: str | None = None

    formats: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_operation_shape(self):

        source_operations = {
            "clean",
            "to_int",
            "protocol",
            "nat_ip",
            "nat_port",
            "constant_if_present",
        }

        if (
            self.op in source_operations
            and not self.source
        ):
            raise ValueError(
                f"{self.op} operation requires source"
            )

        if self.op == "protocol":
            if not self.mapping:
                raise ValueError(
                    "protocol operation requires mapping"
                )

        if self.op == "port":
            if not self.source:
                raise ValueError(
                    "port operation requires source"
                )

            if not self.protocol_source:
                raise ValueError(
                    "port operation requires "
                    "protocol_source"
                )

            if not self.mapping:
                raise ValueError(
                    "port operation requires mapping"
                )

        if self.op == "timestamp":
            if not self.sources:
                raise ValueError(
                    "timestamp operation requires sources"
                )

            if not self.formats:
                raise ValueError(
                    "timestamp operation requires formats"
                )

        return self


class ClassificationRule(FrozenPackModel):
    type: str
    subtype: str

    outcome: str | None = None

    outcome_from_action: bool = False


class ClassificationSpec(FrozenPackModel):
    source_field: str
    action_field: str

    category: str

    default_type: str = "UNKNOWN"
    default_subtype: str = "UNKNOWN"
    default_outcome: str = "UNKNOWN"

    rules: dict[
        str,
        ClassificationRule,
    ] = Field(
        default_factory=dict
    )

    action_outcomes: dict[
        str,
        str,
    ] = Field(
        default_factory=dict
    )


class SemanticsSpec(FrozenPackModel):
    classification: ClassificationSpec

    operations: tuple[
        OperationSpec,
        ...
    ]

    preserve_vendor_fields: bool = True


class OcsfBinding(FrozenPackModel):
    """
    Structural placeholder only.

    OCSF semantics remain owned by the existing
    OCSF workstream.
    """

    status: Literal[
        "deferred",
        "bound",
    ]

    mappings: dict[str, Any] = Field(
        default_factory=dict
    )


class EmbeddedPackTest(FrozenPackModel):
    """
    Declarative test metadata embedded in the pack.

    It is data only and is never executed as code.
    """

    name: str

    raw_subtype: str

    action: str

    expected_type: str
    expected_subtype: str
    expected_outcome: str


class ProvenanceMetadata(FrozenPackModel):
    source: str
    derived_from: str
    created_for: str
    notes: str


class SensitivityMetadata(FrozenPackModel):
    classification: str | None = None

    fields: tuple[str, ...] = ()


class SemanticPack(FrozenPackModel):
    manifest: PackManifest

    syntax: SyntaxSpec

    semantics: SemanticsSpec

    ocsf_binding: OcsfBinding

    tests: tuple[
        EmbeddedPackTest,
        ...
    ]

    provenance: ProvenanceMetadata

    sensitivity: (
        SensitivityMetadata
        | None
    ) = None