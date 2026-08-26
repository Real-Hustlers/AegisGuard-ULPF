import re

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    model_validator,
)

from aegisguard_ulpf.normalization.ocsf.registry import (
    SeverityID,
    StatusID,
    VERIFIED_ACTIVITY_NAMES,
    VERIFIED_CLASSES,
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
    Declarative binding from CommonEvent semantics to the
    pinned OCSF registry.
    """

    status: Literal[
        "deferred",
        "bound",
    ]

    class_uid: StrictInt | None = None

    activity_mappings: dict[str, StrictInt] = Field(
        default_factory=dict
    )

    status_mappings: dict[str, StrictInt] = Field(
        default_factory=dict
    )

    severity_mappings: dict[str, StrictInt] = Field(
        default_factory=dict
    )

    default_severity_id: StrictInt | None = None

    @model_validator(mode="after")
    def validate_ocsf_binding(self):

        has_ocsf_facts = any((
            self.class_uid is not None,
            self.activity_mappings,
            self.status_mappings,
            self.severity_mappings,
            self.default_severity_id is not None,
        ))

        if self.status == "deferred":
            if has_ocsf_facts:
                raise ValueError(
                    "Deferred OCSF binding must not contain OCSF facts"
                )
            return self

        if self.class_uid not in VERIFIED_CLASSES:
            raise ValueError(
                "Bound OCSF binding class_uid is not supported by the "
                "verified OCSF registry"
            )

        if not self.activity_mappings:
            raise ValueError(
                "Bound OCSF binding requires activity_mappings"
            )

        legal_activity_ids = VERIFIED_ACTIVITY_NAMES.get(
            self.class_uid,
            {},
        )
        for semantic_value, activity_id in self.activity_mappings.items():
            if not semantic_value:
                raise ValueError(
                    "OCSF activity mapping semantic value must not be empty"
                )
            if activity_id not in legal_activity_ids:
                raise ValueError(
                    f"OCSF activity_id {activity_id} is not legal for "
                    f"class_uid {self.class_uid}"
                )

        legal_status_ids = {member.value for member in StatusID}
        for semantic_value, status_id in self.status_mappings.items():
            if not semantic_value:
                raise ValueError(
                    "OCSF status mapping semantic value must not be empty"
                )
            if status_id not in legal_status_ids:
                raise ValueError(
                    f"Unsupported OCSF status_id: {status_id}"
                )

        legal_severity_ids = {member.value for member in SeverityID}
        for semantic_value, severity_id in self.severity_mappings.items():
            if not semantic_value:
                raise ValueError(
                    "OCSF severity mapping semantic value must not be empty"
                )
            if severity_id not in legal_severity_ids:
                raise ValueError(
                    f"Unsupported OCSF severity_id: {severity_id}"
                )

        if self.default_severity_id not in legal_severity_ids:
            raise ValueError(
                "Bound OCSF binding requires a supported "
                "default_severity_id"
            )

        return self


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


SensitivityClassification = Literal[
    "normal",
    "network_identifier",
    "personal_identifier",
    "credential",
    "secret",
    "potentially_sensitive",
]


_FIELD_PATH_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

_PROTECTED_SENSITIVITY_PATHS = frozenset({
    "traceability.u_id",
    "traceability.raw_id",
    "mapping_status",
})


class SensitivityField(FrozenPackModel):
    field_path: str = Field(min_length=1)
    semantic_role: str = Field(min_length=1)
    classification: SensitivityClassification

    @model_validator(mode="after")
    def validate_sensitivity_field(self):
        if not _FIELD_PATH_PATTERN.fullmatch(self.field_path):
            raise ValueError("Sensitivity field_path is malformed")
        if not self.semantic_role.strip():
            raise ValueError("Sensitivity semantic_role must not be empty")
        if self.field_path in _PROTECTED_SENSITIVITY_PATHS:
            raise ValueError("Sensitivity field_path targets a protected field")
        return self


class SensitivityMetadata(FrozenPackModel):
    fields: tuple[SensitivityField, ...] = ()

    @model_validator(mode="after")
    def validate_sensitivity_fields(self):
        field_paths = [field.field_path for field in self.fields]
        if len(field_paths) != len(set(field_paths)):
            raise ValueError("Sensitivity field_path declarations must be unique")
        return self


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
