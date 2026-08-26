from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from aegisguard_ulpf.parsing.semantic_packs.models import (
    SensitivityClassification,
)


PrivacyAction = Literal[
    "retain",
    "mask",
    "pseudonymize",
    "drop",
]

SinkProfile = Literal["SOC", "Data Lake"]

_SENSITIVITY_CLASSES = frozenset({
    "normal",
    "network_identifier",
    "personal_identifier",
    "credential",
    "secret",
    "potentially_sensitive",
})


class PrivacyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sink: SinkProfile
    actions: dict[SensitivityClassification, PrivacyAction]

    @model_validator(mode="after")
    def validate_actions(self):
        if set(self.actions) != _SENSITIVITY_CLASSES:
            raise ValueError("Privacy policy must define every sensitivity class")
        return self


class PrivacyReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sink: SinkProfile
    fields_classified: tuple[str, ...] = ()
    fields_retained: tuple[str, ...] = ()
    fields_masked: tuple[str, ...] = ()
    fields_pseudonymized: tuple[str, ...] = ()
    fields_dropped: tuple[str, ...] = ()
    affected_field_paths: tuple[str, ...] = ()


SOC_POLICY = PrivacyPolicy(
    sink="SOC",
    actions={
        "normal": "retain",
        "network_identifier": "retain",
        "personal_identifier": "retain",
        "credential": "drop",
        "secret": "drop",
        "potentially_sensitive": "mask",
    },
)

DATA_LAKE_POLICY = PrivacyPolicy(
    sink="Data Lake",
    actions={
        "normal": "retain",
        "network_identifier": "pseudonymize",
        "personal_identifier": "pseudonymize",
        "credential": "drop",
        "secret": "drop",
        "potentially_sensitive": "mask",
    },
)


def get_builtin_policy(profile: SinkProfile) -> PrivacyPolicy:
    if profile == "SOC":
        return SOC_POLICY
    if profile == "Data Lake":
        return DATA_LAKE_POLICY
    raise ValueError(f"Unsupported sink profile: {profile}")
