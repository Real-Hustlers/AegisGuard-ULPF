import hashlib
import hmac

from typing import Any

from pydantic import BaseModel

from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.parsing.semantic_packs.models import SensitivityMetadata
from aegisguard_ulpf.privacy.models import (
    PrivacyPolicy,
    PrivacyReport,
    SinkProfile,
    get_builtin_policy,
)


_PROTECTED_PATHS = frozenset({
    "traceability.u_id",
    "traceability.raw_id",
    "mapping_status",
})

_MISSING = object()


def _resolve_path(event: CommonEvent, field_path: str):
    current: Any = event
    parts = field_path.split(".")

    for part in parts[:-1]:
        if isinstance(current, BaseModel):
            if part not in current.__class__.model_fields:
                return _MISSING
            current = getattr(current, part)
        elif isinstance(current, dict):
            current = current.get(part, _MISSING)
        else:
            return _MISSING

        if current is _MISSING or current is None:
            return _MISSING

    return current, parts[-1]


def _get_value(container: Any, field_name: str):
    if isinstance(container, BaseModel):
        if field_name not in container.__class__.model_fields:
            return _MISSING
        return getattr(container, field_name)
    if isinstance(container, dict):
        return container.get(field_name, _MISSING)
    return _MISSING


def _set_value(container: Any, field_name: str, value: Any) -> None:
    if isinstance(container, BaseModel):
        setattr(container, field_name, value)
    else:
        container[field_name] = value


def _drop_value(container: Any, field_name: str) -> None:
    if isinstance(container, BaseModel):
        setattr(container, field_name, None)
    else:
        container.pop(field_name, None)


def _pseudonymize(value: Any, key: str | bytes | None) -> str:
    if key is None or key == "" or key == b"":
        raise ValueError("Pseudonymization key is required")
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    value_bytes = str(value).encode("utf-8")
    digest = hmac.new(key_bytes, value_bytes, hashlib.sha256).hexdigest()
    return f"[PSEUDONYMIZED:{digest}]"


def apply_privacy_policy(
    event: CommonEvent,
    sensitivity: SensitivityMetadata | None,
    policy: PrivacyPolicy | SinkProfile,
    *,
    pseudonymization_key: str | bytes | None = None,
) -> tuple[CommonEvent, PrivacyReport]:
    """Return a policy-applied CommonEvent copy and separate privacy report."""

    if not isinstance(event, CommonEvent):
        raise TypeError("Privacy policy requires a normalized CommonEvent")

    resolved_policy = (
        get_builtin_policy(policy)
        if isinstance(policy, str)
        else policy
    )
    transformed = event.model_copy(deep=True)

    if sensitivity is None:
        return transformed, PrivacyReport(sink=resolved_policy.sink)

    classified: list[str] = []
    retained: list[str] = []
    masked: list[str] = []
    pseudonymized: list[str] = []
    dropped: list[str] = []

    for declaration in sensitivity.fields:
        field_path = declaration.field_path
        if field_path in _PROTECTED_PATHS:
            raise ValueError("Privacy policy cannot target a protected field")

        resolved = _resolve_path(transformed, field_path)
        if resolved is _MISSING:
            continue

        container, field_name = resolved
        value = _get_value(container, field_name)
        if value is _MISSING or value is None:
            continue

        classified.append(field_path)
        action = resolved_policy.actions[declaration.classification]

        if action == "retain":
            retained.append(field_path)
        elif action == "mask":
            if not isinstance(value, (str, int, float, bool)):
                raise ValueError("Masking requires a scalar sensitivity value")
            _set_value(container, field_name, "[MASKED]")
            masked.append(field_path)
        elif action == "pseudonymize":
            _set_value(
                container,
                field_name,
                _pseudonymize(value, pseudonymization_key),
            )
            pseudonymized.append(field_path)
        else:
            _drop_value(container, field_name)
            dropped.append(field_path)

    transformed = CommonEvent.model_validate(transformed.model_dump())
    affected = tuple(masked + pseudonymized + dropped)
    return transformed, PrivacyReport(
        sink=resolved_policy.sink,
        fields_classified=tuple(classified),
        fields_retained=tuple(retained),
        fields_masked=tuple(masked),
        fields_pseudonymized=tuple(pseudonymized),
        fields_dropped=tuple(dropped),
        affected_field_paths=affected,
    )
