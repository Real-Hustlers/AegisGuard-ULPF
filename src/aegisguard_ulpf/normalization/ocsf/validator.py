"""Pinned OCSF 1.9.0 contract validator v1.

This validates the stable envelope used by AegisGuard-ULPF. It is not a
complete validator for every class, object, profile, enum, or constraint in
the official OCSF schema.
"""

from aegisguard_ulpf.normalization.ocsf.registry import (
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    SeverityID,
    VERIFIED_ACTIVITY_NAMES,
    VERIFIED_CLASSES,
    make_type_uid,
)
from aegisguard_ulpf.normalization.ocsf.version import OCSF_VERSION


class OCSFValidationResult:
    """Result of pinned OCSF contract validation."""

    def __init__(
        self,
        valid: bool,
        errors: list[str] | None = None,
    ):
        self.valid = valid
        self.errors = errors or []


class OCSFValidator:
    """Validate the pinned OCSF 1.9.0 Base Event contract used in phase v1."""

    REQUIRED_INTEGER_FIELDS = {
        "activity_id",
        "category_uid",
        "class_uid",
        "severity_id",
        "time",
        "type_uid",
    }

    @staticmethod
    def _is_integer(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def validate(self, event: dict) -> OCSFValidationResult:
        errors: list[str] = []

        if not isinstance(event, dict):
            return OCSFValidationResult(False, ["OCSF event must be a dictionary"])

        for field in sorted(self.REQUIRED_INTEGER_FIELDS):
            if field not in event:
                errors.append(f"missing OCSF field: {field}")
            elif not self._is_integer(event[field]):
                errors.append(f"OCSF field must be an integer: {field}")
            elif event[field] < 0:
                errors.append(f"OCSF field must be non-negative: {field}")

        class_uid = event.get("class_uid")
        category_uid = event.get("category_uid")
        activity_id = event.get("activity_id")
        type_uid = event.get("type_uid")

        if all(
            self._is_integer(value)
            for value in (class_uid, activity_id, type_uid)
        ):
            expected_type_uid = make_type_uid(class_uid, activity_id)
            if type_uid != expected_type_uid:
                errors.append(
                    "type_uid must equal class_uid * 100 + activity_id"
                )

        severity_id = event.get("severity_id")
        if self._is_integer(severity_id) and severity_id not in {
            member.value for member in SeverityID
        }:
            errors.append(f"invalid OCSF severity_id: {severity_id}")

        class_definition = (
            VERIFIED_CLASSES.get(class_uid)
            if self._is_integer(class_uid)
            else None
        )
        if class_definition is not None and self._is_integer(category_uid):
            expected_category_uid = class_definition["category_uid"]
            if category_uid != expected_category_uid:
                errors.append(
                    f"category_uid {category_uid} does not match "
                    f"class_uid {class_uid}; expected {expected_category_uid}"
                )

        if class_definition is not None and "class_name" in event:
            expected_class_name = class_definition["class_name"]
            if event["class_name"] != expected_class_name:
                if (
                    class_uid == FILE_SYSTEM_ACTIVITY_CLASS_UID
                    and event["class_name"] == "System Activity"
                ):
                    errors.append(
                        "class_uid 1001 is File System Activity, not System Activity"
                    )
                else:
                    errors.append(
                        f"class_name does not match class_uid {class_uid}; "
                        f"expected {expected_class_name}"
                    )

        if class_definition is not None and "category_name" in event:
            expected_category_name = class_definition["category_name"]
            if event["category_name"] != expected_category_name:
                errors.append(
                    f"category_name does not match category_uid {category_uid}; "
                    f"expected {expected_category_name}"
                )

        activity_names = (
            VERIFIED_ACTIVITY_NAMES.get(class_uid)
            if self._is_integer(class_uid)
            else None
        )
        if activity_names is not None and self._is_integer(activity_id):
            if activity_id not in activity_names:
                errors.append(
                    f"invalid activity_id {activity_id} for class_uid {class_uid}"
                )
            elif activity_id == 99:
                activity_name = event.get("activity_name")
                if not isinstance(activity_name, str) or not activity_name.strip():
                    errors.append(
                        "activity_name is required when activity_id is 99"
                    )
            elif "activity_name" in event:
                expected_activity_name = activity_names[activity_id]
                if event["activity_name"] != expected_activity_name:
                    errors.append(
                        f"activity_name does not match activity_id {activity_id}; "
                        f"expected {expected_activity_name}"
                    )

        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            errors.append("metadata must be a dictionary")
        else:
            if "version" not in metadata:
                errors.append("missing metadata.version")
            elif metadata["version"] != OCSF_VERSION:
                errors.append(
                    f"metadata.version must equal pinned OCSF version {OCSF_VERSION}"
                )

            product = metadata.get("product")
            if not isinstance(product, dict):
                errors.append("metadata.product must be a dictionary")
            elif not any(product.get(key) for key in ("name", "uid")):
                errors.append("metadata.product must contain name or uid")

        return OCSFValidationResult(
            valid=not errors,
            errors=errors,
        )
