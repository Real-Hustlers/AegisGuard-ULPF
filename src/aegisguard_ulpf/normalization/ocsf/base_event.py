"""Builder for the mandatory OCSF 1.9.0 Base Event envelope."""

from aegisguard_ulpf.normalization.ocsf.registry import (
    VERIFIED_ACTIVITY_NAMES,
    VERIFIED_CLASSES,
    make_type_uid,
)
from aegisguard_ulpf.normalization.ocsf.version import OCSF_VERSION


def build_base_event(
    *,
    class_uid: int,
    category_uid: int,
    activity_id: int,
    time: int,
    severity_id: int,
    product_vendor: str,
    product_name: str,
    class_name: str | None = None,
    category_name: str | None = None,
    activity_name: str | None = None,
) -> dict:
    """Build an OCSF envelope without mapping any ULPF common fields."""

    event = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "type_uid": make_type_uid(class_uid, activity_id),
        "time": time,
        "severity_id": severity_id,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "vendor_name": product_vendor,
                "name": product_name,
            },
        },
    }

    class_definition = VERIFIED_CLASSES.get(class_uid)
    resolved_class_name = class_name
    resolved_category_name = category_name

    if class_definition is not None:
        resolved_class_name = resolved_class_name or class_definition["class_name"]
        resolved_category_name = (
            resolved_category_name or class_definition["category_name"]
        )

    resolved_activity_name = activity_name
    if resolved_activity_name is None and activity_id != 99:
        resolved_activity_name = VERIFIED_ACTIVITY_NAMES.get(class_uid, {}).get(
            activity_id
        )

    if resolved_class_name is not None:
        event["class_name"] = resolved_class_name
    if resolved_category_name is not None:
        event["category_name"] = resolved_category_name
    if resolved_activity_name is not None:
        event["activity_name"] = resolved_activity_name

    return event
