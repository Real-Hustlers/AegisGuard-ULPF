import pytest

from aegisguard_ulpf.normalization.ocsf.base_event import build_base_event
from aegisguard_ulpf.normalization.ocsf.registry import (
    AUTHENTICATION_CATEGORY_UID,
    AUTHENTICATION_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_CATEGORY_UID,
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    NETWORK_ACTIVITY_CATEGORY_UID,
    NETWORK_ACTIVITY_CLASS_UID,
    TUNNEL_ACTIVITY_CATEGORY_UID,
    TUNNEL_ACTIVITY_CLASS_UID,
    AuthenticationActivityID,
    NetworkActivityID,
    SeverityID,
    TunnelActivityID,
    make_type_uid,
)
from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator
from aegisguard_ulpf.normalization.ocsf.version import OCSF_VERSION


def make_event(
    class_uid: int = NETWORK_ACTIVITY_CLASS_UID,
    category_uid: int = NETWORK_ACTIVITY_CATEGORY_UID,
    activity_id: int = NetworkActivityID.TRAFFIC,
) -> dict:
    return build_base_event(
        class_uid=class_uid,
        category_uid=category_uid,
        activity_id=activity_id,
        time=1_777_000_000_000,
        severity_id=SeverityID.INFORMATIONAL,
        product_vendor="Fortinet",
        product_name="FortiGate",
    )


def assert_valid(event: dict) -> None:
    result = OCSFValidator().validate(event)
    assert result.valid, result.errors


def test_pinned_ocsf_version():
    assert OCSF_VERSION == "1.9.0"


@pytest.mark.parametrize(
    ("class_uid", "activity_id", "expected"),
    [
        (4001, 6, 400106),
        (3002, 1, 300201),
        (4014, 1, 401401),
    ],
)
def test_make_type_uid(class_uid, activity_id, expected):
    assert make_type_uid(class_uid, activity_id) == expected


@pytest.mark.parametrize(
    ("class_uid", "activity_id", "exception"),
    [
        ("4001", 6, TypeError),
        (4001, True, TypeError),
        (-1, 6, ValueError),
        (4001, -1, ValueError),
    ],
)
def test_make_type_uid_rejects_invalid_inputs(
    class_uid, activity_id, exception
):
    with pytest.raises(exception):
        make_type_uid(class_uid, activity_id)


def test_valid_network_activity_envelope_passes():
    assert_valid(make_event())


def test_valid_authentication_envelope_passes():
    assert_valid(
        make_event(
            AUTHENTICATION_CLASS_UID,
            AUTHENTICATION_CATEGORY_UID,
            AuthenticationActivityID.LOGON,
        )
    )


def test_valid_tunnel_activity_envelope_passes():
    assert_valid(
        make_event(
            TUNNEL_ACTIVITY_CLASS_UID,
            TUNNEL_ACTIVITY_CATEGORY_UID,
            TunnelActivityID.OPEN,
        )
    )


def test_wrong_type_uid_fails():
    event = make_event()
    event["type_uid"] = 400101

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert any("type_uid" in error for error in result.errors)


def test_wrong_category_uid_for_verified_class_fails():
    event = make_event()
    event["category_uid"] = 3

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert any("category_uid" in error for error in result.errors)


def test_missing_metadata_version_fails():
    event = make_event()
    del event["metadata"]["version"]

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert "missing metadata.version" in result.errors


def test_wrong_metadata_version_fails():
    event = make_event()
    event["metadata"]["version"] = "latest"

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert any("metadata.version" in error for error in result.errors)


def test_missing_metadata_product_fails():
    event = make_event()
    del event["metadata"]["product"]

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert "metadata.product must be a dictionary" in result.errors


def test_metadata_product_requires_name_or_uid():
    event = make_event()
    event["metadata"]["product"] = {"vendor_name": "Fortinet"}

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert "metadata.product must contain name or uid" in result.errors


def test_old_fake_system_activity_fails():
    event = make_event(
        FILE_SYSTEM_ACTIVITY_CLASS_UID,
        FILE_SYSTEM_ACTIVITY_CATEGORY_UID,
        1,
    )
    event["class_name"] = "System Activity"

    result = OCSFValidator().validate(event)

    assert not result.valid
    assert (
        "class_uid 1001 is File System Activity, not System Activity"
        in result.errors
    )


def test_file_system_activity_is_not_generic_system_activity():
    event = make_event(
        FILE_SYSTEM_ACTIVITY_CLASS_UID,
        FILE_SYSTEM_ACTIVITY_CATEGORY_UID,
        1,
    )

    assert event["class_name"] == "File System Activity"
    assert event["category_name"] == "System Activity"
    assert_valid(event)
