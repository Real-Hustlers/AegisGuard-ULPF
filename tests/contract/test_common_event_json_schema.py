import json
from pathlib import Path

from aegisguard_ulpf.core.models import CommonEvent


SCHEMA_PATH = (
    Path(__file__).parents[2]
    / "src"
    / "aegisguard_ulpf"
    / "schemas"
    / "aegisguard_event_v1.json"
)

REQUIRED_COMMON_EVENT_FIELDS = {
    "mapping_status",
    "classification",
    "timestamps",
    "vendor",
    "traceability",
}

OPTIONAL_COMMON_EVENT_CONTAINERS = {
    "device",
    "src_endpoint",
    "dst_endpoint",
    "network",
    "actor",
    "policy",
    "nat",
    "resource",
}

NETWORK_COUNTER_FIELDS = {
    "bytes_in",
    "bytes_out",
    "bytes_total",
    "packets_in",
    "packets_out",
    "packets_total",
}

TYPED_NESTED_MODELS = {
    "Actor",
    "Device",
    "Endpoint",
    "EventClassification",
    "EventResource",
    "EventTimestamps",
    "Nat",
    "Network",
    "Policy",
    "TraceabilityReferences",
    "VendorInformation",
}


def load_static_schema():
    return json.loads(
        SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )


def assert_integer_or_null(field_schema):
    assert field_schema["anyOf"] == [
        {
            "type": "integer",
        },
        {
            "type": "null",
        },
    ]


def test_static_common_event_schema_exists_and_is_valid_json():
    assert SCHEMA_PATH.is_file()

    schema = load_static_schema()

    assert schema["title"] == "CommonEvent"
    assert schema["type"] == "object"


def test_static_schema_matches_runtime_common_event_schema():
    assert (
        load_static_schema()
        == CommonEvent.model_json_schema()
    )


def test_common_event_sections_and_extension_containers():
    schema = load_static_schema()
    properties = schema["properties"]

    assert set(schema["required"]) == (
        REQUIRED_COMMON_EVENT_FIELDS
    )

    assert OPTIONAL_COMMON_EVENT_CONTAINERS.issubset(
        properties
    )

    for container in OPTIONAL_COMMON_EVENT_CONTAINERS:
        assert properties[container]["default"] is None
        assert {
            "type": "null",
        } in properties[container]["anyOf"]

    assert properties["details"]["type"] == "object"
    assert (
        properties["details"]["additionalProperties"]
        is True
    )

    assert (
        properties["vendor_fields"]["type"]
        == "object"
    )
    assert (
        properties["vendor_fields"][
            "additionalProperties"
        ]
        is True
    )


def test_mapping_status_contract():
    schema = load_static_schema()

    assert "mapping_status" in schema["required"]
    assert schema["properties"]["mapping_status"][
        "enum"
    ] == [
        "mapped",
        "incomplete",
    ]


def test_event_timestamp_contract():
    timestamp_schema = load_static_schema()[
        "$defs"
    ]["EventTimestamps"]

    assert set(timestamp_schema["required"]) == {
        "observed_time",
        "processed_time",
    }

    assert (
        "event_time"
        not in timestamp_schema["required"]
    )

    properties = timestamp_schema["properties"]

    assert properties["event_time"]["anyOf"] == [
        {
            "format": "date-time",
            "type": "string",
        },
        {
            "type": "null",
        },
    ]

    assert properties["observed_time"]["format"] == (
        "date-time"
    )
    assert properties["processed_time"]["format"] == (
        "date-time"
    )


def test_traceability_and_vendor_requirements():
    definitions = load_static_schema()["$defs"]

    assert set(
        definitions["TraceabilityReferences"][
            "required"
        ]
    ) == {
        "u_id",
        "raw_id",
    }

    assert set(
        definitions["VendorInformation"]["required"]
    ) == {
        "vendor",
        "product",
    }


def test_endpoint_port_is_integer_or_null():
    port_schema = load_static_schema()[
        "$defs"
    ]["Endpoint"]["properties"]["port"]

    assert_integer_or_null(port_schema)


def test_network_counters_are_integer_or_null():
    properties = load_static_schema()[
        "$defs"
    ]["Network"]["properties"]

    for counter in NETWORK_COUNTER_FIELDS:
        assert_integer_or_null(
            properties[counter]
        )


def test_typed_models_reject_additional_properties():
    schema = load_static_schema()

    assert schema["additionalProperties"] is False

    for model_name in TYPED_NESTED_MODELS:
        assert (
            schema["$defs"][model_name][
                "additionalProperties"
            ]
            is False
        )
