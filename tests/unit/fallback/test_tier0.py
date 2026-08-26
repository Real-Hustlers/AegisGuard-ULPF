from aegisguard_ulpf.core.models import (
    DetectionResult,
    RawEvent,
)

from aegisguard_ulpf.fallback.tier0 import (
    Tier0Fallback,
)


def create_detection(
    *,
    format_name: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
) -> DetectionResult:

    return DetectionResult(
        vendor=vendor,
        product=product,
        format=format_name,
        parser_id=None,
        confidence=0.0,
        evidence=[],
    )


def test_tier0_json_structural_extraction():

    fallback = Tier0Fallback()

    event = RawEvent(
        raw=(
            '{"time":"2026-08-26T20:00:00Z",'
            '"host":"box-01",'
            '"foo":"bar"}'
        )
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="json"
        ),
    )

    assert (
        result.fields["mapping_status"]
        == "incomplete"
    )

    assert (
        result.fields["vendor_fields"]
        == {
            "time":
                "2026-08-26T20:00:00Z",
            "host":
                "box-01",
            "foo":
                "bar",
        }
    )

    assert (
        result.fields["details"][
            "tier0"
        ][
            "structural_format"
        ]
        == "json"
    )


def test_tier0_does_not_guess_security_semantics():

    fallback = Tier0Fallback()

    # Intentionally contains security-looking words.
    # Tier 0 must not interpret them.
    event = RawEvent(
        raw=(
            '{"action":"deny",'
            '"severity":"critical",'
            '"src":"10.0.0.1",'
            '"message":"malware detected"}'
        )
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="json"
        ),
    )

    fields = result.fields

    assert fields["vendor"] is None
    assert fields["product"] is None

    assert fields["category"] is None
    assert fields["type"] is None
    assert fields["subtype"] is None
    assert fields["outcome"] is None
    assert fields["severity"] is None
    assert fields["action"] is None

    assert fields["src_ip"] is None
    assert fields["dst_ip"] is None

    # Original unresolved values remain preserved.
    assert (
        fields["vendor_fields"][
            "action"
        ]
        == "deny"
    )

    assert (
        fields["vendor_fields"][
            "severity"
        ]
        == "critical"
    )


def test_tier0_preserves_existing_detection_identity():

    fallback = Tier0Fallback()

    event = RawEvent(
        raw='{"foo":"bar"}'
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="json",
            vendor="ExampleVendor",
            product="ExampleProduct",
        ),
    )

    assert (
        result.fields["vendor"]
        == "ExampleVendor"
    )

    assert (
        result.fields["product"]
        == "ExampleProduct"
    )

    assert (
        result.fields["mapping_status"]
        == "incomplete"
    )


def test_tier0_csv_preserves_positional_rows():

    fallback = Tier0Fallback()

    event = RawEvent(
        raw=(
            "alpha,beta,gamma\n"
            "1,2,3"
        )
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="csv"
        ),
    )

    assert (
        result.fields["details"][
            "tier0"
        ][
            "structural_format"
        ]
        == "csv"
    )

    assert (
        result.fields["vendor_fields"]
        == {
            "rows": [
                [
                    "alpha",
                    "beta",
                    "gamma",
                ],
                [
                    "1",
                    "2",
                    "3",
                ],
            ]
        }
    )


def test_tier0_xml_preserves_structure():

    fallback = Tier0Fallback()

    event = RawEvent(
        raw=(
            '<event source="device">'
            "<message>hello</message>"
            "<value>42</value>"
            "</event>"
        )
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="xml"
        ),
    )

    root = (
        result.fields[
            "vendor_fields"
        ][
            "root"
        ]
    )

    assert root["tag"] == "event"

    assert root["attributes"] == {
        "source": "device"
    }

    assert root["children"][0] == {
        "tag": "message",
        "text": "hello",
    }

    assert (
        result.fields["mapping_status"]
        == "incomplete"
    )


def test_tier0_plain_text_is_preserved():

    fallback = Tier0Fallback()

    raw = (
        "some unsupported application "
        "started successfully"
    )

    event = RawEvent(
        raw=raw
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="text"
        ),
    )

    assert (
        result.fields["vendor_fields"]
        == {
            "text": raw
        }
    )

    assert (
        result.fields["details"][
            "tier0"
        ][
            "structural_format"
        ]
        == "text"
    )


def test_tier0_malformed_json_does_not_crash():

    fallback = Tier0Fallback()

    raw = (
        '{"foo":"bar"'
    )

    event = RawEvent(
        raw=raw
    )

    result = fallback.parse(
        event,
        create_detection(
            format_name="json"
        ),
    )

    # Malformed JSON is preserved as text rather
    # than discarded or semantically guessed.
    assert (
        result.fields[
            "vendor_fields"
        ]
        == {
            "text": raw
        }
    )

    assert (
        result.fields[
            "mapping_status"
        ]
        == "incomplete"
    )


def test_raw_event_remains_attached():

    fallback = Tier0Fallback()

    event = RawEvent(
        raw="unrecognized event"
    )

    result = fallback.parse(
        event,
        create_detection(),
    )

    assert (
        result.raw_event.event_id
        == event.event_id
    )

    assert (
        result.raw_event.raw
        == "unrecognized event"
    )


def test_tier0_parser_identity_is_explicit():

    fallback = Tier0Fallback()

    result = fallback.parse(
        RawEvent(
            raw="anything"
        ),
        create_detection(),
    )

    assert (
        result.parser.parser_id
        == "aegisguard.tier0.structural"
    )

    assert result.warnings