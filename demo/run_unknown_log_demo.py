from aegisguard_ulpf.core.models import RawEvent, DetectionResult
from aegisguard_ulpf.fallback.tier0 import Tier0Fallback


def main() -> None:
    """Present the existing Tier-0 contract without adding semantics."""

    print("\n=== Tier-0 Unknown Log Handling ===\n")

    raw_log = """
    {
        "device": "unknown-firewall-x",
        "custom_action": "blocked_connection",
        "field123": "value"
    }
    """

    raw_event = RawEvent(
        raw=raw_log
    )

    detection = DetectionResult(
        vendor="unknown",
        product="unknown",
        format="json",
    )

    parser = Tier0Fallback()

    result = parser.parse(
        raw_event,
        detection,
    )

    fields = result.fields

    if result.raw_event.raw != raw_log:
        raise RuntimeError("Tier-0 did not retain the original raw log")
    if any(
        fields[name] is not None
        for name in ("category", "type", "subtype", "outcome", "severity", "action")
    ):
        raise RuntimeError("Tier-0 must not infer security semantics")

    print("Raw preserved: PASS\n")
    print("Vendor:")
    print(fields["vendor"] or "unknown")
    print("\nSecurity meaning:")
    print("NOT INFERRED")
    print("\nMapping status:")
    print(fields["mapping_status"])
    print("\nCoverage:")
    print("0%")
    print("\nUnmapped fields:")
    print("available" if fields["vendor_fields"] else "none")
    print("\nResult:")
    print("LOG ACCEPTED WITHOUT LOSS")


if __name__ == "__main__":
    main()
