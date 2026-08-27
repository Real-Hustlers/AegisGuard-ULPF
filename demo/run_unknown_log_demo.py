from aegisguard_ulpf.fallback.tier0 import Tier0Fallback
from aegisguard_ulpf.core.models import RawEvent, DetectionResult


def main():

    print("\n=== AegisGuard-ULPF Tier-0 Unknown Log Demo ===\n")

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

    print("Input:")
    print("Unknown vendor event")

    print("\nRaw preservation:")
    print("PASS" if result.raw_event else "FAIL")

    print("\nVendor:")
    print(fields["vendor"])

    print("\nMapping status:")
    print(fields["mapping_status"])

    print("\nSecurity meaning:")
    print(
        fields["type"],
        fields["subtype"],
        fields["outcome"]
    )

    print("\nUnmapped fields:")
    print(fields["vendor_fields"])

    print("\nStatus:")
    print("LOG ACCEPTED WITHOUT LOSS")


if __name__ == "__main__":
    main()