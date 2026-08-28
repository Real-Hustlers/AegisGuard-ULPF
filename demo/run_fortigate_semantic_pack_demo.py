from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.core.pipeline import ProcessingPipeline
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.normalization.ocsf.mapper import map_common_event_to_ocsf
from aegisguard_ulpf.parsing.registry import ParserRegistry


FORTIGATE_TRAFFIC_LOG = (
    "date=2026-08-27 time=09:30:00 tz=+0530 "
    'devname="FGT-EDGE-01" devid="FGT60FTK12345678" '
    'logid="0000000013" type="traffic" subtype="forward" '
    'level="notice" srcip=10.0.0.10 srcport=50000 '
    'dstip=8.8.8.8 dstport=53 proto=17 action="accept" '
    'sessionid=12345 policyname="DNS Access"'
)


def main() -> None:
    raw_event = RawEvent(
        raw=FORTIGATE_TRAFFIC_LOG,
        transport="syslog_udp",
    )

    # An empty registry proves this event was handled by the data-only pack.
    # If the pack is unavailable, normal deployments continue to a registered
    # legacy parser; this focused demo intentionally requires the pack.
    pipeline = ProcessingPipeline(
        registry=ParserRegistry()
    )
    result = pipeline.process(raw_event)
    runtime = pipeline.semantic_pack_resolver.resolve(
        result.detection
    )

    if runtime is None:
        raise RuntimeError(
            "FortiGate Traffic semantic pack was not loaded"
        )

    common_event = NormalizationEngine().normalize(
        result.parsed_event.fields,
        observed_time=raw_event.ingested_at,
    )
    ocsf_event = map_common_event_to_ocsf(
        common_event,
        runtime.pack.ocsf_binding,
    )

    if common_event.vendor.vendor != "Fortinet":
        raise RuntimeError("Common Taxonomy mapping failed")
    if ocsf_event is None or ocsf_event.get("class_uid") != 4001:
        raise RuntimeError("OCSF mapping failed")

    print("=== FortiGate Semantic Pack Demo ===")
    print()
    print("Raw vendor:")
    print("Fortinet FortiGate Traffic")
    print()
    print("Semantic Pack:")
    print("LOADED")
    print()
    print("Parser modification:")
    print("NONE")
    print()
    print("Engine modification:")
    print("NONE")
    print()
    print("Common Taxonomy:")
    print("SUCCESS")
    print()
    print("OCSF:")
    print("SUCCESS")


if __name__ == "__main__":
    main()
