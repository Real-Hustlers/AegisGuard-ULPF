from pathlib import Path

from aegisguard_ulpf.core.models import (
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)
from aegisguard_ulpf.core.pipeline import ProcessingPipeline
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.normalization.ocsf.mapper import map_common_event_to_ocsf
from aegisguard_ulpf.parsing.base import BaseParser
from aegisguard_ulpf.parsing.registry import ParserRegistry
from aegisguard_ulpf.parsing.semantic_packs import (
    SemanticPackResolver,
    default_fortigate_traffic_pack_path,
    load_semantic_pack,
)
from aegisguard_ulpf.parsing.vendors.fortinet.fortigate.traffic import (
    convert_row,
)


RAW_TRAFFIC = (
    "date=2026-08-27 time=09:30:00 tz=+0530 "
    'devname="FGT-EDGE-01" devid="FGT60FTK12345678" '
    'logid="0000000013" type="traffic" subtype="forward" '
    'level="notice" srcip=10.0.0.10 srcport=50000 '
    'dstip=8.8.8.8 dstport=53 proto=17 action="accept" '
    'sessionid=12345 duration=4 sentbyte=640 rcvdbyte=320 '
    'srcintf="port1" dstintf="wan1" policyname="DNS Access" '
    'custom_field="preserved"'
)


def _raw_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in RAW_TRAFFIC.replace('"DNS Access"', "DNS_Access").split():
        key, value = token.split("=", 1)
        fields[key] = value.strip('"').replace("DNS_Access", "DNS Access")
    return fields


class LegacyFortiGateTrafficParser(BaseParser):
    metadata = ParserMetadata(
        parser_id="fortinet.fortigate.traffic",
        parser_version="legacy-test",
        vendor="Fortinet",
        product="FortiGate",
        supported_formats=["key_value"],
    )

    def parse(self, event: RawEvent) -> ParsedEvent:
        return ParsedEvent(
            raw_event=event,
            parser=self.metadata,
            fields={"legacy_parser_used": True},
        )


def _registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(LegacyFortiGateTrafficParser())
    return registry


def test_fortigate_semantic_pack_loads_with_valid_signature():
    pack = load_semantic_pack(default_fortigate_traffic_pack_path())

    assert pack.manifest.vendor == "Fortinet"
    assert pack.manifest.product == "FortiGate"
    assert pack.manifest.event_family == "traffic"
    assert pack.syntax.input_format == "key_value"
    assert pack.manifest.signature.status == "signed"
    assert pack.ocsf_binding.status == "bound"


def test_resolver_maps_fortigate_fields_before_registry_parser():
    result = ProcessingPipeline(_registry()).process(
        RawEvent(raw=RAW_TRAFFIC)
    )

    fields = result.parsed_event.fields

    assert result.parsed_event.parser.parser_id == (
        "semantic_pack:fortinet.fortigate.traffic"
    )
    assert fields["vendor"] == "Fortinet"
    assert fields["product"] == "FortiGate"
    assert fields["type"] == "traffic"
    assert fields["subtype"] == "forward"
    assert fields["outcome"] == "success"
    assert fields["action"] == "allow"
    assert fields["severity"] == "notice"
    assert fields["src_ip"] == "10.0.0.10"
    assert fields["dst_ip"] == "8.8.8.8"
    assert fields["protocol"] == "UDP"
    assert fields["details"]["policy_name"] == "DNS Access"
    assert fields["vendor_fields"]["custom_field"] == "preserved"
    assert "legacy_parser_used" not in fields


def test_semantic_mapping_matches_existing_parser_for_common_fields():
    result = ProcessingPipeline(_registry()).process(
        RawEvent(raw=RAW_TRAFFIC)
    )
    pack_fields = result.parsed_event.fields
    parser_fields = convert_row(_raw_fields(), 1)

    for field in (
        "timestamp",
        "vendor",
        "product",
        "category",
        "type",
        "subtype",
        "outcome",
        "severity",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "action",
        "vendor_event_id",
    ):
        assert pack_fields[field] == parser_fields[field]


def test_fortigate_pack_normalizes_and_generates_ocsf():
    event = RawEvent(raw=RAW_TRAFFIC)
    pipeline = ProcessingPipeline(_registry())
    result = pipeline.process(event)
    common_event = NormalizationEngine().normalize(
        result.parsed_event.fields,
        observed_time=event.ingested_at,
    )
    runtime = pipeline.semantic_pack_resolver.resolve(result.detection)

    assert runtime is not None

    ocsf_event = map_common_event_to_ocsf(
        common_event,
        runtime.pack.ocsf_binding,
    )

    assert common_event.vendor.vendor == "Fortinet"
    assert common_event.classification.type == "traffic"
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 4001
    assert ocsf_event["activity_id"] == 6
    assert ocsf_event["status_id"] == 1
    assert ocsf_event["raw_data"]["raw_id"] == event.raw_id


def test_missing_pack_falls_back_to_existing_parser():
    resolver = SemanticPackResolver({
        ("Fortinet", "FortiGate", "traffic"):
            Path("missing-fortigate-semantic-pack.json"),
    })
    result = ProcessingPipeline(
        _registry(),
        semantic_pack_resolver=resolver,
    ).process(RawEvent(raw=RAW_TRAFFIC))

    assert result.parsed_event.parser.parser_id == (
        "fortinet.fortigate.traffic"
    )
    assert result.parsed_event.fields == {
        "legacy_parser_used": True,
    }
