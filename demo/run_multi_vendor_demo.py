"""Generate the five-source SIH dashboard artifacts using existing ULPF APIs."""

from __future__ import annotations

import csv
import json
import os
import tempfile

from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

from aegisguard_ulpf.core.models import CommonEvent, RawEvent
from aegisguard_ulpf.core.pipeline import ProcessingPipeline
from aegisguard_ulpf.integration.siem_adapter import adapt_ocsf_jsonl_to_siem
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.normalization.ocsf.mapper import map_common_event_to_ocsf
from aegisguard_ulpf.normalization.ocsf.registry import (
    AUTHENTICATION_CLASS_UID,
    DETECTION_FINDING_CLASS_UID,
    NETWORK_ACTIVITY_CLASS_UID,
    PROCESS_ACTIVITY_CLASS_UID,
)
from aegisguard_ulpf.outputs.json_file import JsonlOutputWriter
from aegisguard_ulpf.parsing.registry import ParserRegistry
from aegisguard_ulpf.parsing.semantic_packs import load_semantic_pack
from aegisguard_ulpf.parsing.semantic_packs.models import OcsfBinding
from aegisguard_ulpf.parsing.semantic_packs.runtime import SemanticPackRuntime
from aegisguard_ulpf.parsing.vendors.cisco import traffic as cisco_traffic
from aegisguard_ulpf.parsing.vendors.cisco import vpn as cisco_vpn
from aegisguard_ulpf.parsing.vendors.linux.syslog import LinuxSyslogParser
from aegisguard_ulpf.parsing.vendors.palaalto.panos import traffic as panos_traffic
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT / "demo" / "input" / "multi_vendor"
OUTPUT_DIR = ROOT / "demo" / "output"
EVIDENCE_DIR = ROOT / "demo" / "evidence"
PANOS_PACK = (
    ROOT
    / "src"
    / "aegisguard_ulpf"
    / "parsing"
    / "semantic_packs"
    / "packs"
    / "paloalto_panos_traffic_v1.json"
)


SEVERITY_MAPPINGS = {
    "unknown": 0,
    "UNKNOWN": 0,
    "debug": 1,
    "informational": 1,
    "information": 1,
    "notice": 2,
    "low": 2,
    "warning": 3,
    "medium": 3,
    "error": 4,
    "high": 4,
    "alert": 5,
    "critical": 5,
    "emergency": 5,
    "fatal": 6,
}

STATUS_MAPPINGS = {
    "unknown": 0,
    "UNKNOWN": 0,
    "success": 1,
    "SUCCESS": 1,
    "failure": 2,
    "FAILURE": 2,
}

NETWORK_BINDING = OcsfBinding(
    status="bound",
    class_uid=NETWORK_ACTIVITY_CLASS_UID,
    activity_mappings={
        "traffic": 6,
        "SESSION": 6,
        "POLICY": 6,
    },
    status_mappings=STATUS_MAPPINGS,
    severity_mappings=SEVERITY_MAPPINGS,
    default_severity_id=0,
)

AUTHENTICATION_BINDING = OcsfBinding(
    status="bound",
    class_uid=AUTHENTICATION_CLASS_UID,
    activity_mappings={
        "vpn": 1,
        "AUTHENTICATION": 1,
    },
    status_mappings=STATUS_MAPPINGS,
    severity_mappings=SEVERITY_MAPPINGS,
    default_severity_id=0,
)

PROCESS_BINDING = OcsfBinding(
    status="bound",
    class_uid=PROCESS_ACTIVITY_CLASS_UID,
    activity_mappings={"PROCESS": 1},
    status_mappings=STATUS_MAPPINGS,
    severity_mappings=SEVERITY_MAPPINGS,
    default_severity_id=0,
)

DETECTION_BINDING = OcsfBinding(
    status="bound",
    class_uid=DETECTION_FINDING_CLASS_UID,
    activity_mappings={"ALERT": 1},
    status_mappings=STATUS_MAPPINGS,
    severity_mappings=SEVERITY_MAPPINGS,
    default_severity_id=0,
)


@dataclass(frozen=True)
class PreparedEvent:
    raw_event: RawEvent
    fields: dict[str, Any]
    binding: OcsfBinding
    parser_path: str


@dataclass(frozen=True)
class DemoResult:
    sources_processed: int
    events_generated: int
    ocsf_events: int
    traceability_passed: bool
    output_dir: Path


def _records(path: Path) -> list[bytes]:
    """Return complete event bytes without treating blank lines as events."""
    if path.suffix.casefold() == ".json":
        raw = path.read_bytes()
        return [raw] if raw.strip() else []

    return [
        line.strip().encode("utf-8")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _raw_event(
    store: RawEvidenceStore,
    raw_bytes: bytes,
    *,
    source_file: str,
    sequence: int,
    vendor: str,
    product: str,
) -> RawEvent:
    identity = {
        "source": source_file,
        "sequence": sequence,
    }
    metadata = {
        "source": source_file,
        "vendor": vendor,
        "product": product,
        "sequence": sequence,
    }
    evidence = store.store(
        raw_bytes,
        identity_context=identity,
        transport="demo_file",
        metadata=metadata,
    )
    return RawEvent(
        event_id=evidence.event_id,
        raw=raw_bytes.decode("utf-8"),
        transport="demo_file",
        metadata=metadata,
        evidence_raw_id=evidence.raw_id,
        raw_sha256=evidence.raw_sha256,
    )


def _trace_fields(fields: dict[str, Any], raw_event: RawEvent) -> dict[str, Any]:
    traced = dict(fields)
    traced["u_id"] = str(raw_event.event_id)
    traced["raw_id"] = raw_event.raw_id

    details = dict(traced.get("details") or {})
    details["raw_sha256"] = raw_event.raw_sha256
    traced["details"] = details
    traced["vendor_fields"] = dict(traced.get("vendor_fields") or {})
    return traced


def _iso_cisco_timestamp(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    try:
        parsed = datetime.strptime(value, "%b %d %Y %H:%M:%S")
    except ValueError:
        return value
    return parsed.replace(tzinfo=timezone.utc).isoformat()


def _leading_iso_timestamp(raw: str) -> str | None:
    token = raw.split(maxsplit=1)[0] if raw.strip() else ""
    if not token:
        return None
    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def _panos_csv(payload: dict[str, Any]) -> str:
    """Project the JSON demo envelope into the existing PAN-OS CSV contract."""
    values = {name: "" for name in panos_traffic.TRAFFIC_FIELD_NAMES}
    values.update({
        "future_use_1": "1",
        "receive_time": payload.get("timestamp"),
        "serial": payload.get("serial"),
        "type": "TRAFFIC",
        "subtype": payload.get("subtype", "end"),
        "config_version": "1",
        "time_generated": payload.get("timestamp"),
        "src": payload.get("src_ip"),
        "dst": payload.get("dst_ip"),
        "natsrc": "0.0.0.0",
        "natdst": "0.0.0.0",
        "rule": payload.get("rule"),
        "app": payload.get("application"),
        "vsys": "vsys1",
        "from_zone": payload.get("source_zone"),
        "to_zone": payload.get("destination_zone"),
        "inbound_if": "ethernet1/1",
        "outbound_if": "ethernet1/2",
        "sessionid": payload.get("session_id"),
        "repeatcnt": 1,
        "sport": payload.get("src_port"),
        "dport": payload.get("dst_port"),
        "proto": payload.get("protocol"),
        "action": payload.get("action"),
        "bytes": payload.get("bytes"),
        "packets": payload.get("packets"),
        "device_name": payload.get("device"),
    })
    stream = StringIO()
    csv.writer(stream, lineterminator="").writerow(
        [values[name] for name in panos_traffic.TRAFFIC_FIELD_NAMES]
    )
    return stream.getvalue()


def _fortigate_events(store: RawEvidenceStore, input_dir: Path) -> Iterable[PreparedEvent]:
    path = input_dir / "fortigate_traffic.log"
    pipeline = ProcessingPipeline(ParserRegistry())
    for sequence, raw_bytes in enumerate(_records(path), start=1):
        raw_event = _raw_event(
            store,
            raw_bytes,
            source_file=path.name,
            sequence=sequence,
            vendor="Fortinet",
            product="FortiGate",
        )
        result = pipeline.process(raw_event)
        runtime = pipeline.semantic_pack_resolver.resolve(result.detection)
        if runtime is None:
            raise RuntimeError("FortiGate Traffic semantic pack was not resolved")
        yield PreparedEvent(
            raw_event=raw_event,
            fields=_trace_fields(result.parsed_event.fields, raw_event),
            binding=runtime.pack.ocsf_binding,
            parser_path=result.parsed_event.parser.parser_id,
        )


def _cisco_events(store: RawEvidenceStore, input_dir: Path) -> Iterable[PreparedEvent]:
    path = input_dir / "cisco_asa_firewall.log"
    for sequence, raw_bytes in enumerate(_records(path), start=1):
        raw_event = _raw_event(
            store,
            raw_bytes,
            source_file=path.name,
            sequence=sequence,
            vendor="Cisco",
            product="ASA",
        )
        is_vpn = "%ASA-6-716001:" in raw_event.raw
        fields = (
            cisco_vpn.convert(raw_event.raw, sequence)
            if is_vpn
            else cisco_traffic.convert(raw_event.raw, sequence)
        )
        fields["timestamp"] = _iso_cisco_timestamp(fields.get("timestamp"))
        fields = _trace_fields(fields, raw_event)
        binding = AUTHENTICATION_BINDING if is_vpn else NETWORK_BINDING
        parser_path = "cisco.asa.vpn" if is_vpn else "cisco.asa.traffic"
        yield PreparedEvent(raw_event, fields, binding, parser_path)


def _paloalto_events(store: RawEvidenceStore, input_dir: Path) -> Iterable[PreparedEvent]:
    path = input_dir / "paloalto_traffic.json"
    pack_runtime = SemanticPackRuntime(load_semantic_pack(PANOS_PACK))
    for sequence, raw_bytes in enumerate(_records(path), start=1):
        raw_event = _raw_event(
            store,
            raw_bytes,
            source_file=path.name,
            sequence=sequence,
            vendor="Palo Alto Networks",
            product="PAN-OS",
        )
        payload = json.loads(raw_event.raw)
        if not isinstance(payload, dict):
            raise ValueError("Palo Alto demo input must be a JSON object")
        fields = pack_runtime.run(
            _panos_csv(payload),
            raw_id=raw_event.raw_id,
            u_id=str(raw_event.event_id),
        )
        fields = _trace_fields(fields, raw_event)
        fields["details"]["input_format"] = "json"
        yield PreparedEvent(
            raw_event,
            fields,
            pack_runtime.pack.ocsf_binding,
            "semantic_pack:paloalto.panos.traffic",
        )


def _suricata_events(store: RawEvidenceStore, input_dir: Path) -> Iterable[PreparedEvent]:
    path = input_dir / "suricata_alert.json"
    fallback_pipeline = ProcessingPipeline(ParserRegistry())
    for sequence, raw_bytes in enumerate(_records(path), start=1):
        raw_event = _raw_event(
            store,
            raw_bytes,
            source_file=path.name,
            sequence=sequence,
            vendor="Suricata",
            product="IDS",
        )
        fallback = fallback_pipeline.process(raw_event)
        payload = fallback.parsed_event.fields.get("vendor_fields")
        if not isinstance(payload, dict):
            raise ValueError("Suricata Tier-0 extraction did not produce an object")
        alert = payload.get("alert")
        source = payload.get("source")
        if not isinstance(alert, dict) or not isinstance(source, dict):
            raise ValueError("Suricata demo input requires source and alert objects")

        severity = {1: "critical", 2: "high", 3: "medium"}.get(
            alert.get("severity"),
            "unknown",
        )
        fields = {
            **fallback.parsed_event.fields,
            "timestamp": payload.get("timestamp"),
            "vendor": source.get("vendor"),
            "product": source.get("product"),
            "category": "detection_finding",
            "type": "ALERT",
            "subtype": alert.get("signature"),
            "outcome": "UNKNOWN",
            "severity": severity,
            "src_ip": payload.get("src_ip"),
            "src_port": payload.get("src_port"),
            "dst_ip": payload.get("dest_ip"),
            "dst_port": payload.get("dest_port"),
            "protocol": payload.get("proto"),
            "action": "alert",
            "reason": alert.get("category"),
            "object_type": "ids_signature",
            "object_name": alert.get("signature"),
            "vendor_event_id": str(alert.get("signature_id")),
            "details": {
                "flow_id": payload.get("flow_id"),
                "signature_revision": alert.get("rev"),
                "tier0_preserved_before_demo_projection": True,
            },
            "vendor_fields": payload,
            "mapping_status": "mapped",
        }
        yield PreparedEvent(
            raw_event,
            _trace_fields(fields, raw_event),
            DETECTION_BINDING,
            "aegisguard.tier0.structural + demo EVE projection",
        )


def _linux_events(store: RawEvidenceStore, input_dir: Path) -> Iterable[PreparedEvent]:
    path = input_dir / "linux_auth.log"
    parser = LinuxSyslogParser()
    for sequence, raw_bytes in enumerate(_records(path), start=1):
        raw_event = _raw_event(
            store,
            raw_bytes,
            source_file=path.name,
            sequence=sequence,
            vendor="Linux",
            product="Syslog",
        )
        fields = parser.parse(raw_event).fields
        fields["timestamp"] = _leading_iso_timestamp(raw_event.raw)
        fields = _trace_fields(fields, raw_event)
        binding = (
            AUTHENTICATION_BINDING
            if fields.get("type") == "AUTHENTICATION"
            else PROCESS_BINDING
        )
        yield PreparedEvent(raw_event, fields, binding, parser.metadata.parser_id)


def _prepared_events(store: RawEvidenceStore, input_dir: Path) -> list[PreparedEvent]:
    events: list[PreparedEvent] = []
    for loader in (
        _fortigate_events,
        _cisco_events,
        _paloalto_events,
        _suricata_events,
        _linux_events,
    ):
        events.extend(loader(store, input_dir))
    return events


def _write_outputs(
    prepared_events: list[PreparedEvent],
    *,
    output_dir: Path,
) -> tuple[list[CommonEvent], list[dict[str, Any]]]:
    engine = NormalizationEngine()
    common_events: list[CommonEvent] = []
    ocsf_events: list[dict[str, Any]] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=".multi_vendor_",
        dir=output_dir,
    ) as temporary:
        writer = JsonlOutputWriter(temporary)
        for prepared in prepared_events:
            common_event = engine.normalize(
                prepared.fields,
                observed_time=prepared.raw_event.ingested_at,
            )
            ocsf_event = map_common_event_to_ocsf(common_event, prepared.binding)
            if ocsf_event is None:
                raise RuntimeError(f"OCSF binding deferred for {prepared.parser_path}")

            raw_data = dict(ocsf_event.get("raw_data") or {})
            raw_data.update({
                "raw_sha256": prepared.raw_event.raw_sha256,
                "source_file": prepared.raw_event.metadata.get("source"),
            })
            ocsf_event["raw_data"] = raw_data
            ocsf_event["unmapped"] = {
                "common_action": common_event.classification.action,
                "common_subtype": common_event.classification.subtype,
                "parser_path": prepared.parser_path,
            }

            writer.write_raw(prepared.raw_event)
            writer.write_normalized(common_event)
            writer.write_ocsf(ocsf_event)
            common_events.append(common_event)
            ocsf_events.append(ocsf_event)

        for staged in (writer.raw_path, writer.normalized_path, writer.ocsf_path):
            os.replace(staged, output_dir / staged.name)

    adapt_ocsf_jsonl_to_siem(
        output_dir / "ocsf_events.jsonl",
        output_dir / "merged_logs.json",
    )
    return common_events, ocsf_events


def run_demo(
    *,
    input_dir: Path = INPUT_DIR,
    output_dir: Path = OUTPUT_DIR,
    evidence_dir: Path = EVIDENCE_DIR,
) -> DemoResult:
    store = RawEvidenceStore(evidence_dir)
    prepared_events = _prepared_events(store, input_dir)
    common_events, ocsf_events = _write_outputs(
        prepared_events,
        output_dir=output_dir,
    )

    sources = {
        (event.vendor.vendor, event.vendor.product)
        for event in common_events
    }
    traceability_passed = all(
        store.verify(str(event.raw_event.event_id)).get("integrity") == "PASS"
        for event in prepared_events
    )
    return DemoResult(
        sources_processed=len(sources),
        events_generated=len(common_events),
        ocsf_events=len(ocsf_events),
        traceability_passed=traceability_passed,
        output_dir=output_dir,
    )


def main() -> None:
    result = run_demo()
    print("=== Multi Vendor Demo ===")
    print()
    print(f"Sources processed: {result.sources_processed}")
    print(f"Events generated: {result.events_generated}")
    print(f"OCSF events: {result.ocsf_events}")
    print(f"Traceability: {'PASS' if result.traceability_passed else 'FAIL'}")
    print()
    print("Dashboard artifacts:")
    for name in (
        "raw_events.jsonl",
        "normalized_events.jsonl",
        "ocsf_events.jsonl",
        "merged_logs.json",
    ):
        print(result.output_dir / name)


if __name__ == "__main__":
    main()
