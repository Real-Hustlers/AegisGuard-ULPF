"""Evidence-based Streamlit dashboard for AegisGuard-ULPF artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from utils.evidence import (
    as_mapping,
    audit_airgap,
    collect_unified_events,
    discover_semantic_packs,
    load_drift_evidence,
    load_jsonl,
    run_pipeline_benchmark,
    validate_ocsf_outputs,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "demo" / "output"
EVIDENCE = ROOT / "demo" / "evidence"

st.set_page_config(
    page_title="AegisGuard-ULPF Evidence Dashboard",
    page_icon="AG",
    layout="wide",
)


def raw_id(event: dict[str, Any]) -> str | None:
    """Resolve identifiers using the documented raw-ID lookup order."""
    traceability = as_mapping(event.get("traceability"))
    raw_data = as_mapping(event.get("raw_data"))
    for candidate in (
        event.get("raw_id"),
        event.get("evidence_raw_id"),
        traceability.get("raw_id"),
        raw_data.get("raw_id"),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def event_id(event: dict[str, Any]) -> str:
    traceability = as_mapping(event.get("traceability"))
    raw_data = as_mapping(event.get("raw_data"))
    for candidate in (
        event.get("event_id"),
        traceability.get("u_id"),
        raw_data.get("u_id"),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    return "unknown-event"


def source_name(raw_event: dict[str, Any]) -> str:
    source = as_mapping(raw_event.get("metadata")).get("source", "unknown source")
    if isinstance(source, dict):
        return str(source.get("product") or source.get("vendor") or "unknown source")
    return str(source)


def vendor_product(event: dict[str, Any]) -> tuple[str, str]:
    vendor = as_mapping(event.get("vendor"))
    return (
        str(vendor.get("vendor") or "unknown"),
        str(vendor.get("product") or "unknown"),
    )


def common_summary(event: dict[str, Any] | None) -> str:
    if event is None:
        return "Unmatched normalized event"
    classification = as_mapping(event.get("classification"))
    return str(classification.get("subtype") or classification.get("type") or "Common Event")


def verify_evidence(identifier: str) -> dict[str, Any] | None:
    """Call the authoritative evidence verifier without changing evidence."""
    if not EVIDENCE.is_dir() or not identifier or identifier == "unknown-event":
        return None
    try:
        from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore

        return RawEvidenceStore(EVIDENCE).verify(identifier)
    except Exception:
        return None


def evidence_caption(*filenames: str) -> None:
    available = [name for name in filenames if (ROOT / name).exists()]
    if available:
        st.caption("Evidence: " + " · ".join(available))


def show_messages(messages: list[str], title: str) -> None:
    if not messages:
        return
    with st.expander(f"{title} ({len(messages)})"):
        for message in messages:
            st.write(f"• {message}")


raw_events, raw_messages = load_jsonl(OUTPUT / "raw_events.jsonl", ROOT)
normalized_events, normalized_messages = load_jsonl(
    OUTPUT / "normalized_events.jsonl",
    ROOT,
)
ocsf_events, ocsf_messages = load_jsonl(OUTPUT / "ocsf_events.jsonl", ROOT)
normalized_by_raw = {
    raw_id(item): item for item in normalized_events if raw_id(item)
}
ocsf_by_raw = {raw_id(item): item for item in ocsf_events if raw_id(item)}


st.title("AegisGuard-ULPF")
st.caption(
    "Evidence dashboard: heterogeneous raw logs → Common Taxonomy → "
    "OCSF → forensic verification"
)


st.header("Pipeline Evidence Summary")
vendors = {vendor_product(event) for event in normalized_events}
unique_event_ids = {
    event_id(event)
    for event in raw_events
    if event_id(event) != "unknown-event"
}
verification_reports = [
    report
    for identifier in unique_event_ids
    if (report := verify_evidence(identifier)) is not None
]
verified_count = sum(
    report.get("integrity") == "PASS" for report in verification_reports
)
integrity_value = (
    f"{verified_count}/{len(unique_event_ids)} verified"
    if verification_reports
    else "Not generated"
)

summary_columns = st.columns(5)
for column, label, value in zip(
    summary_columns,
    (
        "Raw Events",
        "Normalized Events",
        "OCSF Events",
        "Total Security Sources",
        "Integrity",
    ),
    (len(raw_events), len(normalized_events), len(ocsf_events), len(vendors), integrity_value),
):
    column.metric(label, value)

evidence_caption(
    "demo/output/raw_events.jsonl",
    "demo/output/normalized_events.jsonl",
    "demo/output/ocsf_events.jsonl",
    "demo/evidence/evidence_manifest.jsonl",
)
show_messages(raw_messages + normalized_messages + ocsf_messages, "Pipeline artifact notices")


st.header("Multi Vendor Sources")
source_counts: dict[tuple[str, str], int] = {}
for normalized_event in normalized_events:
    source = vendor_product(normalized_event)
    source_counts[source] = source_counts.get(source, 0) + 1

if source_counts:
    ordered_sources = sorted(
        source_counts.items(),
        key=lambda item: (item[0][0].casefold(), item[0][1].casefold()),
    )
    for start in range(0, len(ordered_sources), 3):
        columns = st.columns(3)
        for column, ((vendor, product), count) in zip(
            columns,
            ordered_sources[start : start + 3],
        ):
            with column:
                with st.container(border=True):
                    st.markdown(f"**{vendor}**")
                    st.write(f"Product: {product}")
                    st.metric("Events", count)
    evidence_caption("demo/output/normalized_events.jsonl")
else:
    st.info("No normalized source inventory is available yet.")


st.header("Semantic Pack Registry")
semantic_packs, pack_messages = discover_semantic_packs(ROOT)
validated_pack_count = sum(pack["signature_valid"] for pack in semantic_packs)
pack_metrics = st.columns(4)
pack_metrics[0].metric("Loaded Packs", len(semantic_packs))
pack_metrics[1].metric("Signatures Validated", validated_pack_count)
pack_metrics[2].metric(
    "Field Mapping Operations",
    sum(pack["field_mapping_count"] for pack in semantic_packs),
)
pack_metrics[3].metric(
    "Explicit OCSF Facts",
    sum(pack["ocsf_binding_count"] for pack in semantic_packs),
)

if semantic_packs:
    st.markdown("#### Registered packs")
    for start in range(0, len(semantic_packs), 3):
        columns = st.columns(3)
        for column, pack in zip(columns, semantic_packs[start : start + 3]):
            with column:
                with st.container(border=True):
                    st.markdown(f"**{pack['vendor']} · {pack['product']}**")
                    st.write(f"Event family: {pack['event_family']}")
                    st.write(f"Version: {pack['version']}")
                    st.caption(pack["path"])

    pack_labels = [
        f"{pack['vendor']} | {pack['product']} | {pack['event_family']} | {pack['pack_id']}"
        for pack in semantic_packs
    ]
    selected_pack_label = st.selectbox(
        "Inspect semantic pack",
        pack_labels,
        key="semantic_pack_selector",
    )
    selected_pack = semantic_packs[pack_labels.index(selected_pack_label)]

    with st.container(border=True):
        st.markdown(f"#### {selected_pack['pack_id']}")
        details = st.columns(4)
        details[0].metric("Field Mappings", selected_pack["field_mapping_count"])
        details[1].metric("OCSF Facts", selected_pack["ocsf_binding_count"])
        details[2].metric("Pack Version", selected_pack["version"])
        details[3].metric("Binding", str(selected_pack["ocsf_binding_status"]).upper())
        st.write(f"Vendor: {selected_pack['vendor']}")
        st.write(f"Product: {selected_pack['product']}")
        st.write(f"Event family: {selected_pack['event_family']}")
        st.write("Supported formats: " + ", ".join(selected_pack["supported_formats"]))
        if selected_pack["signature_valid"]:
            st.write(
                "Signature: validated using "
                f"{selected_pack['signature_algorithm']} / "
                f"{selected_pack['signature_key_id']}"
            )
        else:
            st.warning(
                "Signature validation failed: "
                + str(selected_pack["validation_error"] or "unknown validation error")
            )
        st.caption(f"Evidence: {selected_pack['path']}")
else:
    st.info("No readable semantic_pack.json artifacts were found.")
show_messages(pack_messages, "Semantic pack notices")


st.header("Unified Cross Vendor Visibility")
st.caption(
    "Different artifact shapes are projected into the same Common Taxonomy "
    "query fields: vendor, product, event family, endpoints, action, and outcome."
)
unified_events, unified_messages = collect_unified_events(ROOT)
pack_vendors = {str(pack["vendor"]) for pack in semantic_packs}
vendor_options = sorted(
    {str(event["vendor"]) for event in unified_events} | pack_vendors,
    key=str.casefold,
)
family_options = sorted(
    {str(event["event_family"]) for event in unified_events}
    | {str(pack["event_family"]).title() for pack in semantic_packs},
    key=str.casefold,
)
filter_columns = st.columns(2)
selected_vendor = filter_columns[0].selectbox(
    "Vendor",
    ["All vendors", *vendor_options],
    key="unified_vendor_filter",
)
selected_family = filter_columns[1].selectbox(
    "Event Family",
    ["All families", *family_options],
    key="unified_family_filter",
)

filtered_events = [
    event
    for event in unified_events
    if (
        selected_vendor == "All vendors"
        or event["vendor"].casefold() == selected_vendor.casefold()
    )
    and (
        selected_family == "All families"
        or event["event_family"].casefold() == selected_family.casefold()
    )
]

if filtered_events:
    st.write(
        f"Showing {len(filtered_events)} unique taxonomy views from "
        f"{sum(event['artifact_records'] for event in filtered_events)} artifact records."
    )
    for start in range(0, min(len(filtered_events), 12), 3):
        columns = st.columns(3)
        for column, event in zip(columns, filtered_events[start : start + 3]):
            with column:
                with st.container(border=True):
                    st.markdown(f"**{event['vendor']} · {event['product']}**")
                    st.write(f"Event family: {event['event_family']}")
                    st.write(f"Event type: {event['event_type'] or 'not present'}")
                    st.write(f"Raw format: {event['input_format'] or 'not linked'}")
                    st.write(f"Source IP: {event['source_ip'] or 'not present'}")
                    st.write(f"Destination IP: {event['destination_ip'] or 'not present'}")
                    st.write(
                        "Action: "
                        + (str(event["action"]).upper() if event["action"] else "not present")
                    )
                    st.write(f"Outcome: {event['outcome'] or 'not present'}")
                    if event["taxonomy_vendor"] != event["vendor"]:
                        st.caption(f"Taxonomy vendor: {event['taxonomy_vendor']}")
                    st.caption(
                        f"Evidence: {event['source_file']} · "
                        f"records represented: {event['artifact_records']}"
                    )
else:
    st.info(
        "No generated Common Taxonomy event matches these filters. "
        "The vendor may be registered by a semantic pack without a generated event artifact."
    )
show_messages(unified_messages, "Unified artifact notices")


st.header("OCSF Validation Evidence")
ocsf_report = validate_ocsf_outputs(ROOT)
ocsf_columns = st.columns(5)
ocsf_columns[0].metric("Total OCSF Events", ocsf_report["total"])
ocsf_columns[1].metric("Valid", ocsf_report["valid"])
ocsf_columns[2].metric("Invalid", ocsf_report["invalid"])
ocsf_columns[3].metric("Missing Required Fields", ocsf_report["missing_field_occurrences"])
ocsf_columns[4].metric("Compliance", f"{ocsf_report['compliance']:.1f}%")

if ocsf_report["missing_fields"]:
    with st.expander("Missing required field counts"):
        for field, count in sorted(ocsf_report["missing_fields"].items()):
            st.write(f"{field}: {count}")
if ocsf_report["malformed"]:
    st.write(f"Malformed JSON records counted as invalid: {ocsf_report['malformed']}")
if ocsf_report["evidence_files"]:
    st.caption("Evidence: " + " · ".join(ocsf_report["evidence_files"]))
else:
    st.info("No generated ocsf_events.jsonl files were found.")
show_messages(ocsf_report["warnings"], "OCSF validation notices")


st.header("Parser Drift Monitoring")
drift, drift_messages = load_drift_evidence(ROOT)
if drift is None:
    st.info(drift_messages[0])
else:
    with st.container(border=True):
        st.markdown(f"**{drift['vendor']} · {drift['product']} · {drift['event_type']}**")
        drift_columns = st.columns(4)
        drift_columns[0].metric("Previous Coverage", f"{drift['previous_coverage']:.1f}%")
        drift_columns[1].metric("Current Coverage", f"{drift['current_coverage']:.1f}%")
        drift_columns[2].metric("Field Loss", f"{drift['field_loss']:g} fields")
        drift_status = str(drift["status"])
        if drift_status in {"DETECTED", "STABLE"}:
            drift_status = f"PARSER DRIFT {drift_status}"
        drift_columns[3].metric("Status", drift_status)
        st.caption(f"Evidence: {drift['evidence_file']}")
if drift is not None:
    show_messages(drift_messages, "Parser drift notices")


st.header("Event Trace Explorer")
if not raw_events:
    st.info("No raw events are available. Run an existing ULPF demo and refresh.")
else:
    choices: dict[str, dict[str, Any]] = {}
    for index, raw_event in enumerate(raw_events, start=1):
        identifier = raw_id(raw_event) or event_id(raw_event)
        normalized = normalized_by_raw.get(identifier)
        vendor, _ = vendor_product(normalized or {})
        label = (
            f"{source_name(raw_event)} | {vendor} | {common_summary(normalized)} "
            f"| {identifier[:18]}… | record {index}"
        )
        choices[label] = raw_event

    filter_text = st.text_input(
        "Search by source file, vendor, event type, or identifier"
    ).strip().casefold()
    filtered_choices = {
        label: item
        for label, item in choices.items()
        if not filter_text or filter_text in label.casefold()
    }

    if not filtered_choices:
        st.info("No traceable event matches the search.")
    else:
        selected_label = st.selectbox(
            "Select event",
            list(filtered_choices),
            key="trace_event_selector",
        )
        selected_raw = filtered_choices[selected_label]
        selected_raw_id = raw_id(selected_raw)
        selected_normalized = normalized_by_raw.get(selected_raw_id)
        selected_ocsf = ocsf_by_raw.get(selected_raw_id)
        selected_vendor, selected_product = vendor_product(selected_normalized or {})
        verification = verify_evidence(event_id(selected_raw))

        st.markdown("#### Trace identity")
        identity_columns = st.columns(2)
        with identity_columns[0]:
            st.write(f"Event ID: {event_id(selected_raw)}")
            st.write(f"Raw ID: {selected_raw_id or 'not present'}")
            st.write(f"Source file: {source_name(selected_raw)}")
        with identity_columns[1]:
            st.write(f"Vendor: {selected_vendor}")
            st.write(f"Product: {selected_product}")
            st.write(f"SHA256: {selected_raw.get('raw_sha256') or 'not present'}")

        st.markdown("#### Hash-chain verification")
        if verification:
            verification_columns = st.columns(4)
            verification_columns[0].metric(
                "Original Found",
                "YES" if verification.get("original_event_found") else "NO",
            )
            verification_columns[1].metric(
                "Hash Match",
                "YES" if verification.get("raw_sha256_verified") else "NO",
            )
            verification_columns[2].metric(
                "Chain Valid",
                "YES" if verification.get("hash_chain_verified") else "NO",
            )
            verification_columns[3].metric(
                "Chain Index",
                verification.get("chain_index", "not present"),
            )
            st.write(f"Verified SHA256: {verification.get('raw_sha256') or 'not present'}")
            st.caption("Evidence: demo/evidence/evidence_manifest.jsonl")
        else:
            st.info(
                "No authoritative verification report is available for this event. "
                "The raw, taxonomy, and OCSF artifacts remain inspectable below."
            )

        flow_columns = st.columns([1, 0.2, 1, 0.2, 1])
        flow_columns[0].markdown("**Raw Vendor Log**")
        flow_columns[1].markdown("→")
        flow_columns[2].markdown("**Common Taxonomy**")
        flow_columns[3].markdown("→")
        flow_columns[4].markdown("**OCSF Event**")

        with st.expander("1. Original Raw Vendor Log", expanded=True):
            st.code(
                str(
                    selected_raw.get("raw")
                    or selected_raw.get("raw_content")
                    or "Raw text unavailable"
                ),
                language="text",
            )
            raw_details = st.columns(3)
            raw_details[0].write(
                f"Timestamp: {selected_raw.get('ingested_at') or 'not present'}"
            )
            raw_details[1].write(
                f"Transport: {selected_raw.get('transport') or 'not present'}"
            )
            raw_details[2].write(f"Source: {source_name(selected_raw)}")
            st.caption("Evidence: demo/output/raw_events.jsonl")

        with st.expander("2. Common Taxonomy Event", expanded=True):
            if selected_normalized is None:
                st.info("No normalized event matched the selected raw identifier.")
            else:
                classification = as_mapping(selected_normalized.get("classification"))
                src = as_mapping(selected_normalized.get("src_endpoint"))
                dst = as_mapping(selected_normalized.get("dst_endpoint"))
                network = as_mapping(selected_normalized.get("network"))
                taxonomy_columns = st.columns(3)
                with taxonomy_columns[0]:
                    st.write(f"Category: {classification.get('category') or 'not present'}")
                    st.write(f"Type: {classification.get('type') or 'not present'}")
                    st.write(f"Subtype: {classification.get('subtype') or 'not present'}")
                with taxonomy_columns[1]:
                    st.write(f"Action: {classification.get('action') or 'not present'}")
                    st.write(f"Outcome: {classification.get('outcome') or 'not present'}")
                    st.write(f"Severity: {classification.get('severity') or 'not present'}")
                with taxonomy_columns[2]:
                    st.write(f"Source IP: {src.get('ip') or 'not present'}")
                    st.write(f"Destination IP: {dst.get('ip') or 'not present'}")
                    st.write(f"Protocol: {network.get('protocol') or 'not present'}")
                st.write(
                    f"Mapping status: {selected_normalized.get('mapping_status') or 'not present'}"
                )
                st.write(f"Timestamps: {selected_normalized.get('timestamps') or 'not present'}")
                st.caption("Evidence: demo/output/normalized_events.jsonl")

        with st.expander("3. OCSF Event", expanded=True):
            if selected_ocsf is None:
                st.info("No OCSF event matched the selected raw identifier.")
            else:
                metadata = as_mapping(selected_ocsf.get("metadata"))
                ocsf_detail_columns = st.columns(3)
                with ocsf_detail_columns[0]:
                    st.write(f"Class UID: {selected_ocsf.get('class_uid', 'not present')}")
                    st.write(f"Class: {selected_ocsf.get('class_name') or 'not present'}")
                    st.write(
                        "Activity: "
                        + str(
                            selected_ocsf.get("activity_name")
                            or selected_ocsf.get("activity_id", "not present")
                        )
                    )
                with ocsf_detail_columns[1]:
                    st.write(
                        f"Category: {selected_ocsf.get('category_name') or 'not present'}"
                    )
                    st.write(
                        f"Source endpoint: {selected_ocsf.get('src_endpoint') or 'not present'}"
                    )
                    st.write(
                        "Destination endpoint: "
                        f"{selected_ocsf.get('dst_endpoint') or 'not present'}"
                    )
                with ocsf_detail_columns[2]:
                    st.write(f"Product: {metadata.get('product') or 'not present'}")
                    st.write(f"Network: {selected_ocsf.get('network') or 'not present'}")
                    st.write(
                        f"Raw reference: {selected_ocsf.get('raw_data') or 'not present'}"
                    )
                st.caption("Evidence: demo/output/ocsf_events.jsonl")


st.header("Performance Benchmark")
benchmark = run_pipeline_benchmark(str(ROOT), 100)
if benchmark["error"]:
    st.info(f"Local benchmark unavailable: {benchmark['error']}")
else:
    benchmark_columns = st.columns(3)
    benchmark_columns[0].metric("Logs Processed", benchmark["logs_processed"])
    benchmark_columns[1].metric(
        "Processing Time",
        f"{benchmark['processing_seconds']:.4f} s",
    )
    benchmark_columns[2].metric(
        "Throughput",
        f"{benchmark['events_per_second']:.0f} EPS",
    )
    st.write(f"Measured stages: {benchmark['stages']}")
    st.caption(
        "Bounded in-memory local replay; results vary by host. "
        f"Evidence input: {benchmark['evidence_file']}"
    )


st.header("Air-Gap Deployment Evidence")
airgap = audit_airgap(ROOT)
st.subheader(f"Deployment Mode: {airgap['deployment_mode']}")
airgap_columns = st.columns(3)
airgap_columns[0].metric("Internet Dependencies", airgap["internet_dependency_count"])
airgap_columns[1].metric("External API Calls", airgap["external_api_call_count"])
airgap_columns[2].metric("Cloud Dependencies", airgap["cloud_dependency_count"])
st.write(
    "Network-capable runtime imports: "
    + (", ".join(airgap["network_imports"]) or "0 detected")
)
st.write(
    "Cloud SDK imports: "
    + (", ".join(airgap["cloud_imports"]) or "0 detected")
)
st.caption("Evidence: " + " · ".join(airgap["evidence_files"]))


st.divider()
st.caption(
    "AegisGuard-ULPF converts heterogeneous security logs into standardized "
    "OCSF events while preserving raw evidence and forensic traceability."
)
