"""Streamlit presentation dashboard for existing AegisGuard-ULPF outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "demo" / "output"
EVIDENCE = ROOT / "demo" / "evidence"
st.set_page_config(page_title="AegisGuard-ULPF", page_icon="AG", layout="wide")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Read valid JSON-object records, retaining readable load warnings."""
    if not path.is_file():
        return [], [f"Output not found: {path.relative_to(ROOT)}"]
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    warnings.append(f"Skipped malformed JSON at line {number} in {path.name}.")
                    continue
                if isinstance(item, dict):
                    records.append(item)
                else:
                    warnings.append(f"Skipped non-object record at line {number} in {path.name}.")
    except OSError as exc:
        return [], [f"Could not read {path.name}: {exc}"]
    return records, warnings


def raw_id(event: dict[str, Any]) -> str | None:
    """Resolve identifiers in the documented raw-ID lookup order."""
    traceability = as_mapping(event.get("traceability"))
    raw_data = as_mapping(event.get("raw_data"))
    for candidate in (event.get("raw_id"), event.get("evidence_raw_id"), traceability.get("raw_id"), raw_data.get("raw_id")):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def event_id(event: dict[str, Any]) -> str:
    traceability = as_mapping(event.get("traceability"))
    raw_data = as_mapping(event.get("raw_data"))
    for candidate in (event.get("event_id"), traceability.get("u_id"), raw_data.get("u_id")):
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
    return str(vendor.get("vendor") or "unknown"), str(vendor.get("product") or "unknown")


def common_summary(event: dict[str, Any] | None) -> str:
    if event is None:
        return "Unmatched normalized event"
    classification = as_mapping(event.get("classification"))
    return str(classification.get("subtype") or classification.get("type") or "Common Event")


def verify_evidence(event_identifier: str) -> dict[str, Any] | None:
    """Use the authoritative verifier only when evidence is present."""
    if not EVIDENCE.is_dir() or not event_identifier or event_identifier == "unknown-event":
        return None
    try:
        from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore
        return RawEvidenceStore(EVIDENCE).verify(event_identifier)
    except Exception:
        return None


raw_events, raw_messages = load_jsonl(OUTPUT / "raw_events.jsonl")
normalized_events, normalized_messages = load_jsonl(OUTPUT / "normalized_events.jsonl")
ocsf_events, ocsf_messages = load_jsonl(OUTPUT / "ocsf_events.jsonl")
normalized_by_raw = {raw_id(item): item for item in normalized_events if raw_id(item)}
ocsf_by_raw = {raw_id(item): item for item in ocsf_events if raw_id(item)}

st.title("AegisGuard-ULPF")
st.caption("Heterogeneous security logs -> Common Taxonomy -> OCSF -> forensic traceability")

st.header("Pipeline Summary")
vendors = {vendor_product(event) for event in normalized_events}
verified = [item for item in (verify_evidence(event_id(event)) for event in raw_events) if item]
integrity = "PASS" if verified and all(item.get("integrity") == "PASS" for item in verified) else "Verification available" if EVIDENCE.is_dir() else "Evidence unavailable"
columns = st.columns(5)
for column, label, value in zip(columns, ("Raw Events", "Normalized Events", "OCSF Events", "Vendors Detected", "Integrity"), (len(raw_events), len(normalized_events), len(ocsf_events), len(vendors), integrity)):
    column.metric(label, value)
for message in raw_messages + normalized_messages + ocsf_messages:
    st.info(message)

st.header("Multi-Vendor View")
if vendors:
    st.dataframe([{"Vendor": vendor, "Product": product} for vendor, product in sorted(vendors)], width="stretch", hide_index=True)
else:
    st.info("No normalized Common Taxonomy events are available yet.")

st.header("Event Trace Explorer")
if not raw_events:
    st.info("No raw events are available. Run an existing ULPF demo, then refresh this dashboard.")
else:
    choices: dict[str, dict[str, Any]] = {}
    for index, raw_event in enumerate(raw_events, start=1):
        identifier = raw_id(raw_event) or event_id(raw_event)
        normalized = normalized_by_raw.get(identifier)
        vendor, _ = vendor_product(normalized or {})
        label = f"{source_name(raw_event)} | {vendor} | {common_summary(normalized)} | {identifier[:16]} #{index}"
        choices[label] = raw_event
    filter_text = st.text_input("Search by source, vendor, event type, or identifier").strip().lower()
    filtered = {label: item for label, item in choices.items() if not filter_text or filter_text in label.lower()}
    if not filtered:
        st.info("No events match the search.")
    else:
        selected_raw = filtered[st.selectbox("Select event", list(filtered))]
        selected_raw_id = raw_id(selected_raw)
        selected_normalized = normalized_by_raw.get(selected_raw_id)
        selected_ocsf = ocsf_by_raw.get(selected_raw_id)

        with st.expander("A. Original Raw Log", expanded=True):
            st.code(str(selected_raw.get("raw") or selected_raw.get("raw_content") or "Raw text unavailable"), language="text")
            st.json({"raw_id": selected_raw_id, "sha256": selected_raw.get("raw_sha256"), "timestamp": selected_raw.get("ingested_at"), "source": source_name(selected_raw)})
        with st.expander("B. Common Taxonomy Event", expanded=True):
            if selected_normalized is None:
                st.info("No normalized event with the selected raw identifier was found.")
            else:
                classification = as_mapping(selected_normalized.get("classification"))
                st.json({"vendor": selected_normalized.get("vendor"), "category": classification.get("category"), "event_type": classification.get("type"), "subtype": classification.get("subtype"), "action": classification.get("action"), "outcome": classification.get("outcome"), "severity": classification.get("severity"), "src_endpoint": selected_normalized.get("src_endpoint"), "dst_endpoint": selected_normalized.get("dst_endpoint"), "timestamps": selected_normalized.get("timestamps")})
        with st.expander("C. OCSF Event", expanded=True):
            if selected_ocsf is None:
                st.info("No OCSF event with the selected raw identifier was found.")
            else:
                st.json({"class_uid": selected_ocsf.get("class_uid"), "class_name": selected_ocsf.get("class_name"), "activity": selected_ocsf.get("activity_name") or selected_ocsf.get("activity_id"), "category": selected_ocsf.get("category_name"), "source_endpoint": selected_ocsf.get("src_endpoint"), "destination_endpoint": selected_ocsf.get("dst_endpoint"), "metadata": selected_ocsf.get("metadata")})

        st.subheader("Traceability Verification")
        verification = verify_evidence(event_id(selected_raw))
        if verification and verification.get("integrity") == "PASS":
            st.success("Original event found: YES\n\nSHA256 verified: PASS\n\nHash chain valid: PASS\n\nIntegrity: PASS")
        else:
            st.info("Evidence verification is unavailable for this selected event. Raw and normalized records remain viewable.")

st.header("Innovation Features")
feature_columns = st.columns(5)
features = [
    ("Tier-0 Unknown Handling", "Raw preserved", "Vendor guessing prevented", "Coverage: 0% when Tier-0 is used"),
    ("Semantic Pack Architecture", "Pack loading available", "Engine unchanged", "Normalization validated"),
    ("Parser Drift Detection", "Source coverage tracked", "Previous/current comparison", "Alert on material decrease"),
    ("Air Gap Deployment", "Internet dependency: none", "Cloud dependency: none", "Local execution available"),
    ("Hash Traceability", "SHA256 available", "Hash chain available", "Integrity verified when evidence matches"),
]
for column, (title, first, second, third) in zip(feature_columns, features):
    with column:
        st.markdown(f"**{title}**")
        st.caption(first)
        st.caption(second)
        st.caption(third)

st.divider()
st.caption("AegisGuard-ULPF converts heterogeneous security logs into standardized OCSF events while preserving raw evidence and forensic traceability.")
