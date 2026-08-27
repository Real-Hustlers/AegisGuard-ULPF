"""File-based adapters between ULPF outputs and external systems."""

from aegisguard_ulpf.integration.siem_adapter import (
    adapt_ocsf_jsonl_to_siem,
    map_ocsf_event_to_siem,
    read_ocsf_jsonl,
)
from aegisguard_ulpf.integration.siem_contract_mapper import (
    map_ocsf_event_to_siem_contract,
    translate_ocsf_events_to_siem_contract,
    translate_ocsf_events_to_siem_ingestion_envelope,
    translate_ocsf_jsonl_to_siem_merged_logs,
    translate_ocsf_jsonl_to_siem_ingestion_envelope,
)


__all__ = [
    "adapt_ocsf_jsonl_to_siem",
    "map_ocsf_event_to_siem",
    "map_ocsf_event_to_siem_contract",
    "read_ocsf_jsonl",
    "translate_ocsf_events_to_siem_contract",
    "translate_ocsf_events_to_siem_ingestion_envelope",
    "translate_ocsf_jsonl_to_siem_merged_logs",
    "translate_ocsf_jsonl_to_siem_ingestion_envelope",
]
