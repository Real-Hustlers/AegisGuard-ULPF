"""File-based adapters between ULPF outputs and external systems."""

from aegisguard_ulpf.integration.siem_adapter import (
    adapt_ocsf_jsonl_to_siem,
    map_ocsf_event_to_siem,
    read_ocsf_jsonl,
)


__all__ = [
    "adapt_ocsf_jsonl_to_siem",
    "map_ocsf_event_to_siem",
    "read_ocsf_jsonl",
]
