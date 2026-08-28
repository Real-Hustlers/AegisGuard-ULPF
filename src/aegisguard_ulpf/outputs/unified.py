"""Timeline-ready JSONL output for normalized events from multiple sources."""
from aegisguard_ulpf.exporters.json_exporter import export_jsonl
def write_unified_events(events, output_path):
    return export_jsonl(events, output_path)
