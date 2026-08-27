"""Local JSONL exporter for CommonEvent or OCSF dictionaries."""
import json
from pathlib import Path

def _payload(event):
    return event.model_dump(mode="json") if hasattr(event, "model_dump") else event

def export_jsonl(events, output_path):
    path = Path(output_path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            json.dump(_payload(event), handle, ensure_ascii=False, sort_keys=True, default=str)
            handle.write("\n")
    return path
