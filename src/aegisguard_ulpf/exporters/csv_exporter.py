"""Flat CSV exporter for data-lake compatible event rows."""
import csv
import json
from pathlib import Path
from aegisguard_ulpf.exporters.json_exporter import _payload

def _flatten(value, prefix=""):
    output = {}
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict): output.update(_flatten(item, name))
        elif isinstance(item, (list, tuple)): output[name] = json.dumps(item, ensure_ascii=False)
        else: output[name] = item
    return output

def export_csv(events, output_path):
    rows = [_flatten(_payload(event)) for event in events]
    path = Path(output_path); path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    return path
