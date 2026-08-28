"""CommonEvent-only, timeline-ready multi-source visibility output."""
from __future__ import annotations
import json
from pathlib import Path
from aegisguard_ulpf.core.models import CommonEvent

def _timestamp(event: CommonEvent) -> str:
    value = event.timestamps.event_time or event.timestamps.observed_time
    return value.isoformat().replace("+00:00", "Z")

def build_unified_timeline(events):
    """Project normalized events into a stable source-neutral timeline."""
    timeline = []
    for event in events:
        if not isinstance(event, CommonEvent):
            raise TypeError("unified timeline requires CommonEvent instances")
        timeline.append({
            "source": event.vendor.product,
            "vendor": event.vendor.vendor,
            "event_type": event.classification.type or "UNKNOWN",
            "event_subtype": event.classification.subtype,
            "timestamp": _timestamp(event),
            "severity": event.classification.severity,
            "user": event.actor.user if event.actor else None,
            "source_ip": event.src_endpoint.ip if event.src_endpoint else None,
            "u_id": event.traceability.u_id,
            "raw_id": event.traceability.raw_id,
        })
    return sorted(timeline, key=lambda item: item["timestamp"])

def write_unified_timeline(events, output_path):
    path = Path(output_path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in build_unified_timeline(events):
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    return path
