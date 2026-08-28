"""Append-only JSONL evidence and CommonEvent-to-raw trace views."""
from __future__ import annotations
import json
from pathlib import Path
from aegisguard_ulpf.core.models import CommonEvent
from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore

class TraceabilityJsonlWriter:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
    def _append(self, name: str, payload: dict[str, object]) -> Path:
        path = self.output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        return path
    def write_raw_event(self, store: RawEvidenceStore, event_id: str) -> Path:
        return self._append("raw_events.jsonl", store.raw_event_envelope(event_id))
    def write_trace(self, event: CommonEvent, store: RawEvidenceStore) -> Path:
        event_id = event.traceability.u_id
        record = store.get(event_id)
        if record is None:
            raise KeyError(f"Unknown event_id: {event_id}")
        return self._append("traceability.jsonl", {
            "normalized_id": event_id,
            "raw_id": event.traceability.raw_id,
            "source": str(record.identity_context.get("source", "unknown")),
            "hash_verified": store.verify(event_id)["integrity"] == "PASS",
        })
