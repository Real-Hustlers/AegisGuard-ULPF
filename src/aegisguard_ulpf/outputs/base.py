from dataclasses import dataclass

from pathlib import Path


RAW_EVENTS_FILENAME = "raw_events.jsonl"
NORMALIZED_EVENTS_FILENAME = "normalized_events.jsonl"
OCSF_EVENTS_FILENAME = "ocsf_events.jsonl"


@dataclass(frozen=True)
class OutputWriteResult:
    path: Path
    written: bool
