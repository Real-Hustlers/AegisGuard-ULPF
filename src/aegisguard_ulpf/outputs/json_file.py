import json

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from aegisguard_ulpf.core.models import CommonEvent, RawEvent
from aegisguard_ulpf.outputs.base import (
    NORMALIZED_EVENTS_FILENAME,
    OCSF_EVENTS_FILENAME,
    RAW_EVENTS_FILENAME,
    OutputWriteResult,
)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(
        f"Unsupported JSON output value type: {type(value).__name__}"
    )


def _json_object(value: BaseModel | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json")
    elif isinstance(value, dict):
        payload = value
    else:
        raise TypeError("JSONL output requires a Pydantic model or dictionary")

    if not isinstance(payload, dict):
        raise TypeError("JSONL output requires a JSON object")

    return payload


class JsonlOutputWriter:
    """Append pure raw, CommonEvent, and OCSF records to separate JSONL files."""

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    @property
    def raw_path(self) -> Path:
        return self.output_dir / RAW_EVENTS_FILENAME

    @property
    def normalized_path(self) -> Path:
        return self.output_dir / NORMALIZED_EVENTS_FILENAME

    @property
    def ocsf_path(self) -> Path:
        return self.output_dir / OCSF_EVENTS_FILENAME

    def _append(
        self,
        path: Path,
        value: BaseModel | dict[str, Any],
    ) -> OutputWriteResult:
        payload = _json_object(value)
        line = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            default=_json_default,
        )

        self.output_dir.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")

        return OutputWriteResult(path=path, written=True)

    def write_raw(self, raw_event: RawEvent) -> OutputWriteResult:
        """Export a RawEvent view; RawEvidenceStore remains authoritative."""
        if not isinstance(raw_event, RawEvent):
            raise TypeError("raw output requires a RawEvent")

        payload = raw_event.model_dump(mode="json")
        payload["raw_id"] = raw_event.raw_id
        return self._append(self.raw_path, payload)

    def write_normalized(
        self,
        common_event: CommonEvent,
    ) -> OutputWriteResult:
        if not isinstance(common_event, CommonEvent):
            raise TypeError("normalized output requires a CommonEvent")
        return self._append(self.normalized_path, common_event)

    def write_ocsf(
        self,
        ocsf_event: dict[str, Any] | None,
    ) -> OutputWriteResult:
        if ocsf_event is None:
            return OutputWriteResult(path=self.ocsf_path, written=False)
        if not isinstance(ocsf_event, dict):
            raise TypeError("OCSF output requires a dictionary or None")
        return self._append(self.ocsf_path, ocsf_event)
