"""Windows Security Event Log adapter for the ULPF raw-event boundary."""

from __future__ import annotations

import copy
import json

from collections.abc import Mapping
from typing import Any

from aegisguard_ulpf.core.models import RawEvent


WINDOWS_SECURITY_SOURCE = {
    "vendor": "Microsoft",
    "product": "Windows Security",
    "type": "event_log",
}


class WindowsSecurityEventAdapter:
    """Convert a Windows Security event object into a ULPF ``RawEvent``.

    This adapter deliberately does not read the Windows Event Log itself. It
    accepts an event supplied by an existing Windows log source and preserves
    that entire event for the ULPF detection and parsing boundary.
    """

    def adapt(
        self,
        event: Mapping[str, Any] | str,
    ) -> RawEvent:
        """Return a raw ULPF event with Windows Security source metadata."""

        raw, raw_event = _preserve_event(event)

        return RawEvent(
            raw=raw,
            transport="windows_event_log",
            metadata={
                "source": WINDOWS_SECURITY_SOURCE.copy(),
                "raw_event": raw_event,
            },
        )


def _preserve_event(
    event: Mapping[str, Any] | str,
) -> tuple[str, dict[str, Any]]:
    if isinstance(event, str):
        raw = event
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Windows Security event text must be a JSON object"
            ) from exc

        if not isinstance(parsed, dict):
            raise ValueError(
                "Windows Security event text must contain a JSON object"
            )

        return raw, parsed

    if not isinstance(event, Mapping):
        raise TypeError(
            "Windows Security event must be a mapping or JSON object string"
        )

    raw_event = copy.deepcopy(dict(event))

    try:
        raw = json.dumps(
            raw_event,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Windows Security event must contain JSON-compatible values"
        ) from exc

    return raw, raw_event


def adapt_windows_security_event(
    event: Mapping[str, Any] | str,
) -> RawEvent:
    """Adapt one Windows Security event using the default adapter."""

    return WindowsSecurityEventAdapter().adapt(event)
