"""Adapters that convert external log records into ULPF RawEvent objects."""

from aegisguard_ulpf.ingestion.windows import (
    WindowsSecurityEventAdapter,
    adapt_windows_security_event,
)


__all__ = [
    "WindowsSecurityEventAdapter",
    "adapt_windows_security_event",
]
