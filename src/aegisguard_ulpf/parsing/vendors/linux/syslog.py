"""Conservative Linux Syslog parser for authentication and system records."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from aegisguard_ulpf.core.models import ParsedEvent, ParserMetadata, RawEvent
from aegisguard_ulpf.normalization.engine import NormalizationEngine
from aegisguard_ulpf.parsing.base import BaseParser

_SSH_FAILURE = re.compile(r"Failed password for (?:(?:invalid )?user )?(?P<user>\S+) from (?P<ip>\S+)", re.I)
_SUDO = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$", re.I)

class LinuxSyslogParser(BaseParser):
    metadata = ParserMetadata(parser_id="linux.syslog", parser_version="1.0.0", vendor="Linux", product="Syslog", supported_formats=["syslog", "text"])

    def validate(self, event: RawEvent) -> bool:
        return isinstance(event, RawEvent) and bool(event.raw.strip())

    def parse(self, event: RawEvent) -> ParsedEvent:
        if not self.validate(event):
            raise ValueError("Linux Syslog event must contain non-empty raw text")
        raw = event.raw.strip()
        fields = {"u_id": str(event.event_id), "raw_id": event.raw_id, "timestamp": None, "vendor": "Linux", "product": "Syslog", "category": "system_activity", "type": "SYSTEM_EVENT", "subtype": "SYSLOG", "outcome": None, "severity": "informational", "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None, "protocol": None, "user": None, "action": None, "reason": None, "object_type": None, "object_name": None, "details": {}, "vendor_event_id": None, "vendor_fields": {"message": raw}}
        ssh = _SSH_FAILURE.search(raw)
        sudo = _SUDO.search(raw)
        if ssh:
            fields.update({"category": "authentication", "type": "AUTHENTICATION", "subtype": "AUTH_FAILURE", "outcome": "FAILURE", "severity": "medium", "src_ip": ssh.group("ip"), "user": ssh.group("user"), "action": "authentication_failure"})
        elif sudo:
            fields.update({"type": "PROCESS", "subtype": "SUDO_COMMAND", "outcome": "SUCCESS", "user": sudo.group("user"), "action": "command_execution", "object_type": "COMMAND", "object_name": sudo.group("command"), "details": {"command": sudo.group("command")}})
        return ParsedEvent(raw_event=event, parser=self.metadata, fields=fields)

    def normalize(self, event: RawEvent, *, observed_time: datetime | None = None):
        parsed = self.parse(event)
        now = observed_time or datetime.now(timezone.utc)
        return NormalizationEngine().normalize(parsed.fields, observed_time=now, processed_time=now)
