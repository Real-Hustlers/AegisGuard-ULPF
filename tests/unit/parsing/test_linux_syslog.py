import pytest
from datetime import datetime, timezone
from aegisguard_ulpf.core.models import RawEvent
from aegisguard_ulpf.parsing.vendors.linux import LinuxSyslogParser

def test_ssh_failure_extracts_attributes_and_normalizes():
    parser = LinuxSyslogParser()
    event = RawEvent(raw="Aug 27 host sshd[1]: Failed password for user admin from 10.0.0.5 port 22 ssh2")
    parsed = parser.parse(event)
    assert parsed.fields["action"] == "authentication_failure"
    assert parsed.fields["user"] == "admin"
    assert parsed.fields["src_ip"] == "10.0.0.5"
    assert parser.normalize(event, observed_time=datetime.now(timezone.utc)).classification.outcome == "FAILURE"

def test_sudo_and_system_events_are_preserved():
    parser = LinuxSyslogParser()
    sudo = parser.parse(RawEvent(raw="Aug 27 host sudo: alice : COMMAND=/usr/bin/id"))
    system = parser.parse(RawEvent(raw="Aug 27 host systemd[1]: Started service."))
    assert sudo.fields["subtype"] == "SUDO_COMMAND"
    assert sudo.fields["details"]["command"] == "/usr/bin/id"
    assert system.fields["vendor_fields"]["message"].endswith("Started service.")

@pytest.mark.parametrize("raw", ["", "   "])
def test_malformed_or_missing_linux_message_is_rejected(raw):
    with pytest.raises(ValueError):
        LinuxSyslogParser().parse(RawEvent(raw=raw))
