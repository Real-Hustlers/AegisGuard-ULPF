import re

from aegisguard_ulpf.core.models import DetectionResult


class CiscoFingerprint:

    ASA_PATTERN = re.compile(
        r"%ASA-(?P<severity>[0-7])-(?P<message_id>\d{6,7}):"
    )

    def detect(self, raw: str) -> DetectionResult | None:
        match = self.ASA_PATTERN.search(raw)

        if match:
            return DetectionResult(
                vendor="Cisco",
                product="ASA",
                confidence=1.0,
                evidence=[
                    "%ASA syslog facility detected",
                    f"severity={match.group('severity')}",
                    f"message_id={match.group('message_id')}",
                ],
            )

        return None