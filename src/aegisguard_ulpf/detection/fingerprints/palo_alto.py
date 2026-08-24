import csv
import io
import re

from aegisguard_ulpf.core.models import DetectionResult


class PaloAltoFingerprint:

    KNOWN_TYPES = {
        "TRAFFIC",
        "THREAT",
        "SYSTEM",
        "CONFIG",
        "AUTH",
        "GLOBALPROTECT",
        "HIPMATCH",
        "URL",
        "CORRELATION",
        "GTP",
    }

    DATE_PATTERN = re.compile(
        r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}"
    )

    def detect(self, raw: str) -> DetectionResult | None:

        try:
            row = next(
                csv.reader(io.StringIO(raw))
            )
        except (csv.Error, StopIteration):
            return None

        # PAN-OS standard logs need enough leading fields
        # for receive_time, serial, type, subtype, etc.
        if len(row) < 7:
            return None

        receive_time = row[1].strip()
        serial = row[2].strip()
        log_type = row[3].strip().upper()

        score = 0.0
        evidence: list[str] = []

        if log_type in self.KNOWN_TYPES:
            score += 0.50
            evidence.append(
                f"PAN-OS-style log type detected: {log_type}"
            )

        if serial:
            score += 0.20
            evidence.append("device serial field present")

        if self.DATE_PATTERN.fullmatch(receive_time):
            score += 0.20
            evidence.append(
                "PAN-OS-style receive timestamp detected"
            )

        if len(row) >= 15:
            score += 0.10
            evidence.append(
                "field count consistent with PAN-OS log structure"
            )

        if score < 0.70:
            return None

        return DetectionResult(
            vendor="Palo Alto Networks",
            product="PAN-OS",
            confidence=min(score, 1.0),
            evidence=evidence,
        )