import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from aegisguard_ulpf.core.models import DetectionResult, RawEvent


class FormatDetector:
    """
    Detects the structural format of a raw log event.

    This detector does not identify vendor or product.
    """

    SYSLOG_PATTERN = re.compile(
        r"^<\d{1,3}>"
    )

    KEY_VALUE_PATTERN = re.compile(
        r'(?:^|\s)[A-Za-z_][A-Za-z0-9_.-]*=(?:"[^"]*"|\S+)'
    )

    def detect(self, event: RawEvent) -> DetectionResult:
        raw = event.raw.strip()

        if not raw:
            return DetectionResult(
                format="plain_text",
                confidence=0.0,
                evidence=["empty event"],
            )

        # CEF must be checked before generic syslog because
        # CEF messages can also be transported through Syslog.
        if self._is_cef(raw):
            return DetectionResult(
                format="cef",
                confidence=1.0,
                evidence=["CEF header detected"],
            )

        # Same reasoning for LEEF.
        if self._is_leef(raw):
            return DetectionResult(
                format="leef",
                confidence=1.0,
                evidence=["LEEF header detected"],
            )

        if self._is_json(raw):
            return DetectionResult(
                format="json",
                confidence=1.0,
                evidence=["valid JSON structure"],
            )

        if self._is_xml(raw):
            return DetectionResult(
                format="xml",
                confidence=1.0,
                evidence=["valid XML structure"],
            )

        if self._is_syslog(raw):
            return DetectionResult(
                format="syslog",
                confidence=0.95,
                evidence=["Syslog PRI prefix detected"],
            )

        if self._is_key_value(raw):
            return DetectionResult(
                format="key_value",
                confidence=0.90,
                evidence=["multiple key=value fields detected"],
            )

        if self._is_csv(raw):
            return DetectionResult(
                format="csv",
                confidence=0.75,
                evidence=["multiple comma-separated fields detected"],
            )

        return DetectionResult(
            format="plain_text",
            confidence=0.25,
            evidence=[
                "no supported structured format confidently detected"
            ],
        )

    @staticmethod
    def _is_cef(raw: str) -> bool:
        # Direct CEF
        if raw.startswith("CEF:"):
            return True

        # Syslog-wrapped CEF
        return " CEF:" in raw

    @staticmethod
    def _is_leef(raw: str) -> bool:
        # Direct LEEF
        if raw.startswith("LEEF:"):
            return True

        # Syslog-wrapped LEEF
        return " LEEF:" in raw

    @staticmethod
    def _is_json(raw: str) -> bool:
        if not (
            (raw.startswith("{") and raw.endswith("}"))
            or
            (raw.startswith("[") and raw.endswith("]"))
        ):
            return False

        try:
            json.loads(raw)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def _is_xml(raw: str) -> bool:
        if not raw.startswith("<"):
            return False

        try:
            ET.fromstring(raw)
            return True
        except ET.ParseError:
            return False

    def _is_syslog(self, raw: str) -> bool:
        return bool(
            self.SYSLOG_PATTERN.match(raw)
        )

    def _is_key_value(self, raw: str) -> bool:
        matches = self.KEY_VALUE_PATTERN.findall(raw)

        # Requiring at least two fields avoids classifying
        # ordinary text containing one "=" as key-value logs.
        return len(matches) >= 2

    @staticmethod
    def _is_csv(raw: str) -> bool:
        if "," not in raw:
            return False

        try:
            reader = csv.reader(
                io.StringIO(raw)
            )

            row = next(reader)

            # Be conservative: require at least 3 columns.
            return len(row) >= 3

        except (csv.Error, StopIteration):
            return False