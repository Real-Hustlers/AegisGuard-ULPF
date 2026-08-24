import csv
import io
import re
import shlex

from aegisguard_ulpf.core.models import DetectionResult, RawEvent


class EventFamilyDetector:
    """
    Determines the event family after vendor/product detection.

    Supported v1 families:
        traffic
        vpn
        system
        router

    Supported v1 products:
        Fortinet FortiGate
        Cisco ASA
        Palo Alto PAN-OS
    """

    CISCO_ASA_PATTERN = re.compile(
        r"%ASA-(?P<severity>[0-7])-(?P<message_id>\d{6,7}):"
    )

    CISCO_TRAFFIC_MESSAGE_IDS = {
        "302013",
        "302014",
        "302015",
        "302016",
        "302020",
        "302021",
    }

    CISCO_VPN_KEYWORDS = {
        "anyconnect",
        "webvpn",
        "vpn",
        "ipsec",
        "isakmp",
        "ikev1",
        "ikev2",
        "tunnel-group",
    }

    CISCO_ROUTER_KEYWORDS = {
        "bgp",
        "ospf",
        "eigrp",
        "rip",
        "routing",
        "route",
    }

    CISCO_SYSTEM_KEYWORDS = {
        "failover",
        "interface",
        "reload",
        "configuration",
        "config",
        "license",
        "memory",
        "cpu",
    }

    def detect(
        self,
        event: RawEvent,
        source_result: DetectionResult,
    ) -> DetectionResult:

        vendor = source_result.vendor
        product = source_result.product

        if vendor == "Fortinet" and product == "FortiGate":
            return self._detect_fortigate(
                event.raw,
                source_result,
            )

        if vendor == "Cisco" and product == "ASA":
            return self._detect_cisco_asa(
                event.raw,
                source_result,
            )

        if (
            vendor == "Palo Alto Networks"
            and product == "PAN-OS"
        ):
            return self._detect_palo_alto(
                event.raw,
                source_result,
            )

        return self._unknown_family(
            source_result,
            "no event-family detector available for source",
        )

    # =========================================================
    # FORTINET / FORTIGATE
    # =========================================================

    def _detect_fortigate(
        self,
        raw: str,
        source_result: DetectionResult,
    ) -> DetectionResult:

        fields = self._extract_key_values(raw)

        log_type = fields.get("type", "").lower()
        subtype = fields.get("subtype", "").lower()

        if log_type == "traffic":
            return self._family_result(
                source_result,
                family="traffic",
                parser_id="fortinet.fortigate.traffic",
                family_confidence=1.0,
                evidence="FortiGate type=traffic",
            )

        if subtype == "vpn" or log_type == "vpn":
            return self._family_result(
                source_result,
                family="vpn",
                parser_id="fortinet.fortigate.vpn",
                family_confidence=1.0,
                evidence="FortiGate VPN subtype/type detected",
            )

        if subtype in {"router", "routing"}:
            return self._family_result(
                source_result,
                family="router",
                parser_id="fortinet.fortigate.router",
                family_confidence=1.0,
                evidence=f"FortiGate subtype={subtype}",
            )

        if subtype == "system":
            return self._family_result(
                source_result,
                family="system",
                parser_id="fortinet.fortigate.system",
                family_confidence=1.0,
                evidence="FortiGate subtype=system",
            )

        return self._unknown_family(
            source_result,
            "FortiGate source detected but event family is unknown",
        )

    # =========================================================
    # CISCO ASA
    # =========================================================

    def _detect_cisco_asa(
        self,
        raw: str,
        source_result: DetectionResult,
    ) -> DetectionResult:

        lowered = raw.lower()

        match = self.CISCO_ASA_PATTERN.search(raw)

        if match:
            message_id = match.group("message_id")

            if message_id in self.CISCO_TRAFFIC_MESSAGE_IDS:
                return self._family_result(
                    source_result,
                    family="traffic",
                    parser_id="cisco.asa.traffic",
                    family_confidence=1.0,
                    evidence=(
                        f"Cisco ASA traffic message ID "
                        f"{message_id}"
                    ),
                )

        if any(
            keyword in lowered
            for keyword in self.CISCO_VPN_KEYWORDS
        ):
            return self._family_result(
                source_result,
                family="vpn",
                parser_id="cisco.asa.vpn",
                family_confidence=0.90,
                evidence="Cisco ASA VPN terminology detected",
            )

        if any(
            keyword in lowered
            for keyword in self.CISCO_ROUTER_KEYWORDS
        ):
            return self._family_result(
                source_result,
                family="router",
                parser_id="cisco.asa.router",
                family_confidence=0.85,
                evidence="Cisco ASA routing terminology detected",
            )

        if any(
            keyword in lowered
            for keyword in self.CISCO_SYSTEM_KEYWORDS
        ):
            return self._family_result(
                source_result,
                family="system",
                parser_id="cisco.asa.system",
                family_confidence=0.80,
                evidence="Cisco ASA system terminology detected",
            )

        return self._unknown_family(
            source_result,
            "Cisco ASA source detected but event family is unknown",
        )

    # =========================================================
    # PALO ALTO / PAN-OS
    # =========================================================

    def _detect_palo_alto(
        self,
        raw: str,
        source_result: DetectionResult,
    ) -> DetectionResult:

        try:
            row = next(
                csv.reader(
                    io.StringIO(raw)
                )
            )
        except (csv.Error, StopIteration):
            return self._unknown_family(
                source_result,
                "unable to read PAN-OS CSV event",
            )

        if len(row) < 5:
            return self._unknown_family(
                source_result,
                "PAN-OS event has insufficient fields",
            )

        log_type = row[3].strip().upper()
        subtype = row[4].strip().lower()

        if log_type == "TRAFFIC":
            return self._family_result(
                source_result,
                family="traffic",
                parser_id="paloalto.pan_os.traffic",
                family_confidence=1.0,
                evidence="PAN-OS log type TRAFFIC",
            )

        if log_type == "GLOBALPROTECT":
            return self._family_result(
                source_result,
                family="vpn",
                parser_id="paloalto.pan_os.vpn",
                family_confidence=1.0,
                evidence="PAN-OS log type GLOBALPROTECT",
            )

        if log_type == "SYSTEM":

            if subtype in {
                "vpn",
                "sslvpn",
                "global-protect",
                "globalprotect",
            }:
                return self._family_result(
                    source_result,
                    family="vpn",
                    parser_id="paloalto.pan_os.vpn",
                    family_confidence=1.0,
                    evidence=(
                        f"PAN-OS SYSTEM subtype={subtype}"
                    ),
                )

            if subtype in {
                "routing",
                "bfd",
            }:
                return self._family_result(
                    source_result,
                    family="router",
                    parser_id="paloalto.pan_os.router",
                    family_confidence=1.0,
                    evidence=(
                        f"PAN-OS SYSTEM subtype={subtype}"
                    ),
                )

            return self._family_result(
                source_result,
                family="system",
                parser_id="paloalto.pan_os.system",
                family_confidence=1.0,
                evidence=(
                    f"PAN-OS SYSTEM subtype={subtype}"
                ),
            )

        return self._unknown_family(
            source_result,
            (
                "PAN-OS source detected but current parser "
                f"families do not handle log type {log_type}"
            ),
        )

    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def _extract_key_values(
        raw: str,
    ) -> dict[str, str]:

        try:
            tokens = shlex.split(raw)
        except ValueError:
            return {}

        fields: dict[str, str] = {}

        for token in tokens:
            if "=" not in token:
                continue

            key, value = token.split("=", 1)

            key = key.strip()
            value = value.strip()

            if key:
                fields[key] = value

        return fields

    @staticmethod
    def _family_result(
        source_result: DetectionResult,
        family: str,
        parser_id: str,
        family_confidence: float,
        evidence: str,
    ) -> DetectionResult:

        confidence = min(
            source_result.confidence,
            family_confidence,
        )

        return DetectionResult(
            vendor=source_result.vendor,
            product=source_result.product,
            event_family=family,
            format=source_result.format,
            parser_id=parser_id,
            confidence=confidence,
            evidence=[
                *source_result.evidence,
                evidence,
            ],
        )

    @staticmethod
    def _unknown_family(
        source_result: DetectionResult,
        evidence: str,
    ) -> DetectionResult:

        return DetectionResult(
            vendor=source_result.vendor,
            product=source_result.product,
            event_family=None,
            format=source_result.format,
            parser_id=None,
            confidence=source_result.confidence,
            evidence=[
                *source_result.evidence,
                evidence,
            ],
        )