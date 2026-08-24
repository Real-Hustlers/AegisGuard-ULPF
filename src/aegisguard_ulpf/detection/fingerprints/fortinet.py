import shlex

from aegisguard_ulpf.core.models import DetectionResult


class FortinetFingerprint:

    def detect(self, raw: str) -> DetectionResult | None:
        fields = self._extract_fields(raw)

        if not fields:
            return None

        score = 0.0
        evidence: list[str] = []

        devname = fields.get("devname", "").upper()
        devid = fields.get("devid", "").upper()

        if devname.startswith("FGT"):
            score += 0.35
            evidence.append("FortiGate-style devname detected")

        if devid.startswith(("FGT", "FGVM", "FG")):
            score += 0.35
            evidence.append("FortiGate-style device ID detected")

        if "logid" in fields:
            score += 0.10
            evidence.append("FortiGate logid field present")

        if "type" in fields:
            score += 0.05
            evidence.append("type field present")

        if "subtype" in fields:
            score += 0.10
            evidence.append("subtype field present")

        if "vd" in fields:
            score += 0.05
            evidence.append("FortiGate virtual-domain field present")

        if score < 0.50:
            return None

        return DetectionResult(
            vendor="Fortinet",
            product="FortiGate",
            confidence=min(score, 1.0),
            evidence=evidence,
        )

    @staticmethod
    def _extract_fields(raw: str) -> dict[str, str]:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            return {}

        fields = {}

        for token in tokens:
            if "=" not in token:
                continue

            key, value = token.split("=", 1)

            if key:
                fields[key.strip()] = value.strip()

        return fields