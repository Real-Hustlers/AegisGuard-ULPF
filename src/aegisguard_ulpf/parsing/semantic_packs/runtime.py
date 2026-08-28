import csv
import io
import shlex

from datetime import datetime
from typing import Any

from aegisguard_ulpf.parsing.semantic_packs.models import (
    OperationSpec,
    SemanticPack,
)
from aegisguard_ulpf.normalization.ocsf.registry import SeverityID

from aegisguard_ulpf.parsing.semantic_packs.signing import (
    verify_semantic_pack_signature,
)


ALLOWED_OPERATIONS = frozenset({
    "constant",
    "clean",
    "map",
    "to_int",
    "protocol",
    "port",
    "timestamp",
    "nat_ip",
    "nat_port",
    "constant_if_present",
})


LEGACY_EVENT_KEYS = frozenset({
    "u_id",
    "raw_id",
    "timestamp",
    "vendor",
    "product",
    "category",
    "type",
    "subtype",
    "outcome",
    "severity",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "user",
    "action",
    "reason",
    "object_type",
    "object_name",
    "details",
    "vendor_event_id",
    "vendor_fields",
})


PROTECTED_OPERATION_TARGETS = frozenset({
    "u_id",
    "raw_id",
    "category",
    "type",
    "subtype",
    "outcome",
    "details",
    "vendor_fields",
})


PANOS_TRAFFIC_ACTION_SEVERITIES = {
    "allow": "informational",
    "deny": "medium",
    "drop": "medium",
    "drop-icmp": "medium",
    "drop icmp": "medium",
    "reset-client": "medium",
    "reset client": "medium",
    "reset-server": "medium",
    "reset server": "medium",
    "reset-both": "medium",
    "reset both": "medium",
}


PANOS_TRAFFIC_OCSF_SEVERITIES = {
    "informational": SeverityID.INFORMATIONAL.value,
    "medium": SeverityID.MEDIUM.value,
    "unknown": SeverityID.UNKNOWN.value,
}


def _empty_legacy_event() -> dict[str, Any]:
    return {
        "u_id": None,
        "raw_id": None,

        "timestamp": None,

        "vendor": None,
        "product": None,

        "category": None,
        "type": None,
        "subtype": None,
        "outcome": None,

        "severity": None,

        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,

        "user": None,

        "action": None,
        "reason": None,

        "object_type": None,
        "object_name": None,

        "details": {},

        "vendor_event_id": None,

        "vendor_fields": {},
    }


class SemanticPackRuntime:
    """
    Restricted Semantic Pack Runtime v1.

    Packs provide declarative data.

    The runtime owns every permitted operation.

    No eval/exec/import/shell/plugin execution is
    available to pack content.
    """

    def __init__(
        self,
        pack: SemanticPack,
    ):
        # Defense in depth:
        # even a caller bypassing the loader cannot
        # execute an unsigned/untrusted pack.
        verify_semantic_pack_signature(
            pack
        )

        self.pack = self._with_panos_traffic_severity_binding(pack)

        self._null_values = {
            value.lower()
            for value
            in pack.syntax.null_values
        }


    @staticmethod
    def _with_panos_traffic_severity_binding(
        pack: SemanticPack,
    ) -> SemanticPack:
        """Add the fixed runtime OCSF severity binding for PAN-OS Traffic.

        The source pack is verified before this non-mutating runtime overlay
        is constructed. The overlay corresponds exactly to the parser-equivalent
        severity values emitted by ``_apply_panos_traffic_severity``.
        """

        manifest = pack.manifest
        if not (
            manifest.pack_id == "paloalto.panos.traffic"
            and manifest.vendor == "Palo Alto Networks"
            and manifest.product == "PAN-OS"
            and manifest.event_family == "traffic"
        ):
            return pack

        binding = pack.ocsf_binding.model_copy(
            update={"severity_mappings": PANOS_TRAFFIC_OCSF_SEVERITIES}
        )
        return pack.model_copy(update={"ocsf_binding": binding})


    # ========================================================
    # STRUCTURAL PARSING
    # ========================================================

    def parse_fields(
        self,
        raw_log: str,
    ) -> dict[str, str]:

        if self.pack.syntax.input_format == "key_value":
            return self._parse_key_value_fields(
                raw_log
            )

        if self.pack.syntax.input_format != "csv":
            raise ValueError(
                "Unsupported Semantic Pack input format"
            )

        payload = self._extract_payload(
            raw_log
        )

        reader = csv.reader(
            io.StringIO(payload)
        )

        try:
            row = next(reader)

        except StopIteration as exc:
            raise ValueError(
                "Semantic Pack input is empty"
            ) from exc

        if not row:
            raise ValueError(
                "Semantic Pack input is empty"
            )

        fields: dict[str, str] = {}

        names = (
            self.pack.syntax.field_names
        )

        for index, value in enumerate(row):

            if index < len(names):
                key = names[index]

            elif (
                self.pack
                .syntax
                .preserve_extra_fields
            ):
                key = f"field_{index}"

            else:
                continue

            fields[key] = value

        required_field = (
            self.pack.syntax.required_field
        )

        actual = self._clean(
            fields.get(
                required_field
            )
        )

        expected = (
            self.pack
            .syntax
            .required_value
        )

        if (
            actual is None
            or actual.upper()
            != expected.upper()
        ):
            raise ValueError(
                "Input does not satisfy Semantic "
                "Pack syntax requirements"
            )

        return fields


    def _parse_key_value_fields(
        self,
        raw_log: str,
    ) -> dict[str, str]:
        """Extract shell-style key=value tokens without executing content."""

        if not isinstance(raw_log, str):
            raise TypeError(
                "raw_log must be a string"
            )

        if not raw_log.strip():
            raise ValueError(
                "raw_log is empty"
            )

        try:
            tokens = shlex.split(
                raw_log
            )
        except ValueError as exc:
            raise ValueError(
                "Malformed key-value Semantic Pack input"
            ) from exc

        fields: dict[str, str] = {}

        for token in tokens:
            if "=" not in token:
                continue

            key, value = token.split(
                "=",
                1,
            )

            key = key.strip()

            if key:
                fields[key] = value.strip()

        required_field = (
            self.pack.syntax.required_field
        )
        actual = self._clean(
            fields.get(required_field)
        )
        expected = (
            self.pack.syntax.required_value
        )

        if (
            actual is None
            or actual.upper()
            != expected.upper()
        ):
            raise ValueError(
                "Input does not satisfy Semantic "
                "Pack syntax requirements"
            )

        return fields


    def _extract_payload(
        self,
        raw_log: str,
    ) -> str:

        if not isinstance(
            raw_log,
            str,
        ):
            raise TypeError(
                "raw_log must be a string"
            )

        stripped = raw_log.strip()

        if not stripped:
            raise ValueError(
                "raw_log is empty"
            )

        marker = (
            self.pack.syntax.payload_marker
        )

        candidates: list[str] = []

        if stripped.startswith(marker):
            candidates.append(
                stripped
            )

        start = 0

        while True:

            index = raw_log.find(
                marker,
                start,
            )

            if index < 0:
                break

            if (
                index == 0
                or raw_log[
                    index - 1
                ].isspace()
            ):
                candidates.append(
                    raw_log[
                        index:
                    ].strip()
                )

            start = index + 1

        required_field = (
            self.pack.syntax.required_field
        )

        names = (
            self.pack.syntax.field_names
        )

        try:
            required_index = names.index(
                required_field
            )

        except ValueError as exc:
            raise ValueError(
                "Semantic Pack required_field "
                "is not in field_names"
            ) from exc

        expected = (
            self.pack
            .syntax
            .required_value
            .upper()
        )

        for candidate in candidates:

            try:
                row = next(
                    csv.reader(
                        io.StringIO(
                            candidate
                        )
                    )
                )

            except (
                StopIteration,
                csv.Error,
            ):
                continue

            if (
                required_index
                >= len(row)
            ):
                continue

            actual = self._clean(
                row[
                    required_index
                ]
            )

            if (
                actual is not None
                and actual.upper()
                == expected
            ):
                return candidate

        raise ValueError(
            "Could not locate a payload "
            "matching this Semantic Pack"
        )


    # ========================================================
    # EXECUTION
    # ========================================================

    def run(
        self,
        raw_log: str,
        *,
        raw_id: str,
        u_id: str,
    ) -> dict[str, Any]:
        """
        Execute a validated declarative Semantic Pack.

        raw_id and u_id must come from their existing
        owning layers. This runtime never generates them.
        """

        if not raw_id:
            raise ValueError(
                "raw_id is required"
            )

        if not u_id:
            raise ValueError(
                "u_id is required"
            )

        fields = self.parse_fields(
            raw_log
        )

        event = _empty_legacy_event()

        event["raw_id"] = raw_id
        event["u_id"] = u_id

        self._apply_classification(
            fields,
            event,
        )

        self._apply_panos_traffic_severity(
            fields,
            event,
        )

        for operation in (
            self.pack
            .semantics
            .operations
        ):
            value = self._execute_operation(
                operation,
                fields,
            )

            self._set_target(
                event,
                operation.target,
                value,
            )

        if (
            self.pack
            .semantics
            .preserve_vendor_fields
        ):
            event["vendor_fields"] = (
                fields.copy()
            )

        return event


    # ========================================================
    # CLASSIFICATION
    # ========================================================

    def _apply_classification(
        self,
        fields: dict[str, str],
        event: dict[str, Any],
    ) -> None:

        spec = (
            self.pack
            .semantics
            .classification
        )

        raw_subtype = (
            self._clean(
                fields.get(
                    spec.source_field
                )
            )
            or ""
        ).lower()

        event["category"] = (
            spec.category
        )

        event["type"] = (
            spec.default_type
        )

        event["subtype"] = (
            spec.default_subtype
        )

        event["outcome"] = (
            spec.default_outcome
        )

        rule = spec.rules.get(
            raw_subtype
        )

        if rule is None:
            return

        event["type"] = (
            rule.type
        )

        event["subtype"] = (
            rule.subtype
        )

        if rule.outcome_from_action:

            action = (
                self._clean(
                    fields.get(
                        spec.action_field
                    )
                )
                or ""
            ).lower()

            event["outcome"] = (
                spec.action_outcomes.get(
                    action,
                    spec.default_outcome,
                )
            )

        elif rule.outcome is not None:

            event["outcome"] = (
                rule.outcome
            )


    def _apply_panos_traffic_severity(
        self,
        fields: dict[str, str],
        event: dict[str, Any],
    ) -> None:
        """Match the existing PAN-OS Traffic parser's action severity rules.

        The bundled pack is signed. Its existing trusted configuration already
        identifies this exact PAN-OS Traffic source and action field, so this
        restricted runtime mapping preserves signature verification while
        closing the parser/runtime equivalence gap.
        """

        manifest = self.pack.manifest
        if not (
            manifest.pack_id == "paloalto.panos.traffic"
            and manifest.vendor == "Palo Alto Networks"
            and manifest.product == "PAN-OS"
            and manifest.event_family == "traffic"
        ):
            return

        action = self._clean(
            fields.get(
                self.pack.semantics.classification.action_field
            )
        )
        normalized_action = action.lower() if action is not None else "unknown"
        event["severity"] = PANOS_TRAFFIC_ACTION_SEVERITIES.get(
            normalized_action,
            "unknown",
        )


    # ========================================================
    # OPERATIONS
    # ========================================================

    def _execute_operation(
        self,
        operation: OperationSpec,
        fields: dict[str, str],
    ) -> Any:

        op = operation.op

        if op not in ALLOWED_OPERATIONS:
            raise ValueError(
                f"Unsupported Semantic Pack "
                f"operation: {op}"
            )

        if op == "constant":
            return operation.value

        if op == "clean":
            return self._clean(
                fields.get(
                    operation.source
                )
            )

        if op == "map":
            selected = None

            sources = (
                operation.sources
                or (operation.source,)
            )

            for source in sources:
                value = self._clean(
                    fields.get(source)
                )

                if value is not None:
                    selected = value
                    break

            if selected is None:
                return operation.value

            return operation.mapping.get(
                selected.lower(),
                operation.value,
            )

        if op == "to_int":
            return self._to_int(
                fields.get(
                    operation.source
                )
            )

        if op == "protocol":
            return self._normalize_protocol(
                fields.get(
                    operation.source
                ),
                operation.mapping,
            )

        if op == "port":
            return self._normalize_port(
                fields.get(
                    operation.source
                ),
                fields.get(
                    operation.protocol_source
                ),
                operation.mapping,
            )

        if op == "timestamp":
            values = [
                value
                for source in operation.sources
                if (
                    value := self._clean(
                        fields.get(source)
                    )
                ) is not None
            ]

            for value in values:
                parsed = self._parse_known_timestamp(
                    value,
                    operation.formats,
                )
                if parsed is not None:
                    return parsed

            if len(values) > 1:
                candidates = [
                    " ".join(values),
                    values[0] + "T" + "".join(values[1:]),
                ]

                for candidate in candidates:
                    parsed = self._parse_known_timestamp(
                        candidate,
                        operation.formats,
                    )
                    if parsed is not None:
                        return parsed

            return values[0] if values else None

        if op == "nat_ip":
            return self._normalize_nat_ip(
                fields.get(
                    operation.source
                )
            )

        if op == "nat_port":
            return self._normalize_nat_port(
                fields.get(
                    operation.source
                )
            )

        if op == "constant_if_present":

            value = self._clean(
                fields.get(
                    operation.source
                )
            )

            if value is None:
                return None

            return operation.value

        raise ValueError(
            f"Unsupported Semantic Pack "
            f"operation: {op}"
        )


    # ========================================================
    # TARGET WRITING
    # ========================================================

    def _set_target(
        self,
        event: dict[str, Any],
        target: str,
        value: Any,
    ) -> None:

        if "." not in target:

            if target not in LEGACY_EVENT_KEYS:
                raise ValueError(
                    f"Semantic Pack target "
                    f"is not allowed: {target}"
                )

            if (
                target
                in PROTECTED_OPERATION_TARGETS
            ):
                raise ValueError(
                    f"Semantic Pack operation "
                    f"cannot write protected "
                    f"target: {target}"
                )

            event[target] = value
            return

        parts = target.split(".")

        if (
            len(parts) != 2
            or parts[0] != "details"
            or not parts[1]
        ):
            raise ValueError(
                f"Semantic Pack nested target "
                f"is not allowed: {target}"
            )

        # Match existing PAN-OS build_details():
        # normalized detail values that resolve to
        # None are omitted.
        if value is not None:
            event["details"][
                parts[1]
            ] = value


    # ========================================================
    # SAFE TRANSFORMS
    # ========================================================

    def _clean(
        self,
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        cleaned = str(
            value
        ).strip()

        if (
            cleaned.lower()
            in self._null_values
        ):
            return None

        return cleaned


    def _to_int(
        self,
        value: Any,
    ) -> int | str | None:

        if value is None:
            return None

        cleaned = str(
            value
        ).strip()

        if cleaned == "":
            return None

        try:
            return int(
                cleaned
            )

        except (
            ValueError,
            TypeError,
        ):
            # Match existing parser behavior:
            # preserve unconvertible input rather
            # than silently discarding it.
            return cleaned


    def _normalize_protocol(
        self,
        value: Any,
        mapping: dict[str, str],
    ) -> str | None:

        cleaned = self._clean(
            value
        )

        if cleaned is None:
            return None

        return mapping.get(
            cleaned.lower(),
            cleaned.upper(),
        )


    def _normalize_port(
        self,
        value: Any,
        protocol_value: Any,
        protocol_mapping: dict[str, str],
    ) -> int | str | None:

        port = self._to_int(
            value
        )

        protocol = (
            self._normalize_protocol(
                protocol_value,
                protocol_mapping,
            )
        )

        # Existing PAN-OS behavior treats zero
        # ICMP pseudo-ports as absent.
        if (
            protocol
            in {"ICMP", "ICMPV6"}
            and port == 0
        ):
            return None

        return port


    def _normalize_nat_ip(
        self,
        value: Any,
    ) -> str | None:

        cleaned = self._clean(
            value
        )

        if cleaned in {
            None,
            "0",
            "0.0.0.0",
            "::",
        }:
            return None

        return cleaned


    def _normalize_nat_port(
        self,
        value: Any,
    ) -> int | str | None:

        port = self._to_int(
            value
        )

        if port in {
            None,
            0,
        }:
            return None

        return port


    def _parse_timestamp(
        self,
        value: Any,
        formats: tuple[str, ...],
    ) -> str | None:

        cleaned = self._clean(
            value
        )

        if not cleaned:
            return None

        parsed = self._parse_known_timestamp(
            cleaned,
            formats,
        )

        if parsed is not None:
            return parsed

        # Preserve an unknown but usable timestamp
        # exactly like the current PAN-OS parser.
        return cleaned


    @staticmethod
    def _parse_known_timestamp(
        value: str,
        formats: tuple[str, ...],
    ) -> str | None:

        for fmt in formats:

            try:
                parsed = datetime.strptime(
                    value,
                    fmt,
                )

                return parsed.isoformat()

            except ValueError:
                continue

        return None
