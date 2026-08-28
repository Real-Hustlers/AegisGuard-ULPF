from __future__ import annotations

import ast
import json
import re

from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Any


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def relative_name(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path, root: Path) -> tuple[Any, list[str]]:
    if not path.is_file():
        return None, [f"Artifact not found: {relative_name(path, root)}"]

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle), []
    except json.JSONDecodeError as exc:
        return None, [
            f"Malformed JSON in {relative_name(path, root)} at line {exc.lineno}."
        ]
    except OSError as exc:
        return None, [f"Could not read {relative_name(path, root)}: {exc}"]


def load_jsonl(
    path: Path,
    root: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], [f"Artifact not found: {relative_name(path, root)}"]

    records: list[dict[str, Any]] = []
    warnings: list[str] = []

    try:
        with path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    warnings.append(
                        f"Skipped malformed JSON at line {number} in "
                        f"{relative_name(path, root)}."
                    )
                    continue
                if isinstance(item, dict):
                    records.append(item)
                else:
                    warnings.append(
                        f"Skipped non-object record at line {number} in "
                        f"{relative_name(path, root)}."
                    )
    except OSError as exc:
        return [], [f"Could not read {relative_name(path, root)}: {exc}"]

    return records, warnings


def discover_semantic_packs(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    packs: list[dict[str, Any]] = []
    warnings: list[str] = []
    pack_root = root / "examples" / "semantic_packs"

    for path in sorted(pack_root.glob("**/semantic_pack.json")):
        payload, messages = load_json(path, root)
        warnings.extend(messages)
        if not isinstance(payload, dict):
            continue

        manifest = as_mapping(payload.get("manifest"))
        syntax = as_mapping(payload.get("syntax"))
        semantics = as_mapping(payload.get("semantics"))
        binding = as_mapping(payload.get("ocsf_binding"))
        signature = as_mapping(manifest.get("signature"))
        operations = semantics.get("operations")
        if not isinstance(operations, list):
            operations = []

        field_mapping_count = 0
        for operation in operations:
            operation = as_mapping(operation)
            if operation.get("source") or operation.get("sources"):
                field_mapping_count += 1

        ocsf_binding_count = sum(
            len(value) if isinstance(value, dict) else 0
            for value in (
                binding.get("activity_mappings"),
                binding.get("status_mappings"),
                binding.get("severity_mappings"),
            )
        )
        ocsf_binding_count += int(binding.get("class_uid") is not None)
        ocsf_binding_count += int(binding.get("default_severity_id") is not None)

        signature_valid = False
        validation_error: str | None = None
        try:
            from aegisguard_ulpf.parsing.semantic_packs import load_semantic_pack

            load_semantic_pack(path, verify_signature=True)
            signature_valid = True
        except Exception as exc:
            validation_error = str(exc)

        packs.append({
            "path": relative_name(path, root),
            "pack_id": manifest.get("pack_id") or "unknown",
            "vendor": manifest.get("vendor") or "unknown",
            "product": manifest.get("product") or "unknown",
            "event_family": manifest.get("event_family") or "unknown",
            "version": manifest.get("pack_version") or "unknown",
            "supported_formats": [
                value
                for value in (
                    syntax.get("input_format"),
                    manifest.get("format_version"),
                )
                if value
            ],
            "field_mapping_count": field_mapping_count,
            "ocsf_binding_count": ocsf_binding_count,
            "ocsf_binding_status": binding.get("status") or "unknown",
            "signature_valid": signature_valid,
            "signature_algorithm": signature.get("algorithm") or "none",
            "signature_key_id": signature.get("key_id") or "none",
            "validation_error": validation_error,
        })

    if not pack_root.is_dir():
        warnings.append(
            f"Semantic pack directory not found: {relative_name(pack_root, root)}"
        )

    return packs, warnings


def _text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _infer_event_family(category: Any, event_type: Any, subtype: Any) -> str:
    combined = " ".join(
        str(value).casefold()
        for value in (category, event_type, subtype)
        if value is not None
    )
    if any(token in combined for token in ("authentication", "logon", "auth_")):
        return "Authentication"
    if any(token in combined for token in ("system", "process", "service")):
        return "System"
    if any(token in combined for token in ("traffic", "network", "session")):
        return "Traffic"
    return _text(event_type) or _text(category) or "Unknown"


def _common_view(event: dict[str, Any], source_file: str) -> dict[str, Any]:
    vendor_object = as_mapping(event.get("vendor"))
    classification = as_mapping(event.get("classification"))
    src_endpoint = as_mapping(event.get("src_endpoint"))
    dst_endpoint = as_mapping(event.get("dst_endpoint"))

    vendor = (
        _text(vendor_object.get("vendor"))
        or _text(event.get("vendor"))
        or _text(event.get("source"))
        or "Unknown"
    )
    product = (
        _text(vendor_object.get("product"))
        or _text(event.get("product"))
        or _text(event.get("source"))
        or "Unknown"
    )
    category = classification.get("category", event.get("category"))
    event_type = classification.get("type", event.get("event_type", event.get("type")))
    subtype = classification.get("subtype", event.get("event_subtype", event.get("subtype")))
    action = classification.get("action", event.get("action"))
    outcome = classification.get("outcome", event.get("outcome"))
    source_ip = src_endpoint.get("ip", event.get("source_ip", event.get("src_ip")))
    destination_ip = dst_endpoint.get("ip", event.get("destination_ip", event.get("dst_ip")))

    source_vendor = "Windows" if "windows" in product.casefold() else vendor

    return {
        "vendor": source_vendor,
        "taxonomy_vendor": vendor,
        "product": product,
        "event_family": _infer_event_family(category, event_type, subtype),
        "category": category,
        "event_type": event_type,
        "subtype": subtype,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "action": action,
        "outcome": outcome,
        "raw_id": (
            as_mapping(event.get("traceability")).get("raw_id")
            or event.get("raw_id")
        ),
        "source_file": source_file,
        "input_format": None,
    }


def _detected_raw_format(event: dict[str, Any]) -> str:
    raw = _text(event.get("raw")) or ""
    transport = _text(event.get("transport"))
    if raw.startswith(("{", "[")):
        try:
            json.loads(raw)
            return "JSON"
        except json.JSONDecodeError:
            pass
    if len(re.findall(r'(?:^|\s)[A-Za-z_][\w.-]*=(?:"[^"]*"|\S+)', raw)) >= 2:
        return "key-value"
    if raw.count(",") >= 2:
        return "CSV"
    return transport or "unknown"


def collect_unified_events(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    output = root / "demo" / "output"
    paths = (
        output / "normalized_events.jsonl",
        output / "windows-demo" / "normalized_events.jsonl",
        output / "data-pipeline" / "ocsf_or_common_events.jsonl",
        output / "unified-events" / "unified_events.jsonl",
    )
    views: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_formats: dict[str, str] = {}
    source_formats: dict[tuple[str, str], str] = {}

    for raw_path in (
        output / "raw_events.jsonl",
        output / "windows-demo" / "raw_events.jsonl",
    ):
        raw_records, messages = load_jsonl(raw_path, root)
        warnings.extend(messages)
        for raw_record in raw_records:
            identifier = (
                raw_record.get("raw_id")
                or raw_record.get("evidence_raw_id")
            )
            if isinstance(identifier, str) and identifier:
                raw_formats[identifier] = _detected_raw_format(raw_record)
            source = as_mapping(
                as_mapping(raw_record.get("metadata")).get("source")
            )
            source_vendor = _text(source.get("vendor"))
            source_product = _text(source.get("product"))
            if source_vendor and source_product:
                source_formats[
                    (
                        source_vendor.casefold(),
                        source_product.casefold(),
                    )
                ] = _detected_raw_format(raw_record)

    for path in paths:
        records, messages = load_jsonl(path, root)
        warnings.extend(messages)
        source_file = relative_name(path, root)
        views.extend(_common_view(record, source_file) for record in records)

    legacy_path = output / "multivendor-demo" / "common_events.json"
    legacy, messages = load_json(legacy_path, root)
    warnings.extend(messages)
    if isinstance(legacy, list):
        source_file = relative_name(legacy_path, root)
        views.extend(
            _common_view(record, source_file)
            for record in legacy
            if isinstance(record, dict)
        )
    elif legacy is not None:
        warnings.append(f"Expected a JSON list in {relative_name(legacy_path, root)}.")

    for view in views:
        identifier = view.get("raw_id")
        if isinstance(identifier, str):
            view["input_format"] = raw_formats.get(identifier)
        if view["input_format"] is None:
            view["input_format"] = source_formats.get((
                str(view["taxonomy_vendor"]).casefold(),
                str(view["product"]).casefold(),
            ))

    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for view in views:
        key = tuple(
            view.get(field)
            for field in (
                "vendor",
                "product",
                "event_family",
                "event_type",
                "subtype",
                "source_ip",
                "destination_ip",
                "action",
                "outcome",
            )
        )
        if key in unique:
            unique[key]["artifact_records"] += 1
            if unique[key]["input_format"] is None and view["input_format"] is not None:
                unique[key]["input_format"] = view["input_format"]
        else:
            unique[key] = {**view, "artifact_records": 1}

    return list(unique.values()), warnings


def validate_ocsf_outputs(root: Path) -> dict[str, Any]:
    from aegisguard_ulpf.normalization.ocsf.validator import OCSFValidator

    output = root / "demo" / "output"
    paths = sorted(output.glob("**/ocsf_events.jsonl"))
    validator = OCSFValidator()
    total = 0
    valid = 0
    missing_fields: dict[str, int] = {}
    malformed = 0
    warnings: list[str] = []

    for path in paths:
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    total += 1
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        malformed += 1
                        warnings.append(
                            f"Malformed OCSF JSON at {relative_name(path, root)}:"
                            f"{line_number}."
                        )
                        continue
                    result = validator.validate(event)
                    if result.valid:
                        valid += 1
                    for error in result.errors:
                        prefix = "missing OCSF field: "
                        if error.startswith(prefix):
                            field = error.removeprefix(prefix)
                            missing_fields[field] = missing_fields.get(field, 0) + 1
        except OSError as exc:
            warnings.append(f"Could not read {relative_name(path, root)}: {exc}")

    invalid = total - valid
    compliance = round((valid / total) * 100, 1) if total else 0.0

    return {
        "total": total,
        "valid": valid,
        "invalid": invalid,
        "compliance": compliance,
        "missing_field_occurrences": sum(missing_fields.values()),
        "missing_fields": missing_fields,
        "malformed": malformed,
        "evidence_files": [relative_name(path, root) for path in paths],
        "warnings": warnings,
    }


def _percentage(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().removesuffix("%"))
        except ValueError:
            return None
    return None


def load_drift_evidence(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    candidates = (
        root / "demo" / "evidence" / "parser_drift" / "drift_report.json",
        root / "demo" / "output" / "parser_drift" / "drift_report.json",
    )

    for path in candidates:
        if not path.is_file():
            continue
        payload, warnings = load_json(path, root)
        if not isinstance(payload, dict):
            return None, warnings or [f"Invalid drift object in {relative_name(path, root)}."]

        baseline_payload = as_mapping(
            payload.get("baseline")
        )
        current_payload = as_mapping(
            payload.get("current")
        )
        previous = _percentage(
            baseline_payload.get(
                "coverage",
                payload.get(
                    "previous_coverage",
                    payload.get("previous", payload.get("baseline")),
                ),
            )
        )
        current = _percentage(
            current_payload.get(
                "coverage",
                payload.get("current_coverage", payload.get("current")),
            )
        )
        if previous is None or current is None:
            return None, [
                f"Drift evidence lacks previous/current coverage: {relative_name(path, root)}"
            ]

        return {
            "vendor": payload.get("vendor", payload.get("source", "Unknown")),
            "product": payload.get("product", "Unknown"),
            "event_type": payload.get("event_type", payload.get("event_family", "Unknown")),
            "previous_coverage": previous,
            "current_coverage": current,
            "field_loss": payload.get(
                "field_loss",
                round(max(previous - current, 0.0), 1),
            ),
            "status": payload.get("status", payload.get("type")) or (
                "PARSER DRIFT DETECTED" if current < previous else "NO DRIFT DETECTED"
            ),
            "evidence_file": relative_name(path, root),
        }, warnings

    return None, [
        "Parser drift evidence has not been generated. Expected: "
        "demo/evidence/parser_drift/drift_report.json"
    ]


def audit_airgap(root: Path) -> dict[str, Any]:
    network_modules = {
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
    }
    cloud_modules = {
        "boto3",
        "botocore",
        "azure",
        "google.cloud",
    }
    imported_network: set[str] = set()
    imported_cloud: set[str] = set()
    external_api_calls = 0

    for path in (root / "src").rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        network_aliases: set[str] = set()
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in network_modules:
                        network_aliases.add(alias.asname or alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
                if node.module.split(".", 1)[0] in network_modules:
                    network_aliases.update(alias.asname or alias.name for alias in node.names)
            for name in names:
                if any(name == module or name.startswith(f"{module}.") for module in network_modules):
                    imported_network.add(name)
                if any(name == module or name.startswith(f"{module}.") for module in cloud_modules):
                    imported_cloud.add(name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Name) and function.id in network_aliases:
                external_api_calls += 1
            elif isinstance(function, ast.Attribute):
                owner = function.value
                while isinstance(owner, ast.Attribute):
                    owner = owner.value
                if isinstance(owner, ast.Name) and owner.id in network_aliases:
                    external_api_calls += 1

    project_file = root / "pyproject.toml"
    project_text = ""
    try:
        project_text = project_file.read_text(encoding="utf-8").casefold()
    except OSError:
        pass

    network_dependencies = {
        module
        for module in network_modules
        if re.search(rf'"{re.escape(module)}(?:[<>=!~\[]|\")', project_text)
    }
    cloud_dependencies = {
        module
        for module in cloud_modules
        if module in project_text
    }
    docs_path = root / "docs" / "airgap_deployment.md"
    internet_dependency_count = len(network_dependencies)
    external_api_call_count = external_api_calls
    cloud_dependency_count = len(cloud_dependencies | imported_cloud)
    offline = (
        docs_path.is_file()
        and internet_dependency_count == 0
        and external_api_call_count == 0
        and cloud_dependency_count == 0
    )

    return {
        "deployment_mode": "Offline" if offline else "Review required",
        "internet_dependency_count": internet_dependency_count,
        "external_api_call_count": external_api_call_count,
        "cloud_dependency_count": cloud_dependency_count,
        "network_imports": sorted(imported_network),
        "cloud_imports": sorted(imported_cloud),
        "evidence_files": [
            relative_name(docs_path, root),
            relative_name(project_file, root),
            "src/**/*.py (local static import audit)",
        ],
    }


@lru_cache(maxsize=1)
def run_pipeline_benchmark(root_text: str, sample_size: int = 100) -> dict[str, Any]:
    """Measure a bounded, in-memory replay through existing ULPF stages."""

    try:
        from demo.run_fortigate_semantic_pack_demo import FORTIGATE_TRAFFIC_LOG
        from aegisguard_ulpf.core.models import RawEvent
        from aegisguard_ulpf.core.pipeline import ProcessingPipeline
        from aegisguard_ulpf.normalization.engine import NormalizationEngine
        from aegisguard_ulpf.normalization.ocsf.mapper import map_common_event_to_ocsf
        from aegisguard_ulpf.parsing.registry import ParserRegistry

        pipeline = ProcessingPipeline(ParserRegistry())
        normalizer = NormalizationEngine()
        started = perf_counter()

        for _ in range(sample_size):
            raw_event = RawEvent(raw=FORTIGATE_TRAFFIC_LOG, transport="benchmark")
            result = pipeline.process(raw_event)
            common = normalizer.normalize(
                result.parsed_event.fields,
                observed_time=raw_event.ingested_at,
            )
            runtime = pipeline.semantic_pack_resolver.resolve(result.detection)
            if runtime is None:
                raise RuntimeError("FortiGate semantic pack was not resolved")
            if map_common_event_to_ocsf(common, runtime.pack.ocsf_binding) is None:
                raise RuntimeError("OCSF mapping did not produce an event")

        elapsed = perf_counter() - started
        return {
            "logs_processed": sample_size,
            "processing_seconds": elapsed,
            "events_per_second": sample_size / elapsed if elapsed else 0.0,
            "evidence_file": "demo/run_fortigate_semantic_pack_demo.py",
            "stages": "RawEvent → detection → semantic pack → CommonEvent → OCSF",
            "error": None,
        }
    except Exception as exc:
        return {
            "logs_processed": 0,
            "processing_seconds": 0.0,
            "events_per_second": 0.0,
            "evidence_file": relative_name(Path(root_text), Path(root_text)),
            "stages": "Benchmark unavailable",
            "error": str(exc),
        }
