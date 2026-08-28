from __future__ import annotations

from pathlib import Path
from typing import Mapping

from aegisguard_ulpf.core.models import (
    DetectionResult,
    ParsedEvent,
    ParserMetadata,
    RawEvent,
)
from aegisguard_ulpf.parsing.semantic_packs.loader import load_semantic_pack
from aegisguard_ulpf.parsing.semantic_packs.runtime import SemanticPackRuntime


PackIdentity = tuple[str, str, str]


def _normalized_identity(
    vendor: str,
    product: str,
    event_family: str,
) -> PackIdentity:
    return (
        vendor.casefold(),
        product.casefold(),
        event_family.casefold(),
    )


def default_fortigate_traffic_pack_path() -> Path:
    """Return the source-tree demo pack path.

    Pack absence is supported. Installed deployments that do not ship the
    example directory automatically continue through the legacy parser path.
    """

    project_root = Path(__file__).resolve().parents[4]

    return (
        project_root
        / "examples"
        / "semantic_packs"
        / "fortigate_traffic"
        / "semantic_pack.json"
    )


class SemanticPackResolver:
    """Resolve validated data-only packs after source/family detection."""

    def __init__(
        self,
        pack_paths: Mapping[PackIdentity, Path | str] | None = None,
    ) -> None:
        configured = (
            {
                (
                    "Fortinet",
                    "FortiGate",
                    "traffic",
                ): default_fortigate_traffic_pack_path(),
            }
            if pack_paths is None
            else pack_paths
        )

        self._pack_paths = {
            _normalized_identity(*identity): Path(path)
            for identity, path in configured.items()
        }
        self._runtime_cache: dict[PackIdentity, SemanticPackRuntime] = {}

    def resolve(
        self,
        detection: DetectionResult,
    ) -> SemanticPackRuntime | None:
        if not all((
            detection.vendor,
            detection.product,
            detection.event_family,
        )):
            return None

        identity = _normalized_identity(
            detection.vendor,
            detection.product,
            detection.event_family,
        )

        cached = self._runtime_cache.get(identity)
        if cached is not None:
            return cached

        pack_path = self._pack_paths.get(identity)
        if pack_path is None or not pack_path.is_file():
            return None

        try:
            pack = load_semantic_pack(
                pack_path,
                verify_signature=True,
            )
            runtime = SemanticPackRuntime(pack)
        except (OSError, ValueError):
            # Invalid or unavailable optional packs never interrupt the
            # established parser workflow.
            return None

        self._runtime_cache[identity] = runtime
        return runtime

    def parse(
        self,
        event: RawEvent,
        detection: DetectionResult,
    ) -> ParsedEvent | None:
        runtime = self.resolve(detection)
        if runtime is None:
            return None

        try:
            fields = runtime.run(
                event.raw,
                raw_id=event.raw_id,
                u_id=str(event.event_id),
            )
        except (TypeError, ValueError):
            # A valid pack may not apply to a malformed record. In that case,
            # preserve compatibility by delegating to the existing parser.
            return None

        manifest = runtime.pack.manifest

        return ParsedEvent(
            raw_event=event,
            parser=ParserMetadata(
                parser_id=f"semantic_pack:{manifest.pack_id}",
                parser_version=manifest.pack_version,
                vendor=manifest.vendor,
                product=manifest.product,
                supported_formats=[runtime.pack.syntax.input_format],
            ),
            fields=fields,
            warnings=[],
        )
