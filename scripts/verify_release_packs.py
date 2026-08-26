"""Verify all bundled Semantic Packs using the runtime trust configuration."""

import argparse
import json
import sys

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from aegisguard_ulpf.parsing.semantic_packs.loader import (  # noqa: E402
    load_semantic_pack,
    semantic_pack_sha256,
)
from aegisguard_ulpf.parsing.semantic_packs.signing import (  # noqa: E402
    verify_semantic_pack_signature,
)


DEFAULT_PACKS_DIR = (
    SOURCE_ROOT / "aegisguard_ulpf" / "parsing" / "semantic_packs" / "packs"
)


def verify_release_packs(
    packs_dir: str | Path = DEFAULT_PACKS_DIR,
) -> list[dict[str, str | bool]]:
    """Fail closed unless every bundled JSON pack validates and verifies."""

    directory = Path(packs_dir)
    pack_paths = sorted(directory.glob("*.json"))
    if not pack_paths:
        raise ValueError(f"No Semantic Pack JSON files found: {directory}")

    verified_packs: list[dict[str, str | bool]] = []
    for path in pack_paths:
        pack = load_semantic_pack(path, verify_signature=True)
        verify_semantic_pack_signature(pack)
        signature = pack.manifest.signature
        verified_packs.append({
            "filename": path.name,
            "pack_id": pack.manifest.pack_id,
            "pack_version": pack.manifest.pack_version,
            "key_id": signature.key_id or "",
            "algorithm": signature.algorithm or "",
            "semantic_pack_sha256": semantic_pack_sha256(pack),
            "verified": True,
        })

    return verified_packs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify bundled AegisGuard Semantic Packs for release."
    )
    parser.add_argument("--packs-dir", type=Path, default=DEFAULT_PACKS_DIR)
    args = parser.parse_args()

    try:
        metadata = verify_release_packs(args.packs_dir)
    except Exception as exc:
        print(f"Semantic Pack release verification failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
