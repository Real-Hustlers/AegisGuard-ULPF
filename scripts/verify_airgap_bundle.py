"""Verify an AegisGuard Docker air-gap bundle without network access."""

import argparse
import hashlib
import json
import sys

from pathlib import Path
from typing import Any

MANIFEST_FILENAME = "manifest.json"
PACKS_FILENAME = "semantic-packs.json"
CHECKSUMS_FILENAME = "SHA256SUMS"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_airgap_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    bundle = Path(bundle_dir)
    manifest_path = bundle / MANIFEST_FILENAME
    packs_path = bundle / PACKS_FILENAME
    checksums_path = bundle / CHECKSUMS_FILENAME

    for path in (manifest_path, packs_path, checksums_path):
        if not path.is_file():
            raise FileNotFoundError(f"Required bundle file not found: {path.name}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Air-gap manifest is malformed") from exc

    if not isinstance(manifest, dict):
        raise ValueError("Air-gap manifest must be a JSON object")

    artifact_name = manifest.get("artifact_filename")
    expected_sha256 = manifest.get("artifact_sha256")
    if (
        not isinstance(artifact_name, str)
        or Path(artifact_name).name != artifact_name
        or not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
    ):
        raise ValueError("Air-gap manifest is missing valid artifact metadata")

    artifact_path = bundle / artifact_name
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Air-gap image artifact not found: {artifact_name}")

    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != expected_sha256:
        raise ValueError("Air-gap image artifact SHA-256 does not match manifest")

    expected_checksum_line = f"{expected_sha256}  {artifact_name}"
    checksum_lines = checksums_path.read_text(encoding="utf-8").splitlines()
    if checksum_lines != [expected_checksum_line]:
        raise ValueError("Air-gap checksum file does not match manifest")

    try:
        semantic_packs = json.loads(packs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Semantic Pack verification metadata is malformed") from exc

    if semantic_packs != manifest.get("semantic_packs"):
        raise ValueError("Semantic Pack verification metadata does not match manifest")

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AegisGuard air-gap bundle checksum."
    )
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()

    try:
        manifest = verify_airgap_bundle(args.bundle)
    except Exception as exc:
        print(f"Air-gap bundle verification failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
