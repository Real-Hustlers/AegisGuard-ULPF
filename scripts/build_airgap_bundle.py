"""Export a pre-built Docker image and write offline transfer metadata."""

import argparse
import hashlib
import json
import subprocess
import sys

from pathlib import Path
from typing import Any

try:
    from scripts.verify_release_packs import verify_release_packs
except ModuleNotFoundError:
    from verify_release_packs import verify_release_packs


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_FILENAME = "aegisguard-ulpf-image.tar"
MANIFEST_FILENAME = "manifest.json"
PACKS_FILENAME = "semantic-packs.json"
CHECKSUMS_FILENAME = "SHA256SUMS"
OFFLINE_VERIFIER_FILENAME = "verify_airgap_bundle.py"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def project_version() -> str:
    import tomllib

    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def write_bundle_metadata(
    output_dir: str | Path,
    *,
    image: str,
    artifact_path: str | Path,
    semantic_packs: list[dict[str, Any]],
) -> dict[str, Any]:
    output = Path(output_dir)
    artifact = Path(artifact_path)
    if not artifact.is_file():
        raise FileNotFoundError(f"Air-gap image artifact not found: {artifact}")
    if artifact.parent.resolve() != output.resolve():
        raise ValueError("Air-gap image artifact must be inside the output directory")

    artifact_sha256 = sha256_file(artifact)
    manifest = {
        "bundle_format": "aegisguard-ulpf-airgap-v1",
        "project": "aegisguard-ulpf",
        "project_version": project_version(),
        "docker_image": image,
        "artifact_filename": artifact.name,
        "artifact_sha256": artifact_sha256,
        "semantic_packs": semantic_packs,
    }
    (output / PACKS_FILENAME).write_text(
        json.dumps(semantic_packs, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / CHECKSUMS_FILENAME).write_text(
        f"{artifact_sha256}  {artifact.name}\n",
        encoding="utf-8",
    )
    (output / OFFLINE_VERIFIER_FILENAME).write_text(
        (PROJECT_ROOT / "scripts" / OFFLINE_VERIFIER_FILENAME).read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    return manifest


def _run_docker(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Docker tooling is unavailable") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Docker command failed: " + " ".join(command)) from exc


def build_airgap_bundle(image: str, output_dir: str | Path) -> dict[str, Any]:
    _run_docker(["docker", "image", "inspect", image])
    semantic_packs = verify_release_packs()

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / ARTIFACT_FILENAME
    _run_docker(["docker", "save", "--output", str(artifact), image])
    return write_bundle_metadata(
        output,
        image=image,
        artifact_path=artifact,
        semantic_packs=semantic_packs,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export a local AegisGuard Docker image for air-gap transfer."
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        manifest = build_airgap_bundle(args.image, args.output)
    except Exception as exc:
        print(f"Air-gap bundle build failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
