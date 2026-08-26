import json
import subprocess
import sys

from pathlib import Path

import pytest

from scripts.build_airgap_bundle import (
    ARTIFACT_FILENAME,
    CHECKSUMS_FILENAME,
    MANIFEST_FILENAME,
    OFFLINE_VERIFIER_FILENAME,
    PACKS_FILENAME,
    sha256_file,
    write_bundle_metadata,
)
from scripts.verify_airgap_bundle import verify_airgap_bundle
from scripts.verify_release_packs import (
    DEFAULT_PACKS_DIR,
    PROJECT_ROOT,
    verify_release_packs,
)
from aegisguard_ulpf.parsing.semantic_packs.loader import load_semantic_pack
from aegisguard_ulpf.parsing.semantic_packs.signing import (
    verify_semantic_pack_signature,
)


TRUSTED_KEYS_DIR = (
    PROJECT_ROOT
    / "src"
    / "aegisguard_ulpf"
    / "parsing"
    / "semantic_packs"
    / "trusted_keys"
)


def make_bundle(tmp_path: Path) -> tuple[Path, Path, list[dict]]:
    bundle = tmp_path / "airgap"
    bundle.mkdir()
    artifact = bundle / ARTIFACT_FILENAME
    artifact.write_bytes(b"docker image archive bytes")
    metadata = verify_release_packs()
    write_bundle_metadata(
        bundle,
        image="aegisguard-ulpf:0.1.0",
        artifact_path=artifact,
        semantic_packs=metadata,
    )
    return bundle, artifact, metadata


def test_release_verification_reports_existing_signed_pack_deterministically():
    first = verify_release_packs()
    second = verify_release_packs()

    assert first == second
    assert first
    assert first[0]["filename"] == "paloalto_panos_traffic_v1.json"
    assert first[0]["key_id"] == "aegisguard-dev-v3"
    assert first[0]["algorithm"] == "ed25519"
    assert len(first[0]["semantic_pack_sha256"]) == 64
    assert first[0]["verified"] is True


def test_release_verification_fails_for_tampered_pack(tmp_path: Path):
    pack_dir = tmp_path / "packs"
    pack_dir.mkdir()
    source = next(DEFAULT_PACKS_DIR.glob("*.json"))
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["manifest"]["pack_version"] = "tampered"
    (pack_dir / source.name).write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="signature"):
        verify_release_packs(pack_dir)


def test_trusted_key_assets_are_public_only_and_expected_keys_exist():
    expected = {
        "aegisguard-dev-v1.pem",
        "aegisguard-dev-v2.pem",
        "aegisguard-dev-v3.pem",
    }
    assert expected <= {path.name for path in TRUSTED_KEYS_DIR.glob("*.pem")}
    for key_path in TRUSTED_KEYS_DIR.glob("*.pem"):
        contents = key_path.read_text(encoding="utf-8")
        assert "BEGIN PUBLIC KEY" in contents
        assert "PRIVATE KEY" not in contents


def test_existing_verifier_rejects_malformed_trusted_public_key(tmp_path: Path):
    pack = load_semantic_pack(next(DEFAULT_PACKS_DIR.glob("*.json")))
    (tmp_path / "aegisguard-dev-v3.pem").write_text(
        "not a public key",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        verify_semantic_pack_signature(pack, trusted_keys_dir=tmp_path)


def test_airgap_manifest_records_artifact_hash_and_verifies(tmp_path: Path):
    bundle, artifact, metadata = make_bundle(tmp_path)
    manifest = verify_airgap_bundle(bundle)

    assert manifest["artifact_filename"] == ARTIFACT_FILENAME
    assert manifest["artifact_sha256"] == sha256_file(artifact)
    assert manifest["semantic_packs"] == metadata
    assert (bundle / MANIFEST_FILENAME).is_file()
    assert (bundle / PACKS_FILENAME).is_file()
    assert (bundle / CHECKSUMS_FILENAME).is_file()
    assert (bundle / OFFLINE_VERIFIER_FILENAME).is_file()

    result = subprocess.run(
        [
            sys.executable,
            str(bundle / OFFLINE_VERIFIER_FILENAME),
            "--bundle",
            str(bundle),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_airgap_verification_rejects_altered_or_missing_artifact(tmp_path: Path):
    bundle, artifact, _ = make_bundle(tmp_path)
    artifact.write_bytes(b"altered archive bytes")

    with pytest.raises(ValueError, match="SHA-256"):
        verify_airgap_bundle(bundle)

    artifact.unlink()
    with pytest.raises(FileNotFoundError, match="image artifact"):
        verify_airgap_bundle(bundle)


def test_airgap_verification_rejects_malformed_manifest(tmp_path: Path):
    bundle, _, _ = make_bundle(tmp_path)
    (bundle / MANIFEST_FILENAME).write_text("not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="manifest"):
        verify_airgap_bundle(bundle)


def test_airgap_bundle_contains_no_private_key_material(tmp_path: Path):
    bundle, _, _ = make_bundle(tmp_path)

    for path in bundle.iterdir():
        if path.is_file() and path.suffix != ".tar":
            assert "PRIVATE KEY" not in path.read_text(encoding="utf-8")


def test_docker_and_packaging_contracts_are_present():
    dockerfile = (PROJECT_ROOT / "docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(
        encoding="utf-8"
    )
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "AS builder" in dockerfile
    assert "--no-index --find-links=/wheelhouse" in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "aegisguard_ulpf"]' in dockerfile
    assert "USER aegisguard" in dockerfile
    assert "load_semantic_pack" in dockerfile
    assert "aegisguard-dev-v3.pem" in dockerfile
    for entry in (".git", ".venv", "dist", "*.key", "*.pem", "*private*.pem"):
        assert entry in dockerignore
    assert '"packs/*.json"' in pyproject
    assert '"trusted_keys/*.pem"' in pyproject
