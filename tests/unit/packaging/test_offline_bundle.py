import hashlib
import zipfile
from pathlib import Path

import pytest

from scripts.create_offline_bundle import create_offline_bundle


def test_offline_bundle_contains_required_local_deployment_assets(tmp_path):
    wheel_dir = tmp_path / "wheel-source"; wheel_dir.mkdir()
    (wheel_dir / "example-1.0-py3-none-any.whl").write_bytes(b"wheel")
    bundle, archive = create_offline_bundle(tmp_path / "offline_bundle", wheel_dirs=(wheel_dir,))
    for name in ("source", "wheels", "schemas", "semantic_packs", "docker", "checksums"):
        assert (bundle / name).is_dir()
    assert (bundle / "source" / "src" / "aegisguard_ulpf" / "core" / "models.py").is_file()
    assert (bundle / "wheels" / "example-1.0-py3-none-any.whl").is_file()
    assert (bundle / "schemas" / "schemas" / "aegisguard_event_v1.json").is_file()
    assert (bundle / "semantic_packs" / "packs" / "paloalto_panos_traffic_v1.json").is_file()
    checksums = (bundle / "checksums" / "SHA256SUMS").read_text(encoding="utf-8")
    assert "source/pyproject.toml" in checksums
    with zipfile.ZipFile(archive) as zipped:
        assert "offline_bundle/source/pyproject.toml" in zipped.namelist()


def test_bundle_refuses_to_overwrite_existing_target(tmp_path):
    target = tmp_path / "offline_bundle"; target.mkdir()
    with pytest.raises(FileExistsError):
        create_offline_bundle(target)
