"""Create a transferable, locally verifiable AegisGuard-ULPF source bundle."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = ROOT / "offline_bundle"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _copy_wheels(target: Path, wheel_dirs: tuple[Path, ...]) -> int:
    copied = 0
    for directory in wheel_dirs:
        if directory.is_dir():
            for wheel in directory.glob("*.whl"):
                shutil.copy2(wheel, target / wheel.name)
                copied += 1
    return copied


def _export_docker_image(target: Path, image: str | None) -> bool:
    if image is None or shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    if result.returncode != 0:
        return False
    subprocess.run(["docker", "save", "--output", str(target / "aegisguard-ulpf-image.tar"), image], check=True)
    return True


def _write_checksums(bundle: Path) -> Path:
    checksum_dir = bundle / "checksums"
    lines = []
    for path in sorted(item for item in bundle.rglob("*") if item.is_file() and checksum_dir not in item.parents):
        lines.append(f"{_sha256(path)}  {path.relative_to(bundle).as_posix()}")
    manifest = checksum_dir / "SHA256SUMS"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def create_offline_bundle(output_dir: str | Path = DEFAULT_BUNDLE, *, image: str | None = None, wheel_dirs: tuple[str | Path, ...] = ()) -> tuple[Path, Path]:
    """Create bundle directory and sibling ZIP using only local resources."""
    bundle = Path(output_dir)
    if bundle.exists():
        raise FileExistsError(f"Offline bundle target already exists: {bundle}")
    source = bundle / "source"; wheels = bundle / "wheels"; schemas = bundle / "schemas"; packs = bundle / "semantic_packs"; docker = bundle / "docker"
    for directory in (source, wheels, schemas, packs, docker, bundle / "checksums"):
        directory.mkdir(parents=True, exist_ok=True)
    _copy_tree(ROOT / "src", source / "src")
    shutil.copy2(ROOT / "pyproject.toml", source / "pyproject.toml")
    _copy_tree(ROOT / "scripts", source / "scripts")
    _copy_tree(ROOT / "docker", docker / "docker")
    for name in ("docker-compose.yml", ".dockerignore"):
        path = ROOT / name
        if path.is_file(): shutil.copy2(path, docker / name)
    _copy_tree(ROOT / "src" / "aegisguard_ulpf" / "schemas", schemas / "schemas")
    semantic_root = ROOT / "src" / "aegisguard_ulpf" / "parsing" / "semantic_packs"
    _copy_tree(semantic_root / "packs", packs / "packs")
    _copy_tree(semantic_root / "trusted_keys", packs / "trusted_keys")
    _copy_wheels(wheels, tuple(Path(item) for item in wheel_dirs) or (ROOT / "wheels", ROOT / "dist"))
    (wheels / "README.txt").write_text("Place local dependency wheels here before offline installation.\n", encoding="utf-8")
    _export_docker_image(docker, image)
    _write_checksums(bundle)
    archive = Path(shutil.make_archive(str(bundle), "zip", bundle.parent, bundle.name))
    return bundle, archive


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a transferable local AegisGuard-ULPF offline bundle.")
    parser.add_argument("--output", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--image", help="Optional locally available Docker image to export")
    parser.add_argument("--wheel-dir", action="append", default=[], type=Path)
    args = parser.parse_args()
    try:
        _, archive = create_offline_bundle(args.output, image=args.image, wheel_dirs=tuple(args.wheel_dir))
    except Exception as exc:
        print(f"Offline bundle failed: {exc}")
        return 1
    print("Offline Bundle Created")
    print("Checksum Generated")
    print("Deployment Ready")
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
