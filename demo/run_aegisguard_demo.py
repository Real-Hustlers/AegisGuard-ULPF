"""Run the existing ULPF demonstrations as one SIH presentation flow."""

from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WINDOWS_DEMO = REPOSITORY_ROOT / "demo" / "run_windows_siem_demo.py"
MULTIVENDOR_DEMO = REPOSITORY_ROOT / "demo" / "run_multivendor_demo.py"

WINDOWS_OUTPUT = REPOSITORY_ROOT / "demo" / "output" / "windows-demo"
MULTIVENDOR_OUTPUT = REPOSITORY_ROOT / "demo" / "output" / "multivendor-demo"


def _run_existing_demo(script: Path) -> None:
    """Run an existing demo without importing or altering its workflow."""

    environment = os.environ.copy()
    environment.setdefault("PYTHONIOENCODING", "utf-8")

    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{script.name} failed:\n{details}")


def _display_path(path: Path) -> str:
    return path.relative_to(REPOSITORY_ROOT).as_posix()


def main() -> None:
    print("\n=== AegisGuard-ULPF SIH Demonstration ===\n")

    print("[1/2] Windows Security -> ULPF -> OCSF -> SIEM envelope")
    _run_existing_demo(WINDOWS_DEMO)
    print("      complete")

    print("[2/2] Cisco ASA, FortiGate, and PAN-OS -> Common taxonomy")
    _run_existing_demo(MULTIVENDOR_DEMO)
    print("      complete")

    print("\n--- Demonstration Summary ---")
    print("Windows Security: raw evidence view, CommonEvent, OCSF, SIEM envelope")
    print("Multi-vendor: Cisco ASA, FortiGate, and Palo Alto PAN-OS common events")
    print("\nGenerated outputs:")
    print(f"- {_display_path(WINDOWS_OUTPUT)}")
    print(f"- {_display_path(MULTIVENDOR_OUTPUT)}")
    print("\n=== Demonstration Complete ===")


if __name__ == "__main__":
    main()
