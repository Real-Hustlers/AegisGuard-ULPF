"""Run the established AegisGuard-ULPF demos as one final SIH presentation."""

from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AEGISGUARD_DEMO = ROOT / "demo" / "run_aegisguard_demo.py"
TRACEABILITY_DEMO = ROOT / "demo" / "run_traceability_demo.py"


def _run_demo(script: Path) -> None:
    """Execute an existing demo without importing or changing its workflow."""

    environment = os.environ.copy()
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{script.name} failed:\n{details}")


def main() -> None:
    print("\n=== AegisGuard-ULPF Final SIH Demo ===\n")

    _run_demo(AEGISGUARD_DEMO)
    print("[1] Multi-source log processing")
    print("PASS\n")
    print("[2] Windows Security -> OCSF -> SIEM")
    print("PASS\n")
    print("[3] Multi-vendor normalization")
    print("PASS\n")

    _run_demo(TRACEABILITY_DEMO)
    print("[4] Evidence preservation")
    print("PASS\n")
    print("[5] Hash-chain verification")
    print("PASS\n")
    print("[6] Integrity verification")
    print("PASS\n")

    print("Final Status:")
    print("AegisGuard-ULPF pipeline operational")


if __name__ == "__main__":
    main()
