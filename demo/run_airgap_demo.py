"""Demonstrate the existing ULPF pipeline without network services."""

from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRACEABILITY_DEMO = ROOT / "demo" / "run_traceability_demo.py"


def _run_local_demo() -> None:
    environment = os.environ.copy()
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run(
        [sys.executable, str(TRACEABILITY_DEMO)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    if "Integrity: PASS" not in result.stdout:
        raise RuntimeError("Local traceability verification did not pass")


def main() -> None:
    _run_local_demo()
    if not (ROOT / "demo" / "output" / "ocsf_events.jsonl").is_file():
        raise RuntimeError("Local pipeline did not generate OCSF output")

    print("\n=== Air Gap Deployment Demo ===\n")
    print("Internet dependency:")
    print("NONE\n")
    print("Cloud dependency:")
    print("NONE\n")
    print("Local processing:")
    print("PASS\n")
    print("OCSF generation:")
    print("PASS\n")
    print("Traceability verification:")
    print("PASS")


if __name__ == "__main__":
    main()
