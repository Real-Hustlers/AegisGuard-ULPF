"""Run the ULPF demo and convert its OCSF output for SIEM ingestion."""

from __future__ import annotations

import subprocess
import sys

from pathlib import Path

from aegisguard_ulpf.integration.siem_adapter import (
    adapt_ocsf_jsonl_to_siem,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = PROJECT_ROOT / "demo"
ULPF_DEMO_SCRIPT = DEMO_DIR / "run_demo.py"
OCSF_OUTPUT_PATH = DEMO_DIR / "output" / "ocsf_events.jsonl"
SIEM_OUTPUT_PATH = DEMO_DIR / "output" / "merged_logs.json"


def run_siem_integration() -> Path:
    """Execute the existing ULPF demo, then create SIEM-compatible JSON."""

    subprocess.run(
        [sys.executable, str(ULPF_DEMO_SCRIPT)],
        cwd=PROJECT_ROOT,
        check=True,
    )

    if not OCSF_OUTPUT_PATH.is_file():
        raise FileNotFoundError(
            "ULPF demo did not produce OCSF output: "
            f"{OCSF_OUTPUT_PATH}"
        )

    output_path = adapt_ocsf_jsonl_to_siem(
        OCSF_OUTPUT_PATH,
        SIEM_OUTPUT_PATH,
    )

    print("\n=== SIEM ADAPTER OUTPUT ===")
    print(output_path)

    return output_path


if __name__ == "__main__":
    run_siem_integration()
