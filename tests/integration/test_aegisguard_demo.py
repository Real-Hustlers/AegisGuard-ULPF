"""Integration coverage for the presentation-level AegisGuard demo runner."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo" / "run_aegisguard_demo.py"
WORKFLOW_SCRIPTS = (
    ROOT / "demo" / "run_windows_siem_demo.py",
    ROOT / "demo" / "run_multivendor_demo.py",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_presentation_demo_runs_existing_workflows_without_changing_them():
    before = {path: _digest(path) for path in WORKFLOW_SCRIPTS}
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"

    result = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Windows Security -> ULPF -> OCSF -> SIEM envelope" in result.stdout
    assert "Cisco ASA, FortiGate, and PAN-OS -> Common taxonomy" in result.stdout
    assert (ROOT / "demo" / "output" / "windows-demo").is_dir()
    assert (ROOT / "demo" / "output" / "windows-demo" / "ocsf_events.jsonl").is_file()
    assert (
        ROOT / "demo" / "output" / "windows-demo" / "siem_ingestion_envelope.json"
    ).is_file()
    assert (ROOT / "demo" / "output" / "multivendor-demo").is_dir()
    assert (
        ROOT / "demo" / "output" / "multivendor-demo" / "common_events.json"
    ).is_file()
    assert {path: _digest(path) for path in WORKFLOW_SCRIPTS} == before
