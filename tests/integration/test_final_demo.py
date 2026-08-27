"""Integration coverage for the final SIH presentation entry point."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FINAL_DEMO = ROOT / "demo" / "run_final_demo.py"
WORKFLOW_SCRIPTS = (
    ROOT / "demo" / "run_aegisguard_demo.py",
    ROOT / "demo" / "run_traceability_demo.py",
    ROOT / "demo" / "run_windows_siem_demo.py",
    ROOT / "demo" / "run_multivendor_demo.py",
    ROOT / "demo" / "run_demo.py",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_demo_runs_existing_workflows_without_modifying_them():
    before = {path: _digest(path) for path in WORKFLOW_SCRIPTS}
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"

    result = subprocess.run(
        [sys.executable, str(FINAL_DEMO)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "[1] Multi-source log processing" in result.stdout
    assert "[2] Windows Security -> OCSF -> SIEM" in result.stdout
    assert "[3] Multi-vendor normalization" in result.stdout
    assert "[4] Evidence preservation" in result.stdout
    assert "[5] Hash-chain verification" in result.stdout
    assert "[6] Integrity verification" in result.stdout
    assert "AegisGuard-ULPF pipeline operational" in result.stdout

    assert (ROOT / "demo" / "output" / "windows-demo").is_dir()
    assert (ROOT / "demo" / "output" / "windows-demo" / "ocsf_events.jsonl").is_file()
    assert (ROOT / "demo" / "output" / "multivendor-demo").is_dir()
    assert (
        ROOT / "demo" / "output" / "multivendor-demo" / "common_events.json"
    ).is_file()
    assert (ROOT / "demo" / "output" / "ocsf_events.jsonl").is_file()
    assert (ROOT / "demo" / "evidence" / "evidence_manifest.jsonl").is_file()
    assert {path: _digest(path) for path in WORKFLOW_SCRIPTS} == before
