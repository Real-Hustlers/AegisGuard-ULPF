"""Demonstrate OCSF-to-raw evidence traceability and integrity verification."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from pathlib import Path

from aegisguard_ulpf.traceability.raw_store import RawEvidenceStore


ROOT = Path(__file__).resolve().parents[1]
PIPELINE_DEMO = ROOT / "demo" / "run_demo.py"
OCSF_OUTPUT = ROOT / "demo" / "output" / "ocsf_events.jsonl"
EVIDENCE_DIR = ROOT / "demo" / "evidence"


def _latest_ocsf_event() -> dict:
    lines = OCSF_OUTPUT.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError("The pipeline demo did not produce an OCSF event")
    return json.loads(lines[-1])


def main() -> None:
    environment = os.environ.copy()
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run(
        [sys.executable, str(PIPELINE_DEMO)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())

    ocsf_event = _latest_ocsf_event()
    raw_data = ocsf_event.get("raw_data")
    if not isinstance(raw_data, dict):
        raise RuntimeError("OCSF event does not contain traceability raw_data")

    event_id = raw_data.get("u_id")
    raw_id = raw_data.get("raw_id")
    if not isinstance(event_id, str) or not isinstance(raw_id, str):
        raise RuntimeError("OCSF traceability identifiers are missing")

    verification = RawEvidenceStore(EVIDENCE_DIR).verify(event_id)

    print("\n=== AegisGuard-ULPF Hash Chain Traceability ===")
    print("OCSF raw_id:", raw_id)
    print("Original event found:", "YES" if verification["original_event_found"] else "NO")
    print("SHA256 verified:", "PASS" if verification["raw_sha256_verified"] else "FAIL")
    print("Hash chain valid:", "PASS" if verification["hash_chain_verified"] else "FAIL")
    print("Integrity:", verification["integrity"])


if __name__ == "__main__":
    main()
