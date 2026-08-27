import json
import subprocess
import sys

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = PROJECT_ROOT / "demo"
INTEGRATION_DEMO = DEMO_DIR / "run_siem_integration.py"
OCSF_OUTPUT_PATH = DEMO_DIR / "output" / "ocsf_events.jsonl"
SIEM_OUTPUT_PATH = DEMO_DIR / "output" / "merged_logs.json"


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_demo_siem_flow_creates_valid_siem_output():
    subprocess.run(
        [sys.executable, str(INTEGRATION_DEMO)],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert OCSF_OUTPUT_PATH.is_file()
    assert SIEM_OUTPUT_PATH.is_file()

    ocsf_events = read_jsonl(OCSF_OUTPUT_PATH)
    merged_logs = json.loads(
        SIEM_OUTPUT_PATH.read_text(encoding="utf-8")
    )

    assert ocsf_events
    assert isinstance(merged_logs, list)
    assert len(merged_logs) == len(ocsf_events)

    merged_by_event_id = {
        event["event_id"]: event
        for event in merged_logs
    }

    for ocsf_event in ocsf_events:
        raw_data = ocsf_event["raw_data"]
        siem_event = merged_by_event_id[raw_data["u_id"]]

        assert siem_event["raw_id"] == raw_data["raw_id"]
        assert siem_event["ulpf_original_event"] == ocsf_event
