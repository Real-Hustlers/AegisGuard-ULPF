from __future__ import annotations

import json
from pathlib import Path

from aegisguard_ulpf.ingestion.windows import (
    adapt_windows_security_event,
)

from aegisguard_ulpf.normalization.ocsf.windows import (
    map_windows_security_event_to_common_event,
    map_windows_security_event_to_ocsf,
)

from aegisguard_ulpf.outputs.json_file import (
    JsonlOutputWriter,
)

from aegisguard_ulpf.integration.siem_contract_mapper import (
    translate_ocsf_jsonl_to_siem_ingestion_envelope,
)


INPUT_FILE = Path(
    "examples/windows_security_demo_events.json"
)

OUTPUT_DIR = Path(
    "demo/output/windows-demo"
)


def main():

    events = json.loads(
        INPUT_FILE.read_text(
            encoding="utf-8"
        )
    )

    writer = JsonlOutputWriter(
        OUTPUT_DIR
    )

    for event in events:

        # Raw preservation
        raw_event = adapt_windows_security_event(event)
        writer.write_raw(raw_event)

        # ULPF Common Event
        common_event = (
            map_windows_security_event_to_common_event(
                event
            )
        )
        writer.write_normalized(common_event)

        # OCSF Event
        ocsf_event = (
            map_windows_security_event_to_ocsf(
                event
            )
        )
        writer.write_ocsf(ocsf_event)

    # Translate OCSF JSONL to SIEM upload envelope
    translate_ocsf_jsonl_to_siem_ingestion_envelope(
        writer.ocsf_path,
        OUTPUT_DIR / "siem_ingestion_envelope.json",
        machine_id="WIN-DEMO-01",
        hostname="WIN-DEMO",
        os_name="Windows",
    )

    print("Windows SIEM demo completed")
    print(f"Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()