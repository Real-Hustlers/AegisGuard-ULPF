import csv
import io

from datetime import (
    datetime,
    timezone,
)
from pathlib import Path

import pytest

from pydantic import ValidationError

from aegisguard_ulpf.normalization.engine import (
    NormalizationEngine,
)
from aegisguard_ulpf.normalization.ocsf.mapper import (
    map_common_event_to_ocsf,
)

from aegisguard_ulpf.parsing.semantic_packs.loader import (
    load_semantic_pack,
    semantic_pack_sha256,
)

from aegisguard_ulpf.parsing.semantic_packs.models import (
    OperationSpec,
    SemanticPack,
)

from aegisguard_ulpf.parsing.semantic_packs.runtime import (
    ALLOWED_OPERATIONS,
    SemanticPackRuntime,
)

from aegisguard_ulpf.parsing.vendors.palaalto.panos import (
    traffic as python_traffic,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[3]
)


PACK_PATH = (
    PROJECT_ROOT
    / "src"
    / "aegisguard_ulpf"
    / "parsing"
    / "semantic_packs"
    / "packs"
    / "paloalto_panos_traffic_v1.json"
)


def build_panos_traffic_log(
    *,
    subtype: str = "start",
    action: str = "allow",
    log_type: str = "TRAFFIC",
    extra_fields: tuple[str, ...] = (),
) -> str:

    values = {
        name: ""
        for name
        in python_traffic.TRAFFIC_FIELD_NAMES
    }

    values.update({
        "future_use_1":
            "1",

        "receive_time":
            "2026/08/26 18:00:01",

        "serial":
            "PA123456789",

        "type":
            log_type,

        "subtype":
            subtype,

        "config_version":
            "1",

        "time_generated":
            "2026/08/26 18:00:00",

        "src":
            "10.10.10.10",

        "dst":
            "10.20.20.20",

        "natsrc":
            "203.0.113.10",

        "natdst":
            "198.51.100.20",

        "rule":
            "Allow-Web",

        "srcuser":
            "alice",

        "dstuser":
            "server-user",

        "app":
            "ssl",

        "vsys":
            "vsys1",

        "from_zone":
            "trust",

        "to_zone":
            "untrust",

        "inbound_if":
            "ethernet1/1",

        "outbound_if":
            "ethernet1/2",

        "logset":
            "default",

        "sessionid":
            "12345",

        "repeatcnt":
            "1",

        "sport":
            "51515",

        "dport":
            "443",

        "natsport":
            "40000",

        "natdport":
            "8443",

        "flags":
            "0x0",

        "proto":
            "tcp",

        "action":
            action,

        "bytes":
            "1000",

        "bytes_sent":
            "700",

        "bytes_received":
            "300",

        "packets":
            "10",

        "start":
            "2026/08/26 17:59:51",

        "elapsed":
            "9",

        "category":
            "business-systems",

        "seqno":
            "999999",

        "actionflags":
            "0x0",

        "srcloc":
            "10.0.0.0-10.255.255.255",

        "dstloc":
            "10.0.0.0-10.255.255.255",

        "pkts_sent":
            "7",

        "pkts_received":
            "3",

        "session_end_reason":
            "aged-out",

        "vsys_name":
            "vsys1",

        "device_name":
            "PA-FW-01",

        "action_source":
            "policy",

        "src_uuid":
            "SRC-UUID",

        "dst_uuid":
            "DST-UUID",

        "rule_uuid":
            "RULE-UUID-001",

        "policy_id":
            "42",
    })

    row = [
        values[name]
        for name
        in python_traffic.TRAFFIC_FIELD_NAMES
    ]

    row.extend(
        extra_fields
    )

    output = io.StringIO()

    writer = csv.writer(
        output,
        lineterminator="",
    )

    writer.writerow(
        row
    )

    return output.getvalue()


@pytest.fixture(scope="module")
def pack():
    return load_semantic_pack(
        PACK_PATH
    )


@pytest.fixture(scope="module")
def runtime(pack):
    return SemanticPackRuntime(
        pack
    )


def test_pack_loads(pack):
    assert isinstance(
        pack,
        SemanticPack,
    )

    assert (
        pack.manifest.pack_id
        == "paloalto.panos.traffic"
    )

    assert (
        pack.manifest.pack_version
        == "1.0.0"
    )


def test_pack_provenance_exists(pack):
    assert pack.provenance.source

    assert (
        "traffic.py"
        in pack.provenance.derived_from
    )


def test_pack_ocsf_binding_is_honest(pack):
    assert (
        pack.ocsf_binding.status
        == "bound"
    )

    assert (
        pack.ocsf_binding.class_uid
        == 4001
    )

    assert (
        pack.ocsf_binding.activity_mappings
        == {
            "SESSION": 6,
            "POLICY": 6,
            "UNKNOWN": 0,
        }
    )


def test_pack_signature_state_is_honest(pack):
    signature = (
        pack.manifest.signature
    )

    assert signature.status == "signed"

    assert (
        signature.algorithm
        == "ed25519"
    )

    assert (
        signature.key_id
        == "aegisguard-dev-v2"
    )

    assert signature.value

    # Ed25519 signature is Base64 encoded.
    assert len(signature.value) > 40


def test_integrity_fingerprint_is_deterministic(
    pack,
):
    first = semantic_pack_sha256(
        pack
    )

    second = semantic_pack_sha256(
        pack
    )

    assert first == second

    assert len(first) == 64


def test_allowed_operation_set_is_restricted():
    assert ALLOWED_OPERATIONS == {
        "constant",
        "clean",
        "to_int",
        "protocol",
        "port",
        "timestamp",
        "nat_ip",
        "nat_port",
        "constant_if_present",
    }


@pytest.mark.parametrize(
    "operation",
    [
        "python",
        "eval",
        "exec",
        "shell",
        "subprocess",
        "import",
        "jinja",
    ],
)
def test_execution_like_operations_rejected(
    operation,
):
    with pytest.raises(
        ValidationError
    ):
        OperationSpec.model_validate({
            "op": operation,
            "target": "action",
        })


def test_unknown_pack_structure_rejected(pack):
    payload = pack.model_dump(
        mode="json"
    )

    payload["arbitrary_python"] = (
        "print('not allowed')"
    )

    with pytest.raises(
        ValidationError
    ):
        SemanticPack.model_validate(
            payload
        )


def test_runtime_parses_panos_csv(runtime):
    raw = build_panos_traffic_log()

    fields = runtime.parse_fields(
        raw
    )

    assert fields["type"] == "TRAFFIC"
    assert fields["subtype"] == "start"
    assert fields["src"] == "10.10.10.10"


def test_runtime_handles_syslog_wrapper(runtime):
    raw = (
        "<14>Aug 26 18:00:01 PA-FW "
        + build_panos_traffic_log()
    )

    fields = runtime.parse_fields(
        raw
    )

    assert fields["type"] == "TRAFFIC"
    assert fields["src"] == "10.10.10.10"


def test_semantic_operations(runtime):
    raw = build_panos_traffic_log()

    event = runtime.run(
        raw,
        raw_id="RAW-SEM-001",
        u_id="UEV-SEM-001",
    )

    assert event["vendor"] == (
        "Palo Alto Networks"
    )

    assert event["product"] == "PAN-OS"

    assert event["category"] == "TRAFFIC"
    assert event["type"] == "SESSION"

    assert (
        event["subtype"]
        == "SESSION_START"
    )

    assert event["outcome"] == "SUCCESS"

    assert event["protocol"] == "TCP"

    assert event["src_port"] == 51515
    assert event["dst_port"] == 443

    assert event["details"][
        "session_id"
    ] == 12345

    assert event["details"][
        "bytes_total"
    ] == 1000

    assert event["details"][
        "policy_id"
    ] == 42


@pytest.mark.parametrize(
    (
        "subtype",
        "action",
        "expected_type",
        "expected_subtype",
        "expected_outcome",
    ),
    [
        (
            "start",
            "allow",
            "SESSION",
            "SESSION_START",
            "SUCCESS",
        ),
        (
            "end",
            "allow",
            "SESSION",
            "SESSION_END",
            "SUCCESS",
        ),
        (
            "drop",
            "deny",
            "POLICY",
            "TRAFFIC_DROP",
            "FAILURE",
        ),
        (
            "deny",
            "reset-both",
            "POLICY",
            "TRAFFIC_DENY",
            "FAILURE",
        ),
        (
            "future-type",
            "allow",
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
        ),
    ],
)
def test_python_parser_semantic_equivalence(
    runtime,
    subtype,
    action,
    expected_type,
    expected_subtype,
    expected_outcome,
):
    raw = build_panos_traffic_log(
        subtype=subtype,
        action=action,
    )

    python_event = (
        python_traffic.normalize(
            raw_log=raw,
            raw_id="RAW-EQUIV-001",
            u_id="UEV-EQUIV-001",
        )
    )

    pack_event = runtime.run(
        raw,
        raw_id="RAW-EQUIV-001",
        u_id="UEV-EQUIV-001",
    )

    assert (
        pack_event["type"]
        == expected_type
    )

    assert (
        pack_event["subtype"]
        == expected_subtype
    )

    assert (
        pack_event["outcome"]
        == expected_outcome
    )

    assert pack_event == python_event


def test_common_event_equivalence(runtime):
    raw = build_panos_traffic_log(
        subtype="end",
        action="allow",
    )

    python_event = (
        python_traffic.normalize(
            raw_log=raw,
            raw_id="RAW-COMMON-001",
            u_id="UEV-COMMON-001",
        )
    )

    pack_event = runtime.run(
        raw,
        raw_id="RAW-COMMON-001",
        u_id="UEV-COMMON-001",
    )

    observed_time = datetime(
        2026,
        8,
        26,
        18,
        0,
        tzinfo=timezone.utc,
    )

    processed_time = datetime(
        2026,
        8,
        26,
        18,
        0,
        1,
        tzinfo=timezone.utc,
    )

    engine = NormalizationEngine()

    python_common = engine.normalize(
        python_event,
        observed_time=observed_time,
        processed_time=processed_time,
    )

    pack_common = engine.normalize(
        pack_event,
        observed_time=observed_time,
        processed_time=processed_time,
    )

    assert (
        pack_common.model_dump()
        == python_common.model_dump()
    )


def test_pack_binds_common_event_to_ocsf(runtime):
    common_event = NormalizationEngine().normalize(
        runtime.run(
            build_panos_traffic_log(),
            raw_id="RAW-OCSF-001",
            u_id="UEV-OCSF-001",
        ),
        observed_time=datetime(
            2026, 8, 26, 18, 0, tzinfo=timezone.utc
        ),
        processed_time=datetime(
            2026, 8, 26, 18, 0, 1, tzinfo=timezone.utc
        ),
    )

    first = map_common_event_to_ocsf(
        common_event,
        runtime.pack.ocsf_binding,
    )
    second = map_common_event_to_ocsf(
        common_event,
        runtime.pack.ocsf_binding,
    )

    assert first == second
    assert first["class_uid"] == 4001
    assert first["category_uid"] == 4
    assert first["type_uid"] == 400106
    assert first["activity_id"] == 6
    assert first["status_id"] == 1
    assert first["raw_data"] == {
        "u_id": "UEV-OCSF-001",
        "raw_id": "RAW-OCSF-001",
    }


def test_appended_unknown_fields_preserved(
    runtime,
):
    raw = build_panos_traffic_log(
        extra_fields=(
            "future-value-a",
            "future-value-b",
        )
    )

    python_event = (
        python_traffic.normalize(
            raw_log=raw,
            raw_id="RAW-FUTURE-001",
            u_id="UEV-FUTURE-001",
        )
    )

    pack_event = runtime.run(
        raw,
        raw_id="RAW-FUTURE-001",
        u_id="UEV-FUTURE-001",
    )

    assert (
        pack_event["vendor_fields"][
            "field_69"
        ]
        == "future-value-a"
    )

    assert (
        pack_event["vendor_fields"][
            "field_70"
        ]
        == "future-value-b"
    )

    assert (
        pack_event["vendor_fields"]
        == python_event["vendor_fields"]
    )


def test_non_traffic_input_fails_explicitly(
    runtime,
):
    raw = build_panos_traffic_log(
        log_type="THREAT"
    )

    with pytest.raises(
        ValueError
    ):
        runtime.run(
            raw,
            raw_id="RAW-BAD-001",
            u_id="UEV-BAD-001",
        )


def test_runtime_does_not_generate_ids(runtime):
    raw = build_panos_traffic_log()

    with pytest.raises(
        ValueError
    ):
        runtime.run(
            raw,
            raw_id="",
            u_id="UEV-X",
        )

    with pytest.raises(
        ValueError
    ):
        runtime.run(
            raw,
            raw_id="RAW-X",
            u_id="",
        )


def test_runtime_does_not_mutate_pack(
    pack,
    runtime,
):
    before = pack.model_dump(
        mode="json"
    )

    runtime.run(
        build_panos_traffic_log(),
        raw_id="RAW-MUTATE-001",
        u_id="UEV-MUTATE-001",
    )

    after = pack.model_dump(
        mode="json"
    )

    assert before == after
