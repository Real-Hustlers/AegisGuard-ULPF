from pathlib import Path

from aegisguard_ulpf.traceability.raw_store import (
    RawEvidenceStore,
)


def test_replay_is_deterministic(
    tmp_path: Path,
):
    store = RawEvidenceStore(
        tmp_path
    )

    raw = b"same-event"

    first = store.store(
        raw,
        identity_context={
            "source": "test.log",
            "sequence": 1,
        },
    )

    replay = store.store(
        raw,
        identity_context={
            "source": "test.log",
            "sequence": 1,
        },
    )

    assert (
        first.event_id
        == replay.event_id
    )

    assert len(
        store.records
    ) == 1


def test_identical_bytes_different_position_get_distinct_identity(
    tmp_path: Path,
):
    store = RawEvidenceStore(
        tmp_path
    )

    raw = b"same-event"

    first = store.store(
        raw,
        identity_context={
            "source": "test.log",
            "sequence": 1,
        },
    )

    second = store.store(
        raw,
        identity_context={
            "source": "test.log",
            "sequence": 2,
        },
    )

    assert (
        first.event_id
        != second.event_id
    )

    assert (
        first.raw_sha256
        == second.raw_sha256
    )

    assert (
        first.chain_hash
        != second.chain_hash
    )


def test_raw_tampering_is_detected(
    tmp_path: Path,
):
    store = RawEvidenceStore(
        tmp_path
    )

    record = store.store(
        b"original-event",
        identity_context={
            "source": "test.log",
            "sequence": 1,
        },
    )

    result = store.verify(
        record.event_id
    )

    assert (
        result["integrity"]
        == "PASS"
    )

    blob = (
        tmp_path
        / record.blob_file
    )

    blob.write_bytes(
        b"tampered-event"
    )

    result = store.verify(
        record.event_id
    )

    assert (
        result["raw_sha256_verified"]
        is False
    )

    assert (
        result["integrity"]
        == "FAIL"
    )


def test_manifest_chain_tampering_is_detected(
    tmp_path: Path,
):
    store = RawEvidenceStore(
        tmp_path
    )

    first = store.store(
        b"event-one",
        identity_context={
            "source": "test.log",
            "sequence": 1,
        },
    )

    store.store(
        b"event-two",
        identity_context={
            "source": "test.log",
            "sequence": 2,
        },
    )

    manifest = (
        tmp_path
        / "evidence_manifest.jsonl"
    )

    contents = manifest.read_text(
        encoding="utf-8"
    )

    contents = contents.replace(
        '"transport":"unknown"',
        '"transport":"tampered"',
        1,
    )

    manifest.write_text(
        contents,
        encoding="utf-8",
    )

    reloaded = RawEvidenceStore(
        tmp_path
    )

    result = reloaded.verify(
        first.event_id
    )

    assert (
        result["hash_chain_verified"]
        is False
    )

    assert (
        result["integrity"]
        == "FAIL"
    )