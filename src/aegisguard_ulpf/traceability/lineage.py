from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


TRACEABILITY_VERSION = "1"

GENESIS_CHAIN_HASH = "0" * 64


def _canonical_json_bytes(
    value: Any,
) -> bytes:
    """
    Produce deterministic JSON bytes.

    Used for deterministic event identity and
    tamper-evident hash-chain calculations.
    """

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Traceability input must be JSON-serializable "
            "with deterministic values."
        ) from exc

    return encoded.encode("utf-8")


def _validate_sha256(
    value: str,
    *,
    field_name: str,
) -> str:
    value = value.strip().lower()

    if len(value) != 64:
        raise ValueError(
            f"{field_name} must be a 64-character SHA-256 hex digest"
        )

    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must contain hexadecimal characters only"
        ) from exc

    return value


def sha256_bytes(
    raw_bytes: bytes,
) -> str:
    """
    SHA-256 digest of the authoritative original bytes.

    This is an integrity digest, not an event identifier
    and not a hash-chain value.
    """

    if not isinstance(raw_bytes, bytes):
        raise TypeError(
            "raw_bytes must be bytes so integrity is calculated "
            "over the authoritative byte representation"
        )

    return hashlib.sha256(
        raw_bytes
    ).hexdigest()


def derive_event_id(
    *,
    raw_sha256: str,
    identity_context: Mapping[str, Any],
) -> str:
    """
    Build a deterministic replay-safe event identifier.

    Identity is derived from:
      - the raw SHA-256 digest
      - deterministic source/position identity context

    Example identity_context:
        {
            "source": "firewall.log",
            "sequence": 42
        }

    Replaying the same event with the same context returns
    the same event ID.

    Identical raw bytes with different source positions can
    still have different event IDs.
    """

    raw_sha256 = _validate_sha256(
        raw_sha256,
        field_name="raw_sha256",
    )

    if not isinstance(identity_context, Mapping):
        raise TypeError(
            "identity_context must be a mapping"
        )

    material = {
        "version": TRACEABILITY_VERSION,
        "raw_sha256": raw_sha256,
        "identity_context": dict(
            identity_context
        ),
    }

    digest = hashlib.sha256(
        b"AEGISGUARD-ULPF-EVENT-ID-V1\x00"
        + _canonical_json_bytes(material)
    ).hexdigest()

    return f"EVT-{digest}"


def derive_raw_id(
    event_id: str,
) -> str:
    """
    Derive a stable raw-evidence reference.

    raw_id is a reference identifier.
    It is NOT the raw SHA-256 digest.
    """

    if not isinstance(event_id, str):
        raise TypeError(
            "event_id must be a string"
        )

    event_id = event_id.strip()

    if not event_id:
        raise ValueError(
            "event_id cannot be empty"
        )

    digest = hashlib.sha256(
        b"AEGISGUARD-ULPF-RAW-ID-V1\x00"
        + event_id.encode("utf-8")
    ).hexdigest()

    return f"RAW-{digest}"


def compute_chain_hash(
    *,
    chain_index: int,
    event_id: str,
    raw_id: str,
    raw_sha256: str,
    previous_chain_hash: str,
    stored_at: str,
    transport: str,
    identity_context: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> str:
    """
    Calculate one tamper-evident hash-chain link.

    This is deliberately distinct from:
      - event identity
      - raw SHA-256

    Chain:
        H0 = GENESIS_CHAIN_HASH
        Hn = SHA256(
            domain_separator
            + canonical_record_material
        )
    """

    if chain_index < 1:
        raise ValueError(
            "chain_index must be >= 1"
        )

    raw_sha256 = _validate_sha256(
        raw_sha256,
        field_name="raw_sha256",
    )

    previous_chain_hash = _validate_sha256(
        previous_chain_hash,
        field_name="previous_chain_hash",
    )

    material = {
        "version": TRACEABILITY_VERSION,
        "chain_index": chain_index,
        "event_id": event_id,
        "raw_id": raw_id,
        "raw_sha256": raw_sha256,
        "previous_chain_hash": previous_chain_hash,
        "stored_at": stored_at,
        "transport": transport,
        "identity_context": dict(
            identity_context
        ),
        "metadata": dict(
            metadata
        ),
    }

    return hashlib.sha256(
        b"AEGISGUARD-ULPF-HASH-CHAIN-V1\x00"
        + _canonical_json_bytes(material)
    ).hexdigest()