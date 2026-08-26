import json

from pathlib import Path

import pytest

from aegisguard_ulpf.parsing.semantic_packs.loader import (
    load_semantic_pack,
)

from aegisguard_ulpf.parsing.semantic_packs.signing import (
    verify_semantic_pack_signature,
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

TRUSTED_KEYS_PATH = (
    PROJECT_ROOT
    / "src"
    / "aegisguard_ulpf"
    / "parsing"
    / "semantic_packs"
    / "trusted_keys"
)


def test_signed_pack_loads_and_verifies():
    pack = load_semantic_pack(
        PACK_PATH
    )

    assert (
        verify_semantic_pack_signature(
            pack
        )
        is True
    )


def test_pack_is_ed25519_signed():
    pack = load_semantic_pack(
        PACK_PATH
    )

    signature = (
        pack.manifest.signature
    )

    assert signature.status == "signed"
    assert signature.algorithm == "ed25519"
    assert signature.key_id == (
        "aegisguard-dev-v3"
    )

    assert signature.value


def test_existing_v1_and_v2_trust_anchors_are_unchanged():
    assert (
        TRUSTED_KEYS_PATH / "aegisguard-dev-v1.pem"
    ).read_text(encoding="utf-8") == (
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAX9Y8KeJb4TXDPFA9E7deqmbtbZvO9G0xtP4tJHhOgx4=\n"
        "-----END PUBLIC KEY-----\n"
    )
    assert (
        TRUSTED_KEYS_PATH / "aegisguard-dev-v2.pem"
    ).read_text(encoding="utf-8") == (
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEA+Apsmx6otyJ8HuJuJVHqvbpQcT4lj58kMtE8aRbIN7Y=\n"
        "-----END PUBLIC KEY-----\n"
    )


def test_tampered_pack_is_rejected(
    tmp_path,
):
    payload = json.loads(
        PACK_PATH.read_text(
            encoding="utf-8"
        )
    )

    # Change valid semantic data after signing.
    payload[
        "semantics"
    ][
        "classification"
    ][
        "category"
    ] = "TAMPERED"

    tampered_path = (
        tmp_path
        / "tampered_pack.json"
    )

    tampered_path.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="signature",
    ):
        load_semantic_pack(
            tampered_path
        )


def test_unknown_trusted_key_is_rejected(
    tmp_path,
):
    payload = json.loads(
        PACK_PATH.read_text(
            encoding="utf-8"
        )
    )

    payload[
        "manifest"
    ][
        "signature"
    ][
        "key_id"
    ] = "not-a-trusted-key"

    altered_path = (
        tmp_path
        / "unknown_key_pack.json"
    )

    altered_path.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Trusted Semantic Pack key",
    ):
        load_semantic_pack(
            altered_path
        )


def test_unsigned_pack_is_rejected(
    tmp_path,
):
    payload = json.loads(
        PACK_PATH.read_text(
            encoding="utf-8"
        )
    )

    payload[
        "manifest"
    ][
        "signature"
    ] = {
        "status": "unsigned",
        "algorithm": None,
        "key_id": None,
        "value": None,
    }

    unsigned_path = (
        tmp_path
        / "unsigned_pack.json"
    )

    unsigned_path.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="not digitally signed",
    ):
        load_semantic_pack(
            unsigned_path
        )
