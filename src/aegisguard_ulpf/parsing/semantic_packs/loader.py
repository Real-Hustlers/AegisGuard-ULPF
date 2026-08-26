import hashlib
import json

from pathlib import Path

from aegisguard_ulpf.parsing.semantic_packs.models import (
    SemanticPack,
)

from aegisguard_ulpf.parsing.semantic_packs.signing import (
    canonical_pack_bytes,
    verify_semantic_pack_signature,
)


def load_semantic_pack(
    path: Path | str,
    *,
    verify_signature: bool = True,
) -> SemanticPack:
    """
    Load and validate a Semantic Pack.

    Signed packs are verified against the
    AegisGuard trusted-key directory before
    being returned to the runtime.
    """

    pack_path = Path(
        path
    )

    with pack_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        payload = json.load(
            file
        )

    pack = SemanticPack.model_validate(
        payload
    )

    if verify_signature:
        verify_semantic_pack_signature(
            pack
        )

    return pack


def semantic_pack_sha256(
    pack: SemanticPack,
) -> str:
    """
    Deterministic content fingerprint.

    This SHA-256 value is NOT the digital
    signature. Ed25519 handles authentication.
    """

    return hashlib.sha256(
        canonical_pack_bytes(
            pack
        )
    ).hexdigest()