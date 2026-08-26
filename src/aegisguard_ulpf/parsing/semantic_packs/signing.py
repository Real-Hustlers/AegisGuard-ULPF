import base64
import copy
import json
import re

from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import (
    InvalidSignature,
)

from cryptography.hazmat.primitives import (
    serialization,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegisguard_ulpf.parsing.semantic_packs.models import (
    SemanticPack,
)


SIGNATURE_ALGORITHM = "ed25519"

DEFAULT_TRUSTED_KEYS_DIR = (
    Path(__file__).resolve().parent
    / "trusted_keys"
)

_KEY_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9._-]+$"
)


def canonical_pack_bytes(
    pack_or_payload: (
        SemanticPack
        | Mapping[str, Any]
    ),
) -> bytes:
    """
    Produce deterministic bytes for signing.

    signature.value is deliberately set to None
    during canonicalization so the signature does
    not recursively sign itself.
    """

    if isinstance(
        pack_or_payload,
        SemanticPack,
    ):
        payload = pack_or_payload.model_dump(
            mode="json"
        )

    else:
        payload = copy.deepcopy(
            dict(pack_or_payload)
        )

    signature = (
        payload["manifest"]["signature"]
    )

    signature["value"] = None

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return canonical.encode(
        "utf-8"
    )


def generate_ed25519_keypair(
    *,
    private_key_path: Path,
    public_key_path: Path,
) -> None:
    """
    Generate one Ed25519 signing key pair.

    The private key must remain outside the
    repository.

    The public key is the runtime trust anchor.
    """

    private_key_path = Path(
        private_key_path
    )

    public_key_path = Path(
        public_key_path
    )

    if private_key_path.exists():
        raise FileExistsError(
            f"Private key already exists: "
            f"{private_key_path}"
        )

    if public_key_path.exists():
        raise FileExistsError(
            f"Public key already exists: "
            f"{public_key_path}"
        )

    private_key_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    public_key_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    private_bytes = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=(
                serialization.PrivateFormat.PKCS8
            ),
            encryption_algorithm=(
                serialization.NoEncryption()
            ),
        )
    )

    public_bytes = (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=(
                serialization.PublicFormat
                .SubjectPublicKeyInfo
            ),
        )
    )

    private_key_path.write_bytes(
        private_bytes
    )

    public_key_path.write_bytes(
        public_bytes
    )


def sign_semantic_pack_file(
    *,
    pack_path: Path,
    private_key_path: Path,
    key_id: str,
) -> SemanticPack:
    """
    Digitally sign a Semantic Pack using Ed25519.

    The pack is first normalized through the
    SemanticPack model. The normalized form is
    what gets signed and later verified.

    The private key is never written into the pack.
    """

    if not _KEY_ID_PATTERN.fullmatch(
        key_id
    ):
        raise ValueError(
            "Invalid Semantic Pack key_id"
        )

    pack_path = Path(
        pack_path
    )

    private_key_path = Path(
        private_key_path
    )

    payload = json.loads(
        pack_path.read_text(
            encoding="utf-8"
        )
    )

    # --------------------------------------------------------
    # Establish signature metadata WITHOUT the signature value.
    # --------------------------------------------------------

    payload[
        "manifest"
    ][
        "signature"
    ] = {
        "status": "signed",
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,

        # Temporary validation placeholder only.
        # canonical_pack_bytes() removes this value
        # before signing.
        "value": "__PENDING_SIGNATURE__",
    }

    # --------------------------------------------------------
    # IMPORTANT:
    # Normalize through Pydantic BEFORE signing.
    #
    # Pydantic may insert default empty mappings/tuples.
    # Signing the raw JSON first would therefore produce
    # different canonical bytes during later verification.
    # --------------------------------------------------------

    normalized_unsigned_pack = (
        SemanticPack.model_validate(
            payload
        )
    )

    bytes_to_sign = (
        canonical_pack_bytes(
            normalized_unsigned_pack
        )
    )

    # --------------------------------------------------------
    # Load private signing key.
    # --------------------------------------------------------

    private_key = (
        serialization.load_pem_private_key(
            private_key_path.read_bytes(),
            password=None,
        )
    )

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise ValueError(
            "Semantic Pack signing key "
            "is not Ed25519"
        )

    # --------------------------------------------------------
    # Sign the exact normalized canonical representation.
    # --------------------------------------------------------

    signature = private_key.sign(
        bytes_to_sign
    )

    encoded_signature = (
        base64.b64encode(
            signature
        ).decode("ascii")
    )

    # --------------------------------------------------------
    # Start from the SAME normalized representation that
    # was signed, then insert only signature.value.
    # --------------------------------------------------------

    signed_payload = (
        normalized_unsigned_pack.model_dump(
            mode="json"
        )
    )

    signed_payload[
        "manifest"
    ][
        "signature"
    ][
        "value"
    ] = encoded_signature

    validated_signed_pack = (
        SemanticPack.model_validate(
            signed_payload
        )
    )

    # --------------------------------------------------------
    # Persist deterministic normalized pack representation.
    # --------------------------------------------------------

    pack_path.write_text(
        json.dumps(
            validated_signed_pack.model_dump(
                mode="json"
            ),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return validated_signed_pack


def verify_semantic_pack_signature(
    pack: SemanticPack,
    *,
    trusted_keys_dir: (
        Path | None
    ) = None,
) -> bool:
    """
    Verify a Semantic Pack's Ed25519 signature
    against a runtime-controlled trusted key.

    The pack cannot supply its own trust anchor.
    """

    signature_metadata = (
        pack.manifest.signature
    )

    if (
        signature_metadata.status
        != "signed"
    ):
        raise ValueError(
            "Semantic Pack is not digitally signed"
        )

    if (
        signature_metadata.algorithm
        != SIGNATURE_ALGORITHM
    ):
        raise ValueError(
            "Unsupported Semantic Pack "
            "signature algorithm"
        )

    key_id = signature_metadata.key_id

    if (
        not key_id
        or not _KEY_ID_PATTERN.fullmatch(
            key_id
        )
    ):
        raise ValueError(
            "Invalid Semantic Pack key_id"
        )

    trusted_directory = (
        Path(trusted_keys_dir)
        if trusted_keys_dir is not None
        else DEFAULT_TRUSTED_KEYS_DIR
    )

    public_key_path = (
        trusted_directory
        / f"{key_id}.pem"
    )

    if not public_key_path.is_file():
        raise ValueError(
            f"Trusted Semantic Pack key "
            f"not found: {key_id}"
        )

    public_key = (
        serialization.load_pem_public_key(
            public_key_path.read_bytes()
        )
    )

    if not isinstance(
        public_key,
        Ed25519PublicKey,
    ):
        raise ValueError(
            "Trusted Semantic Pack key "
            "is not Ed25519"
        )

    try:
        signature_bytes = (
            base64.b64decode(
                signature_metadata.value,
                validate=True,
            )
        )

    except Exception as exc:
        raise ValueError(
            "Semantic Pack signature "
            "is not valid Base64"
        ) from exc

    try:
        public_key.verify(
            signature_bytes,
            canonical_pack_bytes(
                pack
            ),
        )

    except InvalidSignature as exc:
        raise ValueError(
            "Semantic Pack digital "
            "signature verification failed"
        ) from exc

    return True