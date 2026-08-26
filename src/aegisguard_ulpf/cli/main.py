from __future__ import annotations

import argparse
from pathlib import Path

from aegisguard_ulpf.traceability.raw_store import (
    RawEvidenceStore,
)


def _verify_command(
    event_id: str,
    *,
    store_path: str,
) -> int:

    store = RawEvidenceStore(
        Path(store_path)
    )

    result = store.verify(
        event_id
    )

    print(
        "Event ID:",
        result["event_id"],
    )

    print(
        "Original event found:",
        "YES"
        if result["original_event_found"]
        else "NO",
    )

    print(
        "Raw SHA-256 verified:",
        "PASS"
        if result["raw_sha256_verified"]
        else "FAIL",
    )

    print(
        "Hash chain verified:",
        "PASS"
        if result["hash_chain_verified"]
        else "FAIL",
    )

    print(
        "Integrity:",
        result["integrity"],
    )

    return (
        0
        if result["integrity"] == "PASS"
        else 1
    )


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="ulpf",
        description=(
            "AegisGuard-ULPF command line interface"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify preserved raw-event integrity",
    )

    verify_parser.add_argument(
        "event_id",
        help="Deterministic ULPF event ID",
    )

    verify_parser.add_argument(
        "--store",
        default="evidence",
        help=(
            "Raw evidence directory "
            "(default: evidence)"
        ),
    )

    return parser


def main() -> int:

    parser = build_parser()

    args = parser.parse_args()

    if args.command == "verify":
        return _verify_command(
            args.event_id,
            store_path=args.store,
        )

    parser.error(
        f"Unsupported command: {args.command}"
    )

    return 2


if __name__ == "__main__":
    raise SystemExit(
        main()
    )