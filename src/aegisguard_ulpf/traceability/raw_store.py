from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisguard_ulpf.traceability.lineage import (
    GENESIS_CHAIN_HASH,
    compute_chain_hash,
    derive_event_id,
    derive_raw_id,
    sha256_bytes,
)


@dataclass(frozen=True)
class EvidenceRecord:
    """
    Metadata describing one preserved raw event.

    Important:
        event_id != raw_sha256 != chain_hash
    """

    version: str

    event_id: str
    raw_id: str
    raw_sha256: str

    chain_index: int
    previous_chain_hash: str
    chain_hash: str

    stored_at: str

    transport: str

    identity_context: dict[str, Any]
    metadata: dict[str, Any]

    blob_file: str

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "EvidenceRecord":
        return cls(
            version=str(
                data["version"]
            ),
            event_id=str(
                data["event_id"]
            ),
            raw_id=str(
                data["raw_id"]
            ),
            raw_sha256=str(
                data["raw_sha256"]
            ),
            chain_index=int(
                data["chain_index"]
            ),
            previous_chain_hash=str(
                data["previous_chain_hash"]
            ),
            chain_hash=str(
                data["chain_hash"]
            ),
            stored_at=str(
                data["stored_at"]
            ),
            transport=str(
                data["transport"]
            ),
            identity_context=dict(
                data.get(
                    "identity_context",
                    {},
                )
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
            ),
            blob_file=str(
                data["blob_file"]
            ),
        )


class RawEvidenceStore:
    """
    Restricted raw evidence storage for AegisGuard-ULPF.

    Layout:

        evidence/
            evidence_manifest.jsonl
            blobs/
                RAW-....bin

    The authoritative raw bytes are stored separately from
    normalized/analytics copies.
    """

    MANIFEST_NAME = "evidence_manifest.jsonl"

    def __init__(
        self,
        root: str | Path,
    ) -> None:
        self.root = Path(root)

        self.blob_directory = (
            self.root
            / "blobs"
        )

        self.manifest_path = (
            self.root
            / self.MANIFEST_NAME
        )

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.blob_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._records = (
            self._load_manifest()
        )

        self._by_event_id = {
            record.event_id: record
            for record in self._records
        }

        self._by_raw_id = {
            record.raw_id: record
            for record in self._records
        }

    @property
    def records(
        self,
    ) -> tuple[EvidenceRecord, ...]:
        return tuple(
            self._records
        )

    def _load_manifest(
        self,
    ) -> list[EvidenceRecord]:

        if not self.manifest_path.exists():
            return []

        records: list[
            EvidenceRecord
        ] = []

        with self.manifest_path.open(
            "r",
            encoding="utf-8",
        ) as handle:

            for line_number, line in enumerate(
                handle,
                start=1,
            ):

                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(
                        line
                    )

                    record = (
                        EvidenceRecord.from_dict(
                            data
                        )
                    )

                except Exception as exc:
                    raise ValueError(
                        "Invalid evidence manifest "
                        f"at line {line_number}"
                    ) from exc

                records.append(
                    record
                )

        return records

    def _blob_path(
        self,
        record: EvidenceRecord,
    ) -> Path:
        return (
            self.root
            / record.blob_file
        )

    def _append_manifest(
        self,
        record: EvidenceRecord,
    ) -> None:

        line = json.dumps(
            record.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

        with self.manifest_path.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as handle:

            handle.write(
                line
                + "\n"
            )

            handle.flush()

            os.fsync(
                handle.fileno()
            )

    def _write_blob(
        self,
        *,
        raw_id: str,
        raw_bytes: bytes,
    ) -> str:

        relative_path = (
            Path("blobs")
            / f"{raw_id}.bin"
        )

        final_path = (
            self.root
            / relative_path
        )

        temporary_path = (
            final_path.with_suffix(
                ".tmp"
            )
        )

        with temporary_path.open(
            "wb"
        ) as handle:

            handle.write(
                raw_bytes
            )

            handle.flush()

            os.fsync(
                handle.fileno()
            )

        os.replace(
            temporary_path,
            final_path,
        )

        return relative_path.as_posix()

    def store(
        self,
        raw_bytes: bytes,
        *,
        identity_context: dict[str, Any],
        transport: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Preserve one authoritative raw event.

        Replay behavior:
            same bytes + same identity_context
            -> same event_id
            -> existing record returned
            -> chain is NOT duplicated
        """

        if not isinstance(
            raw_bytes,
            bytes,
        ):
            raise TypeError(
                "raw_bytes must be bytes"
            )

        if not isinstance(
            identity_context,
            dict,
        ):
            raise TypeError(
                "identity_context must be a dict"
            )

        metadata = dict(
            metadata
            or {}
        )

        raw_sha256 = (
            sha256_bytes(
                raw_bytes
            )
        )

        event_id = (
            derive_event_id(
                raw_sha256=raw_sha256,
                identity_context=(
                    identity_context
                ),
            )
        )

        raw_id = derive_raw_id(
            event_id
        )

        existing = (
            self._by_event_id.get(
                event_id
            )
        )

        if existing is not None:

            if (
                existing.raw_sha256
                != raw_sha256
            ):
                raise ValueError(
                    "Event identity collision: "
                    "existing event has a different "
                    "raw SHA-256 digest"
                )

            return existing

        chain_index = (
            len(self._records)
            + 1
        )

        if self._records:
            previous_chain_hash = (
                self._records[
                    -1
                ].chain_hash
            )
        else:
            previous_chain_hash = (
                GENESIS_CHAIN_HASH
            )

        stored_at = (
            datetime.now(
                timezone.utc
            )
            .isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

        blob_file = (
            Path("blobs")
            / f"{raw_id}.bin"
        ).as_posix()

        chain_hash = (
            compute_chain_hash(
                chain_index=chain_index,
                event_id=event_id,
                raw_id=raw_id,
                raw_sha256=raw_sha256,
                previous_chain_hash=(
                    previous_chain_hash
                ),
                stored_at=stored_at,
                transport=transport,
                identity_context=(
                    identity_context
                ),
                metadata=metadata,
            )
        )

        record = EvidenceRecord(
            version="1",
            event_id=event_id,
            raw_id=raw_id,
            raw_sha256=raw_sha256,
            chain_index=chain_index,
            previous_chain_hash=(
                previous_chain_hash
            ),
            chain_hash=chain_hash,
            stored_at=stored_at,
            transport=transport,
            identity_context=dict(
                identity_context
            ),
            metadata=metadata,
            blob_file=blob_file,
        )

        self._write_blob(
            raw_id=raw_id,
            raw_bytes=raw_bytes,
        )

        self._append_manifest(
            record
        )

        self._records.append(
            record
        )

        self._by_event_id[
            event_id
        ] = record

        self._by_raw_id[
            raw_id
        ] = record

        return record

    def get(
        self,
        event_id: str,
    ) -> EvidenceRecord | None:

        return self._by_event_id.get(
            event_id
        )

    def get_by_raw_id(
        self,
        raw_id: str,
    ) -> EvidenceRecord | None:

        return self._by_raw_id.get(
            raw_id
        )

    def read_raw(
        self,
        event_id: str,
    ) -> bytes:

        record = self.get(
            event_id
        )

        if record is None:
            raise KeyError(
                f"Unknown event_id: {event_id}"
            )

        path = self._blob_path(
            record
        )

        if not path.exists():
            raise FileNotFoundError(
                f"Raw evidence not found: {path}"
            )

        return path.read_bytes()

    def _verify_chain_through(
        self,
        chain_index: int,
    ) -> bool:

        previous_hash = (
            GENESIS_CHAIN_HASH
        )

        for expected_index, record in enumerate(
            self._records,
            start=1,
        ):

            if expected_index > chain_index:
                break

            if (
                record.chain_index
                != expected_index
            ):
                return False

            if (
                record.previous_chain_hash
                != previous_hash
            ):
                return False

            calculated = (
                compute_chain_hash(
                    chain_index=(
                        record.chain_index
                    ),
                    event_id=(
                        record.event_id
                    ),
                    raw_id=(
                        record.raw_id
                    ),
                    raw_sha256=(
                        record.raw_sha256
                    ),
                    previous_chain_hash=(
                        record.previous_chain_hash
                    ),
                    stored_at=(
                        record.stored_at
                    ),
                    transport=(
                        record.transport
                    ),
                    identity_context=(
                        record.identity_context
                    ),
                    metadata=(
                        record.metadata
                    ),
                )
            )

            if (
                calculated
                != record.chain_hash
            ):
                return False

            previous_hash = (
                record.chain_hash
            )

        return True

    def verify(
        self,
        event_id: str,
    ) -> dict[str, Any]:
        """
        Verify raw evidence and hash-chain integrity
        for one event.
        """

        record = self.get(
            event_id
        )

        if record is None:

            return {
                "event_id": event_id,
                "original_event_found": False,
                "raw_sha256_verified": False,
                "hash_chain_verified": False,
                "integrity": "FAIL",
            }

        path = self._blob_path(
            record
        )

        raw_found = (
            path.exists()
            and path.is_file()
        )

        raw_verified = False

        if raw_found:

            current_digest = (
                sha256_bytes(
                    path.read_bytes()
                )
            )

            raw_verified = (
                current_digest
                == record.raw_sha256
            )

        chain_verified = (
            self._verify_chain_through(
                record.chain_index
            )
        )

        integrity_pass = (
            raw_found
            and raw_verified
            and chain_verified
        )

        return {
            "event_id": event_id,
            "raw_id": record.raw_id,
            "original_event_found": (
                raw_found
            ),
            "raw_sha256": (
                record.raw_sha256
            ),
            "raw_sha256_verified": (
                raw_verified
            ),
            "chain_index": (
                record.chain_index
            ),
            "hash_chain_verified": (
                chain_verified
            ),
            "integrity": (
                "PASS"
                if integrity_pass
                else "FAIL"
            ),
        }