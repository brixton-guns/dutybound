from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


GENESIS_HASH = "0" * 64


class LedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    record_count: int
    head_hash: str
    open_sessions: tuple[str, ...]
    error: str | None = None


def _canonical_bytes(record_without_hash: dict[str, Any]) -> bytes:
    return json.dumps(
        record_without_hash,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _record_hash(record_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(record_without_hash)).hexdigest()


def _encoded_line(record: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if not raw_line.endswith(b"\n"):
                    raise LedgerError(
                        f"ledger line {line_number} is not newline-terminated"
                    )
                try:
                    record = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise LedgerError(
                        f"ledger line {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(record, dict):
                    raise LedgerError(
                        f"ledger line {line_number} is not a JSON object"
                    )
                records.append(record)
    except OSError as exc:
        raise LedgerError(f"cannot read ledger: {path}") from exc
    return records


def verify_ledger(path: Path) -> VerificationResult:
    try:
        records = read_records(path)
    except LedgerError as exc:
        return VerificationResult(
            valid=False,
            record_count=0,
            head_hash=GENESIS_HASH,
            open_sessions=(),
            error=str(exc),
        )

    expected_previous = GENESIS_HASH
    open_sessions: dict[str, int] = {}
    for index, record in enumerate(records, start=1):
        stored_hash = record.get("record_hash")
        if not isinstance(stored_hash, str):
            return VerificationResult(
                valid=False,
                record_count=index - 1,
                head_hash=expected_previous,
                open_sessions=tuple(open_sessions),
                error=f"ledger record {index} has no record_hash",
            )
        payload = dict(record)
        payload.pop("record_hash", None)
        if payload.get("prev_hash") != expected_previous:
            return VerificationResult(
                valid=False,
                record_count=index - 1,
                head_hash=expected_previous,
                open_sessions=tuple(open_sessions),
                error=f"ledger record {index} has an invalid prev_hash",
            )
        computed_hash = _record_hash(payload)
        if stored_hash != computed_hash:
            return VerificationResult(
                valid=False,
                record_count=index - 1,
                head_hash=expected_previous,
                open_sessions=tuple(open_sessions),
                error=f"ledger record {index} has an invalid record_hash",
            )

        record_type = payload.get("record_type")
        session_id = payload.get("session_id")
        if not isinstance(session_id, str):
            return VerificationResult(
                valid=False,
                record_count=index - 1,
                head_hash=expected_previous,
                open_sessions=tuple(open_sessions),
                error=f"ledger record {index} has no session_id",
            )
        if record_type == "session_started":
            if session_id in open_sessions:
                return VerificationResult(
                    valid=False,
                    record_count=index - 1,
                    head_hash=expected_previous,
                    open_sessions=tuple(open_sessions),
                    error=f"session {session_id} starts more than once",
                )
            open_sessions[session_id] = index
        elif record_type == "effect_observed":
            if session_id not in open_sessions:
                return VerificationResult(
                    valid=False,
                    record_count=index - 1,
                    head_hash=expected_previous,
                    open_sessions=tuple(open_sessions),
                    error=f"effect for session {session_id} has no open session",
                )
        elif record_type == "session_ended":
            if session_id not in open_sessions:
                return VerificationResult(
                    valid=False,
                    record_count=index - 1,
                    head_hash=expected_previous,
                    open_sessions=tuple(open_sessions),
                    error=f"session {session_id} ends without a start",
                )
            del open_sessions[session_id]
        else:
            return VerificationResult(
                valid=False,
                record_count=index - 1,
                head_hash=expected_previous,
                open_sessions=tuple(open_sessions),
                error=f"ledger record {index} has unknown record_type {record_type!r}",
            )
        expected_previous = stored_hash

    return VerificationResult(
        valid=True,
        record_count=len(records),
        head_hash=expected_previous,
        open_sessions=tuple(open_sessions),
    )


def append_records(
    path: Path, records: Iterable[dict[str, Any]]
) -> tuple[list[dict[str, Any]], str]:
    verification = verify_ledger(path)
    if not verification.valid:
        raise LedgerError(verification.error or "ledger verification failed")

    previous_hash = verification.head_hash
    sealed_records: list[dict[str, Any]] = []
    for source_record in records:
        if "record_hash" in source_record or "prev_hash" in source_record:
            raise LedgerError("source records must not provide hash fields")
        payload = dict(source_record)
        payload["prev_hash"] = previous_hash
        current_hash = _record_hash(payload)
        sealed = dict(payload)
        sealed["record_hash"] = current_hash
        sealed_records.append(sealed)
        previous_hash = current_hash

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "ab", closefd=True) as stream:
            for record in sealed_records:
                stream.write(_encoded_line(record))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except OSError as exc:
        raise LedgerError(f"cannot append to ledger: {path}") from exc
    return sealed_records, previous_hash


def records_by_session(path: Path) -> dict[str, list[dict[str, Any]]]:
    sessions: dict[str, list[dict[str, Any]]] = {}
    for record in read_records(path):
        session_id = record.get("session_id")
        if isinstance(session_id, str):
            sessions.setdefault(session_id, []).append(record)
    return sessions

