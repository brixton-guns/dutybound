from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence

from dutybound.diff import compare_snapshots
from dutybound.ids import new_ulid
from dutybound.ledger import (
    LedgerError,
    append_records,
    verify_ledger,
)
from dutybound.models import Alert, Outcome, RunResult
from dutybound.policy import Authorization, evaluate_effect
from dutybound.report import write_session_report
from dutybound.snapshot import INTERNAL_EXCLUDE, SnapshotError, take_snapshot


class SessionError(RuntimeError):
    pass


class RunRejected(SessionError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    interrupted: bool
    stdout_truncated: bool
    stderr_truncated: bool


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def workspace_lock(control_directory: Path) -> Iterator[None]:
    control_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(control_directory, 0o700)
    lock_path = control_directory / "run.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    stream = os.fdopen(descriptor, "a+", encoding="utf-8", closefd=True)
    try:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SessionError("another Dutybound session is active") from exc
        stream.seek(0)
        stream.truncate()
        stream.write(str(os.getpid()))
        stream.flush()
        os.fsync(stream.fileno())
        yield
    finally:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


def _command_digest(command: Sequence[str]) -> str:
    digest = hashlib.sha256()
    for index, argument in enumerate(command):
        if index:
            digest.update(b"\x00")
        digest.update(os.fsencode(argument))
    return digest.hexdigest()


def _drain_pipe(
    source: BinaryIO,
    destination: Path,
    byte_limit: int,
    state: dict[str, bool],
    key: str,
) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    written = 0
    with os.fdopen(descriptor, "wb", closefd=True) as target:
        while chunk := source.read(64 * 1024):
            remaining = max(0, byte_limit - written)
            if remaining:
                selected = chunk[:remaining]
                target.write(selected)
                written += len(selected)
            if len(chunk) > remaining:
                state[key] = True
        target.flush()
        os.fsync(target.fileno())
    source.close()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def execute_process(
    command: Sequence[str],
    workspace: Path,
    session_directory: Path,
    *,
    capture_output: bool,
    output_limit_bytes: int,
) -> ProcessResult:
    if output_limit_bytes < 1:
        raise SessionError("output_limit_bytes must be at least 1")

    state = {"stdout": False, "stderr": False}
    popen_kwargs: dict[str, object] = {
        "cwd": workspace,
        "shell": False,
    }
    if capture_output:
        popen_kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        process = subprocess.Popen(list(command), **popen_kwargs)
    except OSError as exc:
        raise SessionError(f"cannot start process: {exc}") from exc

    threads: list[threading.Thread] = []
    if capture_output:
        assert process.stdout is not None
        assert process.stderr is not None
        threads = [
            threading.Thread(
                target=_drain_pipe,
                args=(
                    process.stdout,
                    session_directory / "stdout.log",
                    output_limit_bytes,
                    state,
                    "stdout",
                ),
                daemon=True,
            ),
            threading.Thread(
                target=_drain_pipe,
                args=(
                    process.stderr,
                    session_directory / "stderr.log",
                    output_limit_bytes,
                    state,
                    "stderr",
                ),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()

    interrupted = False
    try:
        exit_code = process.wait()
    except KeyboardInterrupt:
        interrupted = True
        _stop_process(process)
        exit_code = process.returncode
    finally:
        for thread in threads:
            thread.join()

    return ProcessResult(
        exit_code=exit_code,
        interrupted=interrupted,
        stdout_truncated=state["stdout"],
        stderr_truncated=state["stderr"],
    )


def _blind_spots(authorization: Authorization) -> list[str]:
    blind_spots = [
        f"Tool-owned state is excluded from observation: `{INTERNAL_EXCLUDE}`.",
        "The child process inherits the launching user's permissions and may "
        "modify tool-owned state; M0 is not an adversarial sandbox.",
    ]
    blind_spots.extend(
        f"Configured observation exclusion: `{pattern}`."
        for pattern in authorization.observation_exclude
    )
    blind_spots.extend(
        [
            "Filesystem effects outside the selected workspace are not observed.",
            "Network, API, database, remote repository, process, keychain, and "
            "system-configuration effects are not observed.",
            "Symlink targets are recorded but not followed; writes through an "
            "existing symlink may affect an unobserved external target.",
            "Changes created and reversed within the session leave no net effect.",
            "Concurrent changes by other processes cannot be attributed reliably.",
            "Special-file contents, ownership, groups, ACLs, and extended "
            "attributes are not compared.",
        ]
    )
    return blind_spots


def _write_receipt(path: Path, session_id: str, ledger_head: str) -> None:
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "ledger_head": ledger_head,
        "generated_at": isoformat_utc(utc_now()),
        "integrity_claim": "local-consistency-only",
    }
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
        json.dump(payload, stream, ensure_ascii=True, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_session(
    workspace: Path,
    authorization: Authorization,
    command: Sequence[str],
    *,
    capture_output: bool = False,
    output_limit_bytes: int = 1_048_576,
) -> RunResult:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise SessionError(f"workspace is not a directory: {workspace}")
    if not command:
        raise SessionError("no process command was provided")

    control_directory = workspace / ".dutybound"
    ledger_path = control_directory / "ledger.jsonl"

    with workspace_lock(control_directory):
        initial_verification = verify_ledger(ledger_path)
        if not initial_verification.valid:
            raise SessionError(
                "ledger verification failed before session start: "
                f"{initial_verification.error}"
            )

        started = utc_now()
        preflight_error = authorization.preflight_error(started)
        if preflight_error:
            raise RunRejected(preflight_error)

        session_id = new_ulid()
        session_directory = control_directory / "sessions" / session_id
        session_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(session_directory, 0o700)
        report_path = session_directory / "report.md"

        started_at = isoformat_utc(started)
        executable_name = Path(command[0]).name
        start_record = {
            "schema_version": 1,
            "record_type": "session_started",
            "session_id": session_id,
            "sequence": 0,
            "recorded_at": started_at,
            "workspace": str(workspace),
            "authorization_id": authorization.authorization_id,
            "authorization_sha256": authorization.source_sha256,
            "declared_actor": authorization.declared_actor,
            "executable_name": executable_name,
            "command_sha256": _command_digest(command),
            "output_capture": capture_output,
        }
        try:
            _, ledger_head = append_records(ledger_path, [start_record])
        except LedgerError as exc:
            raise SessionError(str(exc)) from exc

        effects = []
        alerts: list[Alert] = []
        process_result: ProcessResult | None = None
        incomplete_error: str | None = None
        monotonic_start = time.monotonic()

        try:
            initial_snapshot = take_snapshot(
                workspace, authorization.observation_exclude
            )
        except SnapshotError as exc:
            initial_snapshot = None
            incomplete_error = f"Initial snapshot failed: {exc}"

        if initial_snapshot is not None:
            try:
                process_result = execute_process(
                    command,
                    workspace,
                    session_directory,
                    capture_output=capture_output,
                    output_limit_bytes=output_limit_bytes,
                )
            except SessionError as exc:
                incomplete_error = str(exc)

        final_snapshot = None
        if initial_snapshot is not None:
            try:
                final_snapshot = take_snapshot(
                    workspace, authorization.observation_exclude
                )
            except SnapshotError as exc:
                incomplete_error = f"Final snapshot failed: {exc}"

        if initial_snapshot is not None and final_snapshot is not None:
            effects = compare_snapshots(initial_snapshot, final_snapshot)
            for effect in effects:
                evaluate_effect(effect, authorization)
                if effect.out_of_scope:
                    alerts.append(
                        Alert(
                            level="RED",
                            code="AUTHORITY_BREACH",
                            message="; ".join(effect.violations),
                            path=effect.path,
                        )
                    )

        if len(effects) > authorization.max_effects:
            alerts.append(
                Alert(
                    level="RED",
                    code="EFFECT_LIMIT_EXCEEDED",
                    message=(
                        f"Observed {len(effects)} net effects; authorization "
                        f"limit is {authorization.max_effects}. The breach "
                        "applies to the session as a whole because M0 does not "
                        "know effect chronology."
                    ),
                )
            )

        if process_result is not None and process_result.interrupted:
            incomplete_error = "The process was interrupted before normal completion."
        elif process_result is not None and process_result.exit_code != 0:
            alerts.append(
                Alert(
                    level="AMBER",
                    code="PROCESS_EXIT_NONZERO",
                    message=(
                        f"The observed process exited with code "
                        f"{process_result.exit_code}."
                    ),
                )
            )

        if incomplete_error:
            outcome = Outcome.INCOMPLETE
        elif any(alert.level == "RED" for alert in alerts):
            outcome = Outcome.RED
        elif alerts:
            outcome = Outcome.AMBER
        else:
            outcome = Outcome.CLEAR

        ended = utc_now()
        ended_at = isoformat_utc(ended)
        duration_ms = int((time.monotonic() - monotonic_start) * 1000)
        final_records = []
        for sequence, effect in enumerate(effects, start=1):
            final_records.append(
                {
                    "schema_version": 1,
                    "record_type": "effect_observed",
                    "session_id": session_id,
                    "sequence": sequence,
                    "recorded_at": ended_at,
                    **effect.to_record(),
                }
            )
        final_records.append(
            {
                "schema_version": 1,
                "record_type": "session_ended",
                "session_id": session_id,
                "sequence": len(effects) + 1,
                "recorded_at": ended_at,
                "outcome": outcome.value,
                "process_exit_code": (
                    process_result.exit_code if process_result is not None else None
                ),
                "duration_ms": duration_ms,
                "effect_count": len(effects),
                "alert_count": len(alerts),
                "incomplete_reason": incomplete_error,
            }
        )

        try:
            _, ledger_head = append_records(ledger_path, final_records)
        except LedgerError as exc:
            outcome = Outcome.INCOMPLETE
            incomplete_error = (
                f"{incomplete_error + ' ' if incomplete_error else ''}"
                f"Final ledger append failed: {exc}"
            )

        result = RunResult(
            session_id=session_id,
            outcome=outcome,
            process_exit_code=(
                process_result.exit_code if process_result is not None else None
            ),
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            effects=effects,
            alerts=alerts,
            blind_spots=_blind_spots(authorization),
            report_path=report_path,
            ledger_head=ledger_head,
            error=incomplete_error,
            stdout_captured=capture_output,
            stdout_truncated=(
                process_result.stdout_truncated
                if process_result is not None
                else False
            ),
            stderr_truncated=(
                process_result.stderr_truncated
                if process_result is not None
                else False
            ),
        )
        write_session_report(result, authorization, workspace)
        if outcome is not Outcome.INCOMPLETE or incomplete_error is None:
            _write_receipt(
                session_directory / "receipt.json",
                session_id,
                ledger_head,
            )
        return result
