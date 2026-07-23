from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from dutybound import __version__
from dutybound.ledger import LedgerError, records_by_session, verify_ledger
from dutybound.policy import AuthorizationError, load_authorization
from dutybound.report import write_weekly_report
from dutybound.session import (
    RunRejected,
    SessionError,
    run_session,
)


class UsageError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def _workspace(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _authorization_path(workspace: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="dutybound",
        description="Local, deterministic oversight for AI agent sessions.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    init_parser = subparsers.add_parser(
        "init", help="Create a starter authorization file."
    )
    init_parser.add_argument("--workspace", default=".")

    run_parser = subparsers.add_parser(
        "run", help="Run a process inside an observed session."
    )
    run_parser.add_argument("--workspace", default=".")
    run_parser.add_argument("--authorization", default="dutybound.yaml")
    run_parser.add_argument(
        "--capture-output",
        action="store_true",
        help="Persist bounded stdout and stderr files. Disabled by default.",
    )
    run_parser.add_argument(
        "--output-limit-bytes",
        type=int,
        default=1_048_576,
        help="Maximum captured bytes per output stream.",
    )
    run_parser.add_argument("command", nargs=argparse.REMAINDER)

    status_parser = subparsers.add_parser(
        "status", help="Show authorization and ledger status."
    )
    status_parser.add_argument("--workspace", default=".")
    status_parser.add_argument("--authorization", default="dutybound.yaml")

    verify_parser = subparsers.add_parser(
        "verify", help="Verify the local ledger hash chain."
    )
    verify_parser.add_argument("--workspace", default=".")

    report_parser = subparsers.add_parser(
        "report", help="Locate a session report or build a weekly briefing."
    )
    report_parser.add_argument("--workspace", default=".")
    report_parser.add_argument("--session")
    report_parser.add_argument("--week", action="store_true")
    return parser


def _starter_document(expires_at: str) -> str:
    return f"""version: 1

authorization:
  id: AUTH-0001
  objective: >
    Update project documentation without changing credentials,
    repository internals, or executable code.
  declared_actor: codex
  scope:
    allow:
      - "docs/**"
      - "README.md"
    deny:
      - ".git/**"
      - ".env"
      - ".env.*"
      - "**/*.pem"
      - "**/*.key"
  operations:
    allow:
      - create
      - modify
  constraints:
    max_effects: 200
    expires_at: "{expires_at}"
  status: ACTIVE

observation:
  exclude: []
"""


def command_init(args: argparse.Namespace) -> int:
    workspace = _workspace(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    target = workspace / "dutybound.yaml"
    if target.exists():
        raise UsageError(f"authorization file already exists: {target}")
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    target.write_text(
        _starter_document(expires.isoformat().replace("+00:00", "Z")),
        encoding="utf-8",
    )
    control = workspace / ".dutybound"
    control.mkdir(mode=0o700, exist_ok=True)
    print(f"Created authorization: {target}")
    print("Review its objective and scope before running a process.")
    return 0


def _strip_command_separator(command: Sequence[str]) -> list[str]:
    command = list(command)
    if command and command[0] == "--":
        command = command[1:]
    return command


def command_run(args: argparse.Namespace) -> int:
    workspace = _workspace(args.workspace)
    if args.output_limit_bytes < 1:
        raise UsageError("--output-limit-bytes must be at least 1")
    authorization = load_authorization(
        _authorization_path(workspace, args.authorization)
    )
    command = _strip_command_separator(args.command)
    if not command:
        raise UsageError("run requires a process command after --")
    result = run_session(
        workspace,
        authorization,
        command,
        capture_output=args.capture_output,
        output_limit_bytes=args.output_limit_bytes,
    )
    print(
        f"{result.outcome.value} — {len(result.effects)} observed effect(s) — "
        f"session {result.session_id}"
    )
    print(f"Report: {result.report_path}")
    return result.cli_exit_code


def _last_ended_session(
    grouped: dict[str, list[dict[str, object]]]
) -> dict[str, object] | None:
    candidates: list[dict[str, object]] = []
    for session_id, records in grouped.items():
        for record in records:
            if record.get("record_type") == "session_ended":
                candidates.append({**record, "session_id": session_id})
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda record: (
            str(record.get("recorded_at", "")),
            str(record.get("session_id", "")),
        ),
    )


def command_status(args: argparse.Namespace) -> int:
    workspace = _workspace(args.workspace)
    authorization = load_authorization(
        _authorization_path(workspace, args.authorization)
    )
    now = datetime.now(timezone.utc)
    state = authorization.preflight_error(now) or "ready"
    ledger_path = workspace / ".dutybound" / "ledger.jsonl"
    verification = verify_ledger(ledger_path)
    grouped = records_by_session(ledger_path) if verification.valid else {}
    latest = _last_ended_session(grouped)

    print("Dutybound status")
    print(
        f"Authorization: {authorization.authorization_id} "
        f"({authorization.status.value}; {state})"
    )
    if verification.valid:
        print(
            f"Ledger: VERIFIED ({verification.record_count} records; "
            f"head {verification.head_hash})"
        )
    else:
        print(f"Ledger: INVALID ({verification.error})")
    if verification.open_sessions:
        print("Open sessions: " + ", ".join(verification.open_sessions))
    if latest:
        print(
            f"Last session: {latest['session_id']} "
            f"({latest.get('outcome', 'UNKNOWN')})"
        )
    else:
        print("Last session: none")
    return 0 if verification.valid and not verification.open_sessions else 4


def command_verify(args: argparse.Namespace) -> int:
    workspace = _workspace(args.workspace)
    ledger_path = workspace / ".dutybound" / "ledger.jsonl"
    verification = verify_ledger(ledger_path)
    if not verification.valid:
        print(f"INVALID — {verification.error}")
        return 4
    if verification.open_sessions:
        print(
            "INCOMPLETE — internally consistent chain with open session(s): "
            + ", ".join(verification.open_sessions)
        )
        return 4
    print(
        f"VERIFIED — {verification.record_count} records — "
        f"head {verification.head_hash}"
    )
    return 0


def command_report(args: argparse.Namespace) -> int:
    workspace = _workspace(args.workspace)
    control = workspace / ".dutybound"
    ledger_path = control / "ledger.jsonl"
    verification = verify_ledger(ledger_path)
    if not verification.valid:
        raise SessionError(verification.error or "ledger verification failed")
    if args.week and args.session:
        raise UsageError("--week and --session cannot be used together")
    if args.week:
        path = write_weekly_report(
            ledger_path,
            control / "reports",
            datetime.now(timezone.utc),
        )
        print(f"Weekly briefing: {path}")
        return 0

    grouped = records_by_session(ledger_path)
    session_id = args.session
    if session_id is None:
        latest = _last_ended_session(grouped)
        if latest is None:
            raise UsageError("no completed session report exists")
        session_id = str(latest["session_id"])
    if session_id not in grouped:
        raise UsageError(f"unknown session: {session_id}")
    path = control / "sessions" / session_id / "report.md"
    if not path.is_file():
        raise SessionError(f"session report is missing: {path}")
    print(f"Session report: {path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        commands = {
            "init": command_init,
            "run": command_run,
            "status": command_status,
            "verify": command_verify,
            "report": command_report,
        }
        return commands[args.subcommand](args)
    except RunRejected as exc:
        print(f"RED — run rejected: {exc}", file=sys.stderr)
        return 3
    except (UsageError, AuthorizationError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 64
    except (SessionError, LedgerError, OSError) as exc:
        print(f"INCOMPLETE — {exc}", file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print("INCOMPLETE — interrupted", file=sys.stderr)
        return 4
