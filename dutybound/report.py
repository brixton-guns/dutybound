from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from dutybound.ledger import records_by_session
from dutybound.models import RunResult
from dutybound.policy import Authorization


def _inline(value: str) -> str:
    escaped = json.dumps(value, ensure_ascii=True).replace("`", r"\u0060")
    return f"`{escaped}`"


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def write_session_report(
    result: RunResult,
    authorization: Authorization,
    workspace: Path,
) -> None:
    counts = Counter(effect.kind.value for effect in result.effects)
    lines = [
        "# Dutybound Session Report",
        "",
        f"**Outcome:** {result.outcome.value}",
        "",
        "## Session",
        "",
        f"- Session ID: {_inline(result.session_id)}",
        f"- Workspace: {_inline(str(workspace))}",
        f"- Started: {result.started_at}",
        f"- Ended: {result.ended_at}",
        f"- Duration: {result.duration_ms} ms",
        (
            f"- Process exit code: {result.process_exit_code}"
            if result.process_exit_code is not None
            else "- Process exit code: unavailable"
        ),
        "",
        "## Authority",
        "",
        f"- Authorization ID: {_inline(authorization.authorization_id)}",
        f"- Objective: {authorization.objective}",
        f"- Declared actor: {authorization.declared_actor or 'not declared'}",
        f"- Status at session start: {authorization.status.value}",
        f"- Authorization digest: {_inline(authorization.source_sha256)}",
        "",
        "## Observed Effects",
        "",
        f"- Total: {len(result.effects)}",
        f"- Created: {counts['create']}",
        f"- Modified: {counts['modify']}",
        f"- Deleted: {counts['delete']}",
        f"- Renamed: {counts['rename']}",
        "",
    ]
    if result.effects:
        lines.extend(
            [
                "| Effect | Path | Previous path | Verdict |",
                "|---|---|---|---|",
            ]
        )
        for effect in result.effects:
            verdict = "OUT OF SCOPE" if effect.out_of_scope else "AUTHORIZED"
            lines.append(
                "| "
                + " | ".join(
                    [
                        effect.kind.value,
                        _inline(effect.path),
                        _inline(effect.previous_path)
                        if effect.previous_path
                        else "—",
                        verdict,
                    ]
                )
                + " |"
            )
    else:
        lines.append("No net filesystem effects were observed.")

    lines.extend(["", "## Alerts", ""])
    if result.alerts:
        for alert in result.alerts:
            path = f" — {_inline(alert.path)}" if alert.path else ""
            lines.append(
                f"- **{alert.level} · {alert.code}**{path}: {alert.message}"
            )
    else:
        lines.append("No alerts.")

    lines.extend(["", "## Blind Spots", ""])
    lines.extend(f"- {blind_spot}" for blind_spot in result.blind_spots)

    lines.extend(
        [
            "",
            "## Integrity",
            "",
            (
                f"- Ledger head after session: {_inline(result.ledger_head)}"
                if result.ledger_head
                else "- Ledger head after session: unavailable"
            ),
            "- The hash chain proves internal consistency only. Without an "
            "external anchor or signature, it cannot prove that a privileged "
            "local actor did not rewrite the complete ledger.",
        ]
    )
    if result.stdout_captured:
        lines.extend(
            [
                "",
                "## Captured Output",
                "",
                f"- stdout truncated: {'yes' if result.stdout_truncated else 'no'}",
                f"- stderr truncated: {'yes' if result.stderr_truncated else 'no'}",
                "- Output capture was explicitly enabled for this session.",
            ]
        )
    if result.error:
        lines.extend(["", "## Incomplete Evidence", "", result.error])

    lines.extend(
        [
            "",
            "---",
            "",
            "Dutybound records observable net effects. It does not claim to "
            "reconstruct every action performed by the process.",
            "",
        ]
    )
    _write_private_text(result.report_path, "\n".join(lines))


def write_weekly_report(
    ledger_path: Path,
    reports_directory: Path,
    now: datetime,
) -> Path:
    year, week, _ = now.isocalendar()
    path = reports_directory / f"week-{year}-W{week:02d}.md"
    grouped = records_by_session(ledger_path)

    completed: list[dict[str, Any]] = []
    for session_id, records in grouped.items():
        ended = next(
            (
                record
                for record in reversed(records)
                if record.get("record_type") == "session_ended"
            ),
            None,
        )
        if ended is not None:
            completed.append(
                {
                    "session_id": session_id,
                    "ended_at": ended.get("recorded_at", ""),
                    "outcome": ended.get("outcome", "UNKNOWN"),
                    "effect_count": ended.get("effect_count", 0),
                }
            )
    completed.sort(key=lambda item: (item["ended_at"], item["session_id"]))
    week_prefix = f"{year}-W{week:02d}"
    selected = [
        item
        for item in completed
        if _iso_week(item["ended_at"]) == week_prefix
    ]
    outcome_counts = Counter(item["outcome"] for item in selected)
    lines = [
        f"# Dutybound Weekly Briefing — {week_prefix}",
        "",
        f"- Sessions: {len(selected)}",
        f"- CLEAR: {outcome_counts['CLEAR']}",
        f"- AMBER: {outcome_counts['AMBER']}",
        f"- RED: {outcome_counts['RED']}",
        f"- INCOMPLETE: {outcome_counts['INCOMPLETE']}",
        f"- Observed effects: {sum(item['effect_count'] for item in selected)}",
        "",
        "## Sessions",
        "",
    ]
    if selected:
        lines.extend(
            [
                "| Ended | Session | Outcome | Effects |",
                "|---|---|---:|---:|",
            ]
        )
        for item in selected:
            lines.append(
                f"| {item['ended_at']} | {_inline(item['session_id'])} | "
                f"{item['outcome']} | {item['effect_count']} |"
            )
    else:
        lines.append("No completed sessions in this ISO week.")
    lines.append("")
    _write_private_text(path, "\n".join(lines))
    return path


def _iso_week(timestamp: str) -> str | None:
    if not isinstance(timestamp, str):
        return None
    candidate = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    year, week, _ = parsed.isocalendar()
    return f"{year}-W{week:02d}"

