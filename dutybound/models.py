from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Outcome(StrEnum):
    CLEAR = "CLEAR"
    AMBER = "AMBER"
    RED = "RED"
    INCOMPLETE = "INCOMPLETE"


class EffectKind(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"


@dataclass(frozen=True)
class SnapshotEntry:
    entry_type: str
    sha256: str | None
    size: int
    mode: int
    symlink_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_type": self.entry_type,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "symlink_target": self.symlink_target,
        }

    def rename_fingerprint(self) -> tuple[str, str] | None:
        if self.entry_type == "file" and self.sha256 and self.size > 0:
            return ("file", self.sha256)
        if self.entry_type == "symlink" and self.symlink_target is not None:
            return ("symlink", self.symlink_target)
        return None


@dataclass
class Effect:
    kind: EffectKind
    path: str
    previous_path: str | None = None
    before: SnapshotEntry | None = None
    after: SnapshotEntry | None = None
    violations: list[str] = field(default_factory=list)

    @property
    def out_of_scope(self) -> bool:
        return bool(self.violations)

    def to_record(self) -> dict[str, Any]:
        return {
            "effect_type": self.kind.value,
            "path": self.path,
            "previous_path": self.previous_path,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "source": "observed",
            "out_of_scope": self.out_of_scope,
            "violations": list(self.violations),
        }


@dataclass(frozen=True)
class Alert:
    level: str
    code: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }


@dataclass
class RunResult:
    session_id: str
    outcome: Outcome
    process_exit_code: int | None
    started_at: str
    ended_at: str
    duration_ms: int
    effects: list[Effect]
    alerts: list[Alert]
    blind_spots: list[str]
    report_path: Path
    ledger_head: str | None
    error: str | None = None
    stdout_captured: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def cli_exit_code(self) -> int:
        return {
            Outcome.CLEAR: 0,
            Outcome.AMBER: 2,
            Outcome.RED: 3,
            Outcome.INCOMPLETE: 4,
        }[self.outcome]

