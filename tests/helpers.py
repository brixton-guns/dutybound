from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


def write_authorization(
    workspace: Path,
    *,
    allow: tuple[str, ...] = ("docs/**", "README.md"),
    deny: tuple[str, ...] = (".env", ".env.*", ".git/**"),
    operations: tuple[str, ...] = ("create", "modify"),
    max_effects: int = 200,
    status: str = "ACTIVE",
    expires_delta: timedelta = timedelta(days=1),
    excludes: tuple[str, ...] = (),
) -> Path:
    expires = datetime.now(timezone.utc) + expires_delta
    lines = [
        "version: 1",
        "",
        "authorization:",
        "  id: AUTH-TEST-0001",
        "  objective: Test the Dutybound M0 implementation.",
        "  declared_actor: test-process",
        "  scope:",
        "    allow:",
    ]
    lines.extend(f'      - "{item}"' for item in allow)
    lines.append("    deny:")
    lines.extend(f'      - "{item}"' for item in deny)
    lines.extend(["  operations:", "    allow:"])
    lines.extend(f"      - {item}" for item in operations)
    lines.extend(
        [
            "  constraints:",
            f"    max_effects: {max_effects}",
            f'    expires_at: "{expires.isoformat()}"',
            f"  status: {status}",
            "",
            "observation:",
            "  exclude:",
        ]
    )
    lines.extend(f'    - "{item}"' for item in excludes)
    path = workspace / "dutybound.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

