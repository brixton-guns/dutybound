# Dutybound

**Local, deterministic oversight for AI agent workspace sessions.**

> Do you know what your AI agents changed last night?

Dutybound runs any local process between two filesystem snapshots, compares the
observable net effects with a written authorization, appends evidence to a
hash-chained ledger, and produces a short session report.

It does not ask the agent what it did. It observes the selected workspace.

## The model

1. **Authority** — what the process was authorized to change.
2. **Evidence** — what changed between the initial and final snapshots.
3. **Briefing** — what the owner needs to review.

M0 is deliberately small:

- local and offline;
- Python 3.11 or newer;
- standard library plus PyYAML;
- no model-based risk scoring;
- no server, database, or cloud account;
- post-session detection, not runtime prevention.

## Install for development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Thirty-second demo

Create a temporary workspace and a starter authorization:

```bash
mkdir demo
cd demo
dutybound init
```

The starter authorization allows documentation changes and denies `.env`.
Run a process that creates `.env`:

```bash
dutybound run -- python -c \
  'from pathlib import Path; Path(".env").write_text("touched")'
```

Dutybound returns exit code `3` and writes a report containing:

```text
RED · AUTHORITY_BREACH — ".env"
```

The process was not sandboxed or stopped. M0 detected the net effect after the
process ended.

## Authorization

`dutybound.yaml` is strict, versioned YAML:

```yaml
version: 1

authorization:
  id: AUTH-0001
  objective: Update project documentation.
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
    expires_at: "2026-08-15T20:00:00+02:00"
  status: ACTIVE

observation:
  exclude: []
```

The objective is reviewed by a human. M0 automatically evaluates only the
path, operation, status, expiry-at-start, and effect-count rules.

## Commands

```text
dutybound init
dutybound run -- <process command>
dutybound status
dutybound report [--session SESSION_ID]
dutybound report --week
dutybound verify
```

Use `--workspace PATH` on any command to select another workspace.

stdout and stderr are inherited and are not stored by default. Explicit,
bounded capture is available:

```bash
dutybound run --capture-output --output-limit-bytes 1048576 -- command
```

## Outcomes and exit codes

| Exit | Outcome | Meaning |
|---:|---|---|
| `0` | `CLEAR` | Process succeeded and no deterministic rule was breached |
| `2` | `AMBER` | Operational anomaly, currently a non-zero process exit |
| `3` | `RED` | Authorization breach or rejected run |
| `4` | `INCOMPLETE` | Evidence collection or ledger finalization failed |
| `64` | — | Invalid command usage or authorization document |

Precedence is `INCOMPLETE` → `RED` → `AMBER` → `CLEAR`.

## Local state

Dutybound creates:

```text
.dutybound/
  ledger.jsonl
  run.lock
  sessions/
    <ULID>/
      report.md
      receipt.json
      stdout.log      # only with --capture-output
      stderr.log      # only with --capture-output
  reports/
    week-YYYY-Www.md
```

`.dutybound/**` is always excluded from workspace observation.

## Integrity claim

Every ledger record includes the previous record hash and its own hash over
canonical JSON. `dutybound verify` detects malformed records, partial edits,
reordering, deletion inside the chain, and broken session structure.

This proves local internal consistency. It does **not** prove that a privileged
local actor did not rewrite the entire ledger and recompute every hash. A
signature or externally anchored chain head belongs to a later milestone.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Specification

The normative design is in [SPEC.md](SPEC.md).

## License

MIT

