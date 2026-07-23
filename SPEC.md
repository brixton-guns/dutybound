# DUTYBOUND

## Local Oversight for AI Agent Sessions — Specification v0.2

**July 2026 · draft for implementation review · MIT License**

> The watch does not end.

---

## 0. One question

*Do you know what your AI agents changed last night?*

Dutybound exists to answer that question every morning with a document that
can be inspected and a ledger that can be verified.

The exact M0 claim is narrower than the question: Dutybound reports observable
net filesystem effects inside one selected workspace. It does not claim to
reconstruct every action performed by a process.

## 1. The problem

AI agents now exercise real authority over filesystems, repositories,
documents, and configurations. They are often treated as tools, but a tool
does not choose its next action. An agent does.

Any serious operations function must answer three questions:

1. **What was the process authorized to do?**
2. **What evidence shows what changed?**
3. **What needs the owner's attention?**

Agent stacks usually answer a different question: what does the agent say it
did? Self-reported actions are useful, but they are not independent evidence.

Dutybound combines written authority, independent workspace observation, and
a short human briefing.

## 2. Design lineage

Dutybound replaces several retired experiments in agent logging, delegated
authority, and operational monitoring. The old repositories are not restored.
The design starts again from the smallest useful proof.

The project language is English throughout: product names, commands,
configuration fields, states, effects, alerts, reports, and source identifiers.

## 3. The three layers

| Layer | Question | M0 artifact |
|---|---|---|
| **Authority** | What was the process authorized to do? | `dutybound.yaml` |
| **Evidence** | What changed in the observed workspace? | snapshots and `ledger.jsonl` |
| **Briefing** | What needs attention? | `report.md` and exit code |

The evidence trust order is:

1. independently observed workspace state;
2. process exit status;
3. optional process-declared receipts in a later milestone.

A process declaration is never treated as sufficient evidence by itself.

## 4. Non-goals

- **No probabilistic guardrail.** M0 uses no model to decide whether an effect
  appears dangerous.
- **No platform.** M0 is a local command-line tool with no server, account,
  database, or network dependency.
- **No runtime prevention.** M0 detects and reports after the process ends.
- **No complete activity reconstruction.** Two snapshots produce net effects,
  not an ordered history of operations.
- **No compliance certificate.** Dutybound may produce useful operational
  evidence; it does not certify legal or regulatory compliance.
- **No sandbox.** The child process inherits the permissions of the user who
  launched Dutybound.

## 5. Authority

### 5.1 Authorization document

Authority is written before the session in a strict YAML document:

```yaml
version: 1

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
    expires_at: "2026-08-15T20:00:00+02:00"
  status: ACTIVE

observation:
  exclude: []
```

Unknown fields are errors. Deny rules always override allow rules.

### 5.2 Objective semantics

`objective` is normative for the human owner and appears in the session
report. M0 does not decide whether a filesystem effect genuinely served the
objective. That decision would require semantic judgment and would contradict
the deterministic M0 claim.

### 5.3 Path semantics

- Paths and patterns are relative to the workspace.
- `/` is the only separator in v0.2.
- Absolute paths, empty segments, `.`, `..`, backslashes, NUL bytes, and
  negated patterns are rejected.
- Unicode is normalized to NFC.
- Matching is case-sensitive.
- `*` matches within one path segment.
- `**` may cross path segments.
- `docs/**` matches `docs` and every descendant.
- `**/*.pem` matches a `.pem` file at any depth, including the workspace root.
- A rename must keep both its previous and new path inside allowed scope.

### 5.4 Operation semantics

M0 recognizes:

`create | modify | delete | rename`

An effect is authorized only when its operation is listed and every relevant
path is allowed and not denied. A mode-only change is `modify`.

### 5.5 Status and expiry

Declared states are:

`ACTIVE | COMPLETED | EXPIRED | REVOKED | EXHAUSTED`

M0 launches a process only when status is `ACTIVE` and `expires_at` is later
than the session start. Otherwise the run is rejected with `RED` and exit code
`3`.

In M0, `expires_at` is the latest permitted **session start**. M0 does not stop
a process whose authorization expires while it is already running. Runtime
expiry enforcement belongs to M1.

`max_effects` is a per-session maximum over observable net effects. If the
limit is exceeded, the whole session is `RED`. M0 does not pretend to know
which effects occurred first.

Dutybound never rewrites the authorization document automatically.

### 5.6 Legal analogy, not legal identity

The structure resembles familiar concepts of limited authority, excess of
authority, accounting, revocation, and expiry. This is an operational analogy.
An AI agent is not declared to be a legal contracting party or a civil-law
agent merely because Dutybound uses an authorization document.

## 6. Evidence

### 6.1 Session flow

`dutybound run -- <process command>` performs:

1. workspace and control-directory validation;
2. ledger verification and exclusive workspace lock;
3. authorization parsing and preflight;
4. sortable session ID creation;
5. append of `session_started` before the child process;
6. initial snapshot;
7. direct process execution without a shell;
8. final snapshot;
9. deterministic snapshot comparison;
10. authorization evaluation;
11. append of observed effects and `session_ended`;
12. ledger verification material and session report generation.

### 6.2 Snapshot model

For regular files:

- SHA-256 content digest;
- byte size;
- POSIX permission bits.

For symbolic links:

- textual target;
- link size;
- link permission bits where exposed.

For directories:

- existence;
- POSIX permission bits.

For other special entries:

- type marker;
- size and permission metadata only.

Symlinks are not followed. File metadata is checked before and after hashing.
If a file changes while it is being hashed, the snapshot fails and the session
becomes `INCOMPLETE`.

M0 does not compare owner, group, ACLs, extended attributes, timestamps, device
contents, or socket and pipe contents.

### 6.3 Observation exclusions

`.dutybound/**` is always excluded because it contains Dutybound's own runtime
effects. Additional exclusions may be declared under `observation.exclude`.

Every configured exclusion is printed under **Blind Spots**. Excluding a denied
path makes that path unobservable; Dutybound does not describe such a path as
protected.

### 6.4 Net-effect semantics

The snapshot comparison produces net effects:

- an entry created and removed within one session is invisible;
- record order is serialization order, not action chronology;
- one effect is not proof of one operation;
- external and concurrent effects cannot be attributed reliably;
- the event timestamp is observation/recording time, not action time.

Dutybound records only what its evidence supports.

### 6.5 Rename inference

A rename is inferred only when one deleted entry and one created entry share a
unique, non-empty content fingerprint. Ambiguous duplicate content, empty
files, and directories remain `delete` plus `create`.

## 7. Ledger

### 7.1 Location and records

`.dutybound/ledger.jsonl` contains three record types:

- `session_started`;
- `effect_observed`;
- `session_ended`.

A start record is appended and flushed before the child process launches. This
allows an interrupted watch to remain visible as an open session.

### 7.2 Hash chain

Each record contains:

- `prev_hash`: the previous record's hash;
- `record_hash`: SHA-256 over canonical JSON for the current record, excluding
  `record_hash` itself.

Canonical JSON uses sorted keys, UTF-8, ASCII escaping, and compact separators.
The genesis previous hash is 64 zeroes.

`dutybound verify` detects invalid JSON, partial final lines, record edits,
broken links, reordering, invalid session lifecycle, and open sessions.

### 7.3 Exact integrity claim

The chain demonstrates **local internal consistency**. It is not independently
tamper-evident against an actor able to rewrite the entire ledger and recompute
all hashes. M2 may sign reports or anchor chain heads outside the workspace.

The term “append-only” describes Dutybound's write behavior, not an operating
system guarantee.

### 7.4 Data minimization

- Raw command arguments are not stored. Dutybound records the executable name
  and a digest of the argument vector.
- stdout and stderr are inherited and not persisted by default.
- Explicit output capture is bounded per stream.
- File contents are never copied into the ledger.
- Paths, objectives, actor labels, and content hashes may still be sensitive;
  the ledger is not automatically safe for public sharing.

## 8. Briefing

### 8.1 Deterministic outcomes

| Outcome | Trigger |
|---|---|
| `CLEAR` | process exit `0`, complete evidence, no authority breach |
| `AMBER` | operational anomaly such as a non-zero process exit |
| `RED` | denied/out-of-scope path, disallowed operation, effect-limit breach, or rejected run |
| `INCOMPLETE` | snapshot, process launch, interruption, or ledger-finalization failure |

Precedence:

`INCOMPLETE → RED → AMBER → CLEAR`

### 8.2 Exit codes

| Code | Meaning |
|---:|---|
| `0` | `CLEAR` |
| `2` | `AMBER` |
| `3` | `RED` |
| `4` | `INCOMPLETE` |
| `64` | invalid usage or authorization document |

The child process exit code is retained in the ledger and report. Dutybound
does not forward it as the wrapper exit code.

### 8.3 Session report

Every started and finalized session writes:

`.dutybound/sessions/<ULID>/report.md`

Sections:

1. session;
2. authority;
3. observed effects;
4. alerts;
5. blind spots;
6. integrity;
7. incomplete evidence, when applicable.

The report is the two-minute briefing. The ledger remains the line-by-line
record.

### 8.4 Weekly briefing

`dutybound report --week` summarizes completed sessions in the current ISO
week by outcome and effect count.

## 9. Interface

```text
dutybound init
dutybound run -- <process command>
dutybound status
dutybound report [--session SESSION_ID]
dutybound report --week
dutybound verify
```

`--workspace PATH` selects the observed workspace.

## 10. Architecture

### 10.1 Principles

- local and offline;
- one workspace per active session;
- Python 3.11 or newer;
- standard library plus PyYAML;
- ordinary files instead of a database;
- exclusive POSIX file lock;
- no child shell;
- no model dependency;
- no cooperation required from the observed process.

### 10.2 Runtime structure

```text
.dutybound/
  ledger.jsonl
  run.lock
  sessions/
    <ULID>/
      report.md
      receipt.json
      stdout.log
      stderr.log
  reports/
    week-YYYY-Www.md
```

The output files exist only when capture was explicitly enabled.

## 11. M0 acceptance proof

The required demo:

1. authorization objective: update documentation;
2. allowed paths: `docs/**` and `README.md`;
3. denied path: `.env`;
4. allowed operations: `create` and `modify`;
5. the process creates or modifies `.env`;
6. Dutybound exits with `3`;
7. the report contains:

```text
RED · AUTHORITY_BREACH — ".env"
```

M0 is complete when this proof works from a clean installation and its
limitations remain visible in the same report.

## 12. Regulatory context

This section is informational, not legal advice.

The EU AI Act contains requirements concerning automatic event logging for
certain high-risk systems (Article 12), human oversight (Article 14), and
specific duties for deployers of high-risk systems (Article 26). Dutybound may
contribute operational evidence relevant to some governance processes, but its
workspace-effect ledger is not equivalent to the internal system logs required
by the Act, and post-session M0 is not runtime human oversight.

The Act is generally applicable from 2 August 2026 with exceptions. Governance
rules and general-purpose AI model obligations already applied from 2 August
2025. Following the 2026 simplification regulation, high-risk rules have later
application dates: 2 December 2027 for the relevant stand-alone systems and
2 August 2028 for high-risk systems embedded in regulated products.

Primary references:

- [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [European Commission AI Act timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [Council adoption of the 2026 simplification regulation](https://www.consilium.europa.eu/en/press/press-releases/2026/06/29/artificial-intelligence-council-gives-final-green-light-to-simplify-and-streamline-rules/)

Dutybound does not claim conformity, certification, or a one-to-one mapping
between its artifacts and legal obligations.

## 13. Declared limitations

- The declared actor is a label, not an authenticated identity.
- The child process can access `.dutybound` with the launching user's
  permissions; M0 is not an adversarial sandbox.
- Complete-ledger rewriting is not detectable without an external anchor.
- Effects outside the workspace are invisible.
- Network, API, database, remote repository, keychain, process, and system
  effects are invisible.
- Existing symlinks may lead to external writes that M0 cannot observe.
- Concurrent processes create an attribution problem.
- Snapshot traversal is not atomic.
- Net effects hide transient operations.
- Rename inference is intentionally conservative.
- Paths and objectives may contain sensitive information.
- M0 is POSIX-only. Windows behavior is not guaranteed.

Each applicable limitation appears in the session report under **Blind Spots**
or **Integrity**.

## 14. Roadmap

### M1 — Runtime Watch

- continuous filesystem observation;
- runtime deny enforcement;
- expiry and duration enforcement;
- process-declared receipts through hooks or MCP;
- comparison of declared actions with observed effects;
- reversible-effect compensation with explicit owner approval.

### M2 — Multiple Workspaces

- one briefing across multiple workspaces and processes;
- authenticated actors;
- signed session reports;
- externally anchored ledger heads;
- retention and export policy;
- audit-oriented bundle export.

### Never

Dutybound will not turn a model-generated risk score into an authority
decision. Deterministic boundaries remain deterministic.

## 15. The name

**Dutybound** means obliged by an assigned duty. It also carries the project's
central idea inside the word: a process acts under a duty and within bounds.

The project was shaped by twenty-eight years of real shifts in a private
security operations center: alarms, logs, handovers, and reports read by real
owners.

That operations center is gone.

The watch does not end.

---

**Dutybound — Specification v0.2 · July 2026**

