from __future__ import annotations

from collections import defaultdict

from dutybound.models import Effect, EffectKind, SnapshotEntry


def compare_snapshots(
    before: dict[str, SnapshotEntry],
    after: dict[str, SnapshotEntry],
) -> list[Effect]:
    before_paths = set(before)
    after_paths = set(after)

    common = before_paths & after_paths
    deleted_paths = before_paths - after_paths
    created_paths = after_paths - before_paths

    effects: list[Effect] = [
        Effect(
            kind=EffectKind.MODIFY,
            path=path,
            before=before[path],
            after=after[path],
        )
        for path in common
        if before[path] != after[path]
    ]

    deleted_by_fingerprint: dict[tuple[str, str], list[str]] = defaultdict(list)
    created_by_fingerprint: dict[tuple[str, str], list[str]] = defaultdict(list)
    for path in deleted_paths:
        fingerprint = before[path].rename_fingerprint()
        if fingerprint is not None:
            deleted_by_fingerprint[fingerprint].append(path)
    for path in created_paths:
        fingerprint = after[path].rename_fingerprint()
        if fingerprint is not None:
            created_by_fingerprint[fingerprint].append(path)

    renamed_from: set[str] = set()
    renamed_to: set[str] = set()
    for fingerprint in sorted(
        set(deleted_by_fingerprint) & set(created_by_fingerprint)
    ):
        deleted_candidates = sorted(deleted_by_fingerprint[fingerprint])
        created_candidates = sorted(created_by_fingerprint[fingerprint])
        if len(deleted_candidates) == 1 and len(created_candidates) == 1:
            old_path = deleted_candidates[0]
            new_path = created_candidates[0]
            renamed_from.add(old_path)
            renamed_to.add(new_path)
            effects.append(
                Effect(
                    kind=EffectKind.RENAME,
                    path=new_path,
                    previous_path=old_path,
                    before=before[old_path],
                    after=after[new_path],
                )
            )

    effects.extend(
        Effect(kind=EffectKind.DELETE, path=path, before=before[path])
        for path in deleted_paths - renamed_from
    )
    effects.extend(
        Effect(kind=EffectKind.CREATE, path=path, after=after[path])
        for path in created_paths - renamed_to
    )
    return sorted(
        effects,
        key=lambda effect: (
            effect.kind.value,
            effect.path,
            effect.previous_path or "",
        ),
    )

