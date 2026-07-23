from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from pathlib import Path

from dutybound.models import SnapshotEntry
from dutybound.patterns import matches_any


class SnapshotError(RuntimeError):
    pass


INTERNAL_EXCLUDE = ".dutybound/**"


def _relative_name(parent: str, name: str) -> str:
    normalized_name = unicodedata.normalize("NFC", name)
    return f"{parent}/{normalized_name}" if parent else normalized_name


def _hash_regular_file(path: Path, expected: os.stat_result) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino):
                raise SnapshotError(f"entry changed while snapshotting: {path}")
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise SnapshotError(f"cannot read file while snapshotting: {path}") from exc

    stability_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        stat.S_IMODE(before.st_mode),
    )
    stability_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        stat.S_IMODE(after.st_mode),
    )
    if stability_before != stability_after:
        raise SnapshotError(f"file changed while snapshotting: {path}")
    return digest.hexdigest()


def take_snapshot(
    workspace: Path, configured_excludes: tuple[str, ...] = ()
) -> dict[str, SnapshotEntry]:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise SnapshotError(f"workspace is not a directory: {workspace}")

    excludes = (INTERNAL_EXCLUDE, *configured_excludes)
    snapshot: dict[str, SnapshotEntry] = {}

    def walk(directory: Path, relative_parent: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda item: os.fsencode(item.name),
                )
        except OSError as exc:
            raise SnapshotError(f"cannot scan directory: {directory}") from exc

        for directory_entry in entries:
            relative_path = _relative_name(relative_parent, directory_entry.name)
            if matches_any(relative_path, excludes):
                continue
            absolute_path = directory / directory_entry.name
            try:
                metadata = directory_entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SnapshotError(
                    f"cannot inspect entry while snapshotting: {absolute_path}"
                ) from exc

            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(absolute_path)
                except OSError as exc:
                    raise SnapshotError(
                        f"cannot read symlink while snapshotting: {absolute_path}"
                    ) from exc
                snapshot[relative_path] = SnapshotEntry(
                    entry_type="symlink",
                    sha256=None,
                    size=metadata.st_size,
                    mode=mode,
                    symlink_target=target,
                )
            elif stat.S_ISDIR(metadata.st_mode):
                snapshot[relative_path] = SnapshotEntry(
                    entry_type="directory",
                    sha256=None,
                    size=0,
                    mode=mode,
                )
                walk(absolute_path, relative_path)
            elif stat.S_ISREG(metadata.st_mode):
                snapshot[relative_path] = SnapshotEntry(
                    entry_type="file",
                    sha256=_hash_regular_file(absolute_path, metadata),
                    size=metadata.st_size,
                    mode=mode,
                )
            else:
                snapshot[relative_path] = SnapshotEntry(
                    entry_type="special",
                    sha256=None,
                    size=metadata.st_size,
                    mode=mode,
                )

    walk(workspace, "")
    return snapshot
