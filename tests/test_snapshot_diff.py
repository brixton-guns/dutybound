from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dutybound.diff import compare_snapshots
from dutybound.models import EffectKind
from dutybound.snapshot import take_snapshot


class SnapshotDiffTests(unittest.TestCase):
    def test_create_modify_delete_and_unique_rename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "docs").mkdir()
            (workspace / "docs" / "modify.md").write_text("before")
            (workspace / "docs" / "delete.md").write_text("delete me")
            (workspace / "docs" / "old.md").write_text("unique rename content")
            before = take_snapshot(workspace)

            (workspace / "docs" / "modify.md").write_text("after")
            (workspace / "docs" / "delete.md").unlink()
            (workspace / "docs" / "old.md").rename(
                workspace / "docs" / "new.md"
            )
            (workspace / "docs" / "create.md").write_text("created")
            after = take_snapshot(workspace)

            effects = compare_snapshots(before, after)
            summary = {
                (effect.kind, effect.path, effect.previous_path)
                for effect in effects
            }
            self.assertIn(
                (EffectKind.MODIFY, "docs/modify.md", None),
                summary,
            )
            self.assertIn(
                (EffectKind.DELETE, "docs/delete.md", None),
                summary,
            )
            self.assertIn(
                (EffectKind.RENAME, "docs/new.md", "docs/old.md"),
                summary,
            )
            self.assertIn(
                (EffectKind.CREATE, "docs/create.md", None),
                summary,
            )

    def test_empty_file_move_is_not_inferred_as_rename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "old").write_bytes(b"")
            before = take_snapshot(workspace)
            (workspace / "old").rename(workspace / "new")
            after = take_snapshot(workspace)
            effects = compare_snapshots(before, after)
            self.assertEqual(
                [effect.kind for effect in effects],
                [EffectKind.CREATE, EffectKind.DELETE],
            )

    def test_internal_state_is_always_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".dutybound").mkdir()
            (workspace / ".dutybound" / "secret").write_text("internal")
            snapshot = take_snapshot(workspace)
            self.assertNotIn(".dutybound", snapshot)
            self.assertNotIn(".dutybound/secret", snapshot)


if __name__ == "__main__":
    unittest.main()

