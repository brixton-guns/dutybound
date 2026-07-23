from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dutybound.models import Effect, EffectKind
from dutybound.patterns import PatternError, matches, normalize_pattern
from dutybound.policy import evaluate_effect, load_authorization
from tests.helpers import write_authorization


class PatternTests(unittest.TestCase):
    def test_double_star_matches_root_and_descendants(self) -> None:
        self.assertTrue(matches("root.pem", "**/*.pem"))
        self.assertTrue(matches("a/b/root.pem", "**/*.pem"))
        self.assertTrue(matches("docs", "docs/**"))
        self.assertTrue(matches("docs/a/b.md", "docs/**"))
        self.assertFalse(matches("src/a.py", "docs/**"))

    def test_invalid_patterns_are_rejected(self) -> None:
        for pattern in ("/absolute", "../escape", "a//b", r"a\b", "!docs/**"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(PatternError):
                    normalize_pattern(pattern)


class PolicyTests(unittest.TestCase):
    def test_deny_overrides_allow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            path = write_authorization(
                workspace,
                allow=("**",),
                deny=(".env",),
                operations=("create",),
            )
            authorization = load_authorization(path)
            effect = Effect(kind=EffectKind.CREATE, path=".env")
            evaluate_effect(effect, authorization)
            self.assertIn("DENIED_PATH:.env", effect.violations)

    def test_rename_requires_both_paths_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            path = write_authorization(
                workspace,
                allow=("docs/**",),
                deny=(),
                operations=("rename",),
            )
            authorization = load_authorization(path)
            effect = Effect(
                kind=EffectKind.RENAME,
                path="src/a.md",
                previous_path="docs/a.md",
            )
            evaluate_effect(effect, authorization)
            self.assertIn(
                "OUTSIDE_ALLOWED_SCOPE:src/a.md",
                effect.violations,
            )

    def test_disallowed_operation_is_a_violation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            path = write_authorization(
                workspace,
                operations=("modify",),
            )
            authorization = load_authorization(path)
            effect = Effect(kind=EffectKind.DELETE, path="docs/a.md")
            evaluate_effect(effect, authorization)
            self.assertIn("OPERATION_NOT_ALLOWED:delete", effect.violations)


if __name__ == "__main__":
    unittest.main()

