from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import write_authorization


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "dutybound",
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        env={
            **__import__("os").environ,
            "PYTHONPATH": str(PROJECT_ROOT),
        },
        text=True,
        capture_output=True,
        check=False,
    )


class EndToEndTests(unittest.TestCase):
    def test_denied_env_change_produces_red_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "docs").mkdir()
            write_authorization(workspace)
            result = run_cli(
                workspace,
                "run",
                "--workspace",
                str(workspace),
                "--",
                sys.executable,
                "-c",
                'from pathlib import Path; Path(".env").write_text("touched")',
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            reports = list(
                (workspace / ".dutybound" / "sessions").glob("*/report.md")
            )
            self.assertEqual(len(reports), 1)
            report = reports[0].read_text(encoding="utf-8")
            self.assertIn("**Outcome:** RED", report)
            self.assertIn("AUTHORITY_BREACH", report)
            self.assertIn(r'`".env"`', report)

            verify = run_cli(
                workspace,
                "verify",
                "--workspace",
                str(workspace),
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn("VERIFIED", verify.stdout)

    def test_authorized_document_change_is_clear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "docs").mkdir()
            write_authorization(workspace)
            result = run_cli(
                workspace,
                "run",
                "--workspace",
                str(workspace),
                "--",
                sys.executable,
                "-c",
                (
                    'from pathlib import Path; '
                    'Path("docs/note.md").write_text("documented")'
                ),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CLEAR", result.stdout)

    def test_nonzero_process_exit_is_amber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            write_authorization(workspace)
            result = run_cli(
                workspace,
                "run",
                "--workspace",
                str(workspace),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("AMBER", result.stdout)

    def test_expired_authorization_rejects_without_running(self) -> None:
        from datetime import timedelta

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            write_authorization(
                workspace,
                expires_delta=timedelta(seconds=-1),
            )
            marker = workspace / "should-not-exist"
            result = run_cli(
                workspace,
                "run",
                "--workspace",
                str(workspace),
                "--",
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    'Path("should-not-exist").write_text("bad")'
                ),
            )
            self.assertEqual(result.returncode, 3)
            self.assertFalse(marker.exists())

    def test_output_capture_is_bounded_and_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            write_authorization(workspace)
            result = run_cli(
                workspace,
                "run",
                "--workspace",
                str(workspace),
                "--capture-output",
                "--output-limit-bytes",
                "32",
                "--",
                sys.executable,
                "-c",
                'print("x" * 1000)',
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output_files = list(
                (workspace / ".dutybound" / "sessions").glob("*/stdout.log")
            )
            self.assertEqual(len(output_files), 1)
            self.assertEqual(output_files[0].stat().st_size, 32)


if __name__ == "__main__":
    unittest.main()

