from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dutybound.ledger import append_records, verify_ledger


class LedgerTests(unittest.TestCase):
    def test_complete_session_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            append_records(
                ledger,
                [
                    {
                        "record_type": "session_started",
                        "session_id": "S1",
                    },
                    {
                        "record_type": "effect_observed",
                        "session_id": "S1",
                    },
                    {
                        "record_type": "session_ended",
                        "session_id": "S1",
                    },
                ],
            )
            result = verify_ledger(ledger)
            self.assertTrue(result.valid)
            self.assertEqual(result.record_count, 3)
            self.assertEqual(result.open_sessions, ())

    def test_open_session_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            append_records(
                ledger,
                [{"record_type": "session_started", "session_id": "S1"}],
            )
            result = verify_ledger(ledger)
            self.assertTrue(result.valid)
            self.assertEqual(result.open_sessions, ("S1",))

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            sealed, _ = append_records(
                ledger,
                [
                    {
                        "record_type": "session_started",
                        "session_id": "S1",
                    }
                ],
            )
            tampered = dict(sealed[0])
            tampered["session_id"] = "S2"
            ledger.write_text(
                json.dumps(tampered, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = verify_ledger(ledger)
            self.assertFalse(result.valid)
            self.assertIn("invalid record_hash", result.error or "")


if __name__ == "__main__":
    unittest.main()

