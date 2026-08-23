import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import codexpick_cli


class ProbeResultTests(unittest.TestCase):
    def setUp(self):
        self.candidate = codexpick_cli.Candidate("test", Path("auth-test.json"))

    def test_missing_weekly_window_does_not_block_account(self):
        result = codexpick_cli.ProbeResult(
            self.candidate,
            account={"account": None, "requiresOpenaiAuth": True},
            rate_limits={
                "rateLimits": {
                    "primary": {"usedPercent": 25},
                    "secondary": None,
                }
            },
        )

        self.assertTrue(result.usable)

    def test_authentication_is_required_without_account_or_rate_limits(self):
        result = codexpick_cli.ProbeResult(
            self.candidate,
            account={"account": None, "requiresOpenaiAuth": True},
            rate_limits={},
        )

        self.assertEqual(result.blocked_reason, "authentication required")


class ExplicitSelectionTests(unittest.TestCase):
    def test_explicit_selection_switches_without_probing(self):
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            selected = codex_home / "auth-selected.json"
            selected.write_text(json.dumps({"tokens": {"account_id": "selected"}}))
            (codex_home / "auth-other.json").write_text(
                json.dumps({"tokens": {"account_id": "other"}})
            )

            argv = [
                "codexpick",
                "--home",
                str(codex_home),
                "--account",
                "selected",
                "--no-launch",
            ]
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    codexpick_cli,
                    "probe_candidate",
                    side_effect=AssertionError("explicit selection must not probe"),
                ),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(output),
            ):
                result = codexpick_cli.main()

            self.assertEqual(result, 0)
            self.assertEqual((codex_home / "auth.json").read_bytes(), selected.read_bytes())
            self.assertNotIn("Probing", output.getvalue())


if __name__ == "__main__":
    unittest.main()
