import base64
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

    def test_invalid_token_has_compact_status_and_relogin_hint(self):
        result = codexpick_cli.ProbeResult(
            self.candidate,
            error=(
                "failed to fetch rate limits: 401 Unauthorized; "
                '{"error":{"message":"Your authentication token has been '
                'invalidated. Please try signing in again.",'
                '"code":"token_invalidated"}}'
            ),
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            codexpick_cli.print_table([result], None)
            codexpick_cli.print_reauth_hints([result])

        rendered = output.getvalue()
        self.assertIn("reauth required", rendered)
        self.assertIn("codexpick --login test --no-activate", rendered)
        self.assertNotIn("failed to fetch rate limits", rendered)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.codex_home = Path(self.tmp.name)
        self.auth_path = self.codex_home / "auth.json"
        self.selected_path = self.codex_home / "auth-selected.json"
        self.auth_path.write_text(json.dumps({"tokens": {"account_id": "old"}}))
        self.selected_path.write_text(
            json.dumps(
                {
                    "tokens": {
                        "account_id": "selected",
                        "id_token": self._jwt({"email": "selected@example.com"}),
                    }
                }
            )
        )
        self.codex_bin = Path("codex")
        self.daemon_command = mock.patch.object(codexpick_cli, "run_daemon_command")
        self.daemon_command.start()
        self.addCleanup(self.daemon_command.stop)

    @staticmethod
    def _jwt(claims):
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        return f"header.{payload.decode()}.signature"

    def test_active_turn_refuses_switch_before_auth_file_changes(self):
        old_auth = self.auth_path.read_bytes()
        daemon = codexpick_cli.DaemonState(
            Path("/tmp/codex.sock"), "old@example.com", ["active"]
        )

        with (
            mock.patch.object(codexpick_cli, "inspect_managed_daemon", return_value=daemon),
            mock.patch.object(codexpick_cli, "run_daemon_restart") as restart,
        ):
            with self.assertRaises(codexpick_cli.ActivationError):
                codexpick_cli.activate_auth_snapshot(
                    self.auth_path, self.selected_path, self.codex_bin, 1
                )

        self.assertEqual(self.auth_path.read_bytes(), old_auth)
        restart.assert_not_called()

    def test_idle_daemon_is_restarted_after_switch(self):
        daemon = codexpick_cli.DaemonState(
            Path("/tmp/codex.sock"), "old@example.com", []
        )

        with (
            mock.patch.object(codexpick_cli, "inspect_managed_daemon", return_value=daemon),
            mock.patch.object(codexpick_cli, "restart_managed_daemon") as restart,
        ):
            changed, restarted = codexpick_cli.activate_auth_snapshot(
                self.auth_path, self.selected_path, self.codex_bin, 1
            )

        self.assertTrue(changed)
        self.assertTrue(restarted)
        self.assertEqual(self.auth_path.read_bytes(), self.selected_path.read_bytes())
        restart.assert_called_once_with(
            self.codex_home, self.codex_bin, "selected@example.com", 1
        )

    def test_failed_restart_restores_previous_auth_and_daemon(self):
        old_auth = self.auth_path.read_bytes()
        daemon = codexpick_cli.DaemonState(
            Path("/tmp/codex.sock"), "old@example.com", []
        )

        with (
            mock.patch.object(codexpick_cli, "inspect_managed_daemon", return_value=daemon),
            mock.patch.object(
                codexpick_cli,
                "restart_managed_daemon",
                side_effect=codexpick_cli.ActivationError("restart failed"),
            ),
            mock.patch.object(codexpick_cli, "run_daemon_restart") as recover,
        ):
            with self.assertRaises(codexpick_cli.ActivationError):
                codexpick_cli.activate_auth_snapshot(
                    self.auth_path, self.selected_path, self.codex_bin, 1
                )

        self.assertEqual(self.auth_path.read_bytes(), old_auth)
        recover.assert_called_once_with(self.codex_home, self.codex_bin, 1)

    def test_file_error_without_daemon_does_not_start_one(self):
        with (
            mock.patch.object(codexpick_cli, "inspect_managed_daemon", return_value=None),
            mock.patch.object(
                codexpick_cli, "switch_auth", side_effect=OSError("write failed")
            ),
            mock.patch.object(codexpick_cli, "run_daemon_restart") as restart,
        ):
            with self.assertRaises(codexpick_cli.ActivationError):
                codexpick_cli.activate_auth_snapshot(
                    self.auth_path, self.selected_path, self.codex_bin, 1
                )

        restart.assert_not_called()


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
                "--no-update-check",
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
                    codexpick_cli, "inspect_managed_daemon", return_value=None
                ),
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
