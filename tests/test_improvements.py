import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import codexpick_cli as cli


def result(name, *usage, error=None):
    return cli.ProbeResult(
        cli.Candidate(name, Path(f"auth-{name}.json")),
        account={"account": {"planType": "plus"}},
        rate_limits={"rateLimits": dict(zip(
            ("primary", "secondary"), ({"usedPercent": x} for x in usage)))},
        error=error,
    )


class RankingTests(unittest.TestCase):
    def test_tightest_window_wins_not_alphabetic_or_short_window(self):
        a = result("a", 0, 95)
        b = result("b", 30, 40)
        self.assertIs(cli.select_best_account([a, b]), b)

    def test_ties_use_other_window_then_stable_order(self):
        a, b, c = result("a", 60, 30), result("b", 60, 10), result("c", 60, 10)
        self.assertIs(cli.select_best_account([a, b, c]), b)

    def test_unknown_exhausted_error_and_duplicates_cannot_win(self):
        duplicate = result("duplicate", 0)
        duplicate.duplicate_of = "other"
        results = [result("unknown"), result("spent", 100),
                   result("error", 0, error="offline"), duplicate]
        self.assertIsNone(cli.select_best_account(results))

    def test_fractional_usage_is_preserved(self):
        a, b = result("a", 99.9), result("b", 99.1)
        self.assertIs(cli.select_best_account([a, b]), b)

    def test_nonfinite_and_negative_usage_is_unknown(self):
        for value in (float("nan"), float("inf"), -2):
            self.assertIsNone(cli.select_best_account([result("invalid", value)]))

    def test_healthy_duplicate_preferred_over_expired_snapshot(self):
        bad, good = result("bad", error="token_expired"), result("good", 20)
        with mock.patch.object(cli, "read_account_key", return_value="same"):
            cli.mark_duplicate_accounts([bad, good])
        self.assertIs(cli.select_best_account([bad, good]), good)


class FlowTests(unittest.TestCase):
    def test_deletion_preserves_active_auth_and_other_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("auth.json", "auth-one.json", "auth-two.json"):
                (root / name).write_text("fake credential")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.delete_account(root, "one"), 0)
            self.assertFalse((root / "auth-one.json").exists())
            self.assertEqual((root / "auth.json").read_text(), "fake credential")
            self.assertTrue((root / "auth-two.json").exists())
            self.assertEqual(next((root / ".codexpick-trash").iterdir()).read_text(), "fake credential")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.delete_account(root, "../auth.json"), 2)

    def test_relogin_is_optional_and_reprobed_before_activation(self):
        args = argparse.Namespace(login=None, no_activate=False, timeout=10)
        expired = result("expired", error="refresh_token_expired")
        for answer, renewed, expected in (("", result("expired", 0), 1),
                                          ("1", result("expired", 100), 1),
                                          ("expired", result("expired", 10), 0)):
            with self.subTest(answer=answer), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch("builtins.input", return_value=answer), \
                 mock.patch.object(cli, "login_subscription", return_value=0) as login, \
                 mock.patch.object(cli, "probe_candidate", return_value=renewed), \
                 mock.patch.object(cli, "activate_candidate", return_value=0) as activate, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.offer_relogin(args, [expired], Path("."), Path("auth.json"), Path("codex")), expected)
                if answer:
                    self.assertTrue(login.call_args.args[0].no_activate)
                else:
                    login.assert_not_called()
                self.assertEqual(activate.called, expected == 0)

    def test_no_prompt_without_terminal(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
             mock.patch("builtins.input") as prompt:
            self.assertEqual(cli.offer_relogin(None, [result("bad", error="token_expired")], None, None, None), 1)
            prompt.assert_not_called()

    def test_defaults(self):
        with mock.patch.object(sys, "argv", ["codexpick"]):
            self.assertEqual(cli.parse_args().timeout, 10)


class UpdateTests(unittest.TestCase):
    def test_changed_remote_notifies_even_with_same_package_version(self):
        for revision, notify in (("abc", False), ("def", True)):
            output = io.StringIO()
            with mock.patch.object(cli, "installed_revision", return_value="abc"), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, revision + "\tHEAD\n")), \
                 contextlib.redirect_stderr(output):
                cli.check_for_update()
            self.assertEqual("update available" in output.getvalue(), notify)

    def test_offline_check_is_nonfatal(self):
        with mock.patch.object(cli, "installed_revision", return_value="abc"), \
             mock.patch.object(cli.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 2)):
            cli.check_for_update()


class CredentialTests(unittest.TestCase):
    def test_older_active_copy_does_not_replace_newer_saved_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, saved = root / "auth.json", root / "auth-test.json"
            active.write_text(json.dumps({"tokens": {"account_id": "fake", "refresh_token": "old"}}))
            saved.write_text(json.dumps({"tokens": {"account_id": "fake", "refresh_token": "new"}}))
            os.utime(active, (100, 100))
            os.utime(saved, (200, 200))
            cli.refresh_candidates_from_active_auth(active, [cli.Candidate("test", saved)])
            self.assertEqual(json.loads(saved.read_text())["tokens"]["refresh_token"], "new")

    def test_invalid_auth_cannot_overwrite_saved_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source", Path(directory) / "target"
            source.write_text("{}")
            target.write_text('{"other": "data"}')
            self.assertFalse(cli.sync_refreshed_auth(source, target))
            self.assertEqual(target.read_text(), '{"other": "data"}')

    def test_failed_probe_saves_rotated_token_and_forces_file_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = root / "auth-test.json"
            active = root / "auth.json"
            original = json.dumps({"tokens": {"account_id": "fake", "refresh_token": "old-fake"}})
            saved.write_text(original)
            active.write_text(original)
            command = []

            def start(argv, **kwargs):
                command.extend(argv)
                tmp_auth = Path(kwargs["env"]["CODEX_HOME"]) / "auth.json"
                tmp_auth.write_text(json.dumps({"tokens": {"account_id": "fake", "refresh_token": "new-fake"}}))
                return mock.Mock()

            with mock.patch.object(cli.subprocess, "Popen", side_effect=start), \
                 mock.patch.object(cli, "wait_for_socket"), \
                 mock.patch.object(cli, "RawWebSocket"), \
                 mock.patch.object(cli, "rpc", side_effect=cli.ProbeError("quota unavailable")), \
                 mock.patch.object(cli, "stop_process"):
                probed = cli.probe_candidate(cli.Candidate("test", saved), root, Path("codex"), 1)
            self.assertEqual(probed.error, "quota unavailable")
            self.assertEqual(json.loads(saved.read_text())["tokens"]["refresh_token"], "new-fake")
            self.assertEqual(active.read_text(), original)
            self.assertIn('cli_auth_credentials_store="file"', command)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_switch_warns_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, selected = root / "auth.json", root / "auth-test.json"
            active.write_text("old")
            selected.write_text("new")
            output = io.StringIO()

            def switch(*args):
                self.assertIn("Warning:", output.getvalue())
                return True

            with mock.patch.object(cli, "inspect_managed_daemon", return_value=None), \
                 mock.patch.object(cli, "switch_auth", side_effect=switch), \
                 contextlib.redirect_stderr(output):
                cli.activate_auth_snapshot(active, selected, Path("codex"), 1)


class LaunchTests(unittest.TestCase):
    def test_default_launch_uses_best_account_and_passes_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a", "b"):
                (root / f"auth-{name}.json").write_text(json.dumps({"tokens": {"account_id": name}}))

            def probe(candidate, *args):
                response = result(candidate.name, 90 if candidate.name == "a" else 20)
                response.candidate = candidate
                return response

            with mock.patch.object(sys, "argv", ["codexpick", "--home", directory, "--", "resume", "--last"]), \
                 mock.patch.object(cli, "check_for_update") as update, \
                 mock.patch.object(cli, "probe_candidate", side_effect=probe), \
                 mock.patch.object(cli, "inspect_managed_daemon", return_value=None), \
                 mock.patch.object(cli, "resolve_launcher", return_value="fake-codex"), \
                 mock.patch.object(cli, "prepend_binary_dir"), \
                 mock.patch.object(cli.os, "execvp", side_effect=SystemExit(0)) as launch, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    cli.main()
            self.assertEqual(json.loads((root / "auth.json").read_text())["tokens"]["account_id"], "b")
            launch.assert_called_once_with("fake-codex", ["fake-codex", "resume", "--last"])
            update.assert_called_once()
