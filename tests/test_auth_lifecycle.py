import base64
import contextlib
import copy
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import codexpick_cli as cli


def jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    return f"header.{payload.decode()}.signature"


def auth(account="primary", session="primary-session", generation=0):
    return {
        "tokens": {
            "account_id": account,
            "refresh_token": f"synthetic-{session}-{generation}",
            "access_token": jwt({
                "session_id": session, "iat": 1700000000 + generation,
                "https://api.openai.com/auth": {"chatgpt_user_id": "synthetic-user"},
            }),
            "id_token": jwt({"email": f"{account}@example.invalid", "sid": session}),
        },
        "last_refresh": f"2023-11-14T22:13:{20 + generation:02d}+00:00",
    }


def write_auth(path, data):
    path.write_text(json.dumps(data))
    path.chmod(0o600)


def read_auth(path):
    return json.loads(path.read_text())


class FakeSocket:
    def __init__(self, *args):
        pass

    def send_json(self, value):
        pass

    def close(self):
        pass


class AuthLifecycleTests(unittest.TestCase):
    """Real CLI/file operations; only Codex processes and RPCs are simulated."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve()
        self.active = self.home / "auth.json"
        self.profile = self.home / "auth-primary.json"
        self.candidate = cli.Candidate("primary", self.profile)
        write_auth(self.active, auth())
        write_auth(self.profile, auth())
        self.homes = []
        self.inputs = []
        self.events = []
        self.quota_error = None
        self.during_quota = lambda: None
        self.generation = 0
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(cli, "resolve_codex_bin", return_value=Path(sys.executable)))
        self.daemon = self.stack.enter_context(mock.patch.object(cli, "inspect_managed_daemon", return_value=None))
        self.spawn = self.stack.enter_context(mock.patch.object(cli.subprocess, "Popen", side_effect=self.start_process))
        self.stack.enter_context(mock.patch.object(cli, "wait_for_socket"))
        self.stack.enter_context(mock.patch.object(cli, "RawWebSocket", FakeSocket))
        self.stack.enter_context(mock.patch.object(cli, "rpc", side_effect=self.rpc))
        self.stop = self.stack.enter_context(mock.patch.object(cli, "stop_process", side_effect=lambda proc: self.events.append("stop")))

    def start_process(self, command, **kwargs):
        self.current_home = Path(kwargs["env"]["CODEX_HOME"])
        self.homes.append(self.current_home)
        self.inputs.append(read_auth(self.current_home / "auth.json"))
        self.events.append("start")
        self.assertIn('cli_auth_credentials_store="file"', command)
        return object()

    def rpc(self, ws, request_id, method, params, timeout):
        if method == "initialize":
            return {}
        if method == "account/read":
            self.assertIs(params["refreshToken"], False)
            data = read_auth(self.current_home / "auth.json")
            return {"account": {"email": f'{data["tokens"]["account_id"]}@example.invalid'}}
        if method == "account/rateLimits/read":
            self.generation += 1
            before = read_auth(self.current_home / "auth.json")
            session = cli.read_session_id(self.current_home / "auth.json")
            write_auth(self.current_home / "auth.json", auth(before["tokens"]["account_id"], session, self.generation))
            self.during_quota()
            if self.quota_error:
                raise self.quota_error
            return {"rateLimits": {"primary": {"usedPercent": 25, "windowDurationMins": 300}}}
        raise AssertionError(method)

    def run_cli(self, *args):
        with mock.patch.object(sys, "argv", ["codexpick", "--no-update-check", "--home", str(self.home), *args]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main()

    def make_inactive(self):
        write_auth(self.active, auth("other", "other-session"))

    def test_check_only_refreshes_active_in_place_and_saves_latest_profile(self):
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(self.homes, [self.home])
        self.assertEqual(read_auth(self.active), auth(generation=1))
        self.assertEqual(read_auth(self.profile), auth(generation=1))

    def test_repeated_checks_never_restore_consumed_credentials(self):
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(self.inputs, [auth(), auth(generation=1)])
        self.assertEqual(read_auth(self.active), auth(generation=2))
        self.assertEqual(read_auth(self.profile), auth(generation=2))

    def test_failed_alias_does_not_hide_an_independent_login(self):
        saved = self.home / "auth-second.json"
        write_auth(saved, auth(session="independent-session"))
        def quota():
            self.quota_error = (
                cli.ProbeError("refresh_token_expired")
                if self.current_home == self.home else None
            )
        self.during_quota = quota
        self.assertEqual(self.run_cli("--no-launch"), 0)
        self.assertEqual(cli.read_session_id(self.active), "independent-session")
        self.assertEqual(self.spawn.call_count, 2)

    def test_delete_recovers_pending_refresh_and_archives_probe_home(self):
        probe_home = cli.prepare_probe_auth(self.candidate, self.home)
        write_auth(probe_home / "auth.json", auth(generation=1))
        self.assertEqual(self.run_cli("--delete", "primary"), 0)
        self.assertFalse(self.profile.exists())
        self.assertFalse(probe_home.exists())
        saved = next(path for path in (self.home / ".codexpick-trash").iterdir() if path.is_file())
        self.assertEqual(read_auth(saved), auth(generation=1))
        self.assertEqual(read_auth(self.active), auth())
        write_auth(self.profile, auth(session="replacement-session"))
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(cli.read_session_id(self.active), "replacement-session")

    def test_delete_preserves_both_logins_when_recovery_conflicts(self):
        probe_home = cli.prepare_probe_auth(self.candidate, self.home)
        write_auth(probe_home / "auth.json", auth(generation=1))
        write_auth(self.profile, auth(session="external-session"))
        with self.assertRaises(cli.ProbeError):
            self.run_cli("--delete", "primary")
        self.assertEqual(read_auth(self.profile), auth(session="external-session"))
        self.assertEqual(read_auth(probe_home / "auth.json"), auth(generation=1))

    def test_external_active_login_during_probe_does_not_replace_saved_session(self):
        self.during_quota = lambda: write_auth(self.active, auth(session="external-session"))
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(read_auth(self.profile), auth())
        self.assertEqual(read_auth(self.active), auth(session="external-session"))

    def test_auto_selection_activates_refreshed_credentials(self):
        self.assertEqual(self.run_cli("--no-launch"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_first_run_saves_and_probes_the_current_session(self):
        self.profile.unlink()
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="primary"):
            self.assertEqual(self.run_cli("--no-launch"), 0)
        self.assertEqual(self.homes, [self.home])
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_interactive_relogin_refreshes_the_new_session_before_activation(self):
        self.quota_error = cli.ProbeError("refresh_token_expired")
        def login(command, **kwargs):
            write_auth(Path(kwargs["env"]["CODEX_HOME"]) / "auth.json", auth(session="renewed-session"))
            self.quota_error = None
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="1"), \
             mock.patch.object(cli.subprocess, "run", side_effect=login):
            self.assertEqual(self.run_cli("--no-launch"), 0)
        self.assertEqual(read_auth(self.profile), auth(session="renewed-session", generation=2))
        self.assertEqual(read_auth(self.active), read_auth(self.profile))

    def test_inactive_check_preserves_active_account_and_exports_refresh(self):
        self.make_inactive()
        before = self.active.read_bytes()
        self.assertEqual(self.run_cli("--account", "primary", "--check-only"), 0)
        self.assertEqual(self.active.read_bytes(), before)
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.assertTrue((self.homes[0] / "auth.json").exists())
        self.assertNotEqual(self.homes[0], self.home)
        self.assertFalse((self.homes[0] / "source.sha256").exists())

    def test_active_refresh_survives_quota_failure(self):
        self.quota_error = cli.ProbeError("synthetic network failure")
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.active), auth(generation=1))
        self.assertEqual(read_auth(self.profile), auth(generation=1))

    def test_inactive_refresh_survives_quota_failure(self):
        self.make_inactive()
        self.quota_error = cli.ProbeError("synthetic network failure")
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.assertEqual(read_auth(self.homes[0] / "auth.json"), auth(generation=1))

    def test_interrupted_probe_is_recovered_before_explicit_switch(self):
        self.make_inactive()
        durable = cli.prepare_probe_auth(self.candidate, self.home)
        write_auth(durable / "auth.json", auth(generation=1))
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.spawn.assert_not_called()

    def test_restart_after_export_before_checkpoint_removal_is_idempotent(self):
        self.make_inactive()
        durable = cli.prepare_probe_auth(self.candidate, self.home)
        write_auth(durable / "auth.json", auth(generation=1))
        write_auth(self.profile, auth(generation=1))
        cli.finish_probe_auth(self.candidate, self.home)
        cli.finish_probe_auth(self.candidate, self.home)
        self.assertEqual(read_auth(self.profile), auth(generation=1))

    def test_new_login_during_inactive_probe_is_not_overwritten(self):
        self.make_inactive()
        new_login = auth(session="new-independent-session")
        self.during_quota = lambda: write_auth(self.profile, new_login)
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.profile), new_login)
        self.assertEqual(read_auth(self.homes[0] / "auth.json"), auth(generation=1))
        self.assertTrue((self.homes[0] / "source.sha256").exists())

    def test_new_login_during_active_probe_is_not_overwritten(self):
        new_login = auth(session="new-independent-session")
        self.during_quota = lambda: write_auth(self.profile, new_login)
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(read_auth(self.profile), new_login)
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_explicit_switch_keeps_new_login_for_same_account(self):
        new_login = auth(session="new-independent-session")
        write_auth(self.profile, new_login)
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), new_login)
        self.spawn.assert_not_called()

    def test_legacy_newer_saved_profile_is_not_downgraded(self):
        write_auth(self.profile, auth(generation=1))
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.active), auth())
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.spawn.assert_not_called()
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_newer_saved_access_token_is_preserved_when_refresh_token_is_unchanged(self):
        newer = auth(generation=1)
        newer["tokens"]["refresh_token"] = auth()["tokens"]["refresh_token"]
        write_auth(self.profile, newer)
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.profile), newer)
        self.assertEqual(read_auth(self.active), auth())
        self.spawn.assert_not_called()

    def test_active_daemon_is_reused_without_starting_another_writer(self):
        self.current_home = self.home
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", ["active"])
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))
        self.spawn.assert_not_called()
        self.stop.assert_not_called()

    def test_daemon_with_different_account_is_not_probed(self):
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "other@example.invalid", [])
        self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.active), auth())
        self.spawn.assert_not_called()

    def test_status_fallback_uses_latest_auth_after_first_writer_stops(self):
        self.make_inactive()
        self.quota_error = cli.ProbeError("method not found")
        def status(candidate, home, binary, timeout):
            self.assertEqual(self.events, ["start", "stop"])
            self.assertEqual(read_auth(home / "auth.json"), auth(generation=1))
            write_auth(home / "auth.json", auth(generation=2))
            return {"rateLimits": {"primary": {"usedPercent": 25}}}
        with mock.patch.object(cli, "fallback_status_probe", side_effect=status):
            self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(read_auth(self.profile), auth(generation=2))

    def test_failed_status_fallback_preserves_its_refresh(self):
        self.make_inactive()
        self.quota_error = cli.ProbeError("method not found")
        def status(candidate, home, binary, timeout):
            write_auth(home / "auth.json", auth(generation=2))
            raise cli.ProbeError("synthetic /status timeout")
        with mock.patch.object(cli, "fallback_status_probe", side_effect=status):
            self.assertEqual(self.run_cli("--check-only"), 1)
        self.assertEqual(read_auth(self.profile), auth(generation=2))

    def test_launch_uses_updated_credentials_and_custom_command(self):
        with mock.patch.object(cli, "resolve_launcher", return_value="synthetic-launcher"), \
             mock.patch.object(cli.os, "execvp") as execute:
            self.assertEqual(self.run_cli("--cmd", "synthetic-launcher", "--", "resume"), 127)
        execute.assert_called_once_with("synthetic-launcher", ["synthetic-launcher", "resume"])
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_login_no_activate_then_switch_does_not_restore_old_session(self):
        fresh = auth(session="new-login-session")
        def login(command, **kwargs):
            write_auth(Path(kwargs["env"]["CODEX_HOME"]) / "auth.json", fresh)
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(cli.subprocess, "run", side_effect=login):
            self.assertEqual(self.run_cli("--login", "primary", "--no-activate"), 0)
        self.assertEqual(read_auth(self.active), auth())
        self.assertEqual(read_auth(self.profile), fresh)
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), fresh)

    def test_failed_login_preserves_both_existing_files(self):
        with mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            self.assertEqual(self.run_cli("--login", "primary", "--no-activate"), 1)
        self.assertEqual(read_auth(self.active), auth())
        self.assertEqual(read_auth(self.profile), auth())

    def test_login_can_activate_directly_with_or_without_launching(self):
        fresh = auth(session="new-login-session")
        def login(command, **kwargs):
            self.assertIn('cli_auth_credentials_store="file"', command)
            write_auth(Path(kwargs["env"]["CODEX_HOME"]) / "auth.json", fresh)
            return subprocess.CompletedProcess(command, 0)
        for extra, expected in ((["--no-launch"], 0), ([], 127)):
            with self.subTest(extra=extra), \
                 mock.patch.object(cli.subprocess, "run", side_effect=login), \
                 mock.patch.object(cli, "resolve_launcher", return_value="synthetic-launcher"), \
                 mock.patch.object(cli.os, "execvp") as execute:
                self.assertEqual(self.run_cli("--login", "primary", *extra), expected)
            self.assertEqual(read_auth(self.active), fresh)
            self.assertEqual(read_auth(self.profile), fresh)
            self.assertEqual(execute.call_count, int(not extra))

    def test_login_keeps_new_profile_when_activation_is_refused(self):
        fresh = auth(session="new-login-session")
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", ["active"])
        def login(command, **kwargs):
            write_auth(Path(kwargs["env"]["CODEX_HOME"]) / "auth.json", fresh)
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(cli.subprocess, "run", side_effect=login), \
             mock.patch.object(cli, "run_daemon_command") as command:
            self.assertEqual(self.run_cli("--login", "primary", "--no-launch"), 3)
        self.assertEqual(read_auth(self.active), auth())
        self.assertEqual(read_auth(self.profile), fresh)
        command.assert_not_called()

    def test_new_login_can_replace_conflicted_probe_without_losing_recovery_copy(self):
        self.make_inactive()
        durable = cli.prepare_probe_auth(self.candidate, self.home)
        write_auth(durable / "auth.json", auth(generation=1))
        write_auth(self.profile, auth(session="external-login"))
        fresh = auth(session="new-login-session")
        def login(command, **kwargs):
            write_auth(Path(kwargs["env"]["CODEX_HOME"]) / "auth.json", fresh)
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(cli.subprocess, "run", side_effect=login):
            self.assertEqual(self.run_cli("--login", "primary", "--no-activate"), 0)
        self.assertEqual(read_auth(self.profile), fresh)
        self.assertFalse((durable / "source.sha256").exists())
        backups = list(durable.glob("auth.json.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(read_auth(backups[0]), auth(generation=1))

    def test_duplicate_snapshots_are_not_refreshed_twice(self):
        self.make_inactive()
        alias = self.home / "auth-z-alias.json"
        write_auth(alias, auth())
        self.assertEqual(self.run_cli("--check-only"), 0)
        self.assertEqual(len(self.inputs), 1)
        self.assertEqual(read_auth(alias), auth(generation=1))
        self.assertEqual(self.run_cli("--account", "z-alias", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_latest_duplicate_is_recovered_before_forced_selection(self):
        self.make_inactive()
        alias = self.home / "auth-z-alias.json"
        write_auth(alias, auth(generation=1))
        self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(read_auth(self.active), auth(generation=1))

    def test_same_account_new_login_restarts_idle_daemon(self):
        fresh = auth(session="new-independent-session")
        write_auth(self.profile, fresh)
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", [])
        events = []
        def command(home, binary, timeout, action):
            self.assertEqual(action, "stop")
            self.assertEqual(read_auth(self.active), auth())
            events.append("stop")
        def restart(*args):
            self.assertEqual(events, ["stop"])
            self.assertEqual(read_auth(self.active), fresh)
            events.append("restart")
        with mock.patch.object(cli, "run_daemon_command", side_effect=command), \
             mock.patch.object(cli, "restart_managed_daemon", side_effect=restart):
            self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 0)
        self.assertEqual(events, ["stop", "restart"])

    def test_same_account_new_login_does_not_interrupt_active_turn(self):
        write_auth(self.profile, auth(session="new-independent-session"))
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", ["active"])
        with mock.patch.object(cli, "run_daemon_command") as command:
            self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 3)
        self.assertEqual(read_auth(self.active), auth())
        command.assert_not_called()

    def test_failed_restart_saves_both_accounts_latest_tokens(self):
        selected = self.home / "auth-secondary.json"
        write_auth(selected, auth("secondary", "secondary-session"))
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", [])
        stops = []
        def stop(home, binary, timeout, action):
            stops.append(action)
            if len(stops) == 1:
                write_auth(self.active, auth(generation=1))
        def failed_restart(*args):
            write_auth(self.active, auth("secondary", "secondary-session", 2))
            raise cli.ActivationError("synthetic restart failure after refresh")
        with mock.patch.object(cli, "run_daemon_command", side_effect=stop), \
             mock.patch.object(cli, "restart_managed_daemon", side_effect=failed_restart), \
             mock.patch.object(cli, "run_daemon_restart") as recover:
            self.assertEqual(self.run_cli("--account", "secondary", "--no-launch"), 3)
        self.assertEqual(read_auth(self.active), auth(generation=1))
        self.assertEqual(read_auth(self.profile), auth(generation=1))
        self.assertEqual(read_auth(selected), auth("secondary", "secondary-session", 2))
        recover.assert_called_once()

    def test_rollback_preserves_unexpected_external_login_and_backup(self):
        fresh = auth(session="selected-session")
        external = auth("external", "external-session")
        write_auth(self.profile, fresh)
        self.active.chmod(0o644)
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", [])
        def failed_restart(*args):
            write_auth(self.active, external)
            raise cli.ActivationError("synthetic restart failure")
        with mock.patch.object(cli, "run_daemon_command"), \
             mock.patch.object(cli, "restart_managed_daemon", side_effect=failed_restart):
            self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 3)
        self.assertEqual(read_auth(self.active), external)
        self.assertEqual(read_auth(self.profile), fresh)
        backups = list(self.home.glob(".auth.codexpick-rollback.*.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(read_auth(backups[0]), auth())
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_lock_is_inherited_by_probe_but_not_normal_launcher(self):
        def launch(*args):
            self.assertIsNotNone(cli.AUTH_LOCK_FD)
            self.assertFalse(os.get_inheritable(cli.AUTH_LOCK_FD))
        with mock.patch.object(cli.os, "execvp", side_effect=launch):
            self.assertEqual(self.run_cli(), 127)
        self.assertTrue(self.spawn.call_args.kwargs["pass_fds"])

    def test_error_after_atomic_replace_still_restores_outgoing_account(self):
        write_auth(self.profile, auth(session="new-independent-session"))
        self.daemon.return_value = cli.DaemonState(Path("synthetic.sock"), "primary@example.invalid", [])
        original = cli.switch_auth
        failed = []
        def replace_then_fail(target, source, **kwargs):
            result = original(target, source, **kwargs)
            if target == self.active and not failed:
                failed.append(True)
                raise OSError("synthetic directory fsync error after replace")
            return result
        with mock.patch.object(cli, "switch_auth", side_effect=replace_then_fail), \
             mock.patch.object(cli, "run_daemon_command"), \
             mock.patch.object(cli, "run_daemon_restart"):
            self.assertEqual(self.run_cli("--account", "primary", "--no-launch"), 3)
        self.assertEqual(read_auth(self.active), auth())
        self.assertEqual(read_auth(self.profile), auth(session="new-independent-session"))


class AuthWriteTests(unittest.TestCase):
    def test_compare_before_replace_preserves_external_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source.json", Path(tmp) / "target.json"
            write_auth(source, auth(generation=1))
            write_auth(target, auth())
            expected = cli.sha256_file(target)
            write_auth(target, auth(session="external-login"))
            with self.assertRaises(cli.ActivationError):
                cli.switch_auth(target, source, expected_hash=expected)
            self.assertEqual(read_auth(target), auth(session="external-login"))

    def test_unknown_refresh_order_does_not_overwrite_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            active, saved = Path(tmp) / "auth.json", Path(tmp) / "auth-primary.json"
            one = auth()
            two = copy.deepcopy(one)
            two["tokens"]["refresh_token"] = "synthetic-different"
            write_auth(active, one)
            write_auth(saved, two)
            cli.refresh_candidates_from_active_auth(active, [cli.Candidate("primary", saved)])
            self.assertEqual(read_auth(saved), two)

    def test_source_change_after_generation_check_is_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source.json", Path(tmp) / "target.json"
            write_auth(source, auth(generation=2))
            write_auth(target, auth(generation=1))
            expected = cli.sha256_file(source)
            write_auth(source, auth())
            with self.assertRaises(cli.ActivationError):
                cli.sync_refreshed_auth(source, target, expected_source_hash=expected)
            self.assertEqual(read_auth(target), auth(generation=1))

    def test_backups_created_in_same_second_are_distinct_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source.json", Path(tmp) / "target.json"
            write_auth(source, auth(generation=1))
            write_auth(target, auth())
            target.chmod(0o644)
            first = cli.backup_existing_auth(target, source)
            second = cli.backup_existing_auth(target, source)
            self.assertNotEqual(first, second)
            self.assertEqual(read_auth(first), auth())
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)

    def test_nanosecond_refresh_times_order_same_second_generations(self):
        with tempfile.TemporaryDirectory() as tmp:
            active, saved = Path(tmp) / "auth.json", Path(tmp) / "auth-primary.json"
            one = auth()
            two = copy.deepcopy(one)
            one["last_refresh"] = "2023-11-14T22:13:20.123456789Z"
            two["last_refresh"] = "2023-11-14T22:13:20.987654321Z"
            two["tokens"]["refresh_token"] = "synthetic-new"
            write_auth(active, two)
            write_auth(saved, one)
            os.utime(saved, (1900000000, 1900000000))
            self.assertTrue(cli.auth_is_newer(active, saved))

    def test_status_fallback_reports_reused_refresh_token(self):
        with self.assertRaises(cli.ProbeError):
            cli.parse_status_text("refresh token was already used\n5h limit: 75% left")

    def test_probe_home_rejects_names_that_escape_its_account_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            for name in ("", ".", "..", "../other"):
                with self.subTest(name=name), self.assertRaises(cli.ProbeError):
                    cli.saved_probe_home(cli.Candidate(name, home / "auth-test.json"), home)

    def test_status_process_start_failure_closes_both_pty_descriptors(self):
        descriptors = []
        openpty = cli.pty.openpty
        def allocate():
            pair = openpty()
            descriptors.extend(pair)
            return pair
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(cli.pty, "openpty", side_effect=allocate), \
             mock.patch.object(cli.subprocess, "Popen", side_effect=OSError("synthetic start failure")):
            with self.assertRaises(OSError):
                cli.fallback_status_probe(cli.Candidate("test", Path(tmp) / "auth-test.json"), Path(tmp), Path("codex"), 1)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)


class AuthLockTests(unittest.TestCase):
    def test_another_process_cannot_enter_during_an_auth_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with (home / ".codexpick.lock").open("a") as lock:
                cli.fcntl.flock(lock, cli.fcntl.LOCK_EX)
                for args in (("--check-only",), ("--account", "test"),
                             ("--login", "test"), ("--delete", "test")):
                    with self.subTest(args=args):
                        result = subprocess.run(
                            [sys.executable, cli.__file__, "--no-update-check", "--home", str(home), *args],
                            capture_output=True, text=True, timeout=5,
                        )
                        self.assertEqual(result.returncode, 3)
                        self.assertIn("another codexpick operation", result.stderr)

    def test_probe_child_keeps_lock_after_parent_exits(self):
        program = '''
import os, subprocess, sys
from pathlib import Path
import codexpick_cli as cli
home = Path(sys.argv[1])
def leave_child(args, codex_home):
    child = subprocess.Popen(
        [sys.executable, "-c", "import signal; signal.pause()"],
        pass_fds=cli.auth_lock_fds(), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    (home / "child.pid").write_text(str(child.pid))
    os._exit(0)
cli.run_selection = leave_child
sys.argv = ["codexpick", "--no-update-check", "--home", str(home)]
cli.main()
'''
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            child_pid = None
            try:
                subprocess.run([sys.executable, "-c", program, str(home)],
                               cwd=Path(cli.__file__).parent, check=True, timeout=5)
                child_pid = int((home / "child.pid").read_text())
                with mock.patch.object(sys, "argv", ["codexpick", "--no-update-check", "--home", str(home)]):
                    with self.assertRaisesRegex(cli.ActivationError, "another codexpick operation"):
                        cli.main()
            finally:
                if child_pid is not None:
                    os.kill(child_pid, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
