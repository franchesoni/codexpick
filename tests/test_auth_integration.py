"""Opt-in real Codex tests; OAuth and quota traffic stays on loopback.

CODEXPICK_TEST_CODEX_BIN=/absolute/path/to/codex python -m unittest discover -s tests
No real credentials are loaded. The server rejects reuse of a synthetic token.
"""
import base64
import datetime
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


CODEX_BIN = os.environ.get("CODEXPICK_TEST_CODEX_BIN")
ROOT = Path(__file__).resolve().parents[1]


def token(expired=False, account="synthetic-account", session="synthetic-session"):
    issued = int(time.time()) - (9 * 86400 if expired else 0)
    claims = {
        "email": f"{account}@example.invalid", "session_id": session,
        "sid": session, "iat": issued,
        "exp": int(time.time()) + (-60 if expired else 10 * 86400),
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account,
            "chatgpt_user_id": "synthetic-user", "chatgpt_plan_type": "pro",
        },
    }
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return encode({"alg": "none"}) + "." + encode(claims) + ".synthetic"


@unittest.skipUnless(CODEX_BIN, "set CODEXPICK_TEST_CODEX_BIN for loopback integration")
class RealCodexAuthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codexpick-integration-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.codex_home = self.home / ".codex"
        self.codex_home.mkdir()
        self.consumed = []
        self.reused = []
        self.fail_quota = False
        self.identities = {"synthetic-original": ("synthetic-account", "synthetic-session")}
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, code, value):
                data = json.dumps(value).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.path != "/oauth/token":
                    self.send(404, {})
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                refresh = body.get("refresh_token")
                if refresh in test.consumed:
                    test.reused.append(refresh)
                    self.send(401, {"error": {"code": "refresh_token_reused"}})
                    return
                test.consumed.append(refresh)
                account, session = test.identities[refresh]
                new_refresh = f"synthetic-renewed-{len(test.consumed)}"
                test.identities[new_refresh] = (account, session)
                self.send(200, {"access_token": token(account=account, session=session),
                                "id_token": token(account=account, session=session),
                                "refresh_token": new_refresh})

            def do_GET(self):
                if self.path.endswith("/usage"):
                    if test.fail_quota:
                        self.send(400, {"error": "synthetic quota read failure"})
                    else:
                        self.send(200, {
                            "plan_type": "pro", "rate_limit": {
                                "allowed": True, "limit_reached": False,
                                "primary_window": {"used_percent": 25, "limit_window_seconds": 300,
                                                   "reset_after_seconds": 300, "reset_at": 1700000300},
                                "secondary_window": None,
                            },
                        })
                else:
                    self.send(404, {})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        (self.codex_home / "config.toml").write_text(
            'cli_auth_credentials_store = "file"\n'
            'check_for_update_on_startup = false\n'
            f'chatgpt_base_url = "{base_url}"\n'
            '[analytics]\nenabled = false\n'
        )
        self.environment = {
            "HOME": str(self.home), "CODEX_HOME": str(self.codex_home),
            "CODEX_BIN": str(Path(CODEX_BIN).resolve()),
            "PATH": str(Path(CODEX_BIN).parent) + os.pathsep + "/usr/bin:/bin",
            "XDG_STATE_HOME": str(self.home / "state"), "XDG_DATA_HOME": str(self.home / "data"),
            "CODEX_REFRESH_TOKEN_URL_OVERRIDE": base_url + "/oauth/token",
            "NO_COLOR": "1", "RUST_LOG": "error",
        }
        old = {
            "auth_mode": "chatgpt", "OPENAI_API_KEY": None,
            "tokens": {"account_id": "synthetic-account", "access_token": token(True),
                       "id_token": token(True), "refresh_token": "synthetic-original"},
            "last_refresh": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=9)).isoformat(),
        }
        self.profile = self.codex_home / "auth-synthetic.json"
        self.profile.write_text(json.dumps(old))
        self.profile.chmod(0o600)
        self.active = self.codex_home / "auth.json"

    def command(self, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "codexpick_cli.py"), "--no-update-check", "--home", str(self.codex_home), "--timeout", "8", *args],
            cwd=self.home, env=self.environment, capture_output=True, text=True, timeout=35,
        )
        self.assertNotIn("synthetic-original", result.stdout + result.stderr)
        self.assertNotIn("synthetic-renewed-", result.stdout + result.stderr)
        return result

    def test_active_session_refresh_then_repeat_and_select(self):
        self.active.write_bytes(self.profile.read_bytes())
        first = self.command("--check-only")
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        self.assertEqual(len(self.consumed), 1)
        saved = json.loads(self.profile.read_text())["tokens"]["refresh_token"]
        self.assertEqual(json.loads(self.active.read_text())["tokens"]["refresh_token"], saved)
        second = self.command("--check-only")
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        selected = self.command("--account", "synthetic", "--no-launch")
        self.assertEqual(selected.returncode, 0, selected.stderr + selected.stdout)
        self.assertEqual(len(self.consumed), 1)
        self.assertEqual(self.reused, [])

    def test_inactive_refresh_survives_quota_error_and_next_invocation(self):
        self.fail_quota = True
        first = self.command("--check-only")
        self.assertEqual(first.returncode, 1, first.stderr + first.stdout)
        self.assertEqual(len(self.consumed), 1)
        self.assertFalse(self.active.exists())
        self.assertEqual(json.loads(self.profile.read_text())["tokens"]["refresh_token"], "synthetic-renewed-1")
        self.fail_quota = False
        second = self.command("--check-only")
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        selected = self.command("--account", "synthetic", "--no-launch")
        self.assertEqual(selected.returncode, 0, selected.stderr + selected.stdout)
        self.assertEqual(len(self.consumed), 1)
        self.assertEqual(self.reused, [])

    def test_two_accounts_can_refresh_and_switch_back_without_relogin(self):
        self.active.write_bytes(self.profile.read_bytes())
        other = json.loads(self.profile.read_text())
        other["tokens"] = {
            "account_id": "second-account", "refresh_token": "synthetic-second-original",
            "access_token": token(True, "second-account", "second-session"),
            "id_token": token(True, "second-account", "second-session"),
        }
        self.identities["synthetic-second-original"] = ("second-account", "second-session")
        (self.codex_home / "auth-z-secondary.json").write_text(json.dumps(other))
        for arguments in (("--no-launch",), ("--account", "z-secondary", "--no-launch"),
                          ("--check-only",), ("--account", "synthetic", "--no-launch"),
                          ("--check-only",)):
            result = self.command(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(len(self.consumed), 2)
        self.assertEqual(self.reused, [])
        self.assertEqual(json.loads(self.active.read_text())["tokens"]["account_id"], "synthetic-account")


if __name__ == "__main__":
    unittest.main()
