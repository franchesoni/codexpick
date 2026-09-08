#!/usr/bin/env python3
import argparse
import base64
import datetime
import fcntl
import hashlib
import importlib.metadata
import json
import math
import os
import pty
import re
import select
import secrets
import shlex
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
DEFAULT_CODEX_BIN = os.environ.get("CODEX_BIN")
VERSION = "0.2.0"
REPOSITORY = "https://github.com/franchesoni/codexpick.git"
AUTH_LOCK_FD: int | None = None


class ProbeError(Exception):
    pass


class ActivationError(Exception):
    pass


@dataclass
class Candidate:
    name: str
    path: Path


@dataclass
class ProbeResult:
    candidate: Candidate
    account: dict | None = None
    rate_limits: dict | None = None
    error: str | None = None
    duplicate_of: str | None = None

    @property
    def blocked_reason(self) -> str:
        if self.duplicate_of:
            return f"duplicate of {self.duplicate_of}"
        if self.error:
            return self.error
        if not self.account:
            return "no account"
        for snapshot in snapshots(self.rate_limits):
            reached = snapshot.get("rateLimitReachedType") if isinstance(snapshot, dict) else None
            if reached:
                return str(reached)
        snapshot = display_snapshot(self.rate_limits)
        for label, window in named_windows(snapshot).items():
            percent = used_percent(window)
            if percent is not None and percent >= 100:
                return f"{label} quota spent"
        if (
            self.account.get("requiresOpenaiAuth")
            and not self.account.get("account")
            and not snapshots(self.rate_limits)
        ):
            return "authentication required"
        return ""

    @property
    def usable(self) -> bool:
        return not self.blocked_reason


@dataclass
class DaemonState:
    socket_path: Path
    account_email: str | None
    unsafe_thread_statuses: list[str]


class RawWebSocket:
    """Minimal client for Codex's raw WebSocket frames over a Unix socket."""

    def __init__(self, sock_path: Path, timeout: float) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(str(sock_path))
        self._handshake()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send_json(self, obj: dict) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        header = bytearray([0x81])
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend([0x80 | 126])
            header.extend(struct.pack("!H", length))
        else:
            header.extend([0x80 | 127])
            header.extend(struct.pack("!Q", length))

        mask = secrets.token_bytes(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
        self.sock.sendall(bytes(header) + mask + masked)

    def _handshake(self) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "\r\n"
        ).encode("ascii")
        self.sock.sendall(request)

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ProbeError("unexpected EOF during websocket handshake")
            response.extend(chunk)
            if len(response) > 65536:
                raise ProbeError("websocket handshake response too large")

        header = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if not header.startswith("HTTP/1.1 101 ") and not header.startswith("HTTP/1.0 101 "):
            raise ProbeError(f"websocket handshake failed: {header}")

    def recv_json(self) -> dict:
        while True:
            frame = self._recv_frame()
            opcode = frame[0]
            payload = frame[1]
            if opcode == 0x8:
                raise ProbeError("server closed websocket")
            if opcode in (0x9, 0xA):
                continue
            if opcode != 0x1:
                raise ProbeError(f"unexpected websocket opcode {opcode}")
            return json.loads(payload.decode("utf-8"))

    def _recv_frame(self) -> tuple[int, bytes]:
        first = self._recvn(2)
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        masked = bool(first[1] & 0x80)
        if length == 126:
            length = struct.unpack("!H", self._recvn(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recvn(8))[0]
        mask = self._recvn(4) if masked else b""
        payload = self._recvn(length)
        if masked:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        return opcode, payload

    def _recvn(self, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            chunk = self.sock.recv(length - len(chunks))
            if not chunk:
                raise ProbeError("unexpected EOF from app-server")
            chunks.extend(chunk)
        return bytes(chunks)


def main() -> int:
    global AUTH_LOCK_FD
    args = parse_args()
    if not args.no_update_check:
        check_for_update()
    codex_home = args.home.expanduser().resolve()
    codex_home.mkdir(parents=True, exist_ok=True)
    # The descriptor is closed on exec, so launched Codex sessions do not keep
    # the lock. Serialize login, probes, recovery and activation together.
    with (codex_home / ".codexpick.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ActivationError("another codexpick operation is still using this Codex home") from exc
        AUTH_LOCK_FD = lock.fileno()
        try:
            return run_selection(args, codex_home)
        finally:
            AUTH_LOCK_FD = None


def run_selection(args: argparse.Namespace, codex_home: Path) -> int:
    auth_path = codex_home / "auth.json"
    if args.delete:
        return delete_account(codex_home, args.delete)
    codex_bin = resolve_codex_bin()
    if args.login:
        return login_subscription(args, codex_home, auth_path, codex_bin)

    candidates = discover_candidates(codex_home)
    if not candidates:
        if args.account or args.check_only or not sys.stdin.isatty():
            print(f"No candidates found in {codex_home}/auth-*.json", file=sys.stderr)
            return 2
        candidates, status = onboard_first_account(
            args, codex_home, auth_path, codex_bin
        )
        if status is not None:
            return status

    forced_candidate = find_candidate(candidates, args.account) if args.account else None
    if args.account and not forced_candidate:
        print(f"No account named {args.account!r} found in {codex_home}/auth-*.json", file=sys.stderr)
        print("Available accounts: " + ", ".join(c.name for c in candidates), file=sys.stderr)
        return 2

    for candidate in candidates:
        finish_probe_auth(candidate, codex_home)
    for candidate in candidates:
        refresh_candidates_from_active_auth(candidate.path, candidates)
    refresh_candidates_from_active_auth(auth_path, candidates)

    # An explicit account choice is authoritative. Switching it should not
    # contact every saved account (or even the selected account) first.
    if forced_candidate and not args.check_only:
        print(f"Selected: {forced_candidate.name}")
        return activate_candidate(args, auth_path, codex_bin, forced_candidate)

    print(
        "Warning: probes may refresh saved login tokens. Concurrent Codex sessions "
        "using the same login may need to sign in again. Avoid probing while they are running.",
        file=sys.stderr, flush=True,
    )
    results = []
    candidates_to_probe = [forced_candidate] if forced_candidate else candidates
    for candidate in candidates_to_probe:
        # Probe a shared session once, but do not hide an independent login
        # for the same account behind an expired alias.
        previous = next((r.candidate.name for r in results
                         if same_auth_session(r.candidate.path, candidate.path)), None)
        if previous:
            results.append(ProbeResult(candidate, duplicate_of=previous))
            continue
        print(f"Probing {candidate.name}...", file=sys.stderr, flush=True)
        result = probe_candidate(candidate, codex_home, codex_bin, args.timeout)
        refresh_candidates_from_active_auth(candidate.path, candidates)
        results.append(result)
        status = display_result_status(result)
        print(f"Probed {candidate.name}: {status}", file=sys.stderr, flush=True)
    mark_duplicate_accounts(results)
    selected = (
        next((r for r in results if r.candidate == forced_candidate), None)
        if forced_candidate
        else select_best_account(results)
    )
    print_table(results, selected)
    print_reauth_hints(results)

    if not selected:
        print("No usable account found; the active account was not switched.", file=sys.stderr)
        if not args.check_only:
            return offer_relogin(args, results, codex_home, auth_path, codex_bin)
        return 1

    print(f"Selected: {selected.candidate.name}")
    if not forced_candidate:
        print(f"Tightest quota window: {quota_score(selected)[0]:g}% remaining.")
    if forced_candidate and selected.blocked_reason:
        print(f"Forced selection despite status: {selected.blocked_reason}")
    if args.check_only:
        return 0

    return activate_candidate(args, auth_path, codex_bin, selected.candidate)


def quota_score(result: ProbeResult) -> tuple[float, float]:
    remaining = [100 - percent for window in named_windows(display_snapshot(result.rate_limits)).values()
                 if (percent := used_percent(window)) is not None]
    if not remaining:
        return (-1, -1)
    return (min(remaining), sum(remaining) / len(remaining))


def select_best_account(results: list[ProbeResult]) -> ProbeResult | None:
    # The tightest window is the first constraint. Unknown quota is not unlimited.
    return max((r for r in results if r.usable and quota_score(r)[0] > 0),
               key=quota_score, default=None)


def needs_relogin(result: ProbeResult) -> bool:
    return is_reauth_error(result.error) or result.blocked_reason == "authentication required"


def offer_relogin(args, results, codex_home, auth_path, codex_bin) -> int:
    expired = [r for r in results if needs_relogin(r) and not r.duplicate_of]
    if not expired or not sys.stdin.isatty():
        return 1
    print("Saved accounts needing login:")
    for index, result in enumerate(expired, 1):
        print(f"  {index}. {result.candidate.name}")
    try:
        answer = input("Log in to one of these accounts? Enter a number or name (Enter to skip): ").strip()
    except EOFError:
        return 1
    chosen = next((r for r in expired if r.candidate.name == answer), None)
    if chosen is None and answer.isdigit() and 1 <= int(answer) <= len(expired):
        chosen = expired[int(answer) - 1]
    if chosen is None:
        return 1
    login_args = argparse.Namespace(**vars(args))
    login_args.login = chosen.candidate.name
    login_args.no_activate = True
    status = login_subscription(login_args, codex_home, auth_path, codex_bin)
    if status:
        return status
    refreshed = probe_candidate(chosen.candidate, codex_home, codex_bin, args.timeout)
    if not select_best_account([refreshed]):
        print(f"Login saved, but no usable quota confirmed: {display_result_status(refreshed)}", file=sys.stderr)
        return 1
    return activate_candidate(args, auth_path, codex_bin, chosen.candidate)


def onboard_first_account(
    args: argparse.Namespace,
    codex_home: Path,
    auth_path: Path,
    codex_bin: Path,
) -> tuple[list[Candidate], int | None]:
    print(f"No saved logins found in {codex_home}.")
    if read_account_id(auth_path):
        try:
            name = input(
                "Name the current working login "
                "(Enter if there is no working login): "
            ).strip()
        except EOFError:
            return [], 2
        if name:
            name = normalize_auth_name(name)
            target_path = codex_home / f"auth-{name}.json"
            switch_auth(target_path, auth_path)
            print(f"Saved the current login as {target_path.name}.")
            return discover_candidates(codex_home), None

    try:
        name = input("Name a new login to create (Enter to cancel): ").strip()
    except EOFError:
        return [], 2
    if not name:
        print("No login created; auth.json was left unchanged.", file=sys.stderr)
        return [], 2

    login_args = argparse.Namespace(**vars(args))
    login_args.login = normalize_auth_name(name)
    return [], login_subscription(
        login_args, codex_home, auth_path, codex_bin
    )


def delete_account(codex_home: Path, name: str) -> int:
    candidate = find_candidate(discover_candidates(codex_home), name)
    if not candidate:
        print(f"No saved account named {name!r}.", file=sys.stderr)
        return 2
    # Export any interrupted renewal before archiving the saved login.
    finish_probe_auth(candidate, codex_home)
    probe_home = saved_probe_home(candidate, codex_home)
    # Keep removal recoverable, and never log out or remove active auth.json.
    trash = codex_home / ".codexpick-trash"
    trash.mkdir(mode=0o700, exist_ok=True)
    target = trash / f"{candidate.path.name}.{time.time_ns()}"
    if probe_home.exists():
        probe_home.rename(target.with_name(target.name + ".probe"))
    candidate.path.rename(target)
    print(f"Removed saved account {name!r}. Active sessions and auth.json were left unchanged.")
    print(f"Recoverable from {target}")
    return 0


def installed_revision() -> str | None:
    source = Path(__file__).resolve().parent
    if (source / ".git").exists():
        result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    try:
        metadata = importlib.metadata.distribution("codexpick").read_text("direct_url.json")
        return json.loads(metadata or "{}").get("vcs_info", {}).get("commit_id")
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return None


def check_for_update() -> None:
    try:
        local = installed_revision()
        if not local:
            return
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        remote = subprocess.run(["git", "ls-remote", REPOSITORY, "HEAD"],
                                capture_output=True, text=True, timeout=2, env=env)
        if remote.returncode == 0 and remote.stdout.split():
            revision = remote.stdout.split()[0]
            if revision != local:
                print(f"codexpick update available: remote {revision[:8]} (installed {local[:8]}). "
                      "Run: pipx upgrade codexpick", file=sys.stderr)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass  # An offline update check must never block account selection.


def activate_candidate(
    args: argparse.Namespace,
    auth_path: Path,
    codex_bin: Path,
    candidate: Candidate,
) -> int:
    try:
        changed, restarted = activate_auth_snapshot(
            auth_path, candidate.path, codex_bin, args.timeout
        )
    except ActivationError as exc:
        print(f"Account switch refused: {exc}", file=sys.stderr)
        return 3
    print("auth.json updated." if changed else "auth.json already matched selected account.")
    if restarted:
        print("Idle Codex app-server restarted with the selected account.")

    if args.no_launch:
        return 0

    launcher = resolve_launcher(args.cmd, codex_bin)
    prepend_binary_dir(os.environ, codex_bin)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(launcher, [launcher, *args.codex_args])
    return 127


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pick the saved Codex account with the most remaining quota."
    )
    parser.add_argument("--check-only", action="store_true", help="probe without switching accounts; Codex may refresh credentials")
    parser.add_argument("--no-launch", action="store_true", help="switch auth.json but do not launch Codex")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("-a", "--account", help="switch to this auth-* account name regardless of quota status")
    action.add_argument("--login", metavar="NAME", help="run remote Codex login and save it as auth-NAME.json")
    action.add_argument("--delete", metavar="NAME", help="remove one saved account (recoverable; leaves active auth alone)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--no-update-check", action="store_true", help="skip the remote revision check")
    parser.add_argument("--no-activate", action="store_true", help="with --login, save the auth snapshot but leave auth.json unchanged")
    parser.add_argument("--cmd", default="codex", help="launcher command for normal mode, e.g. codex or codexaz")
    parser.add_argument("--home", type=Path, default=Path(os.environ.get("CODEXPICK_HOME", DEFAULT_CODEX_HOME)))
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per account probe (default: 10)")
    parser.add_argument("codex_args", nargs=argparse.REMAINDER, help="arguments passed to the launcher")
    args = parser.parse_args()
    if args.timeout <= 0 or not math.isfinite(args.timeout):
        parser.error("--timeout must be a finite positive number")
    if args.no_activate and not args.login:
        parser.error("--no-activate requires --login")
    if args.check_only and (args.login or args.delete):
        parser.error("--check-only cannot be combined with --login or --delete")
    if args.codex_args and args.codex_args[0] == "--":
        args.codex_args = args.codex_args[1:]
    if args.check_only and args.no_launch:
        args.no_launch = True
    return args


def login_subscription(args: argparse.Namespace, codex_home: Path, auth_path: Path, codex_bin: Path) -> int:
    name = normalize_auth_name(args.login)
    target_path = codex_home / f"auth-{name}.json"
    codex_home.mkdir(parents=True, exist_ok=True)

    tmp_root = codex_home / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"codexpick-login-{name}-", dir=tmp_root) as tmp:
        tmp_home = Path(tmp)
        config = codex_home / "config.toml"
        if config.exists():
            shutil.copy2(config, tmp_home / "config.toml")

        env = os.environ.copy()
        env["CODEX_HOME"] = str(tmp_home)
        prepend_binary_dir(env, codex_bin)

        print(f"Starting Codex remote login for {name!r}.")
        print("Follow the browser/device prompts. The existing auth.json will be left alone until login succeeds.")
        sys.stdout.flush()
        completed = subprocess.run([str(codex_bin), "-c", 'cli_auth_credentials_store="file"',
                                    "login", "--device-auth"], env=env, pass_fds=auth_lock_fds())
        if completed.returncode != 0:
            print(f"Login failed with exit code {completed.returncode}; auth files were left unchanged.", file=sys.stderr)
            return completed.returncode

        new_auth = tmp_home / "auth.json"
        if not new_auth.exists():
            print("Login completed but no auth.json was created; auth files were left unchanged.", file=sys.stderr)
            return 1
        if not read_account_id(new_auth):
            print("Login completed but auth.json does not contain an account id; auth files were left unchanged.", file=sys.stderr)
            return 1

        backup_path = backup_existing_auth(target_path, new_auth)
        changed_snapshot = switch_auth(target_path, new_auth)
        # An explicit new login supersedes an interrupted probe, but retain its
        # credentials in a backup before clearing the recovery checkpoint.
        probe_home = saved_probe_home(Candidate(name, target_path), codex_home)
        backup_existing_auth(probe_home / "auth.json", new_auth)
        (probe_home / "source.sha256").unlink(missing_ok=True)
        print(f"{target_path.name} {'updated' if changed_snapshot else 'already matched new login'}.")
        if backup_path:
            print(f"Previous snapshot backed up as {backup_path.name}.")

        if args.no_activate:
            return 0

        try:
            changed_active, restarted = activate_auth_snapshot(
                auth_path, target_path, codex_bin, args.timeout
            )
        except ActivationError as exc:
            print(f"Saved {target_path.name}, but activation was refused: {exc}", file=sys.stderr)
            return 3
        print("auth.json updated." if changed_active else "auth.json already matched new subscription.")
        if restarted:
            print("Idle Codex app-server restarted with the new subscription.")

        if args.no_launch:
            return 0

        launcher = resolve_launcher(args.cmd, codex_bin)
        prepend_binary_dir(os.environ, codex_bin)
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvp(launcher, [launcher, *args.codex_args])
        return 127


def normalize_auth_name(name: str) -> str:
    normalized = name.strip()
    if normalized.startswith("auth-"):
        normalized = normalized[5:]
    if normalized.endswith(".json"):
        normalized = normalized[:-5]
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", normalized).strip(".-")
    if not normalized:
        raise SystemExit("--login requires a non-empty account name")
    return normalized


def backup_existing_auth(path: Path, replacement_path: Path) -> Path | None:
    if not path.exists() or sha256_file(path) == sha256_file(replacement_path):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fd, backup_name = tempfile.mkstemp(prefix=f"{path.name}.bak-{stamp}-", dir=path.parent)
    os.close(fd)
    backup_path = Path(backup_name)
    shutil.copy2(path, backup_path)
    os.chmod(backup_path, 0o600)
    return backup_path


def discover_candidates(codex_home: Path) -> list[Candidate]:
    candidates = []
    for path in sorted(codex_home.glob("auth-*.json")):
        if path.name == "auth.json" or not path.is_file():
            continue
        name = path.stem.removeprefix("auth-")
        candidates.append(Candidate(name=name, path=path))
    return candidates


def find_candidate(candidates: list[Candidate], name: str) -> Candidate | None:
    for candidate in candidates:
        if candidate.name == name:
            return candidate
    return None


def resolve_codex_bin() -> Path:
    if os.environ.get("CODEX_BIN"):
        return Path(os.environ["CODEX_BIN"]).expanduser()
    from_path = shutil.which("codex")
    if from_path:
        return Path(from_path)
    if DEFAULT_CODEX_BIN:
        return Path(DEFAULT_CODEX_BIN).expanduser()
    return Path("codex")


def resolve_launcher(command: str, codex_bin: Path) -> str:
    found = shutil.which(command)
    if found:
        return found
    if command == "codex":
        return str(codex_bin)
    return str(Path(command).expanduser())


def prepend_binary_dir(env: dict[str, str], binary: Path) -> None:
    if os.sep not in str(binary):
        return
    env["PATH"] = str(binary.parent) + os.pathsep + env.get("PATH", "")


def probe_candidate(candidate: Candidate, codex_home: Path, codex_bin: Path, timeout: float) -> ProbeResult:
    active = codex_home / "auth.json"
    active_session = read_session_id(active)
    expected = sha256_file(candidate.path)
    active_tokens = (read_auth_json(active) or {}).get("tokens") or {}
    saved_tokens = (read_auth_json(candidate.path) or {}).get("tokens") or {}
    follows_active = same_auth_session(active, candidate.path) and not auth_is_newer(candidate.path, active) and (
        active_tokens.get("refresh_token") == saved_tokens.get("refresh_token")
        or auth_is_newer(active, candidate.path)
    )
    try:
        account, rate_limits = probe_app_server(candidate, codex_home, codex_bin, timeout)
        return ProbeResult(candidate=candidate, account=account, rate_limits=rate_limits)
    except Exception as exc:
        return ProbeResult(candidate=candidate, error=compact_error(exc))
    finally:
        if (follows_active and sha256_file(candidate.path) == expected
                and (not active_session or read_session_id(active) == active_session)):
            sync_refreshed_auth(active, candidate.path, expected_hash=expected)


def mark_duplicate_accounts(results: list[ProbeResult]) -> None:
    seen: dict[str, str] = {}
    for result in sorted(results, key=lambda r: (r.usable, quota_score(r)), reverse=True):
        account_key = read_account_key(result.candidate.path)
        if not account_key:
            continue
        previous = seen.get(account_key)
        if previous:
            result.duplicate_of = previous
            continue
        seen[account_key] = result.candidate.name


def probe_app_server(candidate: Candidate, codex_home: Path, codex_bin: Path, timeout: float) -> tuple[dict, dict]:
    if not codex_bin.exists() and os.sep in str(codex_bin):
        raise ProbeError(f"codex binary not found: {codex_bin}")

    active_path = codex_home / "auth.json"
    use_active = same_auth_session(active_path, candidate.path)
    if use_active and auth_is_newer(candidate.path, active_path):
        raise ProbeError(f"active credentials are older than {candidate.path.name}; activate that saved account first")
    if use_active and not auth_is_newer(active_path, candidate.path):
        active_tokens = (read_auth_json(active_path) or {}).get("tokens") or {}
        saved_tokens = (read_auth_json(candidate.path) or {}).get("tokens") or {}
        if active_tokens.get("refresh_token") != saved_tokens.get("refresh_token"):
            raise ProbeError("cannot order saved and active refresh tokens; activate the intended saved login first")
    if (
        not use_active
        and read_account_key(active_path) == read_account_key(candidate.path)
        and not (read_session_id(active_path) and read_session_id(candidate.path))
    ):
        raise ProbeError("cannot safely distinguish saved and active login sessions; renew the saved login")

    if use_active:
        daemon = inspect_managed_daemon(codex_home, codex_bin, timeout)
        if daemon:
            active_email = read_auth_email(active_path)
            if not daemon.account_email or not active_email or daemon.account_email.casefold() != active_email.casefold():
                raise ProbeError("the running Codex account differs from auth.json; activate the intended account first")
            ws = RawWebSocket(daemon.socket_path, timeout)
            try:
                return read_account_and_limits(ws, timeout)
            finally:
                ws.close()

    probe_home = codex_home if use_active else prepare_probe_auth(candidate, codex_home)
    # Only the socket is temporary. Keep its path short even for long homes.
    with tempfile.TemporaryDirectory(prefix="codexpick-", ignore_cleanup_errors=True) as tmp:
        tmp_home = Path(tmp)
        sock_path = tmp_home / "app.sock"
        env = os.environ.copy()
        env["CODEX_HOME"] = str(probe_home)
        prepend_binary_dir(env, codex_bin)

        proc = None
        try:
            proc = subprocess.Popen(
                [str(codex_bin), "-c", 'cli_auth_credentials_store="file"',
                 "app-server", "--listen", f"unix://{sock_path}"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=auth_lock_fds(),
            )
            wait_for_socket(proc, sock_path, timeout)
            ws = RawWebSocket(sock_path, timeout)
            try:
                try:
                    return read_account_and_limits(ws, timeout)
                except ProbeError as exc:
                    if not is_method_unavailable(exc):
                        raise
                # Stop the first writer before /status uses the same auth
                # storage. Never start the fallback from the original snapshot.
                stop_process(proc)
                proc = None
                account = {"account": {"email": read_auth_email(probe_home / "auth.json")}}
                rate_limits = fallback_status_probe(candidate, probe_home, codex_bin, timeout)
                return account, rate_limits
            finally:
                ws.close()
        finally:
            if proc is not None:
                stop_process(proc)
            if not use_active:
                finish_probe_auth(candidate, codex_home)


def read_account_and_limits(ws: RawWebSocket, timeout: float) -> tuple[dict, dict]:
    rpc(ws, 1, "initialize", {
        "clientInfo": {"name": "codexpick", "version": VERSION},
        "capabilities": {"experimentalApi": True},
    }, timeout)
    ws.send_json({"method": "initialized"})
    account = rpc(ws, 2, "account/read", {"refreshToken": False}, timeout)
    rate_limits = rpc(ws, 3, "account/rateLimits/read", None, timeout)
    return account, rate_limits


def auth_lock_fds() -> tuple[int, ...]:
    # A surviving probe/login child must keep the lock if its parent dies.
    # Ordinary launched Codex sessions do not inherit this descriptor.
    return (AUTH_LOCK_FD,) if AUTH_LOCK_FD is not None else ()


def saved_probe_home(candidate: Candidate, codex_home: Path) -> Path:
    if candidate.name in ("", ".", "..") or Path(candidate.name).name != candidate.name:
        raise ProbeError(f"invalid saved account name: {candidate.name!r}")
    return codex_home / ".codexpick" / candidate.name


def prepare_probe_auth(candidate: Candidate, codex_home: Path) -> Path:
    """Keep a refreshable copy durable until its result is safely exported."""
    finish_probe_auth(candidate, codex_home)
    probe_home = saved_probe_home(candidate, codex_home)
    probe_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(probe_home.parent, 0o700)
    os.chmod(probe_home, 0o700)
    config = codex_home / "config.toml"
    if config.exists():
        shutil.copy2(config, probe_home / "config.toml")
    else:
        (probe_home / "config.toml").unlink(missing_ok=True)
    switch_auth(probe_home / "auth.json", candidate.path)
    checkpoint = probe_home / "source.sha256"
    with checkpoint.open("w", encoding="ascii") as stream:
        stream.write(sha256_file(probe_home / "auth.json"))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(checkpoint, 0o600)
    return probe_home


def finish_probe_auth(candidate: Candidate, codex_home: Path) -> None:
    """Recover even after a failed RPC or an interrupted previous invocation."""
    probe_home = saved_probe_home(candidate, codex_home)
    checkpoint = probe_home / "source.sha256"
    if not checkpoint.exists():
        return
    refreshed = probe_home / "auth.json"
    expected = checkpoint.read_text(encoding="ascii").strip()
    if not read_account_key(refreshed) or read_account_key(refreshed) != read_account_key(candidate.path):
        raise ProbeError(f"cannot recover {candidate.name}; credentials preserved in {probe_home}")
    current = sha256_file(candidate.path)
    if current != sha256_file(refreshed):
        if current != expected:
            raise ProbeError(f"{candidate.path.name} changed during a probe; both logins preserved in {probe_home}")
        switch_auth(candidate.path, refreshed, expected_hash=expected)
    checkpoint.unlink()


def wait_for_socket(proc: subprocess.Popen, sock_path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sock_path.exists():
            return
        if proc.poll() is not None:
            stderr = read_stderr(proc)
            raise ProbeError(f"app-server exited: {stderr or proc.returncode}")
        time.sleep(0.05)
    raise ProbeError("timed out waiting for app-server socket")


def rpc(ws: RawWebSocket, request_id: int, method: str, params, timeout: float) -> dict:
    ws.sock.settimeout(timeout)
    request = {"id": request_id, "method": method}
    if params is not None:
        request["params"] = params
    ws.send_json(request)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = ws.recv_json()
        if msg.get("id") != request_id:
            continue
        if "error" in msg:
            err = msg["error"]
            raise ProbeError(err.get("message", str(err)) if isinstance(err, dict) else str(err))
        return msg.get("result")
    raise ProbeError(f"timed out waiting for {method}")


def is_method_unavailable(exc: Exception) -> bool:
    text = str(exc).lower()
    return "method not found" in text or "unknown method" in text or "not implemented" in text


def fallback_status_probe(candidate: Candidate, codex_home: Path, codex_bin: Path, timeout: float) -> dict:
    # The caller owns this auth home and has stopped the preceding app-server.
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    prepend_binary_dir(env, codex_bin)
    master_fd, slave_fd = pty.openpty()
    proc = None
    try:
        proc = subprocess.Popen(
            [str(codex_bin), "-c", 'cli_auth_credentials_store="file"', "--no-alt-screen"],
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
            pass_fds=auth_lock_fds(),
        )
        os.close(slave_fd)
        slave_fd = None
        output = bytearray()
        deadline = time.monotonic() + timeout
        sent_status = False
        while time.monotonic() < deadline:
            if not sent_status:
                os.write(master_fd, b"/status\r")
                sent_status = True
            ready, _, _ = select.select([master_fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                text = strip_ansi(output.decode("utf-8", errors="replace"))
                parsed = parse_status_text(text)
                if parsed is not None:
                    return parsed
    finally:
        if slave_fd is not None:
            os.close(slave_fd)
        try:
            os.write(master_fd, b"\x03")
        except OSError:
            pass
        os.close(master_fd)
        if proc is not None:
            stop_process(proc)
    raise ProbeError("rateLimits API unavailable; /status fallback did not produce a usable result")


def parse_status_text(text: str) -> dict | None:
    lowered = text.lower()
    if is_reauth_error(text):
        raise ProbeError("/status requires a new login; authentication token is invalid")
    blocked_terms = [
        ("workspace_member_credits_depleted", "member credits depleted"),
        ("workspace_owner_credits_depleted", "owner credits depleted"),
        ("workspace_member_usage_limit_reached", "member usage limit reached"),
        ("workspace_owner_usage_limit_reached", "owner usage limit reached"),
        ("rate_limit_reached", "rate limit reached"),
        ("credit_limit_reached", "credit limit"),
        ("usage_limit_reached", "usage limit"),
    ]
    for reason, needle in blocked_terms:
        if needle in lowered:
            return {"rateLimits": {"rateLimitReachedType": reason}}
    if any(token in lowered for token in ("account", "plan", "status", "usage", "quota")):
        return {"rateLimits": {"rateLimitReachedType": None}}
    return None


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        terminate_process_group(proc, signal.SIGTERM)
    try:
        proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        terminate_process_group(proc, signal.SIGKILL)
        proc.communicate()


def terminate_process_group(proc: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    except OSError:
        if sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()


def read_stderr(proc: subprocess.Popen) -> str:
    try:
        _, stderr = proc.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        return ""
    return stderr.decode("utf-8", errors="replace").strip().splitlines()[-1] if stderr else ""


def snapshots(rate_limits: dict | None) -> list[dict]:
    if not isinstance(rate_limits, dict):
        return []
    out = []
    primary = rate_limits.get("rateLimits")
    if isinstance(primary, dict):
        out.append(primary)
    by_id = rate_limits.get("rateLimitsByLimitId")
    if isinstance(by_id, dict):
        for value in by_id.values():
            if isinstance(value, dict) and value not in out:
                out.append(value)
    return out


def display_snapshot(rate_limits: dict | None) -> dict:
    all_snapshots = snapshots(rate_limits)
    if not all_snapshots:
        return {}
    for snapshot in all_snapshots:
        if snapshot.get("limitId") == "codex":
            return snapshot
    return all_snapshots[0]


def named_windows(snapshot: dict) -> dict[str, dict]:
    """Name quota windows by duration, never by their primary/secondary slot."""
    windows = {}
    for slot in ("primary", "secondary"):
        window = snapshot.get(slot)
        if not isinstance(window, dict):
            continue
        minutes = window.get("windowDurationMins")
        if type(minutes) is not int or minutes <= 0:
            label = f"{slot} (duration unknown)"
        elif minutes == 10080:
            label = "weekly"
        elif minutes % 1440 == 0:
            label = f"{minutes // 1440}d"
        elif minutes % 60 == 0:
            label = f"{minutes // 60}h"
        else:
            label = f"{minutes}m"
        if label in windows:
            label = f"{label} ({slot})"
        windows[label] = window
    return windows


def print_table(results: list[ProbeResult], selected: ProbeResult | None) -> None:
    labels = ["5h", "weekly"]
    account_windows = [named_windows(display_snapshot(r.rate_limits)) for r in results]
    for windows in account_windows:
        for label in windows:
            if label not in labels:
                labels.append(label)
    rows = []
    for result, windows in zip(results, account_windows):
        snap = display_snapshot(result.rate_limits)
        account = result.account.get("account") if result.account else None
        plan = snap.get("planType") or (account or {}).get("planType") or "-"
        rows.append([
            "*" if selected is result else " ",
            result.candidate.name,
            str(plan),
            *(fmt_percent(windows.get(label)) for label in labels),
            *(fmt_reset(windows.get(label)) for label in labels),
            display_result_status(result),
        ])

    headers = ["", "account", "plan", *(f"{label} used" for label in labels),
               *(f"{label} reset" for label in labels), "status"]
    widths = [max(len(str(row[i])) for row in [headers, *rows]) for i in range(len(headers))]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(row))))


def display_result_status(result: ProbeResult, max_length: int = 52) -> str:
    reason = result.blocked_reason or ("ok" if quota_score(result)[0] >= 0 else "quota unknown")
    if result.error and is_reauth_error(result.error):
        return "reauth required"
    if len(reason) <= max_length:
        return reason
    return reason[: max_length - 3].rstrip() + "..."


def is_reauth_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    auth_markers = (
        "token_invalidated",
        "unauthorized_unknown",
        "authentication token has been invalidated",
        "could not parse your authentication token",
        "try signing in again",
        "refresh_token_expired",
        "refresh_token_reused",
        "refresh_token_invalidated",
        "refresh token was already used",
        "authentication token is invalid",
        "token_expired",
        "token has expired",
        "401 unauthorized",
        "authentication required",
    )
    return any(marker in lowered for marker in auth_markers)


def print_reauth_hints(results: list[ProbeResult]) -> None:
    affected = [result.candidate.name for result in results if needs_relogin(result)]
    if not affected:
        return
    print("\nRenew saved login(s) without changing the active Codex account:")
    for name in affected:
        print(f"  codexpick --login {shlex.quote(name)} --no-activate")


def fmt_percent(window) -> str:
    percent = used_percent(window)
    if percent is None:
        return "-"
    return f"{percent:g}%"


def used_percent(window) -> float | None:
    if not isinstance(window, dict) or window.get("usedPercent") is None:
        return None
    try:
        value = float(window["usedPercent"])
        return value if math.isfinite(value) and value >= 0 else None
    except (TypeError, ValueError):
        return None


def fmt_reset(window) -> str:
    if not isinstance(window, dict) or not window.get("resetsAt"):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(window["resetsAt"])))


def switch_auth(
    auth_path: Path,
    selected_path: Path,
    expected_hash: str | None = None,
    expected_source_hash: str | None = None,
) -> bool:
    selected_data = selected_path.read_bytes()
    selected_hash = hashlib.sha256(selected_data).hexdigest()
    if expected_source_hash is not None and selected_hash != expected_source_hash:
        raise ActivationError(f"{selected_path.name} changed during the operation; refusing to copy stale credentials")
    if auth_path.exists() and sha256_file(auth_path) == selected_hash:
        return False

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".auth.", suffix=".json", dir=auth_path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as fh:
            fh.write(selected_data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        if not read_account_key(tmp_path):
            raise ActivationError(f"{selected_path.name} does not contain a valid saved account")
        if sha256_file(selected_path) != selected_hash:
            raise ActivationError(f"{selected_path.name} changed during the operation; refusing to copy stale credentials")
        if expected_hash is not None:
            current_hash = sha256_file(auth_path) if auth_path.exists() else ""
            if current_hash != expected_hash:
                raise ActivationError(f"{auth_path.name} changed during the operation; refusing to overwrite it")
        os.replace(tmp_path, auth_path)
        dir_fd = os.open(auth_path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return True
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def activate_auth_snapshot(
    auth_path: Path,
    selected_path: Path,
    codex_bin: Path,
    timeout: float,
) -> tuple[bool, bool]:
    """Install an auth snapshot and safely synchronize a managed app-server.

    A long-lived app-server caches managed ChatGPT credentials. Replacing
    auth.json without restarting that server leaves Codex on the old account.
    Never restart while a turn is active, and never change auth.json if the
    daemon cannot be inspected safely.
    """
    daemon = inspect_managed_daemon(auth_path.parent, codex_bin, timeout)
    selected_email = read_auth_email(selected_path)
    daemon_matches = bool(
        daemon
        and daemon.account_email
        and selected_email
        and daemon.account_email.casefold() == selected_email.casefold()
        and read_account_key(auth_path) == read_account_key(selected_path)
    )
    credentials_changed = not auth_path.exists() or sha256_file(auth_path) != sha256_file(selected_path)
    restart_required = bool(daemon and (credentials_changed or not daemon_matches))

    if restart_required and daemon.unsafe_thread_statuses:
        active = sum(status == "active" for status in daemon.unsafe_thread_statuses)
        detail = (
            f"{active} active turn(s)"
            if active
            else "loaded threads with an unknown or unsafe status"
        )
        raise ActivationError(
            f"the shared Codex app-server must reload credentials and has {detail}; "
            "the active account was not switched. Finish those turns and run codexpick again"
        )

    if restart_required or not auth_path.exists() or sha256_file(auth_path) != sha256_file(selected_path):
        print(
            "Warning: switching shared auth.json can affect currently running Codex sessions; "
            "they may need to reconnect or sign in again."
            + (" The idle shared app-server will be restarted." if restart_required else ""),
            file=sys.stderr, flush=True,
        )

    if restart_required:
        # Freeze the writer before saving the outgoing session. Restarting only
        # after replacement allows the old daemon to refresh over the new login.
        run_daemon_command(auth_path.parent, codex_bin, timeout, "stop")

    previous_path = None
    previous_existed = auth_path.exists()
    changed = False
    recovery_error = None
    installed_hash = None
    expected_active = None
    try:
        refresh_candidates_from_active_auth(auth_path, discover_candidates(auth_path.parent))
        expected_active = sha256_file(auth_path) if auth_path.exists() else ""
        if restart_required and previous_existed:
            fd, previous_name = tempfile.mkstemp(
                prefix=".auth.codexpick-rollback.", suffix=".json", dir=auth_path.parent
            )
            os.close(fd)
            previous_path = Path(previous_name)
            shutil.copy2(auth_path, previous_path)
            os.chmod(previous_path, 0o600)
        installed_hash = sha256_file(selected_path)
        changed = switch_auth(auth_path, selected_path, expected_hash=expected_active)
        if not restart_required:
            return changed, False

        restart_managed_daemon(auth_path.parent, codex_bin, selected_email, timeout)
        return changed, True
    except Exception as exc:
        if restart_required:
            try:
                run_daemon_command(auth_path.parent, codex_bin, timeout, "stop")
                current_hash = sha256_file(auth_path) if auth_path.exists() else ""
                # Directory fsync can fail after the atomic replacement has
                # already succeeded, before switch_auth returns its result.
                if installed_hash and current_hash == installed_hash and current_hash != expected_active:
                    changed = True
                if changed:
                    # A failed startup may already have refreshed the selected
                    # session. Save it before restoring the outgoing account.
                    if current_hash != installed_hash:
                        if not same_auth_session(auth_path, selected_path):
                            raise ActivationError("auth.json changed to another login; automatic rollback refused")
                        sync_refreshed_auth(auth_path, selected_path, expected_hash=installed_hash)
                    if previous_path:
                        switch_auth(auth_path, previous_path, expected_hash=current_hash)
                    elif not previous_existed:
                        auth_path.unlink(missing_ok=True)
                run_daemon_restart(auth_path.parent, codex_bin, timeout)
            except Exception as recovery_exc:
                recovery_error = compact_error(recovery_exc)
        message = compact_error(exc)
        if recovery_error:
            message += f"; restoring the previous daemon state also failed: {recovery_error}"
            if previous_path:
                message += f"; outgoing credentials preserved in {previous_path}"
        action = "reload" if restart_required else "install"
        raise ActivationError(f"could not {action} the selected account ({message})") from exc
    finally:
        if previous_path and not recovery_error:
            previous_path.unlink(missing_ok=True)


def inspect_managed_daemon(
    codex_home: Path,
    codex_bin: Path,
    timeout: float,
) -> DaemonState | None:
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    try:
        completed = subprocess.run(
            [str(codex_bin), "app-server", "daemon", "version"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(3.0, min(timeout, 10.0)),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationError(f"could not inspect the Codex app-server: {compact_error(exc)}") from exc

    fallback_socket = codex_home / "app-server-control" / "app-server-control.sock"
    if completed.returncode != 0:
        if fallback_socket.exists():
            if not unix_socket_is_listening(fallback_socket):
                return None
            detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else completed.returncode
            raise ActivationError(f"could not inspect the running Codex app-server: {detail}")
        # Older Codex installations do not have a managed daemon. In that
        # case the next ordinary Codex process reads auth.json at startup.
        return None

    info = parse_last_json_object(completed.stdout)
    if not info:
        if fallback_socket.exists():
            raise ActivationError("the Codex daemon returned an unreadable status")
        return None
    if info.get("status") != "running":
        return None

    socket_value = info.get("socketPath")
    sock_path = Path(socket_value) if isinstance(socket_value, str) and socket_value else fallback_socket
    if not sock_path.exists():
        raise ActivationError(f"the Codex daemon reports a missing control socket: {sock_path}")

    try:
        ws = RawWebSocket(sock_path, timeout)
        try:
            rpc(ws, 101, "initialize", {
                "clientInfo": {"name": "codexpick", "version": VERSION},
                "capabilities": {"experimentalApi": True},
            }, timeout)
            ws.send_json({"method": "initialized"})
            account_result = rpc(ws, 102, "account/read", {"refreshToken": False}, timeout) or {}
            account = account_result.get("account") or {}
            account_email = account.get("email") if isinstance(account, dict) else None
            if not isinstance(account_email, str) or not account_email:
                account_email = None

            loaded = rpc(ws, 103, "thread/loaded/list", {}, timeout) or {}
            thread_ids = loaded.get("data") if isinstance(loaded, dict) else None
            if not isinstance(thread_ids, list):
                raise ProbeError("thread/loaded/list returned an invalid response")

            unsafe_statuses = []
            for offset, thread_id in enumerate(thread_ids, 104):
                result = rpc(
                    ws,
                    offset,
                    "thread/read",
                    {"threadId": thread_id, "includeTurns": False},
                    timeout,
                ) or {}
                thread = result.get("thread") if isinstance(result, dict) else None
                status = thread.get("status") if isinstance(thread, dict) else None
                status_type = status.get("type") if isinstance(status, dict) else None
                if status_type not in {"idle", "notLoaded", "systemError"}:
                    unsafe_statuses.append(status_type or "unknown")
            return DaemonState(sock_path, account_email, unsafe_statuses)
        finally:
            ws.close()
    except ActivationError:
        raise
    except Exception as exc:
        raise ActivationError(f"could not safely inspect loaded Codex turns: {compact_error(exc)}") from exc


def unix_socket_is_listening(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        probe.connect(str(path))
        return True
    except (ConnectionRefusedError, FileNotFoundError):
        return False
    except OSError:
        # Permission errors and other unknown failures cannot prove the daemon
        # is stopped, so keep the conservative refusal behavior.
        return True
    finally:
        probe.close()


def restart_managed_daemon(
    codex_home: Path,
    codex_bin: Path,
    selected_email: str | None,
    timeout: float,
) -> None:
    run_daemon_restart(codex_home, codex_bin, timeout)
    restarted = inspect_managed_daemon(codex_home, codex_bin, timeout)
    if not restarted:
        raise ActivationError("Codex app-server did not come back after restart")
    if selected_email:
        if not restarted.account_email:
            raise ActivationError("restarted Codex app-server did not load the selected account")
        if restarted.account_email.casefold() != selected_email.casefold():
            raise ActivationError("restarted Codex app-server loaded a different account")


def run_daemon_restart(codex_home: Path, codex_bin: Path, timeout: float) -> None:
    run_daemon_command(codex_home, codex_bin, timeout, "restart")


def run_daemon_command(codex_home: Path, codex_bin: Path, timeout: float, command: str) -> None:
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    try:
        completed = subprocess.run(
            [str(codex_bin), "app-server", "daemon", command],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(10.0, timeout),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationError(f"Codex daemon {command} failed: {compact_error(exc)}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or str(completed.returncode)
        raise ActivationError(f"Codex daemon {command} failed: {compact_error(Exception(detail))}")


def parse_last_json_object(text: str) -> dict | None:
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def refresh_candidates_from_active_auth(auth_path: Path, candidates: list[Candidate]) -> None:
    active_account_key = read_account_key(auth_path)
    if not active_account_key:
        return
    expected_source = sha256_file(auth_path)
    for candidate in candidates:
        if candidate.path == auth_path:
            continue
        expected = sha256_file(candidate.path)
        if same_auth_session(auth_path, candidate.path) and auth_is_newer(auth_path, candidate.path):
            sync_refreshed_auth(auth_path, candidate.path, expected_hash=expected, expected_source_hash=expected_source)


def sync_refreshed_auth(
    source_path: Path,
    target_path: Path,
    expected_hash: str | None = None,
    expected_source_hash: str | None = None,
) -> bool:
    if not source_path.exists() or not target_path.exists():
        return False
    source_key = read_account_key(source_path)
    if not source_key or source_key != read_account_key(target_path):
        return False
    if sha256_file(source_path) == sha256_file(target_path):
        return False
    return switch_auth(target_path, source_path, expected_hash=expected_hash, expected_source_hash=expected_source_hash)


def read_session_id(path: Path) -> str | None:
    data = read_auth_json(path) or {}
    tokens = data.get("tokens") or {}
    for token, claim in (("access_token", "session_id"), ("id_token", "sid")):
        value = read_token_claims(tokens.get(token)).get(claim)
        if isinstance(value, str) and value:
            return value
    return None


def same_auth_session(left: Path, right: Path) -> bool:
    key = read_account_key(left)
    if not key or key != read_account_key(right):
        return False
    left_session, right_session = read_session_id(left), read_session_id(right)
    if left_session and right_session:
        return left_session == right_session
    left_tokens = (read_auth_json(left) or {}).get("tokens") or {}
    right_tokens = (read_auth_json(right) or {}).get("tokens") or {}
    refresh = left_tokens.get("refresh_token")
    return bool(refresh and refresh == right_tokens.get("refresh_token")) or sha256_file(left) == sha256_file(right)


def auth_is_newer(source: Path, target: Path) -> bool:
    """Compare refresh generations of the same session, never file mtimes."""
    if not same_auth_session(source, target):
        return False

    def generation(path: Path) -> tuple[float, float]:
        data = read_auth_json(path) or {}
        tokens = data.get("tokens") or {}
        issued = read_token_claims(tokens.get("access_token")).get("iat")
        try:
            timestamp = data.get("last_refresh", "").replace("Z", "+00:00")
            timestamp = re.sub(r"(\.\d{6})\d+", r"\1", timestamp)
            refreshed = datetime.datetime.fromisoformat(timestamp)
            refresh_time = refreshed.timestamp() if refreshed.tzinfo else 0.0
        except (ValueError, TypeError, AttributeError):
            refresh_time = 0.0
        return (float(issued) if isinstance(issued, (float, int)) else 0.0, refresh_time)

    return generation(source) > generation(target)


def read_account_key(path: Path) -> str | None:
    data = read_auth_json(path)
    if not isinstance(data, dict):
        return None
    tokens = data.get("tokens", {})
    if not isinstance(tokens, dict):
        return None

    account_id = tokens.get("account_id")
    user_id = read_token_user_id(tokens.get("access_token")) or read_token_user_id(tokens.get("id_token"))
    if isinstance(account_id, str) and account_id and isinstance(user_id, str) and user_id:
        return f"{account_id}:{user_id}"
    if isinstance(account_id, str) and account_id:
        return account_id
    return None


def read_account_id(path: Path) -> str | None:
    data = read_auth_json(path)
    account_id = data.get("tokens", {}).get("account_id") if isinstance(data, dict) else None
    return account_id if isinstance(account_id, str) and account_id else None


def read_auth_email(path: Path) -> str | None:
    data = read_auth_json(path)
    tokens = data.get("tokens", {}) if isinstance(data, dict) else {}
    if not isinstance(tokens, dict):
        return None
    for name in ("id_token", "access_token"):
        claims = read_token_claims(tokens.get(name))
        email = claims.get("email") if isinstance(claims, dict) else None
        if isinstance(email, str) and email:
            return email
        profile = claims.get("https://api.openai.com/profile", {}) if isinstance(claims, dict) else {}
        email = profile.get("email") if isinstance(profile, dict) else None
        if isinstance(email, str) and email:
            return email
    return None


def read_auth_json(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def read_token_user_id(token) -> str | None:
    claims = read_token_claims(token)
    if not claims:
        return None
    auth_claims = claims.get("https://api.openai.com/auth", {})
    if isinstance(auth_claims, dict):
        for key in ("chatgpt_user_id", "user_id"):
            value = auth_claims.get(key)
            if isinstance(value, str) and value:
                return value
    value = claims.get("sub")
    return value if isinstance(value, str) and value else None


def read_token_claims(token) -> dict:
    if not isinstance(token, str):
        return {}
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact_error(exc: Exception) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    return " ".join(message.split())


def run() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except (ActivationError, ProbeError) as exc:
        print(f"Account operation refused: {compact_error(exc)}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(run())
