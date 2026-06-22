#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import pty
import re
import select
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
DEFAULT_CODEX_BIN = os.environ.get("CODEX_BIN")
VERSION = "0.1.0"


class ProbeError(Exception):
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
        short_window = used_percent(snapshot.get("primary"))
        if short_window is None:
            return "5h usage missing"
        if short_window >= 100:
            return "5h quota spent"
        weekly = used_percent(snapshot.get("secondary"))
        if weekly is None:
            return "weekly usage missing"
        if weekly >= 100:
            return "weekly quota spent"
        if self.account.get("requiresOpenaiAuth") and not self.account.get("account"):
            return ""
        return ""

    @property
    def usable(self) -> bool:
        return not self.blocked_reason


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
    args = parse_args()
    codex_home = args.home.expanduser().resolve()
    auth_path = codex_home / "auth.json"
    codex_bin = resolve_codex_bin()
    if args.login:
        return login_subscription(args, codex_home, auth_path, codex_bin)

    candidates = discover_candidates(codex_home)
    if not candidates:
        print(f"No candidates found in {codex_home}/auth-*.json", file=sys.stderr)
        return 2

    refresh_candidates_from_active_auth(auth_path, candidates)
    results = []
    for candidate in candidates:
        print(f"Probing {candidate.name}...", file=sys.stderr, flush=True)
        result = probe_candidate(candidate, codex_home, codex_bin, args.timeout)
        results.append(result)
        status = result.blocked_reason or "ok"
        print(f"Probed {candidate.name}: {status}", file=sys.stderr, flush=True)
    mark_duplicate_accounts(results)
    forced_candidate = find_candidate(candidates, args.account) if args.account else None
    if args.account and not forced_candidate:
        print(f"No account named {args.account!r} found in {codex_home}/auth-*.json", file=sys.stderr)
        print("Available accounts: " + ", ".join(c.name for c in candidates), file=sys.stderr)
        return 2
    selected = (
        next((r for r in results if r.candidate == forced_candidate), None)
        if forced_candidate
        else next((r for r in results if r.usable), None)
    )
    print_table(results, selected)

    if not selected:
        print("No usable account found; auth.json was left unchanged.", file=sys.stderr)
        return 1

    print(f"Selected: {selected.candidate.name}")
    if forced_candidate and selected.blocked_reason:
        print(f"Forced selection despite status: {selected.blocked_reason}")
    if args.check_only:
        return 0

    changed = switch_auth(auth_path, selected.candidate.path)
    print("auth.json updated." if changed else "auth.json already matched selected account.")

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
        description="Pick the first auth-*.json account whose live Codex quota is not blocked."
    )
    parser.add_argument("--check-only", action="store_true", help="probe and report without changing auth.json")
    parser.add_argument("--no-launch", action="store_true", help="switch auth.json but do not launch Codex")
    parser.add_argument("-a", "--account", help="switch to this auth-* account name regardless of quota status")
    parser.add_argument("--login", metavar="NAME", help="run remote Codex login and save it as auth-NAME.json")
    parser.add_argument("--no-activate", action="store_true", help="with --login, save the auth snapshot but leave auth.json unchanged")
    parser.add_argument("--cmd", default="codex", help="launcher command for normal mode, e.g. codex or codexaz")
    parser.add_argument("--home", type=Path, default=Path(os.environ.get("CODEXPICK_HOME", DEFAULT_CODEX_HOME)))
    parser.add_argument("--timeout", type=float, default=20.0, help="seconds per account probe")
    parser.add_argument("codex_args", nargs=argparse.REMAINDER, help="arguments passed to the launcher")
    args = parser.parse_args()
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
        completed = subprocess.run([str(codex_bin), "login", "--device-auth"], env=env)
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
        print(f"{target_path.name} {'updated' if changed_snapshot else 'already matched new login'}.")
        if backup_path:
            print(f"Previous snapshot backed up as {backup_path.name}.")

        if args.no_activate:
            return 0

        changed_active = switch_auth(auth_path, target_path)
        print("auth.json updated." if changed_active else "auth.json already matched new subscription.")

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
    backup_path = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup_path)
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
    try:
        account, rate_limits = probe_app_server(candidate, codex_home, codex_bin, timeout)
        return ProbeResult(candidate=candidate, account=account, rate_limits=rate_limits)
    except Exception as exc:
        return ProbeResult(candidate=candidate, error=compact_error(exc))


def mark_duplicate_accounts(results: list[ProbeResult]) -> None:
    seen: dict[str, str] = {}
    for result in results:
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

    tmp_root = codex_home / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="codexpick-", dir=tmp_root) as tmp:
        tmp_home = Path(tmp)
        config = codex_home / "config.toml"
        if config.exists():
            shutil.copy2(config, tmp_home / "config.toml")
        shutil.copy2(candidate.path, tmp_home / "auth.json")

        sock_path = tmp_home / "app.sock"
        env = os.environ.copy()
        env["CODEX_HOME"] = str(tmp_home)
        prepend_binary_dir(env, codex_bin)

        proc = subprocess.Popen(
            [str(codex_bin), "app-server", "--listen", f"unix://{sock_path}"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_for_socket(proc, sock_path, timeout)
            ws = RawWebSocket(sock_path, timeout)
            try:
                rpc(ws, 1, "initialize", {
                    "clientInfo": {"name": "codexpick", "version": VERSION},
                    "capabilities": {"experimentalApi": True},
                }, timeout)
                ws.send_json({"method": "initialized"})
                account = rpc(ws, 2, "account/read", {"refreshToken": True}, timeout)
                try:
                    rate_limits = rpc(ws, 3, "account/rateLimits/read", None, timeout)
                except ProbeError as exc:
                    if not is_method_unavailable(exc):
                        raise
                    rate_limits = fallback_status_probe(candidate, codex_home, codex_bin, timeout)
                sync_refreshed_auth(tmp_home / "auth.json", candidate.path)
                return account, rate_limits
            finally:
                ws.close()
        finally:
            stop_process(proc)


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
    tmp_root = codex_home / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="codexpick-status-", dir=tmp_root) as tmp:
        tmp_home = Path(tmp)
        config = codex_home / "config.toml"
        if config.exists():
            shutil.copy2(config, tmp_home / "config.toml")
        shutil.copy2(candidate.path, tmp_home / "auth.json")

        env = os.environ.copy()
        env["CODEX_HOME"] = str(tmp_home)
        prepend_binary_dir(env, codex_bin)

        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            [str(codex_bin), "--no-alt-screen"],
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)
        output = bytearray()
        try:
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
            try:
                os.write(master_fd, b"\x03")
            except OSError:
                pass
            os.close(master_fd)
            stop_process(proc)
    raise ProbeError("rateLimits API unavailable; /status fallback did not produce a usable result")


def parse_status_text(text: str) -> dict | None:
    lowered = text.lower()
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
        proc.terminate()
    try:
        proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


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


def print_table(results: list[ProbeResult], selected: ProbeResult | None) -> None:
    rows = []
    for result in results:
        snap = display_snapshot(result.rate_limits)
        account = result.account.get("account") if result.account else None
        plan = snap.get("planType") or (account or {}).get("planType") or "-"
        rows.append([
            "*" if selected is result else " ",
            result.candidate.name,
            str(plan),
            fmt_percent(snap.get("primary")),
            fmt_percent(snap.get("secondary")),
            fmt_reset(snap.get("primary")),
            fmt_reset(snap.get("secondary")),
            result.blocked_reason or "ok",
        ])

    headers = ["", "account", "plan", "5h used", "weekly used", "5h reset", "weekly reset", "status"]
    widths = [max(len(str(row[i])) for row in [headers, *rows]) for i in range(len(headers))]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(row))))


def fmt_percent(window) -> str:
    percent = used_percent(window)
    if percent is None:
        return "-"
    return f"{percent}%"


def used_percent(window) -> int | None:
    if not isinstance(window, dict) or window.get("usedPercent") is None:
        return None
    try:
        return int(window["usedPercent"])
    except (TypeError, ValueError):
        return None


def fmt_reset(window) -> str:
    if not isinstance(window, dict) or not window.get("resetsAt"):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(window["resetsAt"])))


def switch_auth(auth_path: Path, selected_path: Path) -> bool:
    selected_hash = sha256_file(selected_path)
    if auth_path.exists() and sha256_file(auth_path) == selected_hash:
        return False

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".auth.", suffix=".json", dir=auth_path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as fh, selected_path.open("rb") as src:
            shutil.copyfileobj(src, fh)
            fh.flush()
            os.fsync(fh.fileno())
        mode = stat.S_IMODE(selected_path.stat().st_mode)
        os.chmod(tmp_path, mode)
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


def refresh_candidates_from_active_auth(auth_path: Path, candidates: list[Candidate]) -> None:
    active_account_key = read_account_key(auth_path)
    if not active_account_key:
        return
    for candidate in candidates:
        if candidate.path == auth_path:
            continue
        if read_account_key(candidate.path) == active_account_key:
            sync_refreshed_auth(auth_path, candidate.path)


def sync_refreshed_auth(source_path: Path, target_path: Path) -> bool:
    if not source_path.exists() or not target_path.exists():
        return False
    if read_account_key(source_path) != read_account_key(target_path):
        return False
    if sha256_file(source_path) == sha256_file(target_path):
        return False
    return switch_auth(target_path, source_path)


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


def read_auth_json(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def read_token_user_id(token) -> str | None:
    if not isinstance(token, str):
        return None
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    auth_claims = claims.get("https://api.openai.com/auth", {})
    if isinstance(auth_claims, dict):
        for key in ("chatgpt_user_id", "user_id"):
            value = auth_claims.get(key)
            if isinstance(value, str) and value:
                return value
    value = claims.get("sub")
    return value if isinstance(value, str) and value else None


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


if __name__ == "__main__":
    raise SystemExit(run())
