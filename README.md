# codexpick

`codexpick` probes local Codex auth snapshots, selects the account with the most remaining quota, switches `auth.json`, and launches Codex.

Selection maximizes the remaining percentage in the account's tightest reported
quota window. For example, an account with 70% short-term and 60% weekly remaining
beats one with 100% short-term but only 5% weekly remaining. Ties prefer the higher
average remaining percentage, then the existing account order. Unknown quota is
never treated as unlimited. Percentages are a practical estimate: different plan
capacities, model costs, future usage, and upcoming resets mean they cannot predict
an exact time until throttling.

## Requirements

- Python 3.10+
- Codex CLI available as `codex` on your `PATH`, or set `CODEX_BIN`
- Local auth snapshots named `auth-NAME.json` in your Codex home directory

## Files this repo intentionally does not include

Do not commit real Codex auth files, logs, SQLite state, or local `.env` files. The `.gitignore` excludes `auth*.json`, `.env`, `*.sqlite`, and logs.

## Install

Recommended with `pipx`:

```bash
pipx install git+ssh://git@github.com/franchesoni/codexpick.git
```

From a local clone:

```bash
git clone git@github.com:franchesoni/codexpick.git
cd codexpick
pipx install .
```

For development:

```bash
git clone git@github.com:franchesoni/codexpick.git
cd codexpick
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

You can also run the local wrapper directly:

```bash
./codexpick --help
```

## Configure

`codexpick` does not require a config file. Export environment variables only if you need custom paths.

On the first interactive run, if no named snapshots exist, `codexpick` asks you
to name the current working `auth.json`. If you have no working login, leave that
prompt blank; it then asks for a name and starts a new device login. Check-only
and noninteractive runs do not prompt.

Variables:

- `CODEXPICK_HOME`: directory containing `auth.json` and `auth-*.json`; defaults to `~/.codex`.
- `CODEX_BIN`: exact Codex CLI binary; defaults to `codex` on `PATH`.

Example:

```bash
export CODEXPICK_HOME=~/.codex
export CODEX_BIN=/path/to/codex
```

## Usage

Check accounts without switching the active account:

```bash
codexpick --check-only
```

Quota columns use each window's `windowDurationMins`, not its
`primary`/`secondary` position. A weekly-only account therefore has `-` in the
5h columns and its usage/reset in the weekly columns. `-` means the window was
not reported; other durations (or windows with unknown duration) get separate
columns.

Switch to the account with the most quota and launch Codex:

```bash
codexpick
```

Switch without launching:

```bash
codexpick --no-launch
```

If a managed Codex app-server is running, `codexpick` checks its in-memory
account before changing `auth.json`. An idle daemon is stopped before replacement
and restarted with the selected credentials, including a new login for the same
account. If any loaded turn is active (or cannot be verified safe), the switch
is refused. Quota checks may still refresh the current account's credentials.

Before probing or switching, warnings explain possible effects on existing
sessions. Login uses a temporary Codex home; probes use the active home or a
persistent home for an inactive login. New processes use file credential storage,
so they do not write to the OS credential store. Probes avoid requesting a forced
refresh, but Codex can still refresh tokens automatically. Refreshed credentials
are saved even when quota lookup fails. Existing sessions sharing those tokens
may need to reconnect or log in again; avoid probing during important running work.
Changing shared `auth.json` also prints a warning before the change, and an idle
shared daemon may restart. This is a shared-auth workflow, not full session isolation.

The default probe timeout is **10 seconds** (previously 20); override it with
`--timeout SECONDS`. If no account has confirmed usable quota and saved logins
have expired, interactive runs offer a numbered login choice. Enter skips it.
After login, quota is checked again before activation. `--check-only` and
noninteractive runs never prompt for login.

Every normal invocation checks the remote Git HEAD, with a two-second network
timeout, and reports a different revision even if the package version has not
changed. It never updates automatically. Git installations and repository
checkouts support this check; `--no-update-check` skips it. Offline checks are
nonfatal. To update a Git installation:

```bash
pipx upgrade codexpick
```

Remove one saved account:

```bash
codexpick --delete NAME
```

This recovers any pending probe renewal, then moves `auth-NAME.json` to
`.codexpick-trash` under the Codex home and prints its recovery path. Its private
probe home, if present, is archived alongside it with a `.probe` suffix. Active
credentials and other accounts are left alone. Recovery conflicts refuse
deletion and preserve both logins. Deletion does not revoke credentials or sign
out existing sessions. To restore it, move the printed file back to `auth-NAME.json`.

Force a named account from `auth-NAME.json`:

```bash
codexpick --account NAME
```

Log in a new subscription, save it as `auth-NAME.json`, and make it active
without launching a new Codex session:

```bash
codexpick --login NAME --no-launch
```

Renew or add a saved login without making it the active account:

```bash
codexpick --login NAME --no-activate
```

## Authentication lifecycle

Quota checks allow Codex's normal token renewal; they do not force a refresh.
For the active login, checks reuse the managed app-server when available, or
run against the actual Codex home. A refresh therefore reaches `auth.json`
directly. Saved snapshots of that session are updated without replacing a
different login for the same account or restoring an older token generation.

Inactive logins use a private, persistent `.codexpick/NAME/` directory inside
the Codex home. Its `auth.json` preserves renewals even when the quota RPC or
the `/status` fallback fails. A `source.sha256` checkpoint permits recovery on
the next invocation and prevents overwriting a snapshot changed during the
probe. Do not remove this directory while recovery is pending. A conflict is
reported with its recovery path; an explicit `--login NAME --no-activate` saves
a fresh login and backs up the interrupted probe before clearing its checkpoint.
The `/status` fallback runs only after the preceding probe process has stopped;
it is not started alongside an existing managed daemon with an unsupported API.

`.codexpick.lock` serializes account operations within one Codex home. A second
operation is refused while the first is running. Probe and login children keep
the lock if their parent is killed; wait for or stop that process before retrying.
The lock is released when launching an ordinary Codex session. It does not
coordinate other programs or other machines: do not replace credentials manually
during an operation, and finish unmanaged CLI sessions before changing accounts.

Use an independent login for each account on each machine. Copying a refreshable
session to several concurrently used machines is not made safe by a local lock.
Existing revoked tokens cannot be repaired by this change. A newer saved profile
can be selected explicitly; if its refresh is also rejected, obtain a fresh login.
See [Codex authentication](https://learn.chatgpt.com/docs/auth) and the
[credential persistence guidance](https://learn.chatgpt.com/docs/auth/ci-cd-auth).

## Tests

Run the regression suite without accounts or network access:

```bash
python -m unittest discover -s tests -v
```

The optional integration tests run a real Codex executable with synthetic
credentials, a temporary home, and OAuth/quota endpoints on loopback. They check
renewal, quota failures, repeated checks, and switching between two accounts.

```bash
CODEXPICK_TEST_CODEX_BIN=/absolute/path/to/codex python -m unittest discover -s tests -v
```
