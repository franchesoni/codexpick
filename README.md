# codexpick

`codexpick` probes local Codex auth snapshots, selects the first account that is not quota-blocked, switches `auth.json`, and launches Codex.

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

Variables:

- `CODEXPICK_HOME`: directory containing `auth.json` and `auth-*.json`; defaults to `~/.codex`.
- `CODEX_BIN`: exact Codex CLI binary; defaults to `codex` on `PATH`.

Example:

```bash
export CODEXPICK_HOME=~/.codex
export CODEX_BIN=/path/to/codex
```

## Usage

Check accounts without changing the active auth file:

```bash
codexpick --check-only
```

Quota columns use each window's `windowDurationMins`, not its
`primary`/`secondary` position. A weekly-only account therefore has `-` in the
5h columns and its usage/reset in the weekly columns. `-` means the window was
not reported; other durations (or windows with unknown duration) get separate
columns.

Switch to the first usable account and launch Codex:

```bash
codexpick
```

Switch without launching:

```bash
codexpick --no-launch
```

If a managed Codex app-server is running, `codexpick` checks its in-memory
account before changing `auth.json`. An idle daemon is restarted so it reloads
the selected credentials. If any loaded turn is active (or cannot be verified
safe), the switch is refused and `auth.json` is left unchanged.

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
