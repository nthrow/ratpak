# CLI

ratpak's command surface. All commands take an explicit subcommand; there are no global flags yet.

## `ratpak list`

Prints every installed flatpak app id, one per line. Wraps `flatpak list --app --columns=application`.

## `ratpak info <appid>`

Prints:
- the `filesystems` declared in the app's manifest (from `flatpak info --show-permissions`)
- the `filesystems` in the user-level override at `~/.local/share/flatpak/overrides/<appid>`, if any

Read-only; runs as the regular user.

## `ratpak observe <appid>`

Launches `flatpak run <appid>` and emits one absolute path per line on stdout for every successful `openat` / `openat2` made by a process in the sandboxed app's mount namespace. Each unique path is also written to a per-session jsonl trace at:

```
~/.local/share/ratpak/traces/<appid>/<UTC-timestamp>Z.jsonl
```

Each line is a record `{"path":"…","comm":"…","pid":N}` describing a unique path the sandboxed app opened, plus the comm and TGID of the first process seen accessing it. The encoder writes straight to the file (no userspace buffer) so a Ctrl-C during observation still leaves a valid trace.

Stderr gets a launch banner, the trace file path, and a final summary count; the wrapped flatpak's own stdout/stderr is forwarded to ratpak's stderr so it doesn't pollute the live path stream.

Requires elevated privileges (`CAP_BPF` + `CAP_PERFMON`):

```
doas ratpak observe com.example.App
# … exercise the app, then close it
```

When run with `doas` / `sudo`, ratpak detects this via `SUDO_USER` / `DOAS_USER`, drops privileges (UID + GID) for the spawned `flatpak run`, restores a session env scraped from one of the user's running processes, and chowns the trace file to that user — so day-to-day reading and `apply`/`profile` runs work without root.

Stops cleanly on Ctrl-C, or when the launched flatpak app exits.

## `ratpak profile <appid> [trace-file|-]`

Classifies observed paths against:

1. flatpak's auto-grants (runtime, sandbox internals, per-app data dir, document portal, etc.) — ignored.
2. the app's manifest filesystem grants — counted as hits per grant, with per-session presence.
3. anything else — listed as "unaccounted", grouped by 4-component prefix.

Source selection:

- **No argument** — reads every saved trace under `~/.local/share/ratpak/traces/<appid>/`, treats each as one session, and unions them. Each grant is reported as `K/N sessions, M hits`. This is the recommended mode for a stable recommendation.
- **A path** — reads that single file as one session.
- **`-`** — reads jsonl (or plain-text) from stdin as one session. Useful for piping or replaying historical traces.

Backward compatibility: trace.Read auto-detects jsonl vs. plain text per line, so v1 `.txt` traces still classify.

Runs as the regular user; no privileges required.

## `ratpak apply <appid> [--commit]`

Computes the same per-session classification as `profile`, then proposes revocations for grants where `sessionsHit == 0` and the term is resolvable.

- **Default (dry-run)** — prints the exact `flatpak override` commands ratpak would run, plus a warning if fewer than 3 sessions were observed.
- **`--commit`** — shells out to `flatpak override --user --nofilesystem=<term> <appid>` for each unused grant. Mode suffixes are stripped (e.g. `xdg-pictures:ro` → `xdg-pictures`) since flatpak rejects modes on `--nofilesystem`.

Refuses to run `--commit` as root (EUID 0): user overrides live in the user's flatpak config, so applying as root would write to root's config instead.

Errors during individual revocations are reported but don't abort the rest; if any failed, the command exits non-zero with a count.

## `ratpak reset <appid> [--commit]`

Removes **all** user overrides for the app — broader than `apply`, since it also clears any dbus / socket / device overrides the user has set.

- **Default (dry-run)** — prints the current override state, says what would be removed.
- **`--commit`** — shells out to `flatpak override --user --reset <appid>`.

Refuses `--commit` as root for the same reason as `apply`. There is currently no granular "undo only what ratpak applied" — `reset` is the all-or-nothing escape hatch.
