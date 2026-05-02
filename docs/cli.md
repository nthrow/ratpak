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

## `ratpak daemon [flags]`

Runs ratpak as a long-lived per-user agent. Loads the eBPF observer once, periodically walks `/proc` to discover flatpak'd processes (via `/proc/<pid>/root/.flatpak-info`), seeds each into the kernel-side tracked set, and demultiplexes incoming openat events by appid into per-app jsonl trace files under `~/.local/share/ratpak/traces/<appid>/`.

```
ratpak daemon                                  # foreground; Ctrl-C / SIGTERM stops cleanly
ratpak daemon --app com.discordapp.Discord     # limit scope to one app
ratpak daemon --exclude com.valvesoftware.Steam --exclude com.brave.Browser
ratpak daemon --mode enforcing --level 2       # auto-revoke unused grants up to risk 4
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--app <id>` | (all) | Restrict the daemon to this app ID. Repeatable. |
| `--exclude <id>` | (none) | Skip this app even if otherwise in scope. Repeatable. |
| `--mode <m>` | `permissive` | `permissive` observes & persists. `enforcing` also auto-applies revocations. |
| `--level <1..4>` | `2` | Aggression cap when enforcing. See "Enforcement levels" below. |

### Privileges

Requires `cap_bpf` + `cap_perfmon` to load the BPF program. Two valid setups:

- **Permissive mode** can run as root (`doas ratpak daemon …`) — only persists trace files.
- **Enforcing mode** *must not* run as root: it shells out to `flatpak override --user` whose effect lives in whatever user identity invokes it. Run the daemon as your normal user with `make setcap` having been applied to the binary so it carries `cap_bpf,cap_perfmon+ep` directly.

### Enforcement levels

Every grant ratpak considers revoking has a `RiskScore` (0-10) representing how disruptive revocation would be — `xdg-pictures:ro` is 2, `xdg-run/pipewire-0` is 4, `xdg-data/foo` is 6, `home` is 8, `host` is 10. The level setting caps which scores get auto-revoked:

| Level | Max risk | Auto-revokes |
|---|---|---|
| 1 | 2 | only the trivial cases (`xdg-pictures`, `xdg-music`, `/var/lib/flatpak/*`) |
| 2 | 4 | also `xdg-download`, `xdg-run/pipewire-0`, `xdg-documents`, etc. |
| 3 | 6 | also `xdg-config/*`, `xdg-data/*`, `host-etc` |
| 4 | 10 | including `home`, `host`, `host-os` |

Independent of level, a grant must have **zero hits across at least 3 sessions** before any auto-revocation fires (hard floor — guards against single-session false positives breaking apps).

The enforcement loop runs once at daemon startup and every 15 minutes thereafter. Each cycle reads all on-disk traces for in-scope apps, computes the unused-grant set, filters by risk and the threshold, and shells out to `flatpak override --user --nofilesystem=<term> <appid>` for new revocations. Already-applied revocations aren't re-applied (deduped against the existing override file), so a stable corpus produces no log churn.

To **undo** the daemon's enforcement decisions: `ratpak reset <appid> --commit` (clears all user overrides, including any non-ratpak ones), or manually edit `~/.local/share/flatpak/overrides/<appid>`. Granular per-decision unapply is a P3 follow-up.

### Sessions

In this iteration a "session" is one daemon run: one trace file per appid that was active during the run. `ratpak profile <appid>` (no arg) unions across daemon-run trace files the same way it does across `observe`-run trace files. Per-app-launch sessions, a sqlite state store, and an IPC server are P1 follow-ups; the socket path (`$XDG_RUNTIME_DIR/ratpak.sock`) is reserved but unused.
