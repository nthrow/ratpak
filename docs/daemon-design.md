# Daemon design

A target architecture for `ratpak` as an always-on, per-user agent that observes every flatpak'd process on the desktop, learns each app's normal access pattern, proposes minimal revocations when grants stay durably unused, and watches for behavioral drift after applying changes.

This document is the plan; most of it isn't built yet. See "Phased delivery" at the bottom for what's prerequisite vs. what's downstream.

## Goal

Capture the full Little-Snitch-style UX for flatpak permissions, with one concrete deviation: **observe-only, not block-on-deny**. The daemon learns from real successful accesses (eBPF tracepoints on `openat`/`openat2`), it doesn't sit in the syscall path. The user's only friction is reviewing prompts that the daemon raises asynchronously; nothing they do is delayed.

## Why ambient

`ratpak observe` today is an explicit act. To get a recommendation worth committing to, the user has to remember to run it across many sessions of varied app activity. They won't. The daemon makes the data passive. Beyond that, an ambient observer can do something the explicit tool fundamentally can't: **detect sudden first-use of a previously-cold grant**. If `xdg-pictures:ro` sat at zero hits across 40 sessions and then suddenly fired today, that's signal — either the user did something new, or the app started reaching for something it never reached for before. Surfacing that is the unique value-add and the main reason daemon mode is worth building over "cron a bunch of `observe` runs".

## Architecture overview

```
┌──────────────────────────────────── per-user daemon ─────────────────────────────────┐
│                                                                                      │
│   eBPF program                                                                       │
│   ├─ sched_process_fork  → maintains tracked-TGID hash map (kernel-side)             │
│   ├─ sched_process_exit  → reaps tracked-TGID entries                                │
│   ├─ sys_enter_openat*   → stash filename ptr (per-tid, LRU)                         │
│   └─ sys_exit_openat*    → emit if tracked AND ret>=0 AND in non-host mntns          │
│                                  │                                                   │
│                                  ▼                                                   │
│   userspace ringbuf reader → event {tgid, comm, path}                                │
│                                  │                                                   │
│            ┌─────────────────────┼─────────────────────┐                             │
│            ▼                     ▼                     ▼                             │
│      appid resolver       per-app session       state store (sqlite)                 │
│      (/.flatpak-info)     boundary tracker      ~/.local/share/ratpak/state.db       │
│                                  │                                                   │
│                                  ▼                                                   │
│                          analysis loop (on session-close)                            │
│                          ├─ refresh per-app baseline (K of last N sessions hit)      │
│                          ├─ detect sudden cold→hot grants                            │
│                          ├─ rank revocation candidates by risk score                 │
│                          └─ enqueue prompts                                          │
│                                  │                                                   │
│                ┌─────────────────┼─────────────────┐                                 │
│                ▼                 ▼                 ▼                                 │
│         IPC server         notification          followup watch                      │
│         ($XDG_RUNTIME_DIR/ dispatcher            (was-revocation-X-hit?)             │
│         ratpak.sock)       (libnotify)                                               │
│                │                                                                     │
└────────────────┼─────────────────────────────────────────────────────────────────────┘
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
   ratpak     ratpak-tray   ratpak-ui
   (CLI)      (notifier)    (browser, later)
```

## Components

### Kernel observer

Extends today's `internal/observer/ebpf/openat.bpf.c`:

- **`sched_process_fork`**: when a process forks, if the parent's TGID is in the tracked set, add the child's TGID. Initial seeding happens at userspace startup by walking `/proc` once for any flatpak'd processes already running (or — simpler — by waiting for new launches and ignoring already-running flatpaks, with a one-shot `ratpak attach` for retroactive coverage).
- **`sched_process_exit`**: remove TGID from tracked set; signal userspace so it can update the per-app session boundary tracker.
- **Existing `openat`/`openat2` enter/exit hooks**: gain a kernel-side filter — only emit if `tgid ∈ tracked_set`. Eliminates today's userspace `IsSandboxed` check and its 50ms polling window.

The mntns-difference filter still matters for the brief window between fork and the bwrap-driven mntns unshare — keep it as a secondary filter.

### Process discovery + appid resolution

For each TGID newly added to the tracked set, userspace reads `/proc/<pid>/root/.flatpak-info` to extract the `[Application]/name=` field. That's the appid. The file is written by flatpak's bwrap setup before the app's own code runs, so it's reliably present once we're past the early fork window.

Falls back to walking the parent chain looking for a `flatpak run …` cmdline if `.flatpak-info` is somehow missing (e.g. a non-flatpak `bwrap` invocation got into the tracked set — shouldn't happen, but defensive).

`flatpak.ResolveAppID(pid int) (string, error)` lives in `internal/flatpak/appid.go` and is the only piece of this component that's prerequisite-scaffolded today.

### State store

Migrate from per-session jsonl files to sqlite at `~/.local/share/ratpak/state.db`. Rough schema:

```sql
CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY,
    appid       TEXT NOT NULL,
    started_at  INTEGER NOT NULL,    -- unix seconds
    ended_at    INTEGER,             -- nullable while open
    pid         INTEGER NOT NULL     -- root TGID of the session
);
CREATE INDEX sessions_appid_started ON sessions(appid, started_at);

CREATE TABLE paths (
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    comm        TEXT,
    PRIMARY KEY (session_id, path)
);
CREATE INDEX paths_path ON paths(path);  -- for cross-session "did any session ever hit X" queries

CREATE TABLE revocations (
    appid                  TEXT NOT NULL,
    term                   TEXT NOT NULL,            -- mode-stripped, as written to override
    applied_at             INTEGER NOT NULL,
    risk_score             INTEGER NOT NULL,
    last_followup_at       INTEGER,
    last_blocked_path      TEXT,                     -- most recent path that would have hit this rule
    last_blocked_at        INTEGER,
    PRIMARY KEY (appid, term)
);

CREATE TABLE prompts (
    id          INTEGER PRIMARY KEY,
    appid       TEXT NOT NULL,
    term        TEXT NOT NULL,
    kind        TEXT NOT NULL,        -- 'revoke_candidate' | 'sudden_use' | 'followup_blocked'
    asked_at    INTEGER NOT NULL,
    answer      TEXT,                 -- 'apply' | 'snooze' | 'never' | NULL while pending
    snooze_until INTEGER
);
```

The existing jsonl trace files become an export/import format for portability (and a debugging aid). On daemon startup, any orphan jsonl files for an app get backfilled into the `sessions` + `paths` tables.

### Analysis loop

Triggered on session-close (last tracked TGID for an appid exits) and on a low-frequency timer (e.g. every 5 minutes) for housekeeping. For each app with a recently-closed session:

- **Baseline**: for each manifest grant, count "sessions hit" over the last N sessions (default N=20) and "sessions in window".
- **Revocation candidate**: grant has 0 hits across all N sessions AND N ≥ session-threshold-for-its-risk-score (see "Risk scoring" below) AND no active prompt for it AND not already revoked.
- **Sudden-use**: grant had 0 hits across the previous N sessions but has hits now. Always prompt, regardless of risk.
- **Followup blocked**: for each currently-applied revocation, scan this session's paths for any that would have matched the revoked term. Update `last_blocked_*` columns and enqueue a `followup_blocked` prompt.

### IPC server

Unix socket at `$XDG_RUNTIME_DIR/ratpak.sock` (per-user, ephemeral, auto-cleaned by tmpfs reboots, no network exposure). Length-prefixed JSON messages, simple request/response with a separate event-stream subscription for prompts.

Sketch of methods:

| Method                | Args                          | Returns                              |
|-----------------------|-------------------------------|--------------------------------------|
| `status`              | —                             | uptime, tracked PIDs, apps observed  |
| `list_apps`           | —                             | `[{appid, sessions, last_seen}]`     |
| `get_profile`         | `appid`                       | aggregated per-grant report          |
| `apply_revocation`    | `appid, term`                 | ok / error                           |
| `unapply_revocation`  | `appid, term`                 | ok / error                           |
| `pending_prompts`     | —                             | list of unanswered prompts           |
| `answer_prompt`       | `id, answer, snooze_until?`   | ok                                   |
| `subscribe_events`    | `kinds`                       | open stream of new prompts           |

Versioned via a `protocol_version` field on every message; clients refuse to talk to a daemon they don't understand.

### Notification dispatcher

Sends desktop notifications via dbus `org.freedesktop.Notifications` (libnotify wire protocol — no library dep, just the dbus call). Each notification carries action buttons whose IDs map to `answer_prompt` calls back to the daemon.

Hard fail-soft: if the user has no notification daemon running, the prompts still queue in the IPC and any client (CLI `ratpak prompts`) can drain them.

### Clients

**ratpak CLI** (existing binary): when the daemon is running, `list`, `info`, `profile`, `apply` all become thin clients that ask the daemon. When the daemon is not running, the existing standalone behavior is the fallback. New subcommands: `daemon` (run the daemon in the foreground), `status`, `prompts`, `answer`.

**ratpak-tray** (future, separate binary): system tray icon (StatusNotifierItem) + libnotify dispatcher consumer. Surfaces the prompt queue, opens the web UI on click.

**ratpak-ui** (future, separate binary): a small HTTP server bound to `127.0.0.1:<random>` that serves a static SPA. The browser is the GUI. Avoids GTK/Qt binding pain and keeps the daemon binary small.

## Privilege model

Per-user daemon. The binary gets `cap_bpf,cap_perfmon+ep` via `setcap` so it can load the BPF program without root. The daemon listens only on `$XDG_RUNTIME_DIR/ratpak.sock` (mode 0600); only the user can connect.

This deliberately avoids:

- a system-wide root daemon (visibility into other users' flatpaks; bigger trust ask)
- a setuid-root binary (the worst of both worlds)

Multi-user systems (kiosks, shared workstations, servers running flatpaks under different users) can run one ratpak daemon per user. A future "system mode" — root daemon, per-user IPC sockets, separate state stores per uid — is possible if anyone asks.

Capability caveat: `setcap`'d binaries can't be read across `nosuid` or some network mounts, and they ignore `LD_LIBRARY_PATH` / `LD_PRELOAD`. Static binary, doesn't matter.

## Risk scoring

Each filesystem term gets a static risk score 0-10 indicating the blast radius of revoking it incorrectly:

| Term family          | Score | Reason                                                          |
|----------------------|-------|-----------------------------------------------------------------|
| `host`, `host-os`    | 10    | Revoking breaks anything reading from `/etc`, `/usr`, etc.      |
| `home`               | 8     | Breaks any in-home access not already covered by `xdg-*`.       |
| `xdg-config`         | 7     | App-specific config; usually load-bearing.                      |
| `host-etc`           | 6     | More targeted than full `host`.                                 |
| `xdg-data`           | 6     | App data; sometimes load-bearing.                               |
| `xdg-run/pipewire-0` | 4     | Audio output stops; recoverable.                                |
| `xdg-download:rw`    | 4     | Save dialogs break.                                             |
| `xdg-download:ro`    | 3     | Open dialogs fail; user can re-grant.                           |
| `xdg-pictures:ro`    | 2     | Narrow effect; easily noticed.                                  |
| `xdg-music:ro`       | 1     | Niche.                                                          |
| `/var/lib/flatpak/*` | 1     | Per-system; usually irrelevant on user-only installs.           |

Used three ways:

1. **Prompt cadence**: revocation candidates with risk ≥ 8 require ≥ 30 sessions of zero-hits before prompting; risk ≤ 3 require ≥ 5. Prevents the daemon from nagging about `home` after one quiet day.
2. **Followup cadence**: higher-risk revocations stay on the followup watch list longer (e.g. risk 10 watched for 60 days, risk 1 for 7).
3. **UX hint in prompts**: "low-risk" revocations get a one-click apply button; "high-risk" require a confirmation step.

Scores live in a Go map in `internal/flatpak/risk.go` (when written), keyed by canonicalized term. Unknown terms default to 5.

## Follow-up watch list

After `apply_revocation`, the term goes into the `revocations` table and stays watched. For each subsequent session, the analysis loop checks: *did any path in this session match the revoked term's resolved prefix?* If yes:

- update `last_blocked_path` / `last_blocked_at`
- enqueue a `followup_blocked` prompt: *"Discord just tried to access /home/nat/Pictures/foo.png — you revoked xdg-pictures 11 days ago. Allow / Keep blocking / Investigate."*

This is what justifies the daemon's existence over manual `ratpak apply` runs: revocations aren't a one-shot decision, they're a watched commitment, and the daemon is what does the watching.

## Init-system independence

The daemon is just a process: starts foreground, handles SIGTERM/SIGINT, logs to stderr, exits 0 cleanly. No PID files, no double-fork. Init systems handle the rest.

Ship example service files under `dist/`:

- `dist/systemd/ratpak.service` — `Type=simple`, `User=%i`, no `After=` since we don't depend on anything beyond the user session.
- `dist/openrc/ratpak` — `command_user=$RC_SVCNAME` style.
- `dist/runit/ratpak/run` — three-line shell script.
- `dist/s6/ratpak/run` — same.
- `dist/dinit/ratpak.dinit` — a service description.

A `dist/README.md` documents which file to copy where for each system and notes that none are installed by `make` — distro packagers and individual users wire it up themselves.

For users who don't run a service manager: `ratpak daemon` in a tmux pane works fine.

## Phased delivery

Numbered to sort, not to gate: items in earlier phases are prerequisites for everything below.

### P0 — Prerequisites

1. **`make setcap`** target — daily-use observation as user, no doas/sudo prompt per run. *Done.*
2. **`flatpak.ResolveAppID(pid int)`** — read `[Application]/name=` from `/proc/<pid>/root/.flatpak-info`. *Done.*
3. **Kernel-side fork tracking** — `tracked_pids` LRU hash + `sched_process_fork` / `sched_process_exit` hooks in `openat.bpf.c`; `Observer.AddRoot(pid)` to seed it. Tracking by kernel TID rather than TGID sidesteps the lack of `task_struct->tgid` in the fork tracepoint context. *Done.*
4. **`internal/daemon/` package skeleton** — package doc, IPC socket-path convention, Server stub. *Done.*
5. **Mount-namespace check in BPF** — minimal `task_struct → nsproxy → mnt_namespace → ns_common` chain with `preserve_access_index` so CO-RE rewrites field offsets at load time. `host_mntns_inum` rodata global, set by userspace from `/proc/self/ns/mnt` before load via `VariableSpec.Set`. The combined `should_emit()` check (tracked tid AND mntns differs from host) replaces the userspace `IsSandboxed`. `pidtracker.go` retired. *Done.*

### Lesson learned during P0 item 3

Different `sched/*` tracepoints use different context-struct layouts (some use `__data_loc` 4-byte encoded comm fields, some use inline `char[16]`). The kernel's verifier rejects sched-tracepoint attaches with `permission denied` — not a verifier-style error message — when a program's field access reads past the actual context size. Always confirm the layout from `/sys/kernel/tracing/events/<group>/<name>/format` before defining the BPF-side struct; don't extrapolate from a sibling tracepoint. Documented in [`docs/observer-ebpf.md`](observer-ebpf.md).

### P1 — Daemon proper

5. `ratpak daemon` foreground command; loads the eBPF program once and runs the ringbuf reader as a long-lived process.
6. Per-app session boundary tracker (open session on first tracked TGID for an appid, close on last exit).
7. Sqlite state store; backfill existing jsonl traces into it on first daemon startup.
8. IPC server with `status`, `list_apps`, `get_profile` (read-only methods first).

### P2 — Analysis + prompts

9. Baselines, sudden-use detection, revocation candidate scoring.
10. `apply_revocation` / `unapply_revocation` IPC methods.
11. Followup watch list.
12. Notification dispatcher (libnotify via dbus).
13. Risk score table + prompt cadence rules.

### P3 — Client integration

14. CLI subcommands `daemon`, `status`, `prompts`, `answer`.
15. Existing CLI subcommands (`list`, `info`, `profile`, `apply`) become daemon-aware: detect socket, ask daemon when present.
16. Granular `unapply` (replaces today's all-or-nothing `reset`) — required because daemon prompts must be per-decision reversible. Implemented as direct override-file editing.

### P4 — UI

17. `ratpak-tray` — separate binary. StatusNotifierItem + notification action handler.
18. `ratpak-ui` — separate binary. Localhost HTTP server + static SPA for review.

### P5 — Stretch

19. LSM-based prompt-on-deny. Real-time blocking, true Little Snitch parity. Big jump in complexity (LSM hooks, deferred decisions on the syscall path, GUI on hot path); only worth it if the observe-only daemon hits a clear ceiling.
20. Community profile database — fetch a known-good per-`<appid>@<version>` profile and apply it without a local observation phase. Cross-version regression diffing. Both already in roadmap stretch.

## Open questions

- **Sqlite as a hard dep**, or stay with jsonl + a periodic compactor that produces a per-app `summary.json`? Sqlite wins on baseline queries (`COUNT(DISTINCT session_id) WHERE path LIKE 'X/%'`) but adds a CGO-or-pure-Go decision and a migration. *Leaning sqlite, modernc.org/sqlite (pure Go) to keep the static-binary property.*
- **Already-running flatpaks at daemon startup**: ignore them, retro-attach via `/proc` walk, or only after a `ratpak attach <appid>` opt-in? *Leaning ignore-by-default with explicit attach, to keep startup cheap.*
- **Flatpak runtimes** (`org.freedesktop.Platform`, etc.) — they have their own permission concept, but they're not "apps". Probably out of scope; we observe app behavior, not runtime behavior.
- **Multi-instance flatpak apps** (rare but possible — `flatpak run --instance-id`). Two TGIDs with the same appid running at once. Is each a separate session, or one session with two PIDs? *Leaning one session per appid, refcount the TGIDs.*
- **Snap / pure bwrap** — sandbox-agnostic eBPF observer, sandbox-specific manifest/override readers. Mentioned in the v2 stretch ideas. The daemon architecture cleanly supports it (parallel `internal/snap/`, etc.), but no work planned until someone asks.
