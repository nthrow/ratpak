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

Launches `flatpak run <appid>` and emits one absolute path per line on stdout for every successful `openat` / `openat2` made by a process in the sandboxed app's mount namespace. Stderr gets a launch banner and a final summary count; the wrapped flatpak's own stdout/stderr is also forwarded to ratpak's stderr so it doesn't pollute the trace.

Requires elevated privileges (`CAP_BPF` + `CAP_PERFMON`). The most common invocation is:

```
doas ratpak observe com.example.App > /tmp/example-trace.txt
# … exercise the app, then close it
```

When run with `doas` / `sudo`, ratpak detects this via `SUDO_USER` / `DOAS_USER`, drops privileges (UID + GID) for the spawned `flatpak run`, and restores a session env scraped from one of your running processes — so the app sees its real user installs and session bus.

Stops cleanly on Ctrl-C, or when the launched flatpak app exits.

## `ratpak profile <appid> [trace-file]`

Reads a trace (one path per line) and classifies each path against:

1. flatpak's auto-grants (runtime, sandbox internals, per-app data dir, document portal, etc.) — ignored.
2. the app's manifest filesystem grants — counted as hits per grant.
3. anything else — listed as "unaccounted", grouped by 4-component prefix.

If no trace file is given, reads from stdin. Runs as the regular user; no privileges required.

## `ratpak apply <appid>`

Stub. Will eventually write `flatpak override --user --nofilesystem=…` for grants flagged as unused over multiple sessions.
