# Architecture

How ratpak is organized, the terms used in the codebase, and the data flow from observation to recommendation.

## Glossary

**App ID** — a flatpak application identifier in reverse-DNS form, e.g. `com.discordapp.Discord`.

**Manifest** — the metadata flatpak stores for an installed app. Includes runtime version, declared permissions, exports, etc. The slice ratpak cares about lives under the `[Context]` section, queryable with `flatpak info --show-permissions <appid>`.

**Permission grant** (or just **grant**) — a single entry in a manifest's permission list. ratpak v1 only handles the `filesystems` axis: tokens like `xdg-download`, `home`, or `/var/lib/flatpak/app:ro` are each a grant. Other axes (`shared`, `sockets`, `devices`, `features`, dbus policies, env vars) are read but not yet observed against.

**Mode suffix** — `:ro`, `:rw` (default), or `:create` appended to a grant. `xdg-pictures:ro` is read-only; `xdg-data/foo:create` allows creating that directory.

**Override** — a user-level (or system) tightening of a manifest grant, written by `flatpak override` and stored at `~/.local/share/flatpak/overrides/<appid>` (or `/var/lib/flatpak/overrides/<appid>` for system). Same INI file format as the manifest's `[Context]` section.

**Resolver** — code that expands a manifest grant token into a host-path prefix that observed paths can be matched against. `xdg-download` resolves to `/home/<user>/Downloads`; `home` resolves to `/home/<user>`. Lives in [`internal/flatpak/match.go`](../internal/flatpak/match.go).

**Auto-grant** — a host-path prefix that flatpak gives every sandboxed app implicitly, without an explicit `filesystem=` term. Examples: `/usr` (the runtime), `/dev/dri` (graphics), `~/.var/app/<appid>/` (per-app persistent data), `/run/user/<uid>/doc` (the document portal). Observed paths under any of these aren't "permission usage" — they're free.

**Observer** — anything that emits a stream of access events for a running flatpak app. v1 has one filesystem observer backed by eBPF; future observers will cover dbus, sockets, devices.

**Trace** — the captured output of a single observe run. v1 format: one absolute path per line on stdout. Designed to be redirected to a file or piped into the next stage.

**Profile** — the result of comparing a trace against a manifest. Three buckets: *used* (path matched a granted prefix), *unused* (a grant got zero hits), *unaccounted* (path matched neither a grant nor an auto-grant — interesting for investigation).

**Sandbox / host mount namespace** — bwrap (the unprivileged sandbox launcher flatpak uses) creates a new mount namespace before exec'ing the app. Processes inside this new namespace see the runtime + app instead of the host's `/usr`, etc. ratpak distinguishes "host mntns" (flatpak's own setup work) from "sandbox mntns" (the actual app) and only counts events from the latter.

**comm** — the kernel-truncated process name (max 15 chars), as in `/proc/<pid>/comm`. ratpak filters out events whose comm is `bwrap`, `ldconfig`, etc. — sandbox-setup tools that aren't the app itself.

**Tracepoint** — a static instrumentation point in the kernel. ratpak hooks the syscall tracepoints `syscalls/sys_enter_openat`, `sys_exit_openat`, and the `openat2` equivalents.

**Ring buffer** — the kernel-to-userspace event channel ratpak's eBPF program uses to ship events back to the Go loader. Created with `BPF_MAP_TYPE_RINGBUF`.

## Data flow

```
       host (root)                               sandbox (user)
       ───────────                               ──────────────

       ratpak                                    flatpak run <appid>
         │                                         │
         │  load BPF program (4 tracepoints)       │
         │  open ringbuf reader                    │
         │  start /proc poller                     │
         ▼                                         ▼
   ┌────────────────────────────────────┐    ┌──────────────┐
   │ kernel: openat enter/exit hooks    │ ←──│ app + libs   │
   │   on enter: stash filename ptr     │    │ doing work   │
   │   on exit (ret≥0): emit to ringbuf │    └──────────────┘
   └────────────────────────────────────┘
                    │
                    │ events: {pid, tgid, comm, path}
                    ▼
              ratpak userspace
                    │
                    │ filter:
                    │   1. PID is descendant of flatpak run PID
                    │   2. PID's mntns ≠ host mntns (i.e. sandboxed)
                    │   3. comm ∉ {bwrap, ldconfig, …}
                    │   4. path is absolute (skip unresolved relative)
                    ▼
              one path per line on stdout
```

For profiling, the captured trace is then read by `ratpak profile`:

```
trace ──┐
        ├─→ classify each path:
manifest┘     • under any auto-granted prefix     → ignore
              • under a manifest-grant prefix     → record hit
              • neither                           → unaccounted
```

## Layout

```
ratpak/
├── main.go                       CLI dispatch + cmdInfo / cmdObserve / cmdProfile / …
├── go.mod
├── Dockerfile                    Alpine 3.23 build env (go, clang, libbpf-dev, …)
├── Makefile                      `make build` runs go generate + go build inside Docker
├── internal/
│   ├── flatpak/
│   │   ├── apps.go               `flatpak list`
│   │   ├── permissions.go        `flatpak info --show-permissions` parser
│   │   ├── overrides.go          ~/.local/share/flatpak/overrides parser
│   │   └── match.go              term resolver + auto-grant list + path matchers
│   └── observer/
│       ├── observer.go           Event + Observer interface
│       ├── pidtracker.go         /proc walker; tracks descendants + mntns
│       └── ebpf/
│           ├── openat.bpf.c      kernel-side: 4 tracepoints + ringbuf + LRU pending map
│           └── observer.go       userspace-side: load, attach, decode events
└── docs/
    └── …
```

## Design choices

**Why eBPF over strace/auditd?** strace serializes the target through ptrace and noticeably slows GUI apps; auditd is system-wide and has its own filtering language. eBPF attaches at the kernel without perturbing the target and lets us write a per-event filter in C.

**Why syscall tracepoints over LSM hooks?** LSM hooks (`file_open`) give resolved paths and proper credentials, but require `CONFIG_BPF_LSM=y` and `lsm=...,bpf` on the kernel command line. Syscall tracepoints work on every kernel ≥ 4.7. For v1 we accept the tradeoff: we capture pre-resolution paths, miss `dirfd`-relative opens (which surface as relative paths and get filtered out in userspace), and rely on userspace classification for sandbox vs host.

**Why enter+exit pairing?** A bare `sys_enter_openat` hook captures every *attempt* to open a file, including `EACCES` denials. For ratpak that's wrong: an app that probes a file the sandbox denies and then handles the denial doesn't *need* that permission. We pair each enter to its exit (storing the filename pointer in an LRU per-tid hash map) and only emit on `ret ≥ 0`.

**Why filter on mount namespace?** flatpak's launcher does substantial pre-bwrap setup work (resolving the runtime, downloading deltas, etc.) in the host mount namespace. Those accesses look like the app's but aren't. After bwrap unshares, anything in the new mntns is the app proper.

**Why scrape `/proc/<pid>/environ` for the user's session env?** Running the eBPF observer needs root, but `flatpak run` needs to run as the actual user with their actual `DBUS_SESSION_BUS_ADDRESS`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, etc. doas/sudo strip most of these. Synthesizing them is brittle (the bus path varies, DISPLAY may or may not exist depending on Xwayland). Reading the env from any of the user's existing processes gets the real values.
