# ratpak

> a flatpak firewall — smoke out the ratlines in your sandboxes

ratpak is a CLI for tightening the runtime permissions of installed flatpak applications. Most flathub packages ask for broader access than they actually need (commonly `--filesystem=home` or even `host`) for packaging convenience. ratpak observes what an app *actually* opens at runtime via eBPF, compares it against the permissions declared in its manifest, and recommends a minimal set of `flatpak override` rules.

## Status

Early but end-to-end on the filesystem axis. The full loop works:

- Read a flatpak app's declared filesystem permissions.
- Trace successful `openat` calls by the sandboxed app via eBPF; persist each session as jsonl under `~/.local/share/ratpak/traces/<appid>/`.
- Aggregate across sessions and diff against the manifest to flag grants that were unused everywhere.
- Apply minimal overrides via `flatpak override --user --nofilesystem=…`, dry-run by default.

Not done yet: dbus / sockets / devices observers, file-capability UX so root isn't required for `observe`, dirfd-relative path resolution, kernel-side PID tracking. See [the roadmap](docs/roadmap.md).

## Requirements

- Linux kernel ≥ 5.11 (eBPF ring buffers).
- `flatpak` installed on the host.
- For development: Docker (the build runs inside an Alpine container so no Go/clang/libbpf are needed on the host).
- For running: root, or `cap_bpf,cap_perfmon+ep` on the binary.

## Build

ratpak builds inside a small Alpine container:

```
make build
```

Produces `bin/ratpak`, a fully static x86_64 binary that runs against the host kernel.

## Usage

```
ratpak list                                # list installed flatpak apps
ratpak info com.example.App                # show its manifest filesystems + your overrides
doas ratpak observe com.example.App        # launch under eBPF; saves trace to ~/.local/share/ratpak/traces/
ratpak profile com.example.App             # union every saved trace, classify
ratpak apply com.example.App               # dry-run: show which grants we'd revoke
ratpak apply com.example.App --commit      # write `flatpak override --nofilesystem=…` for unused grants
ratpak reset com.example.App --commit      # remove all user overrides for the app
```

`observe` requires elevated privileges to load the BPF program (`doas` or `sudo`). ratpak detects this and runs the actual flatpak app as your real user, so the app sees your user-level installs and session bus. The trace file is also chowned to your user.

`profile`, `apply`, and `reset` run as your normal user. `apply --commit` and `reset --commit` refuse to run as root since overrides go to your user's flatpak config.

## Example

Flatseal — a tightly-permissioned reference app. After two short sessions:

```
$ ratpak profile com.github.tchx84.Flatseal
App: com.github.tchx84.Flatseal
Sessions: 2
  …/20260501-022711Z.jsonl  (1006 unique paths)
  …/20260501-022801Z.jsonl  (922 unique paths)
Union: 1019 unique paths

Manifest filesystem grants:
  USED    xdg-data/flatpak/overrides:create → /home/nat/.local/share/flatpak/overrides  (2/2 sessions, 4 hits)
  UNUSED  /var/lib/flatpak/app:ro          → /var/lib/flatpak/app  (0/2 sessions, 0 hits)
  USED    xdg-data/flatpak/app:ro          → /home/nat/.local/share/flatpak/app  (2/2 sessions, 383 hits)

Recommendation: 1/3 declared filesystem grant(s) had zero hits across all 2 sessions — candidates for removal.
```

```
$ ratpak apply com.github.tchx84.Flatseal
…
Would revoke 1 filesystem grant(s) (dry-run; pass --commit to apply):
  flatpak override --user --nofilesystem=/var/lib/flatpak/app com.github.tchx84.Flatseal

Warning: based on only 2 session(s) of observation. Consider capturing more before --commit.
```

A single session won't justify revocation by itself; the more sessions you observe across realistic activity (audio call, file upload, etc.), the more confidence you have in revoking a grant. The `K/N sessions` column makes that explicit.

## Documentation

- [Status & roadmap](docs/roadmap.md) — where v1 stands, what v2 should fix, where to resume
- [Architecture overview](docs/architecture.md) — terminology and data flow
- [CLI commands](docs/cli.md)
- [`internal/flatpak`](docs/flatpak-package.md) — manifest, overrides, term resolution, override writers
- [`internal/observer`](docs/observer.md) — observer interface + PID/mntns tracking
- [`internal/observer/ebpf`](docs/observer-ebpf.md) — eBPF program + Go loader
- [`internal/trace`](docs/trace.md) — jsonl trace persistence and reading
- [Build environment](docs/build.md) — Dockerfile + Makefile

## License

Commons Clause v1.0 (with a consulting carve-out) layered on top of MIT. See [LICENSE.md](LICENSE.md) for the full text. This is **source-available, not OSI-approved open source** — distros and "open source" tooling may treat it as proprietary. Personal, internal, and consulting use are explicitly permitted; reselling ratpak as a product or a hosted/managed service is not.
