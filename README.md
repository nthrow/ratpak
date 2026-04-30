# ratpak

> a flatpak firewall — smoke out the ratlines in your sandboxes

ratpak is a CLI for tightening the runtime permissions of installed flatpak applications. Most flathub packages ask for broader access than they actually need (commonly `--filesystem=home` or even `host`) for packaging convenience. ratpak observes what an app *actually* opens at runtime via eBPF, compares it against the permissions declared in its manifest, and recommends a minimal set of `flatpak override` rules.

## Status

Early. v1 covers:

- Reading a flatpak app's declared filesystem permissions.
- Tracing successful `openat` calls by the sandboxed app via eBPF.
- Diffing the trace against the manifest to flag unused (over-broad) grants.

Not done yet: dbus / sockets / devices observers, multi-session aggregation, automatic override application, file-capability UX so root isn't required.

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
ratpak list                            # list installed flatpak apps
ratpak info com.example.App            # show its manifest filesystems + your overrides
ratpak observe com.example.App > trace # launch under eBPF, write opened paths
ratpak profile com.example.App trace   # classify trace into used / unused / unaccounted
```

`observe` requires elevated privileges to load the BPF program; the simplest invocation is `doas ratpak observe …` or `sudo ratpak observe …`. ratpak detects this and runs the actual flatpak app as your real user, so the app sees your user-level installs and session bus.

## Example

Discord declares five filesystem grants. After a typical "launch, sign in, scroll, close" session:

```
$ ratpak profile com.discordapp.Discord trace
App: com.discordapp.Discord
Trace: 7002 unique paths

Manifest filesystem grants:
  UNUSED  xdg-download                     → /home/nat/Downloads  (0 hits)
  UNUSED  xdg-pictures:ro                  → /home/nat/Pictures  (0 hits)
  UNUSED  xdg-videos:ro                    → /home/nat/Videos  (0 hits)
  UNUSED  xdg-run/pipewire-0               → /run/user/1000/pipewire-0  (0 hits)
  UNUSED  xdg-run/speech-dispatcher        → /run/user/1000/speech-dispatcher  (0 hits)

Recommendation: 5/5 declared filesystem grant(s) had zero hits in this trace — candidates for removal.
```

A single session won't justify revocation by itself — a real recommender wants many sessions across realistic activity (audio call, file upload, etc.) before suggesting tightening. That's the v2 work.

## Documentation

- [Status & roadmap](docs/roadmap.md) — where v1 stands, what v2 should fix, where to resume
- [Architecture overview](docs/architecture.md) — terminology and data flow
- [CLI commands](docs/cli.md)
- [`internal/flatpak`](docs/flatpak-package.md) — manifest, overrides, term resolution
- [`internal/observer`](docs/observer.md) — observer interface + PID/mntns tracking
- [`internal/observer/ebpf`](docs/observer-ebpf.md) — eBPF program + Go loader
- [Build environment](docs/build.md) — Dockerfile + Makefile

## License

Commons Clause v1.0 (with a consulting carve-out) layered on top of MIT. See [LICENSE.md](LICENSE.md) for the full text. This is **source-available, not OSI-approved open source** — distros and "open source" tooling may treat it as proprietary. Personal, internal, and consulting use are explicitly permitted; reselling ratpak as a product or a hosted/managed service is not.
