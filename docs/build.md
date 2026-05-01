# Build environment

ratpak builds inside a small Alpine container so the host stays free of Go, clang, and libbpf headers.

## Container image (`Dockerfile`)

Based on `alpine:3.23`. Installs:

- `go` (currently 1.25.x)
- `clang21`, `llvm` — to compile eBPF C to BPF bytecode
- `libbpf-dev`, `linux-headers` — kernel UAPI + libbpf BPF helpers
- `bpftool` — handy for inspection
- `git`, `make`, `musl-dev` — supporting

A symlink `clang → clang-21` is added so `bpf2go`'s default `-cc clang` resolves.

`GOPATH`, `GOCACHE`, and `GOMODCACHE` are pointed at `/tmp/.go*` so the container can be run as the host user (via `--user $(id -u):$(id -g)`) without permission errors writing the Go module cache.

## Targets (`Makefile`)

```
make image      # build the container
make tidy       # `go mod tidy` inside the container
make generate   # `go generate ./...` (regenerates bpf2go bindings)
make build      # generate + build, output to bin/ratpak
make shell      # interactive shell in the container, source bind-mounted at /work
make clean      # remove bin/
```

`make build` always re-runs `go generate ./...` first, so any change to `openat.bpf.c` is picked up.

## Layout

The container bind-mounts the host project directory at `/work`. Output binaries land in `bin/` on the host, owned by the invoking user thanks to `--user`.

CGo is disabled (`CGO_ENABLED=0`) so the resulting binary is fully static and runs on any glibc/musl system with a recent kernel.

## Running on host

The build container produces a binary; running `observe` requires the host kernel and host privileges:

```
doas ./bin/ratpak observe com.example.App
```

`sudo` works the same way. ratpak reads `SUDO_USER` or `DOAS_USER` to figure out whose user installs and session bus to expose to the spawned `flatpak run`, and to chown the saved trace file under `~/.local/share/ratpak/traces/<appid>/`.

Other commands (`list`, `info`, `profile`, `apply`, `reset`) run as the regular user — `apply --commit` and `reset --commit` actively refuse to run as root, since user overrides live in the user's flatpak config.
