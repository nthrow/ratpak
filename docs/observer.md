# `internal/observer`

The observation layer above the eBPF program. Defines the public type surface for filesystem-access streams.

## `observer.go`

```go
type Event struct {
    PID  int     // TGID of the process that did the openat
    Comm string  // /proc/<pid>/comm value at the time of the event
    Path string  // absolute path that was opened (successful)
}

type Observer interface {
    Observe(ctx context.Context, appID string) (<-chan Event, error)
}
```

The interface lets future observers (dbus, sockets, devices) plug in without changing callers.

## Process tracking

Pre-v2 daemon-track work, this package also held a userspace `PIDTracker` that polled `/proc` every 50ms to maintain the set of TGIDs descended from a launched flatpak app and their mount-namespace inums. That has been retired: kernel-side tracking now lives in [`internal/observer/ebpf/openat.bpf.c`](../internal/observer/ebpf/openat.bpf.c) — a BPF hash map seeded by `Observer.AddRoot`, propagated by a `sched_process_fork` hook, reaped by `sched_process_exit`, and combined with a CO-RE-relocated read of `task->nsproxy->mnt_ns->ns.inum` to filter out events from the host mount namespace. Userspace receives a pre-filtered event stream.

See [observer-ebpf.md](observer-ebpf.md) for details on the kernel-side filter.
