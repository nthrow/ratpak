# `internal/observer`

The observation layer above the eBPF program. Defines the public type surface and tracks the descendants of a launched flatpak app.

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

## `pidtracker.go`

```go
type PIDTracker struct { /* … */ }

func NewPIDTracker(root int, interval time.Duration) *PIDTracker
func (t *PIDTracker) Run(ctx context.Context)              // blocking poll loop
func (t *PIDTracker) Includes(pid int) bool                // is pid descended from root?
func (t *PIDTracker) IsSandboxed(pid int) bool             // descended AND in different mntns
```

A simple `/proc` poller. Every `interval` it walks `/proc/*/stat` to build a `pid → ppid` map, then for each pid that isn't already tracked, walks the parent chain looking for a tracked ancestor. Newly tracked pids have their mount-namespace inum read once via `stat /proc/<pid>/ns/mnt`.

The root pid's mntns becomes the "host" reference. `IsSandboxed` returns true only for tracked pids whose mntns differs from the host — the actual flatpak'd app processes after bwrap unshares.

A polling interval of 50ms is the current default.

### Limitations

- Short-lived children born and died inside one poll interval can be missed.
- A pid can be recycled by the kernel during a long observe; entries are never reaped, but the recycled pid is unlikely to coincidentally match a previously-tracked one.
- Userspace polling means there's a small window between a process's `clone()` and ratpak's `IsSandboxed` answer turning true. Events from that window will fail the filter and be discarded. A future kernel-side improvement would hook `sched_process_fork` and maintain the tracked set in a BPF map.
