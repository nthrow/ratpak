// Package ebpfobs is the eBPF-backed implementation of observer.Observer.
//
// It loads a tiny BPF program that hooks the openat / openat2 syscall
// tracepoints, captures pid/tgid/comm and the requested path, and ships
// each open() to userspace via a ring buffer.
//
// Membership in the "tracked" set is maintained kernel-side: a hash map
// keyed by kernel TID, seeded by Observer.AddRoot, propagated by a
// sched_process_fork hook, and reaped by sched_process_exit. The openat
// hooks early-exit when the calling TID isn't tracked, so non-flatpak
// processes never reach userspace.
package ebpfobs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ratpak/internal/observer"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target amd64,arm64 openat openat.bpf.c

// rawEvent must match `struct event` in openat.bpf.c.
type rawEvent struct {
	PID  uint32
	TGID uint32
	Comm [16]byte
	Path [256]byte
}

// Observer attaches openat tracepoints and streams events.
type Observer struct {
	mu   sync.Mutex
	objs *openatObjects
}

// New returns a fresh Observer. It does not load anything until Observe is called.
func New() *Observer { return &Observer{} }

// Observe attaches the BPF programs and emits an event per openat call until
// ctx is cancelled. The appID argument is currently unused — filtering by app
// is the caller's responsibility. Call AddRoot at least once after Observe
// returns; until then, the kernel-side filter drops every event.
func (o *Observer) Observe(ctx context.Context, _ string) (<-chan observer.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		// Pre-5.11 kernels needed RLIMIT_MEMLOCK raised to load BPF maps;
		// modern kernels account map memory differently, so a failure here
		// is only fatal on old kernels — the load step below will surface it.
		fmt.Fprintf(os.Stderr, "ratpak: warn: remove memlock: %v\n", err)
	}

	objs := &openatObjects{}
	if err := loadOpenatObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	type tpSpec struct {
		group, name string
		prog        *ebpf.Program
	}
	specs := []tpSpec{
		{"syscalls", "sys_enter_openat", objs.TraceOpenatEnter},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2Enter},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit},
		{"sched", "sched_process_fork", objs.TraceSchedFork},
		{"sched", "sched_process_exit", objs.TraceSchedExit},
	}
	var links []link.Link
	for _, s := range specs {
		l, err := link.Tracepoint(s.group, s.name, s.prog, nil)
		if err != nil {
			for _, prev := range links {
				prev.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", s.group, s.name, err)
		}
		links = append(links, l)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	o.mu.Lock()
	o.objs = objs
	o.mu.Unlock()

	ch := make(chan observer.Event, 1024)

	go func() {
		<-ctx.Done()
		rd.Close() // unblocks rd.Read with ringbuf.ErrClosed
	}()

	go func() {
		defer close(ch)
		defer func() {
			for _, l := range links {
				l.Close()
			}
		}()
		defer func() {
			o.mu.Lock()
			o.objs = nil
			o.mu.Unlock()
			objs.Close()
		}()

		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				fmt.Fprintf(os.Stderr, "ratpak: ringbuf read: %v\n", err)
				return
			}
			var ev rawEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
				continue
			}
			select {
			case ch <- observer.Event{PID: int(ev.TGID), Comm: cstr(ev.Comm[:]), Path: cstr(ev.Path[:])}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

// AddRoot adds pid (a kernel TID) to the kernel-side tracked set so events
// from it — and, via the sched_process_fork hook, all of its descendant
// threads and processes — flow through to userspace. Must be called after
// Observe and before the target process forks anything observable; the
// race between cmd.Start and AddRoot is small in practice.
//
// For seeding a multi-threaded process (e.g. when retro-attaching to an
// already-running flatpak), call AddRoot once per thread by walking
// /proc/<tgid>/task/.
func (o *Observer) AddRoot(pid int) error {
	o.mu.Lock()
	objs := o.objs
	o.mu.Unlock()
	if objs == nil {
		return errors.New("observer: AddRoot called before Observe (or after it returned)")
	}
	key := uint32(pid)
	val := uint32(1)
	return objs.TrackedPids.Update(key, val, ebpf.UpdateAny)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
