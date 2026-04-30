package observer

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PIDTracker maintains the set of TGIDs descended from a root PID, by polling
// /proc and walking ppids. It is intentionally simple — short-lived children
// born and dying inside one poll interval may be missed.
//
// Each tracked PID is also tagged with its mount-namespace inum, read once
// from /proc/<pid>/ns/mnt. The root's mntns is recorded as the "host" mntns;
// any tracked PID whose mntns differs is considered "sandboxed" — that's
// where the actual flatpak'd app runs after bwrap unshares. This lets the
// caller cheaply discard events from flatpak's own setup work that happens
// in the host mntns before the sandbox is established.
type PIDTracker struct {
	mu       sync.RWMutex
	tracked  map[int]uint64 // pid -> mntns inum (0 if unknown)
	hostNS   uint64
	interval time.Duration
}

// NewPIDTracker seeds a tracker with `root` and starts polling at the
// given interval.
func NewPIDTracker(root int, interval time.Duration) *PIDTracker {
	hostNS := readMntNS(root)
	t := &PIDTracker{
		tracked:  map[int]uint64{root: hostNS},
		hostNS:   hostNS,
		interval: interval,
	}
	t.refresh()
	return t
}

// Includes reports whether pid is in the tracked set (descended from root).
func (t *PIDTracker) Includes(pid int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.tracked[pid]
	return ok
}

// IsSandboxed reports whether pid is tracked AND in a different mount
// namespace from the root — i.e. it lives inside the flatpak's bwrap
// sandbox rather than alongside the host-side flatpak runner.
func (t *PIDTracker) IsSandboxed(pid int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ns, ok := t.tracked[pid]
	return ok && ns != 0 && ns != t.hostNS
}

// Run polls /proc until ctx is cancelled.
func (t *PIDTracker) Run(ctx context.Context) {
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.refresh()
		}
	}
}

func (t *PIDTracker) refresh() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	parents := make(map[int]int, len(entries))
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ppid, ok := readPPID(pid)
		if !ok {
			continue
		}
		parents[pid] = ppid
		pids = append(pids, pid)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, pid := range pids {
		if _, ok := t.tracked[pid]; ok {
			continue
		}
		// Walk ppid chain up to find a tracked ancestor.
		cur := parents[pid]
		for cur > 1 {
			if _, ok := t.tracked[cur]; ok {
				t.tracked[pid] = readMntNS(pid)
				break
			}
			next, ok := parents[cur]
			if !ok || next == cur {
				break
			}
			cur = next
		}
	}
}

func readPPID(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	// /proc/<pid>/stat: "<pid> (<comm>) <state> <ppid> ..."
	// comm can contain spaces and parentheses, so split on the LAST ')'.
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 || end+1 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[end+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return ppid, true
}

func readMntNS(pid int) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &st); err != nil {
		return 0
	}
	return st.Ino
}
