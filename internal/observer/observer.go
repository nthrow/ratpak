// Package observer captures filesystem accesses by a running flatpak app
// for the purpose of building a minimal-permission profile.
//
// The eBPF-backed implementation will live in a sub-package; this file
// defines the surface the rest of ratpak depends on.
package observer

import "context"

// Event is a single observed filesystem access (a successful openat).
type Event struct {
	PID  int
	Comm string
	Path string
}

// Observer streams filesystem access events for a flatpak app instance.
type Observer interface {
	// Observe runs until ctx is cancelled, emitting events for the
	// flatpak instance with the given app ID. The returned channel is
	// closed when observation ends.
	Observe(ctx context.Context, appID string) (<-chan Event, error)
}
