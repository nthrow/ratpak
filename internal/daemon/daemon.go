// Package daemon runs ratpak as an always-on, per-user agent.
//
// The daemon hooks the kernel's process-fork events to maintain a kernel-side
// set of TGIDs descended from any flatpak'd process, observes their openat
// calls in real time, and persists per-app trace data to a state store. A
// Unix-socket IPC server lets ratpak CLI clients (and a future GUI) query
// app state, apply revocations, and subscribe to prompts.
//
// Status: scaffolding. Server.Run returns ErrNotImplemented. The package
// claims the namespace and pins down the IPC socket convention so future
// work has a fixed landing pad. See docs/daemon-design.md for the full
// architecture.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotImplemented is returned by daemon entry points until the daemon is
// fleshed out.
var ErrNotImplemented = errors.New("daemon: not implemented yet — see docs/daemon-design.md")

// SocketPath returns the per-user IPC socket path. Prefers
// $XDG_RUNTIME_DIR/ratpak.sock; falls back to /tmp/ratpak-<uid>.sock when
// XDG_RUNTIME_DIR is unset.
func SocketPath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "ratpak.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("ratpak-%d.sock", os.Getuid()))
}

// StateDir returns the per-user state directory:
// $XDG_DATA_HOME/ratpak (or ~/.local/share/ratpak as the default).
// Same root as the existing trace files; the daemon will land state.db here.
func StateDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "ratpak")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "ratpak")
}

// Server is the daemon's main entry point. Configured by the CLI's `daemon`
// subcommand; runs the eBPF observer, state store, IPC server, and analysis
// loop concurrently until ctx is cancelled.
type Server struct {
	SocketPath string
	StateDir   string
}

// Run blocks until ctx is cancelled or a fatal error occurs. Currently
// returns ErrNotImplemented without taking any action.
func (s *Server) Run(ctx context.Context) error {
	_ = ctx
	return ErrNotImplemented
}
