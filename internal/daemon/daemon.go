// Package daemon runs ratpak as an always-on, per-user agent.
//
// The daemon hooks the kernel's process-fork events to maintain a kernel-side
// set of TGIDs descended from any flatpak'd process, observes their openat
// calls in real time, and persists per-app trace data to disk.
//
// Two policy axes:
//
//   - scope: which apps the daemon attends to. Default: all flatpak'd
//     processes the user runs. Restricted via Server.IncludeApps and
//     Server.ExcludeApps.
//   - mode: what the daemon does with what it observes.
//     ModePermissive (default) only persists traces. ModeEnforcing also
//     auto-applies revocations when a manifest grant has zero hits across
//     enough sessions, gated by Server.Level (1=conservative … 4=aggressive)
//     against each grant's RiskScore.
//
// First cut keeps state in jsonl trace files via internal/trace; sqlite + an
// IPC server are P1 follow-ups (see docs/daemon-design.md).
package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ratpak/internal/flatpak"
	ebpfobs "ratpak/internal/observer/ebpf"
	"ratpak/internal/trace"
)

// Mode controls whether the daemon merely observes or also acts.
type Mode int

const (
	ModePermissive Mode = iota
	ModeEnforcing
)

func (m Mode) String() string {
	if m == ModeEnforcing {
		return "enforcing"
	}
	return "permissive"
}

// SocketPath returns the per-user IPC socket path. Prefers
// $XDG_RUNTIME_DIR/ratpak.sock; falls back to /tmp/ratpak-<uid>.sock when
// XDG_RUNTIME_DIR is unset. The IPC server itself isn't built yet.
func SocketPath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "ratpak.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("ratpak-%d.sock", os.Getuid()))
}

// StateDir returns the per-user state directory:
// $XDG_DATA_HOME/ratpak (or ~/.local/share/ratpak as the default).
func StateDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "ratpak")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "ratpak")
}

// Server is the daemon's main entry point.
type Server struct {
	SocketPath string
	StateDir   string

	// ScanInterval controls how often the daemon walks /proc looking for
	// new flatpak'd processes to add to the kernel-side tracked set. New
	// apps are picked up with up to one interval of latency. Default 2s.
	ScanInterval time.Duration

	// EnforceInterval controls how often the enforcement loop runs in
	// ModeEnforcing. Default 15 minutes — enforcement decisions don't need
	// to be real-time and excessive churn risks pinging the user with
	// "your overrides changed again" surprises. Ignored in ModePermissive.
	EnforceInterval time.Duration

	// Home / UID / GID are the invoking user's identity, used for trace
	// file ownership when the daemon runs under doas/sudo.
	Home string
	UID  int
	GID  int

	// IncludeApps, if non-empty, restricts the daemon to these app IDs.
	// Empty = all flatpak'd apps.
	IncludeApps []string
	// ExcludeApps lists app IDs the daemon ignores even if otherwise in scope.
	ExcludeApps []string

	Mode  Mode
	Level int // 1..4; only meaningful when Mode == ModeEnforcing
}

// MinSessionsForEnforce is the hard floor on observed sessions required
// before any auto-revocation fires. Below this, no enforcement happens
// regardless of risk score or level. Conservative default.
const MinSessionsForEnforce = 3

type sess struct {
	appid  string
	writer *trace.Writer
	seen   map[string]struct{}
}

// inScope reports whether the daemon should attend to the given app ID,
// applying the IncludeApps and ExcludeApps lists.
func (s *Server) inScope(appid string) bool {
	for _, x := range s.ExcludeApps {
		if x == appid {
			return false
		}
	}
	if len(s.IncludeApps) == 0 {
		return true
	}
	for _, a := range s.IncludeApps {
		if a == appid {
			return true
		}
	}
	return false
}

// Run blocks until ctx is cancelled. Loads the eBPF observer, scans /proc
// for already-running flatpak processes, then enters an event loop that
// demultiplexes openat events by appid into per-app trace files. In
// ModeEnforcing, also runs a periodic enforcement loop that auto-applies
// revocations based on the accumulated trace data.
func (s *Server) Run(ctx context.Context) error {
	if s.ScanInterval == 0 {
		s.ScanInterval = 2 * time.Second
	}
	if s.EnforceInterval == 0 {
		s.EnforceInterval = 15 * time.Minute
	}

	if s.Mode == ModeEnforcing {
		if os.Geteuid() == 0 {
			return fmt.Errorf("daemon: enforcing mode can't run as root — `flatpak override --user` writes to whoever's identity invokes it. Run as your user with `make setcap` granting cap_bpf,cap_perfmon")
		}
		if flatpak.LevelRiskCap(s.Level) == 0 {
			return fmt.Errorf("daemon: enforcing mode requires --level in 1..4 (got %d)", s.Level)
		}
	}

	obs := ebpfobs.New()
	events, err := obs.Observe(ctx, "")
	if err != nil {
		return fmt.Errorf("start observer: %w", err)
	}

	sessions := map[string]*sess{} // appid -> session
	tgidApp := map[int]string{}    // tgid -> appid (cache; "" = negative)

	defer func() {
		for _, s := range sessions {
			if s != nil && s.writer != nil {
				_ = s.writer.Close()
			}
		}
	}()

	added := s.scan(obs, tgidApp)
	fmt.Fprintf(os.Stderr, "ratpak daemon: started in %s mode; %d already-running flatpak process(es) attached\n", s.Mode, added)
	if s.Mode == ModeEnforcing {
		cap := flatpak.LevelRiskCap(s.Level)
		fmt.Fprintf(os.Stderr, "ratpak daemon: enforcing level=%d (auto-revoke risk score ≤ %d, min %d sessions of zero-hits)\n", s.Level, cap, MinSessionsForEnforce)
	}
	if len(s.IncludeApps) > 0 {
		fmt.Fprintf(os.Stderr, "ratpak daemon: scope: only %s\n", strings.Join(s.IncludeApps, ", "))
	}
	if len(s.ExcludeApps) > 0 {
		fmt.Fprintf(os.Stderr, "ratpak daemon: scope: excluding %s\n", strings.Join(s.ExcludeApps, ", "))
	}

	scanTick := time.NewTicker(s.ScanInterval)
	defer scanTick.Stop()

	var enforceTick *time.Ticker
	var enforceCh <-chan time.Time
	if s.Mode == ModeEnforcing {
		enforceTick = time.NewTicker(s.EnforceInterval)
		defer enforceTick.Stop()
		enforceCh = enforceTick.C
		// Run enforcement once at startup so an existing corpus of traces
		// gets acted on immediately rather than after EnforceInterval.
		s.runEnforcement()
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-scanTick.C:
			if added := s.scan(obs, tgidApp); added > 0 {
				fmt.Fprintf(os.Stderr, "ratpak daemon: attached %d new flatpak process(es)\n", added)
			}

		case <-enforceCh:
			s.runEnforcement()

		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if isSetupComm(ev.Comm) {
				continue
			}
			if !strings.HasPrefix(ev.Path, "/") {
				continue
			}

			appid, ok := tgidApp[ev.PID]
			if !ok {
				resolved, err := flatpak.ResolveAppID(ev.PID)
				if err != nil || resolved == "" {
					tgidApp[ev.PID] = ""
					continue
				}
				appid = resolved
				tgidApp[ev.PID] = appid
			}
			if appid == "" || !s.inScope(appid) {
				continue
			}

			session, exists := sessions[appid]
			if !exists {
				w, err := trace.NewWriter(s.Home, appid, s.UID, s.GID)
				if err != nil {
					fmt.Fprintf(os.Stderr, "ratpak daemon: open trace for %s: %v\n", appid, err)
					sessions[appid] = nil
					continue
				}
				session = &sess{appid: appid, writer: w, seen: map[string]struct{}{}}
				sessions[appid] = session
				fmt.Fprintf(os.Stderr, "ratpak daemon: opened session for %s -> %s\n", appid, w.Path)
			} else if session == nil {
				continue
			}

			if _, dup := session.seen[ev.Path]; dup {
				continue
			}
			session.seen[ev.Path] = struct{}{}
			if err := session.writer.Add(trace.Record{Path: ev.Path, Comm: ev.Comm, PID: ev.PID}); err != nil {
				fmt.Fprintf(os.Stderr, "ratpak daemon: warn: trace write for %s: %v\n", appid, err)
			}
		}
	}
}

// scan walks /proc looking for flatpak'd processes whose tgid isn't already
// in the appid cache. For each new in-scope one, it seeds the kernel-side
// tracked set so the BPF fork hook can propagate to descendants. Returns
// the number of newly-attached tgids.
func (s *Server) scan(obs *ebpfobs.Observer, cache map[int]string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	added := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		if _, cached := cache[pid]; cached {
			continue
		}
		appid, err := flatpak.ResolveAppID(pid)
		if err != nil || appid == "" {
			cache[pid] = ""
			continue
		}
		cache[pid] = appid
		if !s.inScope(appid) {
			continue
		}
		if err := obs.AddRoot(pid); err != nil {
			fmt.Fprintf(os.Stderr, "ratpak daemon: warn: AddRoot %d (%s): %v\n", pid, appid, err)
			continue
		}
		added++
	}
	return added
}

// runEnforcement iterates all in-scope apps with at least
// MinSessionsForEnforce non-empty traces, computes their unused-grant set,
// and auto-applies revocations whose RiskScore ≤ LevelRiskCap(Level).
//
// Deliberately re-reads the trace files each cycle: the daemon's in-memory
// `sessions` map only covers the current run, but the user's full session
// corpus across multiple daemon runs is what feeds policy.
func (s *Server) runEnforcement() {
	cap := flatpak.LevelRiskCap(s.Level)
	if cap == 0 {
		return
	}

	tracesRoot := filepath.Join(s.Home, ".local", "share", "ratpak", "traces")
	apps, err := os.ReadDir(tracesRoot)
	if err != nil {
		return
	}

	for _, a := range apps {
		if !a.IsDir() {
			continue
		}
		appid := a.Name()
		if !s.inScope(appid) {
			continue
		}
		s.enforceApp(appid, cap)
	}
}

func (s *Server) enforceApp(appid string, riskCap int) {
	files, err := trace.ListFiles(s.Home, appid)
	if err != nil || len(files) < MinSessionsForEnforce {
		return
	}

	// Load trace files; skip empty ones (failed observes etc.).
	var sessionPaths []map[string]struct{}
	for _, f := range files {
		recs, err := trace.ReadFile(f)
		if err != nil {
			continue
		}
		paths := make(map[string]struct{}, len(recs))
		for _, r := range recs {
			if r.Path != "" {
				paths[r.Path] = struct{}{}
			}
		}
		if len(paths) > 0 {
			sessionPaths = append(sessionPaths, paths)
		}
	}
	if len(sessionPaths) < MinSessionsForEnforce {
		return
	}

	perms, err := flatpak.RequestedPermissions(appid)
	if err != nil {
		return
	}

	// Look at the user's existing overrides so we don't repeatedly
	// re-apply (and re-log) the same revocation each enforcement tick.
	existing, _ := flatpak.UserOverrides(appid)
	already := make(map[string]struct{}, len(existing.Filesystems))
	for _, f := range existing.Filesystems {
		if strings.HasPrefix(f, "!") {
			already[strings.TrimPrefix(f, "!")] = struct{}{}
		}
	}

	for _, raw := range perms.Filesystems {
		if strings.HasPrefix(raw, "!") {
			continue
		}
		risk := flatpak.RiskScore(raw)
		if risk > riskCap {
			continue
		}
		t, _ := flatpak.ResolveFilesystemTerm(raw, s.Home, s.UID)
		if t.Path == "" {
			continue
		}

		hit := false
		for _, paths := range sessionPaths {
			for p := range paths {
				if flatpak.PathUnder(p, t.Path) {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if hit {
			continue
		}

		stripped := flatpak.StripMode(raw)
		if _, dup := already[stripped]; dup {
			continue
		}

		if err := flatpak.AddNoFilesystem(appid, stripped); err != nil {
			fmt.Fprintf(os.Stderr, "ratpak daemon: enforce: failed to revoke %s on %s: %v\n", stripped, appid, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "ratpak daemon: enforce: revoked %s on %s (risk=%d, %d sessions of zero-hits)\n", stripped, appid, risk, len(sessionPaths))
		already[stripped] = struct{}{}
	}
}

// isSetupComm matches process names that do sandbox-setup work but aren't
// the app itself.
func isSetupComm(comm string) bool {
	switch comm {
	case "bwrap", "ldconfig", "flatpak", "flatpak-bwrap":
		return true
	}
	return false
}
