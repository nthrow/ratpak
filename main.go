package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ratpak/internal/flatpak"
	"ratpak/internal/observer"
	ebpfobs "ratpak/internal/observer/ebpf"
)

const usage = `ratpak — flatpak firewall

usage: ratpak <command> [arguments]

commands:
  list                       list installed flatpak apps
  info <appid>               show requested permissions and current overrides for an app
  observe <appid>            launch app under observation, print every path it opens
  profile <appid> [trace]    classify a captured trace into used / unused / unaccounted
                             (reads trace from stdin if no file is given)
  apply <appid>              apply minimal overrides based on observation (not yet implemented)
`

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var err error
	switch args[0] {
	case "list":
		err = cmdList(args[1:])
	case "info":
		err = cmdInfo(args[1:])
	case "observe":
		err = cmdObserve(args[1:])
	case "profile":
		err = cmdProfile(args[1:])
	case "apply":
		err = cmdApply(args[1:])
	case "help", "-h", "--help":
		flag.Usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "ratpak: unknown command %q\n\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratpak: %v\n", err)
		os.Exit(1)
	}
}

func cmdList(_ []string) error {
	apps, err := flatpak.InstalledApps()
	if err != nil {
		return err
	}
	for _, a := range apps {
		fmt.Println(a)
	}
	return nil
}

func cmdInfo(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("info: expected <appid>")
	}
	appID := args[0]

	requested, err := flatpak.RequestedPermissions(appID)
	if err != nil {
		return fmt.Errorf("read manifest permissions: %w", err)
	}
	overrides, err := flatpak.UserOverrides(appID)
	if err != nil {
		return fmt.Errorf("read user overrides: %w", err)
	}

	fmt.Printf("App: %s\n\n", appID)
	printList("Requested filesystems (manifest)", requested.Filesystems)
	printList("User overrides — filesystems", overrides.Filesystems)
	return nil
}

func cmdObserve(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("observe: expected <appid>")
	}
	appID := args[0]

	ctx, cancel := signalContext()
	defer cancel()

	obs := ebpfobs.New()
	events, err := obs.Observe(ctx, appID)
	if err != nil {
		return fmt.Errorf("start observer: %w", err)
	}

	cmd := exec.CommandContext(ctx, "flatpak", "run", appID)
	cmd.Stdout = os.Stderr // keep stdout clean for path output
	cmd.Stderr = os.Stderr
	dropPrivilegesForChild(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("flatpak run %s: %w", appID, err)
	}
	fmt.Fprintf(os.Stderr, "ratpak: launched %s as PID %d (Ctrl-C to stop)\n", appID, cmd.Process.Pid)

	tracker := observer.NewPIDTracker(cmd.Process.Pid, 50*time.Millisecond)
	go tracker.Run(ctx)

	go func() {
		_ = cmd.Wait()
		cancel()
	}()

	seen := make(map[string]struct{})
	for ev := range events {
		if !tracker.IsSandboxed(ev.PID) {
			continue // host-mntns event (flatpak runner setup, etc.)
		}
		if isSetupComm(ev.Comm) {
			continue // bwrap / ldconfig running inside the sandbox
		}
		if !strings.HasPrefix(ev.Path, "/") {
			continue // unresolved relative path; v1 limitation
		}
		if _, ok := seen[ev.Path]; ok {
			continue
		}
		seen[ev.Path] = struct{}{}
		fmt.Println(ev.Path)
	}
	fmt.Fprintf(os.Stderr, "ratpak: %d unique paths observed\n", len(seen))
	return nil
}

// isSetupComm matches process names that do sandbox-setup work but aren't
// the app itself, so their accesses shouldn't influence the permission profile.
func isSetupComm(comm string) bool {
	switch comm {
	case "bwrap", "ldconfig", "flatpak", "flatpak-bwrap":
		return true
	}
	return false
}

func cmdApply(_ []string) error {
	return fmt.Errorf("apply: not yet implemented")
}

func cmdProfile(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("profile: expected <appid> [trace-file]")
	}
	appID := args[0]

	var src io.Reader = os.Stdin
	if len(args) >= 2 {
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
	}

	paths, err := readTrace(src)
	if err != nil {
		return err
	}

	requested, err := flatpak.RequestedPermissions(appID)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	home, uid := profileHomeAndUID()

	type grant struct {
		term flatpak.FilesystemTerm
		hits []string
	}
	grants := make([]grant, 0, len(requested.Filesystems))
	for _, raw := range requested.Filesystems {
		t, ok := flatpak.ResolveFilesystemTerm(raw, home, uid)
		_ = ok // unrecognized terms still get listed; they just match nothing
		grants = append(grants, grant{term: t})
	}

	autoGrants := flatpak.AutoGrantedPaths(appID, home, uid)
	var unaccounted []string

	for _, p := range paths {
		if flatpak.AnyPathUnder(p, autoGrants) {
			continue
		}
		matched := false
		for i := range grants {
			gp := grants[i].term.Path
			if gp == "" {
				continue
			}
			if flatpak.PathUnder(p, gp) {
				grants[i].hits = append(grants[i].hits, p)
				matched = true
				break
			}
		}
		if !matched {
			unaccounted = append(unaccounted, p)
		}
	}

	fmt.Printf("App: %s\n", appID)
	fmt.Printf("Trace: %d unique paths\n\n", len(paths))

	fmt.Println("Manifest filesystem grants:")
	if len(grants) == 0 {
		fmt.Println("  (none)")
	}
	for _, g := range grants {
		status := "USED  "
		count := len(g.hits)
		if count == 0 {
			status = "UNUSED"
		}
		resolved := g.term.Path
		if resolved == "" {
			resolved = "(unresolved)"
		}
		fmt.Printf("  %s  %-32s → %s  (%d hits)\n", status, g.term.Raw, resolved, count)
	}
	fmt.Println()

	if len(unaccounted) > 0 {
		fmt.Println("Unaccounted accesses (outside both manifest and auto-grants):")
		summary := summarizeByDepth(unaccounted, 4)
		for _, kv := range summary {
			fmt.Printf("  %5d  %s\n", kv.count, kv.prefix)
		}
		fmt.Println()
	}

	unused := 0
	for _, g := range grants {
		if len(g.hits) == 0 && g.term.Path != "" {
			unused++
		}
	}
	if unused > 0 {
		fmt.Printf("Recommendation: %d/%d declared filesystem grant(s) had zero hits in this trace — candidates for removal.\n", unused, len(grants))
	} else if len(grants) > 0 {
		fmt.Println("All declared filesystem grants saw use.")
	}
	return nil
}

func readTrace(src io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var paths []string
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		paths = append(paths, line)
	}
	return paths, sc.Err()
}

// profileHomeAndUID picks the home directory and uid to interpret xdg-* terms
// against. When run via sudo/doas we resolve to the invoking user; otherwise
// we use the current process.
func profileHomeAndUID() (string, int) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = os.Getenv("DOAS_USER")
	}
	if name != "" {
		if u, err := user.Lookup(name); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				return u.HomeDir, uid
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home, os.Getuid()
}

type prefixCount struct {
	prefix string
	count  int
}

// summarizeByDepth groups paths by their first `depth` path components and
// returns the counts sorted descending. Useful for compressing long
// unaccounted lists into a digestible summary.
func summarizeByDepth(paths []string, depth int) []prefixCount {
	counts := map[string]int{}
	for _, p := range paths {
		parts := strings.SplitN(p, "/", depth+2)
		key := p
		if len(parts) > depth+1 {
			key = strings.Join(parts[:depth+1], "/")
		}
		counts[key]++
	}
	out := make([]prefixCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, prefixCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].prefix < out[j].prefix
	})
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}

func printList(title string, items []string) {
	fmt.Printf("%s:\n", title)
	if len(items) == 0 {
		fmt.Println("  (none)")
	}
	for _, item := range items {
		fmt.Printf("  %s\n", item)
	}
	fmt.Println()
}

// dropPrivilegesForChild configures cmd to run as the invoking user when
// ratpak itself is running as root via sudo / doas. Without this, `flatpak
// run` as root only sees system-wide installations and can't talk to the
// user's session bus.
func dropPrivilegesForChild(cmd *exec.Cmd) {
	if os.Geteuid() != 0 {
		return
	}
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = os.Getenv("DOAS_USER")
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "ratpak: warn: running as root without SUDO_USER/DOAS_USER — flatpak may not see user installs")
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratpak: warn: lookup %s: %v\n", name, err)
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}

	// Pull the user's actual session env (DBUS_SESSION_BUS_ADDRESS, DISPLAY,
	// WAYLAND_DISPLAY, XDG_RUNTIME_DIR, etc.) from one of their running
	// processes — far more robust than synthesizing. Then merge in our own
	// env for anything the scraped proc lacks but doas/sudo passed through.
	scraped, ok := findUserSessionEnv(uid)
	if !ok {
		fmt.Fprintf(os.Stderr, "ratpak: warn: no user session process found for %s; GUI/dbus may fail\n", name)
		env := os.Environ()
		env = setenv(env, "HOME", u.HomeDir)
		env = setenv(env, "USER", name)
		env = setenv(env, "LOGNAME", name)
		env = setenv(env, "XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", uid))
		cmd.Env = env
		return
	}
	cmd.Env = mergeEnv(scraped, os.Environ())
}

// findUserSessionEnv returns the environment of a process owned by uid that
// looks like a real interactive-session process. Prefers one that has both
// a DBUS_SESSION_BUS_ADDRESS and a display (DISPLAY or WAYLAND_DISPLAY); if
// no such process is found, falls back to any process with the bus address.
// Returns ok=false if nothing suitable is found.
func findUserSessionEnv(uid int) ([]string, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	var fallback []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(fmt.Sprintf("/proc/%d", pid), &st); err != nil {
			continue
		}
		if int(st.Uid) != uid {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil || len(data) == 0 {
			continue
		}
		if !bytes.Contains(data, []byte("DBUS_SESSION_BUS_ADDRESS=")) {
			continue
		}
		env := splitEnviron(data)
		if envHasAny(env, "DISPLAY=", "WAYLAND_DISPLAY=") {
			return env, true
		}
		if fallback == nil {
			fallback = env
		}
	}
	if fallback != nil {
		return fallback, true
	}
	return nil, false
}

func splitEnviron(data []byte) []string {
	var env []string
	for _, b := range bytes.Split(data, []byte{0}) {
		if len(b) > 0 {
			env = append(env, string(b))
		}
	}
	return env
}

func envHasAny(env []string, prefixes ...string) bool {
	for _, e := range env {
		for _, p := range prefixes {
			if strings.HasPrefix(e, p) {
				return true
			}
		}
	}
	return false
}

// mergeEnv returns primary unioned with secondary; on key collisions, primary wins.
func mergeEnv(primary, secondary []string) []string {
	seen := make(map[string]struct{}, len(primary))
	for _, e := range primary {
		if i := strings.IndexByte(e, '='); i > 0 {
			seen[e[:i]] = struct{}{}
		}
	}
	out := append([]string(nil), primary...)
	for _, e := range secondary {
		i := strings.IndexByte(e, '=')
		if i <= 0 {
			continue
		}
		if _, ok := seen[e[:i]]; ok {
			continue
		}
		out = append(out, e)
	}
	return out
}

func setenv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()
	return ctx, cancel
}
