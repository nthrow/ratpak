package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"ratpak/internal/flatpak"
	ebpfobs "ratpak/internal/observer/ebpf"
	"ratpak/internal/trace"
)

const usage = `ratpak — flatpak firewall

usage: ratpak <command> [arguments]

commands:
  list                       list installed flatpak apps
  info <appid>               show requested permissions and current overrides for an app
  observe <appid>            launch app under observation; saves a jsonl trace under
                             ~/.local/share/ratpak/traces/<appid>/ and prints paths live
  profile <appid> [trace]    classify saved traces into used / unused / unaccounted.
                             With no arg, unions every saved trace for the app.
                             With a path or '-' (stdin), classifies that single trace.
  apply <appid> [--commit]   revoke filesystem grants that had zero hits across all
                             saved sessions (dry-run by default; pass --commit to write)
  reset <appid> [--commit]   remove ALL user overrides for the app (dry-run by default;
                             broader than apply — also clears dbus/socket overrides)
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
	case "reset":
		err = cmdReset(args[1:])
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

	home, uid, gid := invokingUser()
	w, err := trace.NewWriter(home, appID, uid, gid)
	if err != nil {
		return fmt.Errorf("open trace: %w", err)
	}
	defer w.Close()

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
	if err := obs.AddRoot(cmd.Process.Pid); err != nil {
		return fmt.Errorf("seed tracked set: %w", err)
	}
	fmt.Fprintf(os.Stderr, "ratpak: launched %s as PID %d (Ctrl-C to stop)\n", appID, cmd.Process.Pid)
	fmt.Fprintf(os.Stderr, "ratpak: writing trace to %s\n", w.Path)

	go func() {
		_ = cmd.Wait()
		cancel()
	}()

	seen := make(map[string]struct{})
	for ev := range events {
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
		if err := w.Add(trace.Record{Path: ev.Path, Comm: ev.Comm, PID: ev.PID}); err != nil {
			fmt.Fprintf(os.Stderr, "ratpak: warn: trace write: %v\n", err)
		}
		fmt.Println(ev.Path)
	}
	fmt.Fprintf(os.Stderr, "ratpak: %d unique paths observed; trace saved to %s\n", len(seen), w.Path)
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

func cmdApply(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("apply: expected <appid> [--commit]")
	}
	appID := args[0]
	commit := false
	for _, a := range args[1:] {
		switch a {
		case "--commit":
			commit = true
		default:
			return fmt.Errorf("apply: unknown flag %q", a)
		}
	}
	if commit && os.Geteuid() == 0 {
		return fmt.Errorf("apply --commit: don't run as root — overrides go to your user's flatpak config; run as the invoking user")
	}

	home, uid, _ := invokingUser()

	files, err := trace.ListFiles(home, appID)
	if err != nil {
		return fmt.Errorf("list traces: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no saved traces for %s; run 'ratpak observe %s' first", appID, appID)
	}
	var sessions []map[string]struct{}
	for _, f := range files {
		recs, err := trace.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		sessions = append(sessions, pathSet(recs))
	}

	requested, err := flatpak.RequestedPermissions(appID)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	type unusedTerm struct {
		raw    string
		stripped string
	}
	var unused []unusedTerm
	for _, raw := range requested.Filesystems {
		if strings.HasPrefix(raw, "!") {
			continue // already a manifest-side negation
		}
		t, _ := flatpak.ResolveFilesystemTerm(raw, home, uid)
		if t.Path == "" {
			continue // unresolved term — don't presume to revoke it
		}
		hit := false
		for _, s := range sessions {
			for p := range s {
				if flatpak.PathUnder(p, t.Path) {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			unused = append(unused, unusedTerm{raw: raw, stripped: stripMode(raw)})
		}
	}

	fmt.Printf("App: %s\n", appID)
	fmt.Printf("Sessions: %d\n", len(sessions))
	if len(unused) == 0 {
		fmt.Println("No unused filesystem grants — nothing to apply.")
		return nil
	}

	if !commit {
		fmt.Printf("\nWould revoke %d filesystem grant(s) (dry-run; pass --commit to apply):\n", len(unused))
		for _, u := range unused {
			fmt.Printf("  flatpak override --user --nofilesystem=%s %s\n", u.stripped, appID)
		}
		if len(sessions) < 3 {
			fmt.Printf("\nWarning: based on only %d session(s) of observation. Consider capturing more before --commit.\n", len(sessions))
		}
		return nil
	}

	fmt.Printf("\nApplying %d revocation(s)...\n", len(unused))
	failed := 0
	for _, u := range unused {
		if err := flatpak.AddNoFilesystem(appID, u.stripped); err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL  --nofilesystem=%s: %v\n", u.stripped, err)
			failed++
			continue
		}
		fmt.Printf("  done  --nofilesystem=%s\n", u.stripped)
	}
	if failed > 0 {
		return fmt.Errorf("apply: %d/%d revocations failed", failed, len(unused))
	}
	fmt.Printf("\nDone. To undo all user overrides for this app: ratpak reset %s --commit\n", appID)
	return nil
}

func cmdReset(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("reset: expected <appid> [--commit]")
	}
	appID := args[0]
	commit := false
	for _, a := range args[1:] {
		switch a {
		case "--commit":
			commit = true
		default:
			return fmt.Errorf("reset: unknown flag %q", a)
		}
	}
	if commit && os.Geteuid() == 0 {
		return fmt.Errorf("reset --commit: don't run as root — overrides live in your user's flatpak config")
	}

	overrides, err := flatpak.UserOverrides(appID)
	if err != nil {
		return fmt.Errorf("read overrides: %w", err)
	}

	fmt.Printf("App: %s\n", appID)
	fmt.Println("Current user overrides — filesystems:")
	if len(overrides.Filesystems) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, f := range overrides.Filesystems {
			fmt.Printf("  %s\n", f)
		}
	}

	if !commit {
		fmt.Println("\nWould reset ALL user overrides (filesystems, dbus, sockets, …) for this app — dry-run.")
		fmt.Printf("Run 'ratpak reset %s --commit' to apply.\n", appID)
		return nil
	}

	if err := flatpak.ResetUser(appID); err != nil {
		return err
	}
	fmt.Println("\nDone. All user overrides for this app removed.")
	return nil
}

// stripMode returns a flatpak filesystem term without its mode suffix
// (:ro / :rw / :create). flatpak's --nofilesystem rejects mode suffixes.
func stripMode(raw string) string {
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		switch raw[i+1:] {
		case "ro", "rw", "create":
			return raw[:i]
		}
	}
	return raw
}

func cmdProfile(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("profile: expected <appid> [trace-file|-]")
	}
	appID := args[0]
	home, uid, _ := invokingUser()

	type session struct {
		label string
		paths map[string]struct{}
	}
	var sessions []session

	switch {
	case len(args) >= 2 && args[1] == "-":
		recs, err := trace.Read(os.Stdin)
		if err != nil {
			return err
		}
		sessions = []session{{label: "<stdin>", paths: pathSet(recs)}}
	case len(args) >= 2:
		recs, err := trace.ReadFile(args[1])
		if err != nil {
			return err
		}
		sessions = []session{{label: args[1], paths: pathSet(recs)}}
	default:
		files, err := trace.ListFiles(home, appID)
		if err != nil {
			return fmt.Errorf("list traces: %w", err)
		}
		if len(files) == 0 {
			return fmt.Errorf("no saved traces for %s; run 'ratpak observe %s' first", appID, appID)
		}
		for _, f := range files {
			recs, err := trace.ReadFile(f)
			if err != nil {
				return fmt.Errorf("read %s: %w", f, err)
			}
			paths := pathSet(recs)
			if len(paths) == 0 {
				continue // skip 0-path traces (failed observes, immediate exits)
			}
			sessions = append(sessions, session{label: f, paths: paths})
		}
		if len(sessions) == 0 {
			return fmt.Errorf("found %d trace file(s) for %s but all are empty; run 'ratpak observe %s' to capture a real session", len(files), appID, appID)
		}
	}

	union := make(map[string]struct{})
	for _, s := range sessions {
		for p := range s.paths {
			union[p] = struct{}{}
		}
	}

	requested, err := flatpak.RequestedPermissions(appID)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	autoGrants := flatpak.AutoGrantedPaths(appID, home, uid)

	type grant struct {
		term        flatpak.FilesystemTerm
		sessionsHit int // sessions in which at least one path landed under this grant
		totalHits   int // unique paths in the union under this grant
	}
	grants := make([]grant, len(requested.Filesystems))
	for i, raw := range requested.Filesystems {
		t, _ := flatpak.ResolveFilesystemTerm(raw, home, uid)
		grants[i].term = t
	}

	var unaccounted []string
	for p := range union {
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
				grants[i].totalHits++
				matched = true
				break
			}
		}
		if !matched {
			unaccounted = append(unaccounted, p)
		}
	}
	sort.Strings(unaccounted)

	for i := range grants {
		gp := grants[i].term.Path
		if gp == "" {
			continue
		}
		for _, s := range sessions {
			for p := range s.paths {
				if flatpak.PathUnder(p, gp) {
					grants[i].sessionsHit++
					break
				}
			}
		}
	}

	n := len(sessions)
	fmt.Printf("App: %s\n", appID)
	fmt.Printf("Sessions: %d\n", n)
	listed := sessions
	truncated := 0
	if n > 5 {
		listed = sessions[:3]
		truncated = n - 3
	}
	for _, s := range listed {
		fmt.Printf("  %s  (%d unique paths)\n", s.label, len(s.paths))
	}
	if truncated > 0 {
		fmt.Printf("  ... %d more\n", truncated)
	}
	fmt.Printf("Union: %d unique paths\n\n", len(union))

	fmt.Println("Manifest filesystem grants:")
	if len(grants) == 0 {
		fmt.Println("  (none)")
	}
	for _, g := range grants {
		status := "USED  "
		if g.sessionsHit == 0 {
			status = "UNUSED"
		}
		resolved := g.term.Path
		if resolved == "" {
			resolved = "(unresolved)"
		}
		fmt.Printf("  %s  %-32s → %s  (%d/%d sessions, %d hits)\n",
			status, g.term.Raw, resolved, g.sessionsHit, n, g.totalHits)
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
		if g.sessionsHit == 0 && g.term.Path != "" {
			unused++
		}
	}
	if unused > 0 {
		if n == 1 {
			fmt.Printf("Recommendation: %d/%d declared filesystem grant(s) had zero hits — candidates for removal (caveat: 1 session is not strong evidence; capture more before applying).\n", unused, len(grants))
		} else {
			fmt.Printf("Recommendation: %d/%d declared filesystem grant(s) had zero hits across all %d sessions — candidates for removal.\n", unused, len(grants), n)
		}
	} else if len(grants) > 0 {
		fmt.Println("All declared filesystem grants saw use.")
	}
	return nil
}

func pathSet(recs []trace.Record) map[string]struct{} {
	s := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		if r.Path != "" {
			s[r.Path] = struct{}{}
		}
	}
	return s
}

// invokingUser returns the home, uid, gid of the user we should attribute
// trace files (and override writes) to. Under sudo/doas that's the invoking
// user; otherwise it's the current process's user. Falls back silently to the
// current process if SUDO_USER lookup fails — caller-side diagnostics are
// dropPrivilegesForChild's job, not ours.
func invokingUser() (string, int, int) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = os.Getenv("DOAS_USER")
	}
	if name != "" {
		if u, err := user.Lookup(name); err == nil {
			uid, err1 := strconv.Atoi(u.Uid)
			gid, err2 := strconv.Atoi(u.Gid)
			if err1 == nil && err2 == nil {
				return u.HomeDir, uid, gid
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home, os.Getuid(), os.Getgid()
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
