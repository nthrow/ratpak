package flatpak

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FilesystemTerm is a parsed flatpak --filesystem= permission term.
type FilesystemTerm struct {
	Raw  string // original ("xdg-download:ro")
	Path string // resolved host path prefix ("/home/nat/Downloads")
	Mode string // "rw" (default), "ro", or "create"
}

// ResolveFilesystemTerm expands a flatpak filesystem term to a host path
// prefix that observed paths must be under to count as "covered" by it.
// Returns ok=false if the term is unrecognized (e.g. an opaque alias the
// runtime defines that we don't handle yet).
func ResolveFilesystemTerm(raw, home string, uid int) (FilesystemTerm, bool) {
	t := FilesystemTerm{Raw: raw, Mode: "rw"}

	// Strip mode suffix (:ro / :rw / :create).
	term := raw
	if i := strings.LastIndexByte(term, ':'); i > 0 {
		switch term[i+1:] {
		case "ro", "rw", "create":
			t.Mode = term[i+1:]
			term = term[:i]
		}
	}

	// Negative permission ("!filesystems=…") — leave as raw, don't resolve.
	if strings.HasPrefix(term, "!") {
		return t, false
	}

	switch {
	case term == "host", term == "host-os":
		t.Path = "/"
		return t, true
	case term == "host-etc":
		t.Path = "/etc"
		return t, true
	case term == "home":
		t.Path = home
		return t, true
	case strings.HasPrefix(term, "/"):
		t.Path = term
		return t, true
	case strings.HasPrefix(term, "~/"):
		t.Path = filepath.Join(home, term[2:])
		return t, true
	case strings.HasPrefix(term, "xdg-"):
		if p, ok := resolveXDG(term, home, uid); ok {
			t.Path = p
			return t, true
		}
	}
	return t, false
}

func resolveXDG(term, home string, uid int) (string, bool) {
	// xdg-* may have a /subpath suffix: "xdg-config/foo" → ~/.config/foo
	base, sub := term, ""
	if i := strings.IndexByte(term, '/'); i > 0 {
		base, sub = term[:i], term[i:]
	}
	var root string
	switch base {
	case "xdg-download":
		root = filepath.Join(home, "Downloads")
	case "xdg-pictures":
		root = filepath.Join(home, "Pictures")
	case "xdg-videos":
		root = filepath.Join(home, "Videos")
	case "xdg-music":
		root = filepath.Join(home, "Music")
	case "xdg-documents":
		root = filepath.Join(home, "Documents")
	case "xdg-templates":
		root = filepath.Join(home, "Templates")
	case "xdg-public-share":
		root = filepath.Join(home, "Public")
	case "xdg-desktop":
		root = filepath.Join(home, "Desktop")
	case "xdg-config":
		root = filepath.Join(home, ".config")
	case "xdg-cache":
		root = filepath.Join(home, ".cache")
	case "xdg-data":
		root = filepath.Join(home, ".local", "share")
	case "xdg-run":
		root = fmt.Sprintf("/run/user/%d", uid)
	default:
		return "", false
	}
	if sub != "" {
		root += sub
	}
	return root, true
}

// AutoGrantedPaths returns host-path roots that flatpak grants to every
// sandboxed app implicitly — paths that don't require an explicit
// filesystem= term. Observed paths under (or equal to) any of these should
// not count toward "unaccounted" accesses.
func AutoGrantedPaths(appID, home string, uid int) []string {
	return []string{
		"/usr", "/lib", "/lib64", "/bin", "/sbin", // runtime internals
		"/app",                          // installed app payload
		"/etc",                          // sandbox /etc
		"/proc", "/sys", "/dev",         // kernel + dev nodes
		"/tmp", "/var/tmp",              // sandbox-private tmp
		"/run/host", "/run/flatpak",     // flatpak's own bind-mounts
		"/.flatpak-info",                // sandbox marker file at /
		fmt.Sprintf("/run/user/%d/doc", uid),       // xdg-document-portal
		fmt.Sprintf("/run/user/%d/app/%s", uid, appID),
		filepath.Join(home, ".var", "app", appID),
		filepath.Join(home, ".local", "share", "flatpak", "exports"),
	}
}

// PathUnder reports whether path equals base or is contained under it,
// respecting path-component boundaries.
func PathUnder(path, base string) bool {
	if path == base {
		return true
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return strings.HasPrefix(path, base)
}

// AnyPathUnder is PathUnder over a list of bases.
func AnyPathUnder(path string, bases []string) bool {
	for _, b := range bases {
		if PathUnder(path, b) {
			return true
		}
	}
	return false
}
