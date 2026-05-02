package flatpak

import "strings"

// RiskScore returns a 0-10 estimate of how disruptive it would be to revoke
// the given filesystem term, used by the daemon's enforcing mode to gate
// auto-revocation. Values:
//
//	0-2  trivial (xdg-pictures, xdg-music, /var/lib/flatpak/...)
//	3-4  noticeable but recoverable (xdg-download, xdg-run/pipewire, etc.)
//	5    unknown / unrecognized term — defaults here to keep us conservative
//	6-7  load-bearing for many apps (xdg-config, xdg-data, host-etc)
//	8-10 likely-fatal-to-app (home, host, host-os)
//
// The level setting on the daemon caps which risk scores it will auto-apply:
// see LevelRiskCap.
func RiskScore(rawTerm string) int {
	t := StripMode(rawTerm)
	mode := termMode(rawTerm)
	switch {
	case t == "host", t == "host-os":
		return 10
	case t == "home":
		return 8
	case t == "host-etc":
		return 6
	case strings.HasPrefix(t, "xdg-config"):
		return 7
	case strings.HasPrefix(t, "xdg-data"):
		return 6
	case strings.HasPrefix(t, "xdg-cache"):
		return 5
	case strings.HasPrefix(t, "xdg-run/pipewire"),
		strings.HasPrefix(t, "xdg-run/speech-dispatcher"):
		return 4
	case strings.HasPrefix(t, "xdg-download"):
		if mode == "ro" {
			return 3
		}
		return 4
	case strings.HasPrefix(t, "xdg-documents"):
		return 4
	case strings.HasPrefix(t, "xdg-templates"), strings.HasPrefix(t, "xdg-public-share"):
		return 3
	case strings.HasPrefix(t, "xdg-desktop"):
		return 3
	case strings.HasPrefix(t, "xdg-pictures"):
		return 2
	case strings.HasPrefix(t, "xdg-music"), strings.HasPrefix(t, "xdg-videos"):
		return 1
	case strings.HasPrefix(t, "/var/lib/flatpak"):
		return 1
	case strings.HasPrefix(t, "/"):
		// Absolute path the packager cared enough to spell out — assume
		// load-bearing unless we can tell otherwise.
		return 6
	}
	return 5
}

// LevelRiskCap maps a daemon enforcement level (1-4) to the maximum
// RiskScore it will auto-revoke. Returns 0 for invalid levels.
func LevelRiskCap(level int) int {
	switch level {
	case 1:
		return 2
	case 2:
		return 4
	case 3:
		return 6
	case 4:
		return 10
	}
	return 0
}

// StripMode returns a flatpak filesystem term without its mode suffix
// (:ro / :rw / :create). flatpak's --nofilesystem rejects mode suffixes.
func StripMode(raw string) string {
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		switch raw[i+1:] {
		case "ro", "rw", "create":
			return raw[:i]
		}
	}
	return raw
}

func termMode(raw string) string {
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		switch raw[i+1:] {
		case "ro", "rw", "create":
			return raw[i+1:]
		}
	}
	return "rw"
}
