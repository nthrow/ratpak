// Package flatpak wraps the host `flatpak` CLI and override files to read
// and (eventually) write the permission state of installed apps.
package flatpak

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// Permissions mirrors the [Context] section of a flatpak manifest or override
// file. Only the fields ratpak v1 cares about are populated; the rest of the
// schema (env vars, dbus policies, etc.) will be added when those stages land.
type Permissions struct {
	Shared      []string
	Sockets     []string
	Devices     []string
	Filesystems []string
	Features    []string
}

// RequestedPermissions returns the permissions declared in the app's manifest
// — i.e. what the packager asked for — by shelling out to
// `flatpak info --show-permissions`.
func RequestedPermissions(appID string) (*Permissions, error) {
	out, err := exec.Command("flatpak", "info", "--show-permissions", appID).Output()
	if err != nil {
		return nil, fmt.Errorf("flatpak info: %w", err)
	}
	return parsePermissions(string(out))
}

func parsePermissions(s string) (*Permissions, error) {
	p := &Permissions{}
	scanner := bufio.NewScanner(strings.NewReader(s))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		if section != "Context" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		items := splitList(value)
		switch strings.TrimSpace(key) {
		case "shared":
			p.Shared = items
		case "sockets":
			p.Sockets = items
		case "devices":
			p.Devices = items
		case "filesystems":
			p.Filesystems = items
		case "features":
			p.Features = items
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
