package flatpak

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UserOverrides reads the user-level override file for the given app.
// If no override exists, returns an empty Permissions and no error.
func UserOverrides(appID string) (*Permissions, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".local", "share", "flatpak", "overrides", appID)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Permissions{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parsePermissions(string(data))
}

// AddNoFilesystem revokes a filesystem term in the user override for appID by
// shelling out to `flatpak override --user --nofilesystem=TERM APPID`. The
// term must be mode-free (e.g. "xdg-pictures", not "xdg-pictures:ro") because
// flatpak rejects mode suffixes on --nofilesystem.
func AddNoFilesystem(appID, term string) error {
	cmd := exec.Command("flatpak", "override", "--user", "--nofilesystem="+term, appID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("flatpak override --nofilesystem=%s: %w (%s)", term, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ResetUser removes all user overrides for appID by shelling out to
// `flatpak override --user --reset APPID`. This is broader than ratpak's
// own changes — it nukes any filesystem/dbus/socket overrides the user has.
func ResetUser(appID string) error {
	cmd := exec.Command("flatpak", "override", "--user", "--reset", appID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("flatpak override --reset: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
