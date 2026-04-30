package flatpak

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
