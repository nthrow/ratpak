package flatpak

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// InstalledApps returns the list of installed flatpak app IDs (user + system).
func InstalledApps() ([]string, error) {
	out, err := exec.Command("flatpak", "list", "--app", "--columns=application").Output()
	if err != nil {
		return nil, fmt.Errorf("flatpak list: %w", err)
	}
	var apps []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		apps = append(apps, line)
	}
	return apps, scanner.Err()
}
