package flatpak

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// ResolveAppID returns the flatpak app ID for a running process by reading
// the [Application]/name= field of /proc/<pid>/root/.flatpak-info. flatpak's
// bwrap setup writes this file before exec'ing the app's own code, so it's
// reliably present once the process has fully entered its sandbox mount
// namespace.
//
// Returns "" with a non-nil error for non-flatpak processes (the file won't
// exist), processes whose .flatpak-info lacks an Application section, or
// processes whose /proc entry isn't readable by the calling user.
func ResolveAppID(pid int) (string, error) {
	path := fmt.Sprintf("/proc/%d/root/.flatpak-info", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return parseFlatpakInfoAppID(data)
}

func parseFlatpakInfoAppID(data []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 8*1024), 64*1024)
	section := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		if section != "Application" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == "name" {
			return strings.TrimSpace(v), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("flatpak: no [Application]/name in .flatpak-info")
}
