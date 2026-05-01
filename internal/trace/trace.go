// Package trace persists observe runs to disk and reads them back.
//
// A trace is one jsonl file per observe session, living under
// <home>/.local/share/ratpak/traces/<appid>/<timestamp>.jsonl. Each line is
// a Record describing a unique path the sandboxed app opened successfully,
// plus the comm and pid of the first process seen accessing it.
package trace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Record is one row in a trace file.
type Record struct {
	Path string `json:"path"`
	Comm string `json:"comm,omitempty"`
	PID  int    `json:"pid,omitempty"`
}

// Dir returns <home>/.local/share/ratpak/traces/<appid>/.
func Dir(home, appID string) string {
	return filepath.Join(home, ".local", "share", "ratpak", "traces", appID)
}

// Writer streams Records to a new timestamped jsonl file.
type Writer struct {
	f    *os.File
	enc  *json.Encoder
	Path string
}

// NewWriter creates a fresh trace file under Dir(home, appID). When uid and
// gid are non-negative the file (and any directories newly created on the way)
// are chowned to that user — so a root-elevated observe still produces
// user-owned trace files.
func NewWriter(home, appID string, uid, gid int) (*Writer, error) {
	dir := Dir(home, appID)
	if err := mkdirAllOwned(dir, uid, gid); err != nil {
		return nil, fmt.Errorf("create trace dir: %w", err)
	}
	name := time.Now().UTC().Format("20060102-150405Z") + ".jsonl"
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if uid >= 0 && gid >= 0 {
		_ = os.Chown(path, uid, gid)
	}
	return &Writer{f: f, enc: json.NewEncoder(f), Path: path}, nil
}

// Add writes one record. The encoder writes directly to the underlying file
// (no userspace buffer), so a Ctrl-C mid-run still leaves a valid trace.
func (w *Writer) Add(rec Record) error {
	return w.enc.Encode(rec)
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	return w.f.Close()
}

// ListFiles returns trace files for an app, sorted oldest first. Returns
// (nil, nil) if no traces exist for the app.
func ListFiles(home, appID string) ([]string, error) {
	dir := Dir(home, appID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".jsonl") && !strings.HasSuffix(n, ".txt") {
			continue
		}
		out = append(out, filepath.Join(dir, n))
	}
	sort.Strings(out)
	return out, nil
}

// ReadFile parses a trace file. Detects jsonl (lines starting with `{`) and
// falls back to one-path-per-line plain text for compat with hand-saved traces.
func ReadFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read parses jsonl or plain-text trace content from r.
func Read(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Record
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line[0] == '{' {
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				return nil, fmt.Errorf("parse trace line: %w", err)
			}
			if rec.Path != "" {
				out = append(out, rec)
			}
			continue
		}
		out = append(out, Record{Path: line})
	}
	return out, sc.Err()
}

// mkdirAllOwned mkdirs path, chowning each segment that didn't already exist
// to uid/gid (when both are non-negative).
func mkdirAllOwned(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return os.MkdirAll(path, 0o755)
	}
	var fresh []string
	cur := filepath.Clean(path)
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		fresh = append(fresh, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	for _, c := range fresh {
		_ = os.Chown(c, uid, gid)
	}
	return nil
}
