# `internal/trace`

Persists observe runs to disk and reads them back. Pure userspace, no privileges required.

## On-disk layout

```
~/.local/share/ratpak/traces/<appid>/<UTC-timestamp>Z.jsonl
```

One file per `observe` run. Timestamps are UTC, in `20060102-150405Z` form, so `ls` lists oldest first. Sub-directories are created on demand.

When ratpak's `observe` runs under `doas` / `sudo`, `Writer` chowns each freshly-created directory and the new file to the invoking user — so `profile` and `apply` (which run as that user) can read and prune them without elevated privileges.

## Record format (one JSON object per line)

```json
{"path":"/usr/lib/x86_64-linux-gnu/libfoo.so.1","comm":"Discord","pid":12345}
```

| Field  | Meaning                                                        |
|--------|----------------------------------------------------------------|
| `path` | Absolute path the sandboxed app opened successfully.           |
| `comm` | `/proc/<pid>/comm` of the first process seen accessing it. Kernel-truncated to 15 chars. Optional. |
| `pid`  | TGID of the same process. Optional.                            |

One record per *unique* path within a session — observe dedupes in memory before writing. comm/pid reflect the first occurrence; subsequent accesses by other threads or processes aren't recorded separately.

## Public surface

```go
type Record struct {
    Path string `json:"path"`
    Comm string `json:"comm,omitempty"`
    PID  int    `json:"pid,omitempty"`
}

func Dir(home, appID string) string

type Writer struct{ Path string /* ... */ }
func NewWriter(home, appID string, uid, gid int) (*Writer, error)
func (w *Writer) Add(rec Record) error
func (w *Writer) Close() error

func ListFiles(home, appID string) ([]string, error)
func ReadFile(path string) ([]Record, error)
func Read(r io.Reader) ([]Record, error)
```

`NewWriter` creates and timestamps a fresh file. Pass `uid=-1, gid=-1` to skip the chown (e.g. when ratpak is already running as the invoking user).

`Add` writes one record. The encoder writes straight to the underlying `*os.File` — no userspace buffering — so a Ctrl-C mid-`observe` still leaves a valid jsonl file with all records up to the last one written.

`ListFiles` returns trace files for an app sorted oldest first. Filenames ending in `.jsonl` or `.txt` are included.

`Read` and `ReadFile` parse jsonl. For backward compatibility with any v1 plain-text traces the user has lying around, lines that don't start with `{` are treated as bare path strings (a `Record` with only `Path` set).

## Why a separate package

The persistence concern is independent of both the observer (which doesn't care where its events go) and the classifier (which doesn't care where its input came from). Keeping the file conventions and on-disk format in one place means changes to either don't ripple across packages — and a future trace format (per-event, with timestamps) can land here without touching `main.go` or `internal/observer/`.
