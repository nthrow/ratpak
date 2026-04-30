# `internal/flatpak`

Wraps the host `flatpak` CLI and the on-disk override files. Pure userspace, no privileges required.

## Files

### `apps.go`

```go
func InstalledApps() ([]string, error)
```

Shells out to `flatpak list --app --columns=application` and returns the app IDs. Used by `ratpak list`.

### `permissions.go`

```go
type Permissions struct {
    Shared, Sockets, Devices, Filesystems, Features []string
}

func RequestedPermissions(appID string) (*Permissions, error)
```

Calls `flatpak info --show-permissions <appid>` and parses the INI-formatted output. Only the `[Context]` section is decoded; environment variables and dbus policies are read but discarded.

The same parser is reused by `overrides.go`.

### `overrides.go`

```go
func UserOverrides(appID string) (*Permissions, error)
```

Reads `~/.local/share/flatpak/overrides/<appid>` (the user-level override file) and parses it the same way as a manifest. Returns an empty `Permissions` if the file doesn't exist (this is not an error).

System-level overrides at `/var/lib/flatpak/overrides/<appid>` aren't read yet.

### `match.go`

The resolver and matcher.

```go
type FilesystemTerm struct {
    Raw  string  // "xdg-download:ro"
    Path string  // "/home/nat/Downloads"
    Mode string  // "rw" | "ro" | "create"
}

func ResolveFilesystemTerm(raw, home string, uid int) (FilesystemTerm, bool)
func AutoGrantedPaths(appID, home string, uid int) []string
func PathUnder(path, base string) bool
func AnyPathUnder(path string, bases []string) bool
```

`ResolveFilesystemTerm` strips the mode suffix, then expands the term:

- `host`, `host-os`, `host-etc`, `home` — fixed prefixes.
- absolute paths and `~/`-prefixed paths — used as-is (with `~/` joined to home).
- `xdg-*` — mapped to standard XDG dirs (`xdg-download` → `~/Downloads`, `xdg-config` → `~/.config`, `xdg-run` → `/run/user/<uid>`, etc.). A subpath suffix like `xdg-config/foo` is preserved.

Returns `ok=false` for terms it doesn't recognize (negative permissions starting with `!`, opaque aliases). Unrecognized terms still appear in the profile output but match no paths.

`AutoGrantedPaths` returns the implicit prefixes flatpak gives every app: runtime (`/usr`, `/lib`, `/app`), sandbox internals (`/etc`, `/proc`, `/sys`, `/dev`, `/tmp`), flatpak's own bind-mounts (`/run/host`, `/run/flatpak`, `/.flatpak-info`), the document portal (`/run/user/<uid>/doc`), the per-app runtime dir (`/run/user/<uid>/app/<appid>`), and the per-app persistent data directory (`~/.var/app/<appid>`).

`PathUnder` is a directory-boundary-respecting prefix check — `/foo/bar` matches base `/foo` but `/foobar` does not. `AnyPathUnder` is the same over a list of bases.

## Why this lives outside `main.go`

`main.go` orchestrates; this package owns the format. If flatpak grows a new permission token (or we start handling negative permissions, or system-level overrides), the changes belong here, not in command code.
