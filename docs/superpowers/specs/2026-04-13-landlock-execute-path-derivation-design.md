# Landlock Execute Path Derivation from File Rules

**Date**: 2026-04-13
**Status**: Draft

## Problem

`DeriveExecutePathsFromPolicy` only extracts execute paths from command rules that contain path separators (e.g., `/usr/bin/git`). Real-world policies use bare command names (`git`, `bash`, `node`), so the function returns empty. This leaves the Landlock ruleset with no execute permissions for system binary directories, causing every exec outside the workspace to fail with EACCES.

Secondary issue: if someone puts glob patterns (e.g., `/bin/**`) in the server config's `landlock.allow_execute` to work around this, `unix.Open` receives the literal string and fails with ENOENT. The path is silently skipped, producing the same EACCES result.

## Root Cause

Landlock distinguishes `LANDLOCK_ACCESS_FS_READ_FILE` from `LANDLOCK_ACCESS_FS_EXECUTE`. A policy's file rules granting read access to `/bin/**` produce read-only Landlock rules — they do not grant execute. The execute derivation depends entirely on command rules having full paths or the server config's explicit `allow_execute` list.

## Design

### 1. Server-side: Derive execute paths from file rules

New function `DeriveExecutePathsFromFileRules(p *policy.Policy) []string` in `internal/landlock/policy.go`.

**Logic:**
1. Iterate `p.FileRules` where `decision == "allow"` and operations include `read`, `open`, or `*`
2. For each path, run `extractBaseDir` to strip glob characters (e.g., `/bin/**` -> `/bin`)
3. Check if the extracted directory IS a known binary directory or is a PARENT of one (see heuristic below)
4. Collect matching directories, deduplicated

**Heuristic — `couldContainBinaries`:** A path qualifies if it equals or is an ancestor of any FHS standard binary directory:

```go
var knownBinaryDirs = []string{
    "/bin", "/sbin",
    "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
}

func couldContainBinaries(dir string) bool {
    for _, binDir := range knownBinaryDirs {
        if dir == binDir || strings.HasPrefix(binDir, dir+"/") {
            return true
        }
    }
    return false
}
```

This correctly handles:
- `/bin` → equals `/bin` → **included**
- `/usr` → is prefix of `/usr/bin` → **included** (Landlock is hierarchical, covers `/usr/bin`)
- `/usr/local` → is prefix of `/usr/local/bin` → **included**
- `/lib`, `/lib64`, `/dev`, `/etc` → no match → **excluded**
- `/opt` → no match → **excluded** (custom binary dirs under `/opt/*/bin` need explicit config)

No filesystem probing needed — pure string matching. This runs on the server; it must not depend on the sandbox VM's filesystem.

**Integration points:**
- `internal/api/core.go` ~line 228: append `DeriveExecutePathsFromFileRules(pol)` to `seccompCfg.AllowExecute`
- `internal/api/wrap.go` ~line 168: same
- `internal/landlock/policy.go` `BuildFromConfig`: call new function alongside existing `DeriveExecutePathsFromPolicy`

**Example with Accomplish policy:**
- File rule `allow-system-read` has paths: `/usr/**`, `/lib/**`, `/lib64/**`, `/bin/**`, `/sbin/**`, `/opt/**`, `/dev/**`
- After `extractBaseDir`: `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`, `/dev`
- After `couldContainBinaries` filter: `/usr`, `/bin`, `/sbin`
- Excluded: `/lib`, `/lib64`, `/opt`, `/dev` (not FHS binary dir ancestors)

### 2. Wrapper-side: Glob-stripping in ruleset builder

New helper `stripGlobPrefix(path string) string` in `internal/landlock/ruleset.go`:
- Scans for first glob character (`*`, `?`, `[`)
- Returns the prefix up to that point (trimming trailing `/`)
- Returns the original path if no glob characters found

Apply in `AddExecutePath`, `AddReadPath`, `AddWritePath`:
- Call `stripGlobPrefix` before `filepath.Abs`
- If the path was modified, log `slog.Warn` with original and cleaned path

Also: add `slog.Debug` in `addPathRule` when `unix.Open` fails, replacing silent error return. This aids debugging when paths don't exist.

### 3. Files to modify

| File | Change |
|------|--------|
| `internal/landlock/policy.go` | Add `DeriveExecutePathsFromFileRules`, update `BuildFromConfig` to call it |
| `internal/landlock/ruleset.go` | Add `stripGlobPrefix`, apply in Add*Path methods, add logging in `addPathRule` |
| `internal/api/core.go` ~L228 | Append file-rule-derived execute paths after policy-derived paths |
| `internal/api/wrap.go` ~L168 | Same |
| `internal/landlock/policy_test.go` | Test `DeriveExecutePathsFromFileRules` with Accomplish-style policy |
| `internal/landlock/ruleset_test.go` | Test `stripGlobPrefix` and glob-stripping in `AddExecutePath` |

### 4. Behavior matrix

| Policy pattern | Before | After |
|---|---|---|
| Commands as bare names + file rules with `/bin/**` read | No execute paths -> EACCES | Execute paths derived from file rules |
| Commands as full paths (`/usr/bin/git`) | Works (existing logic) | Works (unchanged) |
| Server config `allow_execute: [/usr/bin, /bin]` | Works | Works (unchanged) |
| Server config `allow_execute: [/bin/**]` | Silent ENOENT, no execute | Stripped to `/bin`, works + warning logged |
| No file rules with bin paths, no config paths | No execute paths | No execute paths (correct -- no policy intent) |

## Verification

1. `go test ./internal/landlock/...` -- new tests pass
2. `go test ./internal/api/...` -- existing tests still pass
3. `go build ./...` -- compiles
4. `GOOS=windows go build ./...` -- cross-compile check (landlock files are build-tagged linux)
5. Manual: with Accomplish policy, verify Landlock config JSON sent to wrapper includes execute paths for `/usr`, `/bin`, `/sbin`
