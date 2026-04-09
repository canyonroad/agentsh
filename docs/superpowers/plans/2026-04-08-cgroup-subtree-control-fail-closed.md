# Cgroup v2 Subtree-Control Fail-Closed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace silent-failure in cgroup v2 resource-limit enforcement with a probe → mode-selection → fail-closed flow. Covers issue [#197](https://github.com/erans/agentsh/issues/197).

**Architecture:** Introduce a thin `cgroupFS` filesystem abstraction, a `ProbeCgroupsV2` function implementing the nested → top-level → unavailable decision tree, and a `CgroupManager` that routes per-command cgroup creation based on the probed mode. `enableControllers()` is fixed to surface errors instead of swallowing them. The native Linux API handler is migrated to use the manager; `agentsh detect` gains a structured cgroup block. Lima and WSL2 are **out of scope** and tracked as a follow-up.

**Tech Stack:** Go, Linux cgroup v2, standard library (`os`, `errors`, `syscall`, `path/filepath`), existing `internal/events` broker and store for audit emission.

**Spec:** `docs/superpowers/specs/2026-04-08-cgroup-subtree-control-fail-closed-design.md`

---

## File Structure

**New files:**
- `internal/limits/cgroup_fs.go` — `cgroupFS` interface and `osCgroupFS` real implementation (Linux-only)
- `internal/limits/cgroup_fs_fake_test.go` — `fakeCgroupFS` in-memory test double
- `internal/limits/cgroupv2_errors.go` — `EnableControllersError`, `CgroupUnavailableError` types
- `internal/limits/cgroupv2_probe.go` — `ProbeCgroupsV2` function and `CgroupProbeResult`/`CgroupMode` types
- `internal/limits/cgroupv2_manager.go` — `CgroupManager` struct, `NewCgroupManager`, `Apply`, `ReapOrphans`
- `internal/limits/cgroupv2_probe_test.go` — unit tests for the probe (uses `fakeCgroupFS`)
- `internal/limits/cgroupv2_manager_test.go` — unit tests for `CgroupManager.Apply`
- `internal/limits/cgroupv2_integration_test.go` — integration tests, build tag `linux && cgroup_integration`

**Modified files:**
- `internal/limits/cgroupv2_linux.go` — rewrite `enableControllers`, remove `ApplyCgroupV2`, retain `DetectCgroupV2`/`CurrentCgroupDir`/`cgroupUnpopulated`/`CgroupV2.Close`/`cpuMaxFromPct`/`sanitizeCgroupName`
- `internal/limits/cgroupv2_linux_test.go` — migrate `TestApplyCgroupV2_CreatesAndCleansUp` to use the manager
- `internal/events/types.go` — add three new event type constants
- `internal/api/cgroups.go` — replace `limits.ApplyCgroupV2` call with `app.cgroupMgr.Apply`, handle `CgroupUnavailableError` as a structured refusal
- `internal/api/app.go` (or wherever `App` is defined) — add `cgroupMgr *limits.CgroupManager` field
- `internal/server/server.go` — construct `CgroupManager` and pass into `NewApp`
- `internal/capabilities/check_cgroups_linux.go` — rewrite `probeCgroupsV2` to call `limits.ProbeCgroupsV2` and return richer detail
- `internal/capabilities/detect_linux.go` — populate new `cgroups_v2_*` keys in the flat capability map
- `internal/capabilities/check_cgroups_other.go` (if exists) — no-op stub for non-Linux (leave as-is)

---

## Task Dependency Order

Tasks 1–8 are the core implementation; each task produces a commit and builds/tests pass at every commit.

1. Event type constants (trivial, unblocks later tasks)
2. `cgroupFS` interface + `osCgroupFS` real impl
3. `fakeCgroupFS` test double
4. Error types (`EnableControllersError`, `CgroupUnavailableError`)
5. Fix `enableControllers()` to return errors + unit test
6. `ProbeCgroupsV2` function + unit tests
7. `CgroupManager` + unit tests
8. Integration tests (build-tag gated)
9. Migrate `internal/api/cgroups.go` to the manager
10. Wire manager into `api.App` and `server.New`
11. Remove package-level `ApplyCgroupV2` and migrate existing test
12. Rewrite `probeCgroupsV2` in capabilities + extend detect output
13. Final cross-compile and full-suite verification

---

## Task 1: Add event type constants

**Files:**
- Modify: `internal/events/types.go`

- [ ] **Step 1: Read the existing event type file to see the style**

Run: `head -60 internal/events/types.go`
Expected: A list of `const` event name strings like `EventSeccompBlocked = "seccomp_blocked"`.

- [ ] **Step 2: Add three new event type constants**

Append to the existing `const` block in `internal/events/types.go` (alongside similar sandbox-related events):

```go
// Cgroup v2 probe and enforcement events (see issue #197).
const (
    EventCgroupMode               = "cgroup_mode"
    EventCgroupOrphansReaped      = "cgroup_orphans_reaped"
    EventCgroupUnavailableRefusal = "cgroup_unavailable_refusal"
)
```

Do not remove or rename any existing constants.

- [ ] **Step 3: Build to verify the file still compiles**

Run: `go build ./internal/events/...`
Expected: exit 0, no output.

- [ ] **Step 4: Commit**

```bash
git add internal/events/types.go
git commit -m "events: add cgroup_mode / orphans_reaped / unavailable_refusal types"
```

---

## Task 2: Introduce `cgroupFS` interface and real `osCgroupFS`

**Files:**
- Create: `internal/limits/cgroup_fs.go`

- [ ] **Step 1: Create the file with interface and real implementation**

Write `internal/limits/cgroup_fs.go`:

```go
//go:build linux

package limits

import (
    "io"
    "os"
)

// cgroupFS is a narrow abstraction over the /sys/fs/cgroup filesystem used by
// the probe and manager, so they can be unit-tested with an in-memory fake.
// All paths are absolute (e.g. "/sys/fs/cgroup/agentsh.slice/cgroup.controllers").
type cgroupFS interface {
    ReadFile(path string) ([]byte, error)
    WriteFile(path string, data []byte, perm os.FileMode) error
    Mkdir(path string, perm os.FileMode) error
    Remove(path string) error
    Stat(path string) (os.FileInfo, error)
    ReadDir(path string) ([]os.DirEntry, error)
    // OpenFile returns a writer for append-style writes to subtree_control.
    OpenFile(path string, flag int, perm os.FileMode) (cgroupFile, error)
}

// cgroupFile is the subset of *os.File the manager uses for subtree_control
// writes. *os.File satisfies this interface via its own WriteString/Close.
type cgroupFile interface {
    io.StringWriter
    io.Closer
}

// osCgroupFS is the production implementation backed by the os package.
type osCgroupFS struct{}

func (osCgroupFS) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func (osCgroupFS) WriteFile(p string, d []byte, m os.FileMode) error {
    return os.WriteFile(p, d, m)
}
func (osCgroupFS) Mkdir(p string, m os.FileMode) error { return os.Mkdir(p, m) }
func (osCgroupFS) Remove(p string) error                { return os.Remove(p) }
func (osCgroupFS) Stat(p string) (os.FileInfo, error)   { return os.Stat(p) }
func (osCgroupFS) ReadDir(p string) ([]os.DirEntry, error) {
    return os.ReadDir(p)
}
func (osCgroupFS) OpenFile(p string, flag int, perm os.FileMode) (cgroupFile, error) {
    return os.OpenFile(p, flag, perm)
}
```

- [ ] **Step 2: Build to verify**

Run: `go build ./internal/limits/...`
Expected: exit 0, no output.

- [ ] **Step 3: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: exit 0. (This file has `//go:build linux` and should be skipped on Windows.)

- [ ] **Step 4: Commit**

```bash
git add internal/limits/cgroup_fs.go
git commit -m "limits: add cgroupFS abstraction for unit-testable cgroup ops"
```

---

## Task 3: Introduce `fakeCgroupFS` test double

**Files:**
- Create: `internal/limits/cgroup_fs_fake_test.go`

- [ ] **Step 1: Create the fake filesystem file**

Write `internal/limits/cgroup_fs_fake_test.go`:

```go
//go:build linux

package limits

import (
    "bytes"
    "fmt"
    "io/fs"
    "os"
    "path"
    "sort"
    "strings"
    "syscall"
    "time"
)

// fakeCgroupFS is an in-memory cgroupFS used by unit tests.
// Paths are treated as a flat map; parent directories are auto-created on Mkdir.
type fakeCgroupFS struct {
    // files maps absolute path → entry. An entry with isDir=true represents a directory.
    files map[string]*fakeEntry
    // writeErrs optionally returns a specific error for WriteFile(path) or OpenFile(path) calls.
    writeErrs map[string]error
    // openErrs mirrors writeErrs but for OpenFile (subtree_control writes).
    openErrs map[string]error
}

type fakeEntry struct {
    content []byte
    isDir   bool
}

func newFakeCgroupFS() *fakeCgroupFS {
    return &fakeCgroupFS{
        files:     map[string]*fakeEntry{"/sys/fs/cgroup": {isDir: true}},
        writeErrs: map[string]error{},
        openErrs:  map[string]error{},
    }
}

// seedDir creates a directory and its parents.
func (f *fakeCgroupFS) seedDir(p string) {
    p = path.Clean(p)
    parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
    cur := ""
    for _, part := range parts {
        cur = cur + "/" + part
        if _, ok := f.files[cur]; !ok {
            f.files[cur] = &fakeEntry{isDir: true}
        }
    }
}

// seedFile writes content at an absolute path, creating parent dirs.
func (f *fakeCgroupFS) seedFile(p string, content string) {
    f.seedDir(path.Dir(p))
    f.files[path.Clean(p)] = &fakeEntry{content: []byte(content)}
}

func (f *fakeCgroupFS) ReadFile(p string) ([]byte, error) {
    e, ok := f.files[path.Clean(p)]
    if !ok {
        return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOENT}
    }
    if e.isDir {
        return nil, &fs.PathError{Op: "read", Path: p, Err: syscall.EISDIR}
    }
    return append([]byte(nil), e.content...), nil
}

func (f *fakeCgroupFS) WriteFile(p string, data []byte, perm os.FileMode) error {
    p = path.Clean(p)
    if err, ok := f.writeErrs[p]; ok {
        return &fs.PathError{Op: "write", Path: p, Err: err}
    }
    if e, ok := f.files[p]; ok && e.isDir {
        return &fs.PathError{Op: "write", Path: p, Err: syscall.EISDIR}
    }
    if _, ok := f.files[path.Dir(p)]; !ok {
        return &fs.PathError{Op: "write", Path: p, Err: syscall.ENOENT}
    }
    f.files[p] = &fakeEntry{content: append([]byte(nil), data...)}
    return nil
}

func (f *fakeCgroupFS) Mkdir(p string, perm os.FileMode) error {
    p = path.Clean(p)
    if _, ok := f.files[p]; ok {
        return &fs.PathError{Op: "mkdir", Path: p, Err: syscall.EEXIST}
    }
    if _, ok := f.files[path.Dir(p)]; !ok {
        return &fs.PathError{Op: "mkdir", Path: p, Err: syscall.ENOENT}
    }
    f.files[p] = &fakeEntry{isDir: true}
    return nil
}

func (f *fakeCgroupFS) Remove(p string) error {
    p = path.Clean(p)
    if _, ok := f.files[p]; !ok {
        return &fs.PathError{Op: "remove", Path: p, Err: syscall.ENOENT}
    }
    delete(f.files, p)
    return nil
}

func (f *fakeCgroupFS) Stat(p string) (os.FileInfo, error) {
    p = path.Clean(p)
    e, ok := f.files[p]
    if !ok {
        return nil, &fs.PathError{Op: "stat", Path: p, Err: syscall.ENOENT}
    }
    return &fakeFileInfo{name: path.Base(p), size: int64(len(e.content)), isDir: e.isDir}, nil
}

func (f *fakeCgroupFS) ReadDir(p string) ([]os.DirEntry, error) {
    p = path.Clean(p)
    if e, ok := f.files[p]; !ok || !e.isDir {
        return nil, &fs.PathError{Op: "readdir", Path: p, Err: syscall.ENOENT}
    }
    var names []string
    prefix := p + "/"
    for k := range f.files {
        if k == p {
            continue
        }
        if strings.HasPrefix(k, prefix) && !strings.Contains(strings.TrimPrefix(k, prefix), "/") {
            names = append(names, path.Base(k))
        }
    }
    sort.Strings(names)
    out := make([]os.DirEntry, 0, len(names))
    for _, n := range names {
        full := path.Join(p, n)
        e := f.files[full]
        out = append(out, &fakeDirEntry{name: n, isDir: e.isDir})
    }
    return out, nil
}

func (f *fakeCgroupFS) OpenFile(p string, flag int, perm os.FileMode) (cgroupFile, error) {
    p = path.Clean(p)
    if err, ok := f.openErrs[p]; ok {
        return nil, &fs.PathError{Op: "open", Path: p, Err: err}
    }
    if _, ok := f.files[p]; !ok {
        return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOENT}
    }
    return &fakeWriter{fs: f, path: p}, nil
}

type fakeWriter struct {
    fs   *fakeCgroupFS
    path string
    buf  bytes.Buffer
}

func (w *fakeWriter) WriteString(s string) (int, error) {
    if err, ok := w.fs.openErrs[w.path+":write"]; ok {
        return 0, &fs.PathError{Op: "write", Path: w.path, Err: err}
    }
    w.buf.WriteString(s)
    // Append to the underlying file content on every write, mimicking
    // cgroup subtree_control semantics (each write appends a token).
    e := w.fs.files[w.path]
    if e == nil {
        return 0, &fs.PathError{Op: "write", Path: w.path, Err: syscall.ENOENT}
    }
    sep := ""
    if len(e.content) > 0 && !bytes.HasSuffix(e.content, []byte(" ")) {
        sep = " "
    }
    e.content = append(e.content, []byte(sep+s)...)
    return len(s), nil
}

func (w *fakeWriter) Close() error { return nil }

type fakeFileInfo struct {
    name  string
    size  int64
    isDir bool
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode  { if f.isDir { return os.ModeDir | 0o755 }; return 0o644 }
func (f *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool        { return f.isDir }
func (f *fakeFileInfo) Sys() any           { return nil }

type fakeDirEntry struct {
    name  string
    isDir bool
}

func (d *fakeDirEntry) Name() string               { return d.name }
func (d *fakeDirEntry) IsDir() bool                { return d.isDir }
func (d *fakeDirEntry) Type() os.FileMode          { if d.isDir { return os.ModeDir }; return 0 }
func (d *fakeDirEntry) Info() (os.FileInfo, error) {
    return &fakeFileInfo{name: d.name, isDir: d.isDir}, nil
}

// assertSubtreeControl returns an error unless path's content contains all of
// the given controllers (used in tests).
func (f *fakeCgroupFS) assertSubtreeControl(p string, want ...string) error {
    e, ok := f.files[path.Clean(p)]
    if !ok {
        return fmt.Errorf("%s does not exist", p)
    }
    have := strings.Fields(string(e.content))
    set := map[string]bool{}
    for _, h := range have {
        set[strings.TrimPrefix(h, "+")] = true
    }
    for _, w := range want {
        if !set[w] {
            return fmt.Errorf("%s missing controller %q (have %q)", p, w, string(e.content))
        }
    }
    return nil
}
```

- [ ] **Step 2: Add a smoke-test that the fake compiles and basic ops work**

Append to the same file:

```go
// TestFakeCgroupFS_Smoke covers basic behaviors of the fake itself.
// Run via: go test ./internal/limits/ -run TestFakeCgroupFS_Smoke
func TestFakeCgroupFS_Smoke(t *testing.T) {
    f := newFakeCgroupFS()
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids")
    data, err := f.ReadFile("/sys/fs/cgroup/cgroup.controllers")
    if err != nil {
        t.Fatalf("ReadFile: %v", err)
    }
    if string(data) != "cpuset cpu io memory pids" {
        t.Fatalf("unexpected content: %q", data)
    }

    if err := f.Mkdir("/sys/fs/cgroup/agentsh.slice", 0o755); err != nil {
        t.Fatalf("Mkdir: %v", err)
    }
    entries, err := f.ReadDir("/sys/fs/cgroup")
    if err != nil {
        t.Fatalf("ReadDir: %v", err)
    }
    found := false
    for _, e := range entries {
        if e.Name() == "agentsh.slice" && e.IsDir() {
            found = true
        }
    }
    if !found {
        t.Fatalf("expected agentsh.slice in readdir, got %v", entries)
    }
}
```

Add `"testing"` to the imports if the go tool doesn't auto-add it.

- [ ] **Step 3: Run the smoke test**

Run: `go test ./internal/limits/ -run TestFakeCgroupFS_Smoke -v`
Expected: `PASS: TestFakeCgroupFS_Smoke`.

- [ ] **Step 4: Commit**

```bash
git add internal/limits/cgroup_fs_fake_test.go
git commit -m "limits: add fakeCgroupFS in-memory test double"
```

---

## Task 4: Introduce error types

**Files:**
- Create: `internal/limits/cgroupv2_errors.go`

- [ ] **Step 1: Create the errors file**

Write `internal/limits/cgroupv2_errors.go`:

```go
//go:build linux

package limits

import "fmt"

// EnableControllersError is returned by enableControllers when writing to
// a cgroup.subtree_control file fails. The underlying syscall errno is
// preserved via Unwrap so callers can discriminate EBUSY / EACCES / ENOENT.
type EnableControllersError struct {
    ParentDir  string
    Controller string
    Err        error
}

func (e *EnableControllersError) Error() string {
    return fmt.Sprintf("enable controller %q in %s: %v", e.Controller, e.ParentDir, e.Err)
}

func (e *EnableControllersError) Unwrap() error { return e.Err }

// CgroupUnavailableError is returned by CgroupManager.Apply when the manager's
// probed mode is ModeUnavailable and the caller's policy requires one or more
// non-zero resource limits. The error carries the probe reason and the
// requested limits so that audit events can record the refusal context.
type CgroupUnavailableError struct {
    Reason string
    Limits CgroupV2Limits
}

func (e *CgroupUnavailableError) Error() string {
    return fmt.Sprintf(
        "cgroup enforcement unavailable (%s); policy requires %s — refusing command",
        e.Reason, e.Limits.Summary())
}

// Summary returns a compact human-readable description of non-zero limits.
func (l CgroupV2Limits) Summary() string {
    parts := []string{}
    if l.MaxMemoryBytes > 0 {
        parts = append(parts, fmt.Sprintf("memory.max=%d", l.MaxMemoryBytes))
    }
    if l.PidsMax > 0 {
        parts = append(parts, fmt.Sprintf("pids.max=%d", l.PidsMax))
    }
    if l.CPUQuotaPct > 0 {
        parts = append(parts, fmt.Sprintf("cpu.quota=%d%%", l.CPUQuotaPct))
    }
    if len(parts) == 0 {
        return "no limits"
    }
    return joinComma(parts)
}

func joinComma(parts []string) string {
    out := ""
    for i, p := range parts {
        if i > 0 {
            out += ", "
        }
        out += p
    }
    return out
}

// IsEmpty reports whether the limits struct contains no enforceable values.
// A caller can skip cgroup creation entirely when IsEmpty is true.
func (l CgroupV2Limits) IsEmpty() bool {
    return l.MaxMemoryBytes <= 0 && l.CPUQuotaPct <= 0 && l.PidsMax <= 0
}
```

- [ ] **Step 2: Build**

Run: `go build ./internal/limits/...`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/limits/cgroupv2_errors.go
git commit -m "limits: add cgroup v2 structured error types + limits summary helpers"
```

---

## Task 5: Fix `enableControllers()` to return errors

**Files:**
- Modify: `internal/limits/cgroupv2_linux.go` (lines 171-185)
- Modify: `internal/limits/cgroupv2_linux_test.go` — add one test

- [ ] **Step 1: Write the failing test first**

Append to `internal/limits/cgroupv2_linux_test.go`:

```go
import "errors"
import "syscall"

// Test that enableControllers surfaces errors instead of silently swallowing them.
func TestEnableControllers_ReturnsError(t *testing.T) {
    // Create a fake FS where subtree_control exists but WriteString injects EBUSY.
    f := newFakeCgroupFS()
    f.seedFile("/sys/fs/cgroup/system.slice/agentsh.service/cgroup.subtree_control", "")
    f.openErrs["/sys/fs/cgroup/system.slice/agentsh.service/cgroup.subtree_control:write"] = syscall.EBUSY

    err := enableControllersFS(f, "/sys/fs/cgroup/system.slice/agentsh.service", []string{"cpu", "memory", "pids"})
    if err == nil {
        t.Fatalf("expected error, got nil")
    }
    var ece *EnableControllersError
    if !errors.As(err, &ece) {
        t.Fatalf("expected *EnableControllersError, got %T: %v", err, err)
    }
    if ece.Controller != "cpu" {
        t.Fatalf("expected first failing controller to be 'cpu', got %q", ece.Controller)
    }
    if !errors.Is(err, syscall.EBUSY) {
        t.Fatalf("expected wrapped EBUSY, got %v", err)
    }
}
```

Make sure both import additions are merged into the existing import block rather than duplicating the `import` keyword.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/limits/ -run TestEnableControllers_ReturnsError -v`
Expected: FAIL with "undefined: enableControllersFS" (we haven't added it yet).

- [ ] **Step 3: Rewrite `enableControllers` and add `enableControllersFS`**

In `internal/limits/cgroupv2_linux.go`, replace the existing `enableControllers` function (around lines 171-185) with two functions — a thin wrapper for production callers and the FS-injectable form for tests:

```go
// enableControllers writes "+<ctrl>" to parentDir/cgroup.subtree_control for each
// controller in ctrls. On the first write failure it returns a wrapped
// *EnableControllersError; on success it returns nil. This is a change from
// prior behavior, which silently continued past per-controller errors and
// masked delegation issues (issue #197).
func enableControllers(parentDir string, ctrls []string) error {
    return enableControllersFS(osCgroupFS{}, parentDir, ctrls)
}

func enableControllersFS(fsys cgroupFS, parentDir string, ctrls []string) error {
    path := filepath.Join(parentDir, "cgroup.subtree_control")
    f, err := fsys.OpenFile(path, os.O_WRONLY, 0)
    if err != nil {
        return &EnableControllersError{
            ParentDir:  parentDir,
            Controller: "*",
            Err:        err,
        }
    }
    defer f.Close()
    for _, c := range ctrls {
        if _, err := f.WriteString("+" + c); err != nil {
            return &EnableControllersError{
                ParentDir:  parentDir,
                Controller: c,
                Err:        err,
            }
        }
    }
    return nil
}
```

- [ ] **Step 4: Run the new test again to verify it passes**

Run: `go test ./internal/limits/ -run TestEnableControllers_ReturnsError -v`
Expected: PASS.

- [ ] **Step 5: Run the whole `limits` package to check nothing else broke**

Run: `go test ./internal/limits/...`
Expected: all tests pass (or the existing `TestApplyCgroupV2_CreatesAndCleansUp` skips on this host, which is fine).

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/limits/cgroupv2_linux.go internal/limits/cgroupv2_linux_test.go
git commit -m "limits: surface errors from enableControllers (fix #197 silent swallow)"
```

---

## Task 6: Implement `ProbeCgroupsV2`

**Files:**
- Create: `internal/limits/cgroupv2_probe.go`
- Create: `internal/limits/cgroupv2_probe_test.go`

- [ ] **Step 1: Create the probe file with types and decision tree**

Write `internal/limits/cgroupv2_probe.go`:

```go
//go:build linux

package limits

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "syscall"
)

// CgroupMode names an operating mode for cgroup v2 enforcement.
type CgroupMode string

const (
    ModeNested      CgroupMode = "nested"
    ModeTopLevel    CgroupMode = "top-level"
    ModeUnavailable CgroupMode = "unavailable"
)

// requiredControllers are the cgroup v2 controllers the probe insists on.
// io is tracked separately as a best-effort flag (see CgroupProbeResult.IOAvailable).
var requiredControllers = []string{"cpu", "memory", "pids"}

// CgroupProbeResult is the output of ProbeCgroupsV2. Callers store it on
// a CgroupManager or pass it to the detect command.
type CgroupProbeResult struct {
    Mode        CgroupMode
    Reason      string
    OwnCgroup   string // absolute path to the process's own cgroup dir
    SliceDir    string // absolute path to /sys/fs/cgroup/agentsh.slice (top-level mode only; empty otherwise)
    IOAvailable bool   // true if the io controller is usable in the chosen mode
    // OrphansReaped is populated in top-level mode when the probe removed
    // leftover unpopulated child cgroups from a prior agentsh run.
    OrphansReaped []string
}

// DefaultSliceDir is the stable top-level parent used when nested enforcement
// is not reachable. Exported so tests and the detect command can reference it.
const DefaultSliceDir = "/sys/fs/cgroup/agentsh.slice"

// ProbeCgroupsV2 runs the decision tree described in the design spec:
//
//  1. Resolve the "own" cgroup (ownHint overrides /proc/self/cgroup if non-empty).
//  2. If the own cgroup's cgroup.controllers lacks any required controller, try top-level.
//  3. If the own cgroup's cgroup.subtree_control already delegates the required set, return nested.
//  4. Try to enable the required set in subtree_control; on success, return nested.
//  5. On EBUSY / EACCES / other enable error, fall through to top-level.
//  6. Top-level: verify root controllers, ensure DefaultSliceDir exists with controller files,
//     reap orphans, return top-level.
//  7. Otherwise return unavailable with a structured reason.
//
// fs is the filesystem abstraction (osCgroupFS in production, fakeCgroupFS in tests).
// ownHint is an optional override for the "own" cgroup path used in step 1
// (intended to honor cfg.Sandbox.Cgroups.BasePath). Empty means "discover via /proc/self/cgroup".
func ProbeCgroupsV2(ctx context.Context, fs cgroupFS, ownHint string) (*CgroupProbeResult, error) {
    own := ownHint
    if own == "" {
        discovered, err := CurrentCgroupDir()
        if err != nil {
            return nil, fmt.Errorf("discover own cgroup: %w", err)
        }
        own = discovered
    } else if !filepath.IsAbs(own) {
        // Relative paths are joined with the process's current cgroup dir, matching
        // the prior behavior of internal/api/cgroups.go.
        cur, err := CurrentCgroupDir()
        if err != nil {
            return nil, fmt.Errorf("discover own cgroup for relative base path: %w", err)
        }
        own = filepath.Join(cur, own)
    }

    // Step 2: does the own cgroup even expose the required controllers?
    ownAvailable, err := readControllerSet(fs, filepath.Join(own, "cgroup.controllers"))
    if err != nil {
        // If we cannot read own controllers, fall through to top-level as a defensive measure.
        return tryTopLevel(ctx, fs, own, fmt.Sprintf("read own cgroup.controllers: %v", err))
    }
    if !containsAll(ownAvailable, requiredControllers) {
        missing := missingControllers(ownAvailable, requiredControllers)
        return tryTopLevel(ctx, fs, own,
            fmt.Sprintf("own cgroup missing controllers %v", missing))
    }

    // Step 3: already delegated?
    ownDelegated, err := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
    if err == nil && containsAll(ownDelegated, requiredControllers) {
        return &CgroupProbeResult{
            Mode:        ModeNested,
            Reason:      "already delegated",
            OwnCgroup:   own,
            IOAvailable: contains(ownDelegated, "io"),
        }, nil
    }

    // Step 4: try to enable the required set.
    enableErr := enableControllersFS(fs, own, requiredControllers)
    if enableErr == nil {
        // Re-read to confirm and to pick up the io flag.
        delegatedNow, _ := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
        return &CgroupProbeResult{
            Mode:        ModeNested,
            Reason:      "enabled by probe",
            OwnCgroup:   own,
            IOAvailable: contains(delegatedNow, "io"),
        }, nil
    }

    // Step 5: classify the enable failure and fall through to top-level.
    reason := classifyEnableError(enableErr)
    return tryTopLevel(ctx, fs, own, reason)
}

// tryTopLevel runs steps 5b through 5f of the decision tree.
func tryTopLevel(ctx context.Context, fs cgroupFS, own, nestedFailureReason string) (*CgroupProbeResult, error) {
    rootAvailable, err := readControllerSet(fs, "/sys/fs/cgroup/cgroup.controllers")
    if err != nil {
        return &CgroupProbeResult{
            Mode:      ModeUnavailable,
            Reason:    fmt.Sprintf("%s; read root cgroup.controllers: %v", nestedFailureReason, err),
            OwnCgroup: own,
        }, nil
    }
    if !containsAll(rootAvailable, requiredControllers) {
        missing := missingControllers(rootAvailable, requiredControllers)
        return &CgroupProbeResult{
            Mode:      ModeUnavailable,
            Reason:    fmt.Sprintf("%s; root cgroup missing controllers %v", nestedFailureReason, missing),
            OwnCgroup: own,
        }, nil
    }

    rootDelegated, _ := readControllerSet(fs, "/sys/fs/cgroup/cgroup.subtree_control")
    if !containsAll(rootDelegated, requiredControllers) {
        if err := enableControllersFS(fs, "/sys/fs/cgroup", requiredControllers); err != nil {
            return &CgroupProbeResult{
                Mode:      ModeUnavailable,
                Reason:    fmt.Sprintf("%s; root subtree_control not writable: %v", nestedFailureReason, err),
                OwnCgroup: own,
            }, nil
        }
        rootDelegated, _ = readControllerSet(fs, "/sys/fs/cgroup/cgroup.subtree_control")
    }

    // Ensure the slice exists with controller files populated.
    if err := fs.Mkdir(DefaultSliceDir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
        return &CgroupProbeResult{
            Mode:      ModeUnavailable,
            Reason:    fmt.Sprintf("%s; mkdir %s: %v", nestedFailureReason, DefaultSliceDir, err),
            OwnCgroup: own,
        }, nil
    }
    if _, err := fs.Stat(filepath.Join(DefaultSliceDir, "memory.max")); err != nil {
        // memory.max is the canary: if it's missing, controller files weren't created
        // even though mkdir succeeded — enforcement is not possible here.
        return &CgroupProbeResult{
            Mode:      ModeUnavailable,
            Reason:    fmt.Sprintf("%s; %s missing controller files after mkdir", nestedFailureReason, DefaultSliceDir),
            OwnCgroup: own,
            SliceDir:  DefaultSliceDir,
        }, nil
    }

    // Reap orphans left behind by a prior agentsh crash.
    reaped := reapOrphansFS(fs, DefaultSliceDir)

    return &CgroupProbeResult{
        Mode:          ModeTopLevel,
        Reason:        fmt.Sprintf("%s; using %s", nestedFailureReason, DefaultSliceDir),
        OwnCgroup:     own,
        SliceDir:      DefaultSliceDir,
        IOAvailable:   contains(rootDelegated, "io"),
        OrphansReaped: reaped,
    }, nil
}

// reapOrphansFS removes empty (unpopulated) children of the slice directory.
// It returns the names of the removed children. Errors on individual children
// are logged to stderr and skipped; this function never returns an error.
func reapOrphansFS(fs cgroupFS, sliceDir string) []string {
    entries, err := fs.ReadDir(sliceDir)
    if err != nil {
        return nil
    }
    var reaped []string
    for _, e := range entries {
        if !e.IsDir() {
            continue
        }
        child := filepath.Join(sliceDir, e.Name())
        data, err := fs.ReadFile(filepath.Join(child, "cgroup.events"))
        if err != nil {
            // Skip children whose events file is unreadable — they may be actively used.
            continue
        }
        if !isUnpopulated(data) {
            continue
        }
        if err := fs.Remove(child); err != nil {
            fmt.Fprintf(os.Stderr, "agentsh: reap orphan %s: %v\n", child, err)
            continue
        }
        reaped = append(reaped, e.Name())
    }
    return reaped
}

// classifyEnableError turns an enableControllersFS error into a short human string.
func classifyEnableError(err error) string {
    var ece *EnableControllersError
    if !errors.As(err, &ece) {
        return fmt.Sprintf("enable controllers: %v", err)
    }
    switch {
    case errors.Is(err, syscall.EBUSY):
        return "parent cgroup has internal processes (EBUSY)"
    case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
        return "parent cgroup subtree_control not writable (EACCES)"
    default:
        return fmt.Sprintf("enable controller %q failed: %v", ece.Controller, ece.Err)
    }
}

// readControllerSet reads a cgroup.controllers or cgroup.subtree_control file and
// returns the whitespace-separated controller names it contains.
func readControllerSet(fs cgroupFS, path string) ([]string, error) {
    data, err := fs.ReadFile(path)
    if err != nil {
        return nil, err
    }
    return strings.Fields(strings.TrimSpace(string(data))), nil
}

func contains(set []string, want string) bool {
    for _, s := range set {
        if s == want {
            return true
        }
    }
    return false
}

func containsAll(set, want []string) bool {
    for _, w := range want {
        if !contains(set, w) {
            return false
        }
    }
    return true
}

func missingControllers(have, want []string) []string {
    var out []string
    for _, w := range want {
        if !contains(have, w) {
            out = append(out, w)
        }
    }
    return out
}

func isUnpopulated(eventsFileContent []byte) bool {
    for _, line := range strings.Split(string(eventsFileContent), "\n") {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "populated ") {
            return strings.TrimPrefix(line, "populated ") == "0"
        }
    }
    return false
}
```

- [ ] **Step 2: Write the failing probe tests**

Write `internal/limits/cgroupv2_probe_test.go`:

```go
//go:build linux

package limits

import (
    "context"
    "strings"
    "syscall"
    "testing"
)

// seedHealthyRoot seeds the root cgroup with all needed controllers already
// delegated. Used as a starting point for tests that then adjust own-cgroup state.
func seedHealthyRoot(f *fakeCgroupFS) {
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids")
    f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "cpuset cpu io memory pids")
}

func TestProbe_NestedAlreadyDelegated(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu io memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "cpu io memory pids")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeNested {
        t.Fatalf("mode: got %q, want nested", res.Mode)
    }
    if res.Reason != "already delegated" {
        t.Fatalf("reason: got %q, want 'already delegated'", res.Reason)
    }
    if !res.IOAvailable {
        t.Fatalf("expected io_available=true")
    }
}

func TestProbe_NestedEnableSucceeds(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeNested || res.Reason != "enabled by probe" {
        t.Fatalf("mode/reason: got %q/%q, want nested/enabled by probe", res.Mode, res.Reason)
    }
    if err := f.assertSubtreeControl(own+"/cgroup.subtree_control", "cpu", "memory", "pids"); err != nil {
        t.Fatalf("expected subtree_control populated: %v", err)
    }
}

func TestProbe_EnableEBUSY_FallbackToTopLevel(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")
    // Injected: the enable write fails with EBUSY.
    f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
    // Top-level needs to be ready: slice dir will be created by probe, but we
    // must seed memory.max to appear after mkdir (our fake doesn't auto-create
    // controller files, so we prepopulate the file at the expected path).
    f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeTopLevel {
        t.Fatalf("mode: got %q, want top-level", res.Mode)
    }
    if !strings.Contains(res.Reason, "EBUSY") {
        t.Fatalf("reason missing EBUSY: %q", res.Reason)
    }
    if res.SliceDir != DefaultSliceDir {
        t.Fatalf("slice dir: got %q", res.SliceDir)
    }
}

func TestProbe_EnableEACCES_FallbackToTopLevel(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")
    f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EACCES
    f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeTopLevel {
        t.Fatalf("mode: got %q, want top-level", res.Mode)
    }
    if !strings.Contains(res.Reason, "EACCES") {
        t.Fatalf("reason missing EACCES: %q", res.Reason)
    }
}

func TestProbe_TopLevelMissingMemoryController(t *testing.T) {
    f := newFakeCgroupFS()
    // Root is missing memory.
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids")
    f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "")
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu pids")
    f.seedFile(own+"/cgroup.subtree_control", "")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeUnavailable {
        t.Fatalf("mode: got %q, want unavailable", res.Mode)
    }
    if !strings.Contains(res.Reason, "memory") {
        t.Fatalf("reason should name missing memory: %q", res.Reason)
    }
}

func TestProbe_TopLevelSliceMissingControllerFiles(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")
    f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
    // Do NOT seed agentsh.slice/memory.max — our fake mkdir won't auto-create it.

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeUnavailable {
        t.Fatalf("mode: got %q, want unavailable", res.Mode)
    }
    if !strings.Contains(res.Reason, "missing controller files") {
        t.Fatalf("reason should name missing controller files: %q", res.Reason)
    }
}

func TestProbe_TopLevelOrphanReap(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")
    f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
    f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")
    // Orphan A is unpopulated → should be reaped.
    f.seedFile("/sys/fs/cgroup/agentsh.slice/orphan-A/cgroup.events", "populated 0\nfrozen 0\n")
    // Orphan B is populated → should be left alone.
    f.seedFile("/sys/fs/cgroup/agentsh.slice/orphan-B/cgroup.events", "populated 1\nfrozen 0\n")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeTopLevel {
        t.Fatalf("mode: got %q, want top-level", res.Mode)
    }
    if len(res.OrphansReaped) != 1 || res.OrphansReaped[0] != "orphan-A" {
        t.Fatalf("expected orphan-A reaped, got %v", res.OrphansReaped)
    }
    if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/orphan-A"); err == nil {
        t.Fatalf("orphan-A should have been removed")
    }
    if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/orphan-B"); err != nil {
        t.Fatalf("orphan-B should still exist: %v", err)
    }
}

func TestProbe_IOControllerOptional(t *testing.T) {
    f := newFakeCgroupFS()
    // Root has everything except io.
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory pids")
    f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "cpu memory pids")
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")

    res, err := ProbeCgroupsV2(context.Background(), f, own)
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if res.Mode != ModeNested {
        t.Fatalf("mode: got %q, want nested", res.Mode)
    }
    if res.IOAvailable {
        t.Fatalf("expected io_available=false")
    }
}
```

- [ ] **Step 3: Run probe tests**

Run: `go test ./internal/limits/ -run TestProbe -v`
Expected: All seven probe tests pass.

- [ ] **Step 4: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add internal/limits/cgroupv2_probe.go internal/limits/cgroupv2_probe_test.go
git commit -m "limits: add ProbeCgroupsV2 with nested/top-level/unavailable decision tree"
```

---

## Task 7: Implement `CgroupManager`

**Files:**
- Create: `internal/limits/cgroupv2_manager.go`
- Create: `internal/limits/cgroupv2_manager_test.go`

- [ ] **Step 1: Create the manager file**

Write `internal/limits/cgroupv2_manager.go`:

```go
//go:build linux

package limits

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "syscall"
)

// CgroupManager is the production entry point for per-command cgroup v2 enforcement.
// Construct one at server startup via NewCgroupManager; all per-exec calls go through Apply.
//
// The manager captures an immutable probe result at construction time. If the
// environment changes mid-run, restart agentsh.
type CgroupManager struct {
    fs     cgroupFS
    probe  *CgroupProbeResult
}

// NewCgroupManager runs ProbeCgroupsV2 once and returns a manager bound to the result.
// ownHint is the optional user-configured cgroup base path (cfg.Sandbox.Cgroups.BasePath).
// Pass an empty string to have the probe discover the process's own cgroup.
//
// NewCgroupManager never fails for expected reasons — environment gaps are reflected
// in the probed mode, not in the return error. An error is only returned if the
// process cannot even determine its own cgroup path.
func NewCgroupManager(ctx context.Context, ownHint string) (*CgroupManager, error) {
    return newCgroupManagerFS(ctx, osCgroupFS{}, ownHint)
}

// newCgroupManagerFS is the FS-injectable form used by unit tests.
func newCgroupManagerFS(ctx context.Context, fs cgroupFS, ownHint string) (*CgroupManager, error) {
    probe, err := ProbeCgroupsV2(ctx, fs, ownHint)
    if err != nil {
        return nil, fmt.Errorf("probe cgroups v2: %w", err)
    }
    return &CgroupManager{fs: fs, probe: probe}, nil
}

// Probe returns the immutable probe result captured at construction.
func (m *CgroupManager) Probe() *CgroupProbeResult { return m.probe }

// Apply creates a per-command cgroup (named `name`), writes the non-zero limits,
// and attaches `pid`. It returns a handle whose Close() removes the cgroup when
// the command exits.
//
// If the manager's probed mode is ModeUnavailable and any limit in lim is non-zero,
// Apply returns *CgroupUnavailableError without creating anything. This is the
// fail-closed path.
func (m *CgroupManager) Apply(name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
    if pid <= 0 {
        return nil, fmt.Errorf("invalid pid %d", pid)
    }

    // Fail-closed: if limits are required but enforcement is unavailable, refuse.
    if m.probe.Mode == ModeUnavailable {
        if !lim.IsEmpty() {
            return nil, &CgroupUnavailableError{Reason: m.probe.Reason, Limits: lim}
        }
        // No limits requested: allow the command but create no cgroup.
        return nil, nil
    }

    parent := m.parentDir()
    safe := sanitizeCgroupName(name)
    dir := filepath.Join(parent, safe)

    if err := m.fs.Mkdir(dir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
        return nil, fmt.Errorf("mkdir cgroup (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
    }

    if lim.MaxMemoryBytes > 0 {
        if err := m.fs.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(lim.MaxMemoryBytes, 10)), 0o644); err != nil {
            return nil, fmt.Errorf("write memory.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
        }
    }
    if lim.PidsMax > 0 {
        if err := m.fs.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(lim.PidsMax)), 0o644); err != nil {
            return nil, fmt.Errorf("write pids.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
        }
    }
    if lim.CPUQuotaPct > 0 {
        q, p := cpuMaxFromPct(lim.CPUQuotaPct)
        if err := m.fs.WriteFile(filepath.Join(dir, "cpu.max"), []byte(fmt.Sprintf("%d %d", q, p)), 0o644); err != nil {
            return nil, fmt.Errorf("write cpu.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
        }
    }

    if err := m.fs.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
        return nil, fmt.Errorf("attach pid (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
    }

    return &CgroupV2{Path: dir}, nil
}

// parentDir returns the directory under which per-command cgroups are created.
func (m *CgroupManager) parentDir() string {
    if m.probe.Mode == ModeTopLevel {
        return m.probe.SliceDir
    }
    return m.probe.OwnCgroup
}

// silence unused-import warning for os when no helper here needs it.
var _ = os.O_WRONLY
```

- [ ] **Step 2: Write manager tests**

Write `internal/limits/cgroupv2_manager_test.go`:

```go
//go:build linux

package limits

import (
    "context"
    "errors"
    "strings"
    "testing"
)

func TestManagerApply_NestedWritesLimits(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")

    m, err := newCgroupManagerFS(context.Background(), f, own)
    if err != nil {
        t.Fatalf("new manager: %v", err)
    }
    if m.Probe().Mode != ModeNested {
        t.Fatalf("mode: %q", m.Probe().Mode)
    }

    cg, err := m.Apply("agentsh-sess-cmd", 4242, CgroupV2Limits{MaxMemoryBytes: 16 << 20, PidsMax: 64})
    if err != nil {
        t.Fatalf("apply: %v", err)
    }
    if cg == nil || !strings.HasPrefix(cg.Path, own+"/") {
        t.Fatalf("nested cgroup path: %q (want prefix %q)", cg.Path, own)
    }
    data, _ := f.ReadFile(cg.Path + "/memory.max")
    if string(data) != "16777216" {
        t.Fatalf("memory.max: got %q, want 16777216", data)
    }
    data, _ = f.ReadFile(cg.Path + "/pids.max")
    if string(data) != "64" {
        t.Fatalf("pids.max: got %q, want 64", data)
    }
    data, _ = f.ReadFile(cg.Path + "/cgroup.procs")
    if string(data) != "4242" {
        t.Fatalf("cgroup.procs: got %q, want 4242", data)
    }
}

func TestManagerApply_TopLevelWritesUnderSlice(t *testing.T) {
    f := newFakeCgroupFS()
    seedHealthyRoot(f)
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
    f.seedFile(own+"/cgroup.subtree_control", "")
    f.openErrs[own+"/cgroup.subtree_control:write"] = syscallEBUSY()
    f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

    m, err := newCgroupManagerFS(context.Background(), f, own)
    if err != nil {
        t.Fatalf("new manager: %v", err)
    }
    if m.Probe().Mode != ModeTopLevel {
        t.Fatalf("mode: %q", m.Probe().Mode)
    }

    cg, err := m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
    if err != nil {
        t.Fatalf("apply: %v", err)
    }
    if !strings.HasPrefix(cg.Path, DefaultSliceDir+"/") {
        t.Fatalf("top-level cgroup path: %q (want prefix %q)", cg.Path, DefaultSliceDir)
    }
}

func TestManagerApply_UnavailableNoLimitsAllows(t *testing.T) {
    f := newFakeCgroupFS()
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids") // no memory
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu pids")

    m, err := newCgroupManagerFS(context.Background(), f, own)
    if err != nil {
        t.Fatalf("new manager: %v", err)
    }
    if m.Probe().Mode != ModeUnavailable {
        t.Fatalf("mode: %q", m.Probe().Mode)
    }

    cg, err := m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{})
    if err != nil {
        t.Fatalf("apply with empty limits should succeed, got %v", err)
    }
    if cg != nil {
        t.Fatalf("expected nil cgroup in unavailable mode with no limits, got %+v", cg)
    }
}

func TestManagerApply_UnavailableWithLimitsRefuses(t *testing.T) {
    f := newFakeCgroupFS()
    f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids")
    own := "/sys/fs/cgroup/system.slice/agentsh.service"
    f.seedFile(own+"/cgroup.controllers", "cpu pids")

    m, err := newCgroupManagerFS(context.Background(), f, own)
    if err != nil {
        t.Fatalf("new manager: %v", err)
    }

    _, err = m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
    if err == nil {
        t.Fatalf("expected error, got nil")
    }
    var ue *CgroupUnavailableError
    if !errors.As(err, &ue) {
        t.Fatalf("expected *CgroupUnavailableError, got %T: %v", err, err)
    }
    if !strings.Contains(ue.Reason, "memory") {
        t.Fatalf("reason should mention missing memory: %q", ue.Reason)
    }
}

// syscallEBUSY returns syscall.EBUSY as an error without importing syscall at package level.
func syscallEBUSY() error { return errEBUSY }
```

- [ ] **Step 3: Add the helper error at the top of the file**

Prepend the following to `internal/limits/cgroupv2_manager_test.go` imports section or add after the imports block:

```go
import "syscall"

var errEBUSY = syscall.EBUSY
```

(Merge into the existing import block.)

- [ ] **Step 4: Run the manager tests**

Run: `go test ./internal/limits/ -run TestManagerApply -v`
Expected: All four tests pass.

- [ ] **Step 5: Run the full `limits` package test suite**

Run: `go test ./internal/limits/...`
Expected: All probe, fake-smoke, manager, enableControllers, and existing tests pass (or `TestApplyCgroupV2_CreatesAndCleansUp` skips if cgroup v2 is unavailable on the dev host).

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_manager.go internal/limits/cgroupv2_manager_test.go
git commit -m "limits: add CgroupManager with mode-aware Apply and fail-closed refusal"
```

---

## Task 8: Integration tests (build-tag gated)

**Files:**
- Create: `internal/limits/cgroupv2_integration_test.go`

- [ ] **Step 1: Create the integration test file**

Write `internal/limits/cgroupv2_integration_test.go`:

```go
//go:build linux && cgroup_integration

package limits

import (
    "context"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

// Run with:
//   go test -tags cgroup_integration ./internal/limits/... -v
// on a Linux host with privileges to write /sys/fs/cgroup.

func TestIntegration_ProbeReal(t *testing.T) {
    if !DetectCgroupV2() {
        t.Skip("cgroup v2 not mounted")
    }
    m, err := NewCgroupManager(context.Background(), "")
    if err != nil {
        t.Fatalf("NewCgroupManager: %v", err)
    }
    p := m.Probe()
    t.Logf("probe: mode=%s reason=%s own=%s slice=%s io=%v",
        p.Mode, p.Reason, p.OwnCgroup, p.SliceDir, p.IOAvailable)
    switch p.Mode {
    case ModeNested, ModeTopLevel, ModeUnavailable:
    default:
        t.Fatalf("unexpected mode %q", p.Mode)
    }
}

func TestIntegration_TopLevelApplyAndEnforce(t *testing.T) {
    if !DetectCgroupV2() {
        t.Skip("cgroup v2 not mounted")
    }
    m, err := NewCgroupManager(context.Background(), "")
    if err != nil {
        t.Fatalf("NewCgroupManager: %v", err)
    }
    if m.Probe().Mode != ModeTopLevel {
        t.Skipf("not in top-level mode (got %s)", m.Probe().Mode)
    }

    cmd := exec.Command("sleep", "0.2")
    if err := cmd.Start(); err != nil {
        t.Skipf("cannot start sleep: %v", err)
    }
    defer func() { _ = cmd.Process.Kill() }()

    cg, err := m.Apply("agentsh-integ-top-level", cmd.Process.Pid, CgroupV2Limits{
        MaxMemoryBytes: 8 << 20,
    })
    if err != nil {
        t.Fatalf("apply: %v", err)
    }
    defer func() {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        _ = cg.Close(ctx)
    }()
    if !strings.HasPrefix(cg.Path, DefaultSliceDir) {
        t.Fatalf("expected top-level path under %s, got %q", DefaultSliceDir, cg.Path)
    }
    data, err := os.ReadFile(filepath.Join(cg.Path, "memory.max"))
    if err != nil {
        t.Fatalf("read memory.max: %v", err)
    }
    if strings.TrimSpace(string(data)) != "8388608" {
        t.Fatalf("memory.max: got %q, want 8388608", data)
    }
    _ = cmd.Wait()
}

func TestIntegration_OrphanReap(t *testing.T) {
    if !DetectCgroupV2() {
        t.Skip("cgroup v2 not mounted")
    }
    // This test only runs meaningfully in top-level mode.
    probe, err := ProbeCgroupsV2(context.Background(), osCgroupFS{}, "")
    if err != nil {
        t.Fatalf("probe: %v", err)
    }
    if probe.Mode != ModeTopLevel {
        t.Skipf("not in top-level mode (got %s)", probe.Mode)
    }

    orphan := filepath.Join(DefaultSliceDir, "integ-orphan")
    if err := os.Mkdir(orphan, 0o755); err != nil && !os.IsExist(err) {
        t.Fatalf("mkdir orphan: %v", err)
    }
    // Pre-verify the orphan is unpopulated.
    if _, err := os.ReadFile(filepath.Join(orphan, "cgroup.events")); err != nil {
        t.Fatalf("read events on orphan: %v", err)
    }

    // Re-probe to trigger reap.
    probe2, err := ProbeCgroupsV2(context.Background(), osCgroupFS{}, "")
    if err != nil {
        t.Fatalf("re-probe: %v", err)
    }
    _ = probe2
    if _, err := os.Stat(orphan); err == nil {
        t.Fatalf("orphan %s should have been reaped", orphan)
    }
}
```

- [ ] **Step 2: Verify the file only builds under the `cgroup_integration` tag**

Run: `go build ./internal/limits/...`
Expected: exit 0, and the integration file is ignored.

Run: `go build -tags cgroup_integration ./internal/limits/...`
Expected: exit 0, file compiles.

- [ ] **Step 3: Commit**

```bash
git add internal/limits/cgroupv2_integration_test.go
git commit -m "limits: add cgroup v2 integration tests (build-tag gated)"
```

---

## Task 9: Migrate `internal/api/cgroups.go` to the manager

**Files:**
- Modify: `internal/api/cgroups.go`

The current code calls the package-level `limits.ApplyCgroupV2` directly and emits a misleading error event. After this task it calls `app.cgroupMgr.Apply`, handles `CgroupUnavailableError` as a structured refusal, and uses the new `EventCgroupUnavailableRefusal` event type. The wiring of `app.cgroupMgr` itself happens in Task 10; for this task, reference the field name with the expectation that Task 10 will satisfy it.

- [ ] **Step 1: Read the full current implementation one more time**

Run: `sed -n '1,80p' internal/api/cgroups.go`
Expected: Shows the current `applyCgroupV2` function signature and the `limits.ApplyCgroupV2` call site (around line 42).

- [ ] **Step 2: Change the `applyCgroupV2` helper to use the manager**

In `internal/api/cgroups.go`, replace lines 21-61 (the function prelude, the `limits.ApplyCgroupV2` call, and its error-handling) with:

```go
func applyCgroupV2(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID string, pid int, lim policy.Limits, m *metrics.Collector, pol *policy.Engine) (func() error, error) {
    cfg := app.cfg
    if cfg == nil || !cfg.Sandbox.Cgroups.Enabled {
        return nil, nil
    }

    ebpfEnabled := cfg.Sandbox.Network.EBPF.Enabled
    ebpfRequired := cfg.Sandbox.Network.EBPF.Required
    ebpfEnforce := cfg.Sandbox.Network.EBPF.Enforce
    enforceNoDNS := cfg.Sandbox.Network.EBPF.EnforceWithoutDNS

    memBytes := int64(0)
    if lim.MaxMemoryMB > 0 {
        memBytes = int64(lim.MaxMemoryMB) * 1024 * 1024
    }
    cgLimits := limits.CgroupV2Limits{
        MaxMemoryBytes: memBytes,
        CPUQuotaPct:    lim.CPUQuotaPercent,
        PidsMax:        lim.PidsMax,
    }

    if app.cgroupMgr == nil {
        return nil, fmt.Errorf("cgroup manager not initialized")
    }

    cg, err := app.cgroupMgr.Apply("agentsh-"+sanitizeCgroupTag(sessionID)+"-"+sanitizeCgroupTag(cmdID), pid, cgLimits)
    if err != nil {
        var ue *limits.CgroupUnavailableError
        if errors.As(err, &ue) {
            ev := types.Event{
                ID:        uuid.NewString(),
                Timestamp: time.Now().UTC(),
                Type:      events.EventCgroupUnavailableRefusal,
                SessionID: sessionID,
                CommandID: cmdID,
                Fields: map[string]any{
                    "reason":        ue.Reason,
                    "max_memory_mb": lim.MaxMemoryMB,
                    "cpu_quota_pct": lim.CPUQuotaPercent,
                    "pids_max":      lim.PidsMax,
                },
            }
            _ = emit.AppendEvent(ctx, ev)
            emit.Publish(ev)
            return nil, err
        }
        ev := types.Event{
            ID:        uuid.NewString(),
            Timestamp: time.Now().UTC(),
            Type:      "cgroup_apply_failed",
            SessionID: sessionID,
            CommandID: cmdID,
            Fields: map[string]any{
                "error": err.Error(),
            },
        }
        _ = emit.AppendEvent(ctx, ev)
        emit.Publish(ev)
        return nil, err
    }

    // If unavailable mode allowed us (empty limits), cg is nil. Treat as no-op.
    if cg == nil {
        return func() error { return nil }, nil
    }

    ev := types.Event{
        ID:        uuid.NewString(),
        Timestamp: time.Now().UTC(),
        Type:      "cgroup_applied",
        SessionID: sessionID,
        CommandID: cmdID,
        Fields: map[string]any{
            "path":          cg.Path,
            "mode":          string(app.cgroupMgr.Probe().Mode),
            "max_memory_mb": lim.MaxMemoryMB,
            "cpu_quota_pct": lim.CPUQuotaPercent,
            "pids_max":      lim.PidsMax,
        },
    }
    _ = emit.AppendEvent(ctx, ev)
    emit.Publish(ev)
```

The rest of the function (ebpf wiring, lines 80-313 of the current file) continues unchanged from the original — it still uses `cg` as the parent for ebpf attach. Do not re-paste those lines; leave them intact after the replacement block above.

- [ ] **Step 3: Update the single caller of `applyCgroupV2` to pass `app`**

Grep for `applyCgroupV2(` to find the call site in the package:

Run: `grep -rn "applyCgroupV2(" internal/api/`
Expected: one or two call sites, most likely in `internal/api/exec.go` or `internal/api/commands.go`.

At each call site, change the first argument block to pass `app` (the receiver, usually `a` or `s`) instead of `cfg`:

```go
// before
cleanup, err := applyCgroupV2(ctx, emit, a.cfg, sessionID, cmdID, pid, lim, a.metrics, a.policy)

// after
cleanup, err := applyCgroupV2(ctx, emit, a, sessionID, cmdID, pid, lim, a.metrics, a.policy)
```

- [ ] **Step 4: Add the required imports to `internal/api/cgroups.go`**

Ensure `internal/api/cgroups.go` imports (add any that are missing):

```go
import (
    "context"
    "errors"
    "fmt"
    "path/filepath"
    "strings"
    "time"

    "github.com/cilium/ebpf"

    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/internal/events"
    "github.com/agentsh/agentsh/internal/limits"
    "github.com/agentsh/agentsh/internal/metrics"
    ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
    "github.com/agentsh/agentsh/internal/policy"
    "github.com/agentsh/agentsh/pkg/types"
    "github.com/google/uuid"
)
```

Remove `path/filepath` if it is now unused after the prior `parent := ...` block was removed.

- [ ] **Step 5: Build and expect it to fail on `app.cgroupMgr`**

Run: `go build ./internal/api/...`
Expected: build failure pointing at `app.cgroupMgr` (field not yet defined). That's expected — Task 10 adds the field. This task cannot be committed in isolation; combine the commit with Task 10.

Leave the working tree with both Task 9 and Task 10 edits applied and commit them together in Task 10.

---

## Task 10: Add `cgroupMgr` to `api.App` and wire it in `server.New`

**Files:**
- Modify: `internal/api/app.go` (or whichever file defines `type App struct`)
- Modify: `internal/server/server.go`

- [ ] **Step 1: Locate the `App` struct definition**

Run: `grep -rn "type App struct" internal/api/`
Expected: one hit, likely in `internal/api/app.go`.

- [ ] **Step 2: Add the manager field**

Add `cgroupMgr *limits.CgroupManager` to the `App` struct in its definition file, adjacent to other infrastructure fields such as `cfg`, `store`, `broker`:

```go
type App struct {
    cfg       *config.Config
    sessions  *sessions.Store
    store     *eventstore.Store
    policy    *policy.Engine
    broker    *events.Broker
    cgroupMgr *limits.CgroupManager // issue #197: per-process cgroup manager, nil on non-Linux
    // … other existing fields …
}
```

Ensure `"github.com/agentsh/agentsh/internal/limits"` is in the imports (it may already be).

- [ ] **Step 3: Extend `NewApp` signature to accept the manager**

Find the `NewApp` constructor in the same file and add `cgroupMgr *limits.CgroupManager` as the final parameter:

```go
func NewApp(
    cfg *config.Config,
    sessions *sessions.Store,
    store *eventstore.Store,
    engine *policy.Engine,
    broker *events.Broker,
    apiKeyAuth *auth.APIKeyAuth,
    oidcAuth *auth.OIDCAuth,
    approvals *approvals.Manager,
    metrics *metrics.Collector,
    policyLoader *policy.Loader,
    cgroupMgr *limits.CgroupManager,
) *App {
    return &App{
        cfg:       cfg,
        sessions:  sessions,
        store:     store,
        policy:    engine,
        broker:    broker,
        // … other assignments …
        cgroupMgr: cgroupMgr,
    }
}
```

(Match whichever parameter order the current constructor uses — the important change is the added tail parameter and the assignment.)

- [ ] **Step 4: Construct the manager in `server.New` and pass it to `NewApp`**

Open `internal/server/server.go` and find the call to `api.NewApp(...)` (around line 412 per the earlier exploration). Immediately before the call, add:

```go
var cgroupMgr *limits.CgroupManager
if runtime.GOOS == "linux" {
    mgr, err := limits.NewCgroupManager(ctx, cfg.Sandbox.Cgroups.BasePath)
    if err != nil {
        // Probe should not fail for expected environmental reasons. A real
        // error here means /proc/self/cgroup could not be read — log and
        // continue with nil; Apply() will return a clear error per-exec.
        log.Warn().Err(err).Msg("cgroup v2 probe failed; per-command limits unavailable")
    } else {
        cgroupMgr = mgr
        modeEvent := types.Event{
            ID:        uuid.NewString(),
            Timestamp: time.Now().UTC(),
            Type:      events.EventCgroupMode,
            Fields: map[string]any{
                "mode":          string(mgr.Probe().Mode),
                "reason":        mgr.Probe().Reason,
                "own_cgroup":    mgr.Probe().OwnCgroup,
                "slice_dir":     mgr.Probe().SliceDir,
                "io_available":  mgr.Probe().IOAvailable,
            },
        }
        _ = store.AppendEvent(ctx, modeEvent)
        broker.Publish(modeEvent)
        if reaped := mgr.Probe().OrphansReaped; len(reaped) > 0 {
            reapEvent := types.Event{
                ID:        uuid.NewString(),
                Timestamp: time.Now().UTC(),
                Type:      events.EventCgroupOrphansReaped,
                Fields: map[string]any{
                    "count": len(reaped),
                    "names": reaped,
                },
            }
            _ = store.AppendEvent(ctx, reapEvent)
            broker.Publish(reapEvent)
        }
    }
}
```

Then pass `cgroupMgr` as the final argument to the `api.NewApp(...)` call.

Add to `internal/server/server.go` imports (if missing):

```go
"runtime"
"time"
"github.com/agentsh/agentsh/internal/events"
"github.com/agentsh/agentsh/internal/limits"
"github.com/agentsh/agentsh/pkg/types"
"github.com/google/uuid"
```

The `ctx`, `log`, `store`, `broker`, and `cfg` identifiers are whatever the surrounding function already uses — match those names rather than introducing new ones.

- [ ] **Step 5: Build the whole tree**

Run: `go build ./...`
Expected: exit 0, no undefined-symbol errors.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: exit 0. The `runtime.GOOS == "linux"` guard and the `//go:build linux` tag on `limits/cgroupv2_*.go` prevent the Windows build from trying to compile Linux-specific code. If Windows build fails because `limits.CgroupManager` is unresolved, add a non-Linux stub in a new `internal/limits/cgroupv2_other.go`:

```go
//go:build !linux

package limits

import "context"

// CgroupManager is a no-op stub on non-Linux platforms.
type CgroupManager struct{}

// NewCgroupManager returns a nil manager on non-Linux; callers must check
// runtime.GOOS before using per-command enforcement.
func NewCgroupManager(ctx context.Context, ownHint string) (*CgroupManager, error) {
    return nil, nil
}
```

(Only add the stub if the Windows build fails without it.)

- [ ] **Step 7: Run the test suite**

Run: `go test ./internal/limits/... ./internal/api/... ./internal/server/...`
Expected: all tests pass. (Integration tests are behind a build tag and will not run.)

- [ ] **Step 8: Commit Task 9 + Task 10 together**

```bash
git add internal/api/cgroups.go internal/api/app.go internal/server/server.go internal/limits/cgroupv2_other.go 2>/dev/null
git add -u internal/api/ internal/server/ internal/limits/
git commit -m "api,server: route cgroup enforcement through CgroupManager

Wire a single CgroupManager into api.App at server startup. The per-exec
helper in internal/api/cgroups.go consults the manager, emits
cgroup_mode at startup and cgroup_unavailable_refusal on refusals, and
no longer calls the removed package-level limits.ApplyCgroupV2.

Refs #197."
```

(If the second `git add` complains about a path that doesn't exist, drop it — `git add -u` picks up anything tracked.)

---

## Task 11: Remove the package-level `ApplyCgroupV2` and migrate its test

**Files:**
- Modify: `internal/limits/cgroupv2_linux.go`
- Modify: `internal/limits/cgroupv2_linux_test.go`

- [ ] **Step 1: Verify the function has no remaining callers**

Run: `grep -rn "limits.ApplyCgroupV2\|ApplyCgroupV2(" --include='*.go' .`
Expected: only the function definition in `internal/limits/cgroupv2_linux.go` and the test in `internal/limits/cgroupv2_linux_test.go`. No production callers.

If grep finds production callers, abort this task and fix those call sites first (most likely they were introduced between Tasks 6–10).

- [ ] **Step 2: Delete the `ApplyCgroupV2` function**

In `internal/limits/cgroupv2_linux.go`, remove the `ApplyCgroupV2` function (lines ~55-104 of the original file, which by this point have been through the enableControllers rewrite in Task 5). Keep `DetectCgroupV2`, `CurrentCgroupDir`, `CgroupV2`, `CgroupV2.Close`, `cpuMaxFromPct`, `sanitizeCgroupName`, `cgroupUnpopulated`, `enableControllers`, and `enableControllersFS`.

- [ ] **Step 3: Rewrite the existing test to use the manager**

Replace the body of `TestApplyCgroupV2_CreatesAndCleansUp` in `internal/limits/cgroupv2_linux_test.go` with:

```go
func TestManagerApply_CreatesAndCleansUp_Integration(t *testing.T) {
    if !DetectCgroupV2() {
        t.Skip("cgroup v2 not available")
    }

    cmd := exec.Command("sleep", "0.2")
    if err := cmd.Start(); err != nil {
        t.Skipf("cannot start sleep: %v", err)
    }
    defer func() { _ = cmd.Process.Kill() }()

    m, err := NewCgroupManager(context.Background(), "")
    if err != nil {
        t.Skipf("cannot construct cgroup manager: %v", err)
    }
    if m.Probe().Mode == ModeUnavailable {
        t.Skipf("cgroup enforcement unavailable: %s", m.Probe().Reason)
    }

    cg, err := m.Apply("agentsh-test-"+strings.ReplaceAll(t.Name(), "/", "_"), cmd.Process.Pid, CgroupV2Limits{
        PidsMax: 100,
    })
    if err != nil {
        t.Skipf("cannot apply cgroup limits in this environment: %v", err)
    }
    if cg == nil || cg.Path == "" {
        t.Fatalf("expected cgroup path")
    }
    if !strings.HasPrefix(cg.Path, "/sys/fs/cgroup") {
        t.Fatalf("unexpected cgroup path: %q", cg.Path)
    }
    if filepath.Base(cg.Path) == "" {
        t.Fatalf("expected basename for cgroup path: %q", cg.Path)
    }

    _ = cmd.Wait()

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    if err := cg.Close(ctx); err != nil {
        t.Fatalf("close cgroup: %v", err)
    }
}
```

Delete the old `TestApplyCgroupV2_CreatesAndCleansUp` function entirely.

- [ ] **Step 4: Build & test**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both exit 0.

Run: `go test ./internal/limits/...`
Expected: all tests pass (the migrated integration-like test may skip if cgroup v2 is unavailable on the dev host).

- [ ] **Step 5: Commit**

```bash
git add internal/limits/cgroupv2_linux.go internal/limits/cgroupv2_linux_test.go
git commit -m "limits: remove deprecated ApplyCgroupV2 package function"
```

---

## Task 12: Rewrite capabilities probe + extend detect output

**Files:**
- Modify: `internal/capabilities/check_cgroups_linux.go`
- Modify: `internal/capabilities/detect_linux.go`

- [ ] **Step 1: Read the current probe**

Run: `sed -n '1,40p' internal/capabilities/check_cgroups_linux.go`
Expected: Shows `probeCgroupsV2()` returning a simple `ProbeResult{Available bool, Detail string}`.

- [ ] **Step 2: Rewrite `probeCgroupsV2()` to call the manager probe**

Replace the body of `probeCgroupsV2()` in `internal/capabilities/check_cgroups_linux.go` with:

```go
func probeCgroupsV2() ProbeResult {
    if !limits.DetectCgroupV2() {
        return ProbeResult{Available: false, Detail: "cgroup2 not mounted"}
    }
    res, err := limits.ProbeCgroupsV2(context.Background(), limitsOSCgroupFS(), "")
    if err != nil {
        return ProbeResult{Available: false, Detail: "probe error: " + err.Error()}
    }
    cacheCgroupProbe(res) // store for detect_linux.go
    detail := string(res.Mode) + ": " + res.Reason
    return ProbeResult{
        Available: res.Mode != limits.ModeUnavailable,
        Detail:    detail,
    }
}

// limitsOSCgroupFS returns the production cgroupFS; exposed via a helper to
// keep the unexported type out of this package's API surface.
func limitsOSCgroupFS() interface{} { return nil } // placeholder — see note below
```

**Note on `limitsOSCgroupFS`:** because `cgroupFS` is unexported in `internal/limits`, the capabilities package cannot construct one directly. Instead, expose a new helper in `internal/limits/cgroupv2_probe.go`:

```go
// ProbeCgroupsV2Default is a convenience wrapper that runs ProbeCgroupsV2 with
// the production cgroupFS and no ownHint. It is intended for callers outside
// the limits package (e.g. the capabilities probe).
func ProbeCgroupsV2Default(ctx context.Context) (*CgroupProbeResult, error) {
    return ProbeCgroupsV2(ctx, osCgroupFS{}, "")
}
```

Then the capabilities probe becomes:

```go
func probeCgroupsV2() ProbeResult {
    if !limits.DetectCgroupV2() {
        return ProbeResult{Available: false, Detail: "cgroup2 not mounted"}
    }
    res, err := limits.ProbeCgroupsV2Default(context.Background())
    if err != nil {
        return ProbeResult{Available: false, Detail: "probe error: " + err.Error()}
    }
    cacheCgroupProbe(res)
    return ProbeResult{
        Available: res.Mode != limits.ModeUnavailable,
        Detail:    string(res.Mode) + ": " + res.Reason,
    }
}
```

Drop the placeholder `limitsOSCgroupFS` helper in `check_cgroups_linux.go`.

Imports needed in `check_cgroups_linux.go`:

```go
import (
    "context"

    "github.com/agentsh/agentsh/internal/limits"
)
```

- [ ] **Step 3: Add the cache helper**

Add to the top of `internal/capabilities/check_cgroups_linux.go`:

```go
// cgroupProbeCache stores the most recent rich probe result so that
// detect_linux.go can pull structured fields into the flat capabilities map.
// Updated by probeCgroupsV2; read by backwardCompatCaps.
var cgroupProbeCache *limits.CgroupProbeResult

func cacheCgroupProbe(r *limits.CgroupProbeResult) {
    cgroupProbeCache = r
}

// LastCgroupProbe returns the most recent probe result, or nil if the probe
// has not been run in this process. Exposed for detect output formatting.
func LastCgroupProbe() *limits.CgroupProbeResult {
    return cgroupProbeCache
}
```

- [ ] **Step 4: Extend `backwardCompatCaps` in `detect_linux.go`**

Open `internal/capabilities/detect_linux.go` and modify `backwardCompatCaps` (around lines 122-156) to populate the richer keys when a probe result is available:

```go
func backwardCompatCaps(caps *SecurityCapabilities, domains []ProtectionDomain) map[string]any {
    m := map[string]any{
        // … existing entries unchanged …
    }
    for _, d := range domains {
        for _, b := range d.Backends {
            switch b.Name {
            case "ebpf":
                m["ebpf"] = b.Available
            case "cgroups-v2":
                m["cgroups_v2"] = b.Available
            case "pid-namespace":
                m["pid_namespace"] = b.Available
            case "capability-drop":
                m["capabilities_drop"] = b.Available
            case "fuse":
                if b.Available {
                    m["fuse_mount_method"] = b.Detail
                }
            }
        }
    }
    if _, ok := m["fuse_mount_method"]; !ok {
        m["fuse_mount_method"] = "none"
    }

    // Enrich the cgroups_v2 view with probe details (issue #197).
    if p := LastCgroupProbe(); p != nil {
        m["cgroups_v2_mode"] = string(p.Mode)
        m["cgroups_v2_reason"] = p.Reason
        m["cgroups_v2_own_cgroup"] = p.OwnCgroup
        if p.SliceDir != "" {
            m["cgroups_v2_slice_dir"] = p.SliceDir
        }
        m["cgroups_v2_io_available"] = p.IOAvailable
    }

    return m
}
```

- [ ] **Step 5: Build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: exit 0.

- [ ] **Step 7: Run the capabilities and limits test suites**

Run: `go test ./internal/capabilities/... ./internal/limits/...`
Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add internal/capabilities/check_cgroups_linux.go internal/capabilities/detect_linux.go internal/limits/cgroupv2_probe.go
git commit -m "capabilities: report cgroup v2 mode/reason/slice_dir from real probe"
```

---

## Task 13: Final verification

**Files:** _none modified_

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 2: Full cross-compile**

Run: `GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: both exit 0.

- [ ] **Step 3: Full test suite**

Run: `go test ./...`
Expected: all tests pass. Any `t.Skip` messages related to cgroup v2 availability are acceptable; outright failures are not.

- [ ] **Step 4: Vet**

Run: `go vet ./...`
Expected: no warnings.

- [ ] **Step 5: Confirm the final git log**

Run: `git log --oneline origin/main..HEAD`
Expected: a commit per task (Task 9 and 10 combined), the spec commit from brainstorming at the bottom, and this plan file itself if committed separately.

- [ ] **Step 6: Sanity-check `agentsh detect` on the dev host**

Run: `go run ./cmd/agentsh detect`
Expected: output contains a `cgroups_v2` key plus the new `cgroups_v2_mode` / `cgroups_v2_reason` fields. The mode will be whatever applies to the dev host (`nested`, `top-level`, or `unavailable`).

- [ ] **Step 7: File the Lima/WSL2 follow-up issue**

Open a new GitHub issue titled: "Apply cgroup v2 fail-closed probe to Lima and WSL2 platforms" referencing issue #197 and the design spec, noting the silent-swallow pattern at `internal/platform/lima/resources.go:100-103` and `internal/platform/wsl2/resources.go:100-103`.

```bash
gh issue create --title "Apply cgroup v2 fail-closed probe to Lima and WSL2 platforms" --body "$(cat <<'EOF'
Follow-up to #197.

The native Linux path now uses a probe → mode → fail-closed flow for cgroup
v2 enforcement (see `docs/superpowers/specs/2026-04-08-cgroup-subtree-control-fail-closed-design.md`).
The same silent-swallow pattern still exists in the Lima and WSL2 resource
limiters:

- `internal/platform/lima/resources.go:100-103`
- `internal/platform/wsl2/resources.go:100-103`

Both pipe `echo '...' > cgroup.subtree_control 2>/dev/null || true`, which
will silently ignore the same class of failure the native fix addresses.

Port the probe and fail-closed semantics to Lima and WSL2 as a follow-up.
The execution model is different (shell scripts inside the guest VM), so
this is its own design conversation.
EOF
)"
```

(If `gh` is not available, file the issue manually with the same content.)

---

## Self-Review Against the Spec

**Spec coverage — each requirement maps to a task:**

- Three operating modes (`nested`, `top-level`, `unavailable`) → Task 6 (`CgroupMode` enum, `ProbeCgroupsV2` decision tree).
- Probe algorithm (steps 1–5 in spec) → Task 6 (`ProbeCgroupsV2`, `tryTopLevel`, `reapOrphansFS`, `classifyEnableError`, `readControllerSet`).
- "No internal processes" handling via EBUSY fallback → Task 6 (`TestProbe_EnableEBUSY_FallbackToTopLevel`).
- Behaviour per mode at exec time, fail-closed per-command → Task 7 (`CgroupManager.Apply`, `TestManagerApply_Unavailable*`).
- `io` controller as best-effort → Task 6 (`IOAvailable` field, `TestProbe_IOControllerOptional`).
- `enableControllers()` fix — surface errors → Task 5 (`enableControllersFS`, `TestEnableControllers_ReturnsError`).
- Structured error types → Task 4 (`EnableControllersError`, `CgroupUnavailableError`, `CgroupV2Limits.Summary`).
- Error message hygiene (`write memory.max (mode=%s, dir=%s)`) → Task 7 (`CgroupManager.Apply` error wrapping).
- Boundaries — new files at `internal/limits/` and manager field on `api.App` → Task 2 (interface), Task 7 (manager), Task 10 (wiring).
- Audit events `cgroup_mode`, `cgroup_orphans_reaped`, `cgroup_unavailable_refusal` → Task 1 (constants), Task 9 (refusal emission), Task 10 (startup emission).
- `agentsh detect` structured block → Task 12 (`cgroupProbeCache`, `backwardCompatCaps` extension).
- Lifecycle of `agentsh.slice/` (eager creation, orphan reaping, stable dir) → Task 6 (`tryTopLevel`, `reapOrphansFS`) + Task 10 (startup reap event emission).
- Policy schema unchanged → no task needed; reconfirmed by not touching `internal/policy/model.go`.
- Behaviour-change release-notes guidance → Task 13 step 7 (follow-up issue body) + spec already committed.
- Unit tests (all 14 tests listed in spec) → Tasks 5 / 6 / 7.
- Integration tests (three listed in spec) → Task 8.
- Lima / WSL2 explicit follow-up → Task 13 step 7.

**Placeholder scan:** no "TBD", "fill in later", or "similar to above" phrasing. Each step contains concrete code or exact commands.

**Type consistency:** `CgroupMode`, `CgroupProbeResult`, `CgroupManager`, `CgroupV2Limits`, `EnableControllersError`, `CgroupUnavailableError` — method names and field names are used consistently across Tasks 4, 6, 7, 9, 10, 12. `cgroupFS` / `cgroupFile` / `osCgroupFS` / `fakeCgroupFS` follow a consistent naming scheme. `Apply(name, pid, lim)` signature is stable from Task 7 through Task 11.

**Scope check:** single plan, single PR-sized change. Lima and WSL2 are explicitly out of scope.
