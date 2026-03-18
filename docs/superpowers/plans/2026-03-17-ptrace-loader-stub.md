# Ptrace Loader Stub Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pre-install seccomp BPF filter via a loader binary to eliminate ~4-8ms of deferred injection overhead per exec in ptrace mode.

**Architecture:** New `agentsh-loader` binary reads a serialized BPF filter from an inherited pipe fd, installs it via prctl+seccomp, then execs the real command. Server wraps commands with the loader when ptrace is active. Tracer skips deferred injection when the filter is pre-installed.

**Tech Stack:** Go, Linux seccomp, `golang.org/x/sys/unix`, `os/exec`

**Spec:** `docs/superpowers/specs/2026-03-17-ptrace-loader-stub-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `cmd/agentsh-loader/main.go` | Create | Loader binary — read filter, install seccomp, exec real command |
| `internal/ptrace/filter_serialize.go` | Create | `buildSessionFilter`, `SerializeFilter`, `DeserializeFilter` |
| `internal/ptrace/filter_serialize_test.go` | Create | Tests for serialization round-trip and buildSessionFilter |
| `internal/ptrace/inject_seccomp.go` | Modify | Use shared `buildSessionFilter` instead of inline filter construction |
| `internal/ptrace/tracer.go` | Modify | Add `prefilterInstalled` to `attachOpts`, `WithPrefilterInstalled()` |
| `internal/ptrace/attach.go` | Modify | Skip deferred injection when prefilter installed, resume with PtraceCont |
| `internal/api/exec.go` | Modify | Wrap command with loader in ptrace mode |
| `internal/api/exec_loader_linux.go` | Create | `wrapWithLoader` — Linux-only loader wrapping logic |
| `internal/api/exec_loader_other.go` | Create | No-op `wrapWithLoader` stub for non-Linux platforms |
| `internal/api/exec_ptrace_linux.go` | Modify | Pass `WithPrefilterInstalled()` to AttachPID |
| `internal/api/exec_ptrace_other.go` | Modify | Add `prefilterInstalled` parameter to `ptraceExecAttach` stub |
| `Dockerfile.bench` | Modify | Build and copy agentsh-loader |

---

### Task 1: Filter serialization and buildSessionFilter

**Files:**
- Create: `internal/ptrace/filter_serialize.go`
- Create: `internal/ptrace/filter_serialize_test.go`
- Modify: `internal/ptrace/inject_seccomp.go:31-60`

- [ ] **Step 1: Write tests for filter serialization**

Create `internal/ptrace/filter_serialize_test.go`:

```go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	cfg := &TracerConfig{
		TraceExecve:  true,
		TraceFile:    true,
		TraceNetwork: true,
		TraceSignal:  true,
	}
	filters, err := buildSessionFilter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) == 0 {
		t.Fatal("empty filter")
	}

	data := SerializeFilter(filters)
	got, err := DeserializeFilter(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(filters) {
		t.Fatalf("round-trip count: got %d, want %d", len(got), len(filters))
	}
	for i, f := range filters {
		if got[i] != f {
			t.Errorf("instruction %d: got %+v, want %+v", i, got[i], f)
		}
	}
}

func TestSerializeDeserializeEmpty(t *testing.T) {
	data := SerializeFilter(nil)
	got, err := DeserializeFilter(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

func TestDeserializeInvalidData(t *testing.T) {
	// Too short
	_, err := DeserializeFilter([]byte{0x01})
	if err == nil {
		t.Error("expected error for short data")
	}

	// Count doesn't match data length
	_, err = DeserializeFilter([]byte{0x05, 0x00}) // says 5 filters, no data
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestBuildSessionFilterWithDenies(t *testing.T) {
	cfg := &TracerConfig{
		TraceNetwork: true,
		NetworkHandler: nil, // nil → static deny for connect+bind
	}
	filters, err := buildSessionFilter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Should contain ERRNO return instructions for the static denies
	hasErrno := false
	for _, f := range filters {
		if f.Code == bpfRET|bpfK && f.K != seccompRetAllow && f.K != seccompRetTrace {
			hasErrno = true
			break
		}
	}
	if !hasErrno {
		t.Error("expected ERRNO return in filter for nil network handler")
	}
}

func TestBuildSessionFilterNoDenies(t *testing.T) {
	cfg := &TracerConfig{
		TraceExecve: true,
		TraceFile:   true,
	}
	filters, err := buildSessionFilter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// All returns should be ALLOW or TRACE (no ERRNO)
	for _, f := range filters {
		if f.Code == bpfRET|bpfK && f.K != seccompRetAllow && f.K != seccompRetTrace {
			t.Errorf("unexpected ERRNO return 0x%x in filter without denies", f.K)
		}
	}
}
```

- [ ] **Step 2: Run tests — should fail**

Run: `go test ./internal/ptrace/ -run "TestSerialize|TestBuildSessionFilter" -v`
Expected: FAIL — functions don't exist

- [ ] **Step 3: Implement filter_serialize.go**

Create `internal/ptrace/filter_serialize.go`:

```go
//go:build linux

package ptrace

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// buildSessionFilter constructs the narrow seccomp BPF filter for a session,
// including any static deny rules from handlers. This is the shared logic
// used by both the deferred injection path (injectSeccompFilter) and the
// loader stub serialization path.
//
// The staticDenyChecker parameter allows passing a custom checker for testing.
// Pass nil to use the default collectStaticDenies logic via the Tracer.
func buildSessionFilter(cfg *TracerConfig, denies []StaticDeny) ([]unix.SockFilter, error) {
	narrowNums := narrowTracedSyscallNumbers(cfg)

	if len(denies) > 0 {
		denySet := make(map[int]uint32)
		for _, d := range denies {
			denySet[d.Nr] = seccompRetErrno(d.Errno)
		}

		var actions []bpfSyscallAction
		for _, nr := range narrowNums {
			if errnoAction, ok := denySet[nr]; ok {
				actions = append(actions, bpfSyscallAction{Nr: nr, Action: errnoAction})
				delete(denySet, nr)
			} else {
				actions = append(actions, bpfSyscallAction{Nr: nr, Action: seccompRetTrace})
			}
		}
		for nr, action := range denySet {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: action})
		}

		return buildBPFForActions(actions)
	}

	return buildNarrowPrefilterBPF(cfg)
}

// SerializeFilter encodes a BPF filter for transmission to the loader binary.
// Wire format: [uint16 LE count] [count * 8 bytes sock_filter instructions]
func SerializeFilter(filters []unix.SockFilter) []byte {
	n := len(filters)
	buf := make([]byte, 2+n*8)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(n))
	for i, f := range filters {
		off := 2 + i*8
		binary.LittleEndian.PutUint16(buf[off:], f.Code)
		buf[off+2] = f.Jt
		buf[off+3] = f.Jf
		binary.LittleEndian.PutUint32(buf[off+4:], f.K)
	}
	return buf
}

// DeserializeFilter decodes a BPF filter from the loader wire format.
func DeserializeFilter(data []byte) ([]unix.SockFilter, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("filter data too short: %d bytes", len(data))
	}
	n := int(binary.LittleEndian.Uint16(data[0:2]))
	if n == 0 {
		return nil, nil
	}
	expected := 2 + n*8
	if len(data) < expected {
		return nil, fmt.Errorf("filter data truncated: have %d bytes, need %d", len(data), expected)
	}
	filters := make([]unix.SockFilter, n)
	for i := range filters {
		off := 2 + i*8
		filters[i] = unix.SockFilter{
			Code: binary.LittleEndian.Uint16(data[off:]),
			Jt:   data[off+2],
			Jf:   data[off+3],
			K:    binary.LittleEndian.Uint32(data[off+4:]),
		}
	}
	return filters, nil
}
```

- [ ] **Step 4: Update injectSeccompFilter to use buildSessionFilter**

In `internal/ptrace/inject_seccomp.go`, replace lines 31-60 (the filter construction part of `injectSeccompFilter`) with:

```go
func (t *Tracer) injectSeccompFilter(tid int) error {
	denies := t.collectStaticDenies()
	filters, bpfErr := buildSessionFilter(&t.cfg, denies)
	if bpfErr != nil {
		return bpfErr
	}
	if len(filters) == 0 {
		return fmt.Errorf("empty BPF program")
	}
	// ... rest of function unchanged (getRegs, scratch page, serialize, inject prctl+seccomp)
```

Also move the static deny logging to after successful installation (at the end of the function, before `return nil`):

```go
	for _, d := range denies {
		slog.Info("seccomp static deny active", "tid", tid, "nr", d.Nr, "errno", d.Errno)
	}
```

Note: `denies` must remain in scope for this — it is declared at function top.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/ptrace/ -run "TestSerialize|TestBuildSessionFilter" -v`
Expected: PASS

- [ ] **Step 6: Run full suite**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/filter_serialize.go internal/ptrace/filter_serialize_test.go internal/ptrace/inject_seccomp.go
git commit -m "refactor(ptrace): extract buildSessionFilter and filter serialization

Shared buildSessionFilter replaces inline filter construction in
injectSeccompFilter. SerializeFilter/DeserializeFilter encode BPF
programs for pipe transport to the loader binary."
```

---

### Task 2: agentsh-loader binary

**Files:**
- Create: `cmd/agentsh-loader/main.go`

- [ ] **Step 1: Create the loader binary**

Create `cmd/agentsh-loader/main.go`:

```go
//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Parse --filter-fd=N and -- separator
	filterFD := -1
	sepIdx := -1
	for i, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--filter-fd=") {
			fd, err := strconv.Atoi(arg[len("--filter-fd="):])
			if err != nil || fd < 0 {
				fmt.Fprintf(os.Stderr, "agentsh-loader: invalid --filter-fd: %s\n", arg)
				return 126
			}
			filterFD = fd
		} else if arg == "--" {
			sepIdx = i + 1 // +1 because we started from Args[1:]
			break
		}
	}
	if filterFD < 0 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: missing --filter-fd=N\n")
		return 126
	}
	if sepIdx < 0 || sepIdx+1 >= len(os.Args) {
		fmt.Fprintf(os.Stderr, "agentsh-loader: missing -- separator or command\n")
		return 126
	}

	cmdArgs := os.Args[sepIdx+1:]
	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: no command after --\n")
		return 126
	}

	// Read BPF filter from fd
	f := os.NewFile(uintptr(filterFD), "filter-pipe")
	if f == nil {
		fmt.Fprintf(os.Stderr, "agentsh-loader: cannot open fd %d\n", filterFD)
		return 126
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-loader: read filter: %v\n", err)
		return 126
	}

	// Deserialize filter
	if len(data) < 2 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: filter data too short\n")
		return 126
	}
	n := int(binary.LittleEndian.Uint16(data[0:2]))
	if n == 0 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: empty filter\n")
		return 126
	}
	expected := 2 + n*8
	if len(data) < expected {
		fmt.Fprintf(os.Stderr, "agentsh-loader: filter truncated: %d < %d\n", len(data), expected)
		return 126
	}

	// Build sock_filter array
	filterBuf := data[2:expected]

	// Install PR_SET_NO_NEW_PRIVS
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, 38, 1, 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: prctl(PR_SET_NO_NEW_PRIVS): %v\n", errno)
		return 126
	}

	// Build sock_fprog and install seccomp filter
	type sockFprog struct {
		Len    uint16
		_      [6]byte // padding
		Filter uintptr
	}
	prog := sockFprog{
		Len:    uint16(n),
		Filter: uintptr(unsafe.Pointer(&filterBuf[0])),
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, 1, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		fmt.Fprintf(os.Stderr, "agentsh-loader: seccomp(SET_MODE_FILTER): %v\n", errno)
		return 126
	}

	// Resolve command path
	cmdPath := cmdArgs[0]
	if !strings.Contains(cmdPath, "/") {
		resolved, err := exec.LookPath(cmdPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentsh-loader: %s: %v\n", cmdPath, err)
			return 127
		}
		cmdPath = resolved
	}

	// Exec the real command — replaces this process
	if err := syscall.Exec(cmdPath, cmdArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-loader: exec %s: %v\n", cmdPath, err)
		return 126
	}
	return 0 // unreachable
}
```

- [ ] **Step 2: Write loader argument parsing tests**

Create `cmd/agentsh-loader/main_test.go`:

```go
//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestLoaderBuilds(t *testing.T) {
	// Verify the loader binary compiles
	cmd := exec.Command("go", "build", "-o", "/dev/null", ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
}

func TestLoaderMissingFilterFD(t *testing.T) {
	if os.Getenv("TEST_LOADER_EXEC") == "1" {
		os.Args = []string{"agentsh-loader", "--", "/bin/true"}
		os.Exit(run())
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLoaderMissingFilterFD")
	cmd.Env = append(os.Environ(), "TEST_LOADER_EXEC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 126 {
			t.Errorf("exit code = %d, want 126", exitErr.ExitCode())
		}
	}
	_ = out
}

func TestLoaderMissingSeparator(t *testing.T) {
	if os.Getenv("TEST_LOADER_EXEC") == "1" {
		os.Args = []string{"agentsh-loader", "--filter-fd=99"}
		os.Exit(run())
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLoaderMissingSeparator")
	cmd.Env = append(os.Environ(), "TEST_LOADER_EXEC=1")
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
}
```

- [ ] **Step 3: Verify it compiles and tests pass**

Run: `go build ./cmd/agentsh-loader/ && go test ./cmd/agentsh-loader/ -v && GOOS=windows go build ./...`
Expected: PASS (loader is linux-only, windows build skips it)

- [ ] **Step 3: Commit**

```bash
git add cmd/agentsh-loader/
git commit -m "feat(ptrace): add agentsh-loader binary for seccomp prefilter pre-installation

Reads serialized BPF filter from inherited pipe fd, installs via
prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SET_MODE_FILTER), then execs
the real command. Eliminates deferred BPF injection overhead per exec."
```

---

### Task 3: WithPrefilterInstalled attach option

**Files:**
- Modify: `internal/ptrace/tracer.go:212-234` (attachOpts, AttachOption)
- Modify: `internal/ptrace/attach.go:139-158` (prefilter and resume logic)

- [ ] **Step 1: Write test for WithPrefilterInstalled**

Add to `internal/ptrace/tracer_test.go`:

```go
func TestWithPrefilterInstalled(t *testing.T) {
	opts := attachOpts{}
	WithPrefilterInstalled()(&opts)
	if !opts.prefilterInstalled {
		t.Error("expected prefilterInstalled to be true")
	}
}
```

- [ ] **Step 2: Run test — should fail**

Run: `go test ./internal/ptrace/ -run TestWithPrefilterInstalled -v`
Expected: FAIL — `prefilterInstalled` field and `WithPrefilterInstalled` don't exist

- [ ] **Step 3: Add prefilterInstalled to attachOpts**

In `internal/ptrace/tracer.go`, add field to `attachOpts` struct (line 212):

```go
type attachOpts struct {
	sessionID          string
	commandID          string
	keepStopped        bool
	prefilterInstalled bool
}
```

Add the option constructor after `WithKeepStopped` (line 234):

```go
// WithPrefilterInstalled indicates the tracee already has the seccomp
// prefilter installed (e.g., via agentsh-loader). Skips deferred injection
// and uses PtraceCont for the initial resume.
func WithPrefilterInstalled() AttachOption {
	return func(o *attachOpts) { o.prefilterInstalled = true }
}
```

- [ ] **Step 4: Update attach.go to use prefilterInstalled**

In `internal/ptrace/attach.go`, replace lines 139-158:

```go
	// Mark for deferred seccomp prefilter injection, unless the loader
	// already installed the filter.
	if opts.prefilterInstalled {
		t.mu.Lock()
		if s := t.tracees[tid]; s != nil {
			s.HasPrefilter = true
		}
		t.mu.Unlock()
	} else if t.cfg.SeccompPrefilter && opts.sessionID != "" {
		t.mu.Lock()
		if s := t.tracees[tid]; s != nil {
			s.PendingPrefilter = true
		}
		t.mu.Unlock()
	}

	// Resume the tracee (unless keepStopped for cgroup hook).
	// Use PtraceCont when prefilter is already installed (first stop
	// will be PTRACE_EVENT_SECCOMP). Otherwise use PtraceSyscall for
	// deferred injection on first syscall stop.
	var resumeErr error
	if opts.keepStopped {
		// Already registered in parkedTracees above.
	} else if opts.prefilterInstalled {
		resumeErr = unix.PtraceCont(tid, 0)
	} else {
		resumeErr = unix.PtraceSyscall(tid, 0)
	}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/ptrace/ -run TestWithPrefilterInstalled -v`
Expected: PASS

- [ ] **Step 6: Run full suite**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go internal/ptrace/attach.go
git commit -m "feat(ptrace): add WithPrefilterInstalled attach option

When the loader pre-installs the seccomp filter, skip deferred
injection and resume with PtraceCont. Sets HasPrefilter=true
immediately so allowSyscall uses the fast path from the first stop."
```

---

### Task 4: Server-side loader wrapping

**Files:**
- Modify: `internal/api/exec.go:130-160` (command wrapping)
- Modify: `internal/api/exec_ptrace_linux.go` (pass WithPrefilterInstalled)

- [ ] **Step 1: Add loader wrapping helper**

Create `internal/api/exec_loader_linux.go`:

```go
//go:build linux

package api

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"

	"github.com/agentsh/agentsh/internal/ptrace"
)

// loaderPath is resolved once at init time. Empty if not found.
var loaderPath string

func init() {
	path, err := exec.LookPath("agentsh-loader")
	if err != nil {
		slog.Debug("agentsh-loader not found, will use deferred BPF injection", "error", err)
		return
	}
	loaderPath = path
	slog.Info("agentsh-loader found", "path", loaderPath)
}

// wrapWithLoader wraps a command with agentsh-loader if available.
// Returns true if the loader was used. The caller must pass this to
// ptraceExecAttach so it sets WithPrefilterInstalled.
//
// The wrapping is applied to the INNER command args, not the outer
// command path. This means for netns mode (ip netns exec <ns> cmd args),
// the loader wraps cmd, not ip.
func wrapWithLoader(cmd *exec.Cmd, tracer *ptrace.Tracer) bool {
	if loaderPath == "" || tracer == nil {
		return false
	}

	filters, err := tracer.BuildSessionFilter()
	if err != nil {
		slog.Warn("loader: failed to build session filter, falling back", "error", err)
		return false
	}
	if len(filters) == 0 {
		return false
	}

	data := ptrace.SerializeFilter(filters)

	pr, pw, err := os.Pipe()
	if err != nil {
		slog.Warn("loader: pipe failed, falling back", "error", err)
		return false
	}

	if _, err := pw.Write(data); err != nil {
		pr.Close()
		pw.Close()
		slog.Warn("loader: pipe write failed, falling back", "error", err)
		return false
	}
	pw.Close()

	// Calculate fd number: ExtraFiles fds start at 3
	filterFD := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, pr)

	// Rewrite cmd.Args to insert loader BEFORE the real command.
	// For netns mode, cmd.Path is "ip" and cmd.Args is:
	//   ["ip", "netns", "exec", "<ns>", "realcmd", "arg1", ...]
	// We need to insert the loader before "realcmd":
	//   ["ip", "netns", "exec", "<ns>", "agentsh-loader", "--filter-fd=N", "--", "realcmd", "arg1", ...]
	//
	// For normal mode, cmd.Path is "realcmd" and cmd.Args is:
	//   ["realcmd", "arg1", ...]
	// We rewrite to:
	//   ["agentsh-loader", "--filter-fd=N", "--", "realcmd", "arg1", ...]

	loaderArgs := []string{loaderPath, "--filter-fd=" + strconv.Itoa(filterFD), "--"}

	if len(cmd.Args) >= 4 && cmd.Args[0] == "ip" && cmd.Args[1] == "netns" && cmd.Args[2] == "exec" {
		// Netns mode: ip netns exec <ns> <cmd> <args...>
		// Insert loader after the netns prefix (first 4 args)
		nsPrefix := cmd.Args[:4] // ["ip", "netns", "exec", "<ns>"]
		innerCmd := cmd.Args[4:] // ["cmd", "args..."]
		cmd.Args = append(nsPrefix, append(loaderArgs, innerCmd...)...)
		// cmd.Path stays as "ip"
	} else {
		// Normal mode: rewrite entirely
		cmd.Path = loaderPath
		cmd.Args = append(loaderArgs, cmd.Args...)
	}

	return true
}
```

Create `internal/api/exec_loader_other.go`:

```go
//go:build !linux

package api

import "os/exec"

// wrapWithLoader is a no-op on non-Linux platforms.
func wrapWithLoader(_ *exec.Cmd, _ any) bool {
	return false
}
```

- [ ] **Step 2: Integrate wrapWithLoader into exec.go**

In `internal/api/exec.go`, after `cmd.ExtraFiles = append(cmd.ExtraFiles, extra.extraFiles...)` (line 209), add the loader wrapping:

```go
	// Wrap with loader for seccomp prefilter pre-installation (ptrace mode only)
	var usedLoader bool
	if tracer != nil {
		usedLoader = wrapWithLoader(cmd, tracer)
	}
```

Note: `wrapWithLoader` accepts `any` on non-Linux (the stub), and `*ptrace.Tracer` on Linux. The Linux version does the type assertion internally.

The `usedLoader` bool needs to be passed to `ptraceExecAttach` so it adds `WithPrefilterInstalled()`.

- [ ] **Step 3: Add BuildSessionFilter method to Tracer**

In `internal/ptrace/filter_serialize.go`, add a method on Tracer that calls `buildSessionFilter` with the tracer's config and denies:

```go
// BuildSessionFilter builds the narrow BPF filter for this tracer's session,
// including static deny rules. Used by the loader wrapping path.
func (t *Tracer) BuildSessionFilter() ([]unix.SockFilter, error) {
	denies := t.collectStaticDenies()
	return buildSessionFilter(&t.cfg, denies)
}
```

- [ ] **Step 4: Update ptraceExecAttach to accept usedLoader**

In `internal/api/exec_ptrace_linux.go`, update `ptraceExecAttach` to accept and pass `usedLoader`:

```go
func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool, prefilterInstalled bool) (waitExit func() ptraceExecResult, resume func() error, err error) {
```

Add `WithPrefilterInstalled()` to opts when `prefilterInstalled` is true:

```go
	if prefilterInstalled {
		opts = append(opts, ptrace.WithPrefilterInstalled())
	}
```

Update the call site in `exec.go` (around line 295) to pass `usedLoader`:

```go
	waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil, usedLoader)
```

- [ ] **Step 5: Update exec_ptrace_other.go for new parameter**

Find `internal/api/exec_ptrace_other.go` (the non-Linux stub for `ptraceExecAttach`). Add the `prefilterInstalled bool` parameter to match the Linux signature:

```go
func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool, prefilterInstalled bool) (waitExit func() ptraceExecResult, resume func() error, err error) {
```

The body is unchanged (it returns an error since ptrace is Linux-only).

- [ ] **Step 6: Build and fix compile errors**

Run: `go build ./...`
Fix any compilation issues — there may be callers of `ptraceExecAttach` on other platforms that need the new parameter (check for `exec_ptrace_` files for other OS).

- [ ] **Step 6: Run full suite**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/api/exec.go internal/api/exec_loader_linux.go internal/api/exec_ptrace_linux.go internal/ptrace/filter_serialize.go
git commit -m "feat(ptrace): wrap exec with agentsh-loader for pre-installed seccomp

Server wraps commands with agentsh-loader when ptrace mode is active.
Loader pre-installs BPF filter via pipe, tracer skips deferred injection.
Fallback to deferred injection if loader binary not found."
```

---

### Task 5: Dockerfile.bench build integration

**Files:**
- Modify: `Dockerfile.bench`

- [ ] **Step 1: Add loader to Docker build**

In `Dockerfile.bench`, line 23-26, add the loader to the build:

```dockerfile
RUN go build -o /out/agentsh          ./cmd/agentsh && \
    go build -o /out/agentsh-shell-shim ./cmd/agentsh-shell-shim && \
    go build -o /out/agentsh-unixwrap  ./cmd/agentsh-unixwrap && \
    go build -o /out/agentsh-stub      ./cmd/agentsh-stub && \
    go build -o /out/agentsh-loader    ./cmd/agentsh-loader
```

After line 41 (the last COPY --from=builder), add:

```dockerfile
COPY --from=builder /out/agentsh-loader    /usr/bin/agentsh-loader
```

- [ ] **Step 2: Verify Docker builds**

Run: `docker build -f Dockerfile.bench -t agentsh-bench:latest . 2>&1 | tail -10`
Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add Dockerfile.bench
git commit -m "build: add agentsh-loader to benchmark Docker image"
```

---

### Task 6: Experimental PTRACE_SYSEMU for denies

**Files:**
- Modify: `internal/ptrace/tracer.go` (hasSysemu field, probe, deny path)

- [ ] **Step 1: Write test for SYSEMU probe**

Add to `internal/ptrace/tracer_test.go`:

```go
func TestProbePtraceSysemu(t *testing.T) {
	// Just verify the probe doesn't crash. Whether it returns true or false
	// depends on the kernel. On most Linux 5.3+ kernels it should return
	// a definitive result.
	result := probePtraceSysemu()
	t.Logf("PTRACE_SYSEMU probe result: %v", result)
}
```

- [ ] **Step 2: Implement SYSEMU probe and deny path**

In `internal/ptrace/tracer.go`:

Add field to Tracer struct (near `hasSyscallInfo`):
```go
hasSysemu      bool // set at startup if PTRACE_SYSEMU is available (basic probe only)
```

Add SYSEMU constant and probe function:
```go
// ptraceSysemu is the ptrace request for PTRACE_SYSEMU.
// Defined locally since golang.org/x/sys/unix may not export it in all versions.
const ptraceSysemu = 0x1f

// probePtraceSysemu returns true if the kernel recognizes PTRACE_SYSEMU.
// This is a basic availability check (ESRCH for pid=0 means the request
// is known). It does NOT verify that SYSEMU works correctly from
// SECCOMP_RET_TRACE stops — that interaction is undocumented and should
// be validated via integration tests before relying on this in production.
func probePtraceSysemu() bool {
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		ptraceSysemu,
		0, 0, 0, 0, 0,
	)
	return errno == unix.ESRCH
}
```

In `Run()`, after the `hasSyscallInfo` probe:
```go
t.hasSysemu = probePtraceSysemu()
if t.hasSysemu {
    slog.Info("ptrace: PTRACE_SYSEMU supported")
}
```

In `denySyscall` (`tracer.go:523`), add SYSEMU fast path before the existing logic:
```go
func (t *Tracer) denySyscall(tid int, errno int) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
			return nil
		}
		return err
	}

	// SYSEMU fast path: skip syscall execution, set return directly (1 stop).
	// Only used when the prefilter is installed (seccomp mode, not TRACESYSGOOD).
	// Note: the SYSEMU+seccomp interaction is not well-documented in the kernel.
	// If SYSEMU fails at runtime, we fall through to the standard 2-stop path.
	if t.hasSysemu {
		t.mu.Lock()
		hasPrefilter := false
		if s := t.tracees[tid]; s != nil {
			hasPrefilter = s.HasPrefilter
		}
		t.mu.Unlock()

		if hasPrefilter {
			regs.SetReturnValue(int64(-errno))
			if err := t.setRegs(tid, regs); err != nil {
				return err
			}
			if _, _, e := unix.RawSyscall6(unix.SYS_PTRACE, ptraceSysemu, uintptr(tid), 0, 0, 0, 0); e != 0 {
				slog.Debug("PTRACE_SYSEMU failed, using standard deny", "tid", tid, "errno", e)
			} else {
				return nil
			}
		}
	}

	// Standard path: nullify syscall + exit fixup (2 stops)
	regs.SetSyscallNr(-1)
	// ... rest of existing denySyscall unchanged
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/ptrace/ -run TestProbePtraceSysemu -v`
Expected: PASS

- [ ] **Step 4: Run full suite**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "feat(ptrace): experimental PTRACE_SYSEMU for single-stop denies

Probe SYSEMU support at startup. When available and prefilter is
installed, deny syscalls with a single stop (set RAX=-errno, resume
with SYSEMU) instead of the standard 2-stop path (nullify + exit fixup).
Falls back to standard path if SYSEMU call fails."
```

---

### Task 7: Final verification and benchmark

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS

- [ ] **Step 2: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 3: Run benchmark**

Run: `make bench`
Expected: Ptrace overhead should be measurably lower than +394% baseline. Compare per-phase results.

- [ ] **Step 4: Update docs if benchmark shows improvement**

Update `docs/security-modes.md` benchmark table with new results.
