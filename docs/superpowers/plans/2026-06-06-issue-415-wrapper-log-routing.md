# Issue #415: Wrapper Log-FD Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route `agentsh-unixwrap` diagnostics (the per-exec `seccomp: filter loaded` slog line plus stdlib `log` noise) off the wrapped command's stderr via an inherited log fd, in all three spawn paths.

**Architecture:** The wrapper reads `AGENTSH_WRAPPER_LOG_FD=<n>` at startup and points both its default slog handler and the stdlib `log` package at that fd (CLOEXEC so the wrapped command never inherits it; env var stripped before exec). The server exec path backs the fd with a pipe drained into the server log; the shim relay and `agentsh wrap` CLI paths back it with an `O_APPEND` state-dir file. Unset env var → stderr (today's behavior). The handshake protocol and `internal/netmonitor/unix` are untouched, so `TestInstallFilter_*` regression tests pass unchanged.

**Tech Stack:** Go, `log/slog`, `os.Pipe`, `golang.org/x/sys/unix` (fcntl/fstat).

**Spec:** `docs/superpowers/specs/2026-06-06-issue-415-wrapper-log-routing-design.md`

**Project workflow notes:**
- Work on a branch: `git checkout -b fix-415-wrapper-log-routing` before Task 1.
- Per project convention, run `roborev` between tasks and fix all issues above "low" before proceeding.
- Before final commit: `GOOS=windows go build ./...` must pass (CLAUDE.md requirement).
- Some tests fail only in this local environment (long TMPDIR, workspace-policy mount, symlink sandbox) — they pass in CI and are not regressions; don't chase them.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/wrapperlog/wrapperlog.go` | Create | Shared env-key constant + state-dir log file opener |
| `internal/wrapperlog/wrapperlog_test.go` | Create | Tests for the above |
| `cmd/agentsh-unixwrap/logging.go` | Create | `setupLogging()` (fd routing, CLOEXEC, env strip) + `fatalf`/`writeFatal` |
| `cmd/agentsh-unixwrap/logging_test.go` | Create | Tests for the above |
| `cmd/agentsh-unixwrap/main.go` | Modify | Call `setupLogging()`; replace 13 `log.Fatalf` call sites with `fatalf` |
| `internal/api/exec.go` | Modify | Two new `extraProcConfig` fields; close-write-end + start-drain in `startWrapperHandlers` |
| `internal/api/wrapper_log.go` | Create | `startWrapperLogDrain` goroutine |
| `internal/api/wrapper_log_test.go` | Create | Drain test |
| `internal/api/core.go` | Modify | Create the pipe in `buildWrapperSetup`, set env, append ExtraFile |
| `internal/shim/kernelinstall/install_linux.go` | Modify | Open state log file in `runRelay`, pass as fd 4; strip key in `filterShimInternalEnv` and `assembleWrapperEnv` |
| `internal/shim/kernelinstall/install_linux_test.go` | Modify | Env-strip tests |
| `internal/cli/wrap_linux.go` | Modify | Open state log file in `platformSetupWrap`, append to extraFiles + env |
| `internal/integration/wrapper_log_routing_test.go` | Create | End-to-end server-path test |

---

### Task 1: `internal/wrapperlog` package

**Files:**
- Create: `internal/wrapperlog/wrapperlog.go`
- Test: `internal/wrapperlog/wrapperlog_test.go`

- [ ] **Step 1: Write the failing test**

```go
package wrapperlog

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenStateLogFile_CreatesDirAndAppends(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_STATE_HOME redirection is linux-only")
	}
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	f, err := OpenStateLogFile()
	if err != nil {
		t.Fatalf("OpenStateLogFile: %v", err)
	}
	if _, err := f.WriteString("first\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// A second open must append, not truncate.
	f2, err := OpenStateLogFile()
	if err != nil {
		t.Fatalf("OpenStateLogFile (second): %v", err)
	}
	if _, err := f2.WriteString("second\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f2.Close()

	got, err := os.ReadFile(filepath.Join(stateHome, "agentsh", "logs", "unixwrap.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(got) != "first\nsecond\n" {
		t.Fatalf("log content = %q, want %q", got, "first\nsecond\n")
	}
}

func TestEnvKey_Value(t *testing.T) {
	// The wrapper and all three parents must agree on this string;
	// pin it so a rename can't silently desynchronize them.
	if EnvKey != "AGENTSH_WRAPPER_LOG_FD" {
		t.Fatalf("EnvKey = %q", EnvKey)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wrapperlog/ -v`
Expected: FAIL — package does not exist / `OpenStateLogFile` undefined.

- [ ] **Step 3: Write the implementation**

```go
// Package wrapperlog defines the env contract and fallback file
// destination for routing agentsh-unixwrap diagnostics off the wrapped
// command's stderr (issue #415). The wrapper execs the real command in
// place, so anything it logs to stderr lands on the user-visible stream
// of the wrapped command; parents pass an inherited fd via EnvKey
// instead.
package wrapperlog

import (
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
)

// EnvKey names the env var carrying the inherited fd number that
// agentsh-unixwrap routes its diagnostics (slog + stdlib log) to.
// Unset means stderr (legacy behavior).
const EnvKey = "AGENTSH_WRAPPER_LOG_FD"

// OpenStateLogFile opens <user-state-dir>/logs/unixwrap.log for append,
// creating the directory as needed. Used by parents that have no live
// log sink of their own (shell-shim relay, agentsh wrap CLI); O_APPEND
// keeps concurrent wrapper invocations line-atomic.
func OpenStateLogFile() (*os.File, error) {
	dir := filepath.Join(config.GetUserStateDir(), "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "unixwrap.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/wrapperlog/ -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/wrapperlog/
git commit -m "feat(#415): add wrapperlog package — env contract + state-dir log file"
```

---

### Task 2: Wrapper-side `setupLogging` + `fatalf`

**Files:**
- Create: `cmd/agentsh-unixwrap/logging.go`
- Test: `cmd/agentsh-unixwrap/logging_test.go`

Both files need the `//go:build linux && cgo` tag — every file in this package has it; an untagged file would break non-Linux builds of `./...`.

- [ ] **Step 1: Write the failing tests**

```go
//go:build linux && cgo

package main

import (
	"io"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/wrapperlog"
	"golang.org/x/sys/unix"
)

// resetLogging restores the process-global logging state mutated by
// setupLogging so tests don't leak into each other.
func resetLogging(origSlog *slog.Logger) {
	log.SetOutput(os.Stderr)
	slog.SetDefault(origSlog)
	logDest = nil
}

func TestSetupLogging_RoutesBothSinksAndSetsCloexec(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	// Keep w reachable for the whole test: logDest wraps the same fd
	// number, and w's finalizer must not close it mid-test.
	defer runtime.KeepAlive(w)

	t.Setenv(wrapperlog.EnvKey, strconv.Itoa(int(w.Fd())))

	setupLogging()

	if os.Getenv(wrapperlog.EnvKey) != "" {
		t.Error("env var not stripped after setupLogging")
	}
	if logDest == nil {
		t.Fatal("logDest not set for a valid fd")
	}
	flags, err := unix.FcntlInt(w.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("fcntl(F_GETFD): %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("FD_CLOEXEC not set on log fd")
	}

	log.Printf("stdlib-marker")
	slog.Info("slog-marker")

	logDest.Close() // closes the shared fd; reader gets EOF
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "stdlib-marker") {
		t.Errorf("stdlib log not routed, got: %s", s)
	}
	if !strings.Contains(s, "slog-marker") {
		t.Errorf("slog not routed, got: %s", s)
	}
}

func TestSetupLogging_InvalidFDFallsBackToStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	// Learn a definitely-closed fd number.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	closedFD := int(w.Fd())
	r.Close()
	w.Close()

	t.Setenv(wrapperlog.EnvKey, strconv.Itoa(closedFD))
	setupLogging()
	if logDest != nil {
		t.Fatal("expected stderr fallback for closed fd")
	}
	if os.Getenv(wrapperlog.EnvKey) != "" {
		t.Error("env var must be stripped even on fallback")
	}
}

func TestSetupLogging_NonNumericFallsBackToStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	t.Setenv(wrapperlog.EnvKey, "not-a-number")
	setupLogging()
	if logDest != nil {
		t.Fatal("expected stderr fallback for non-numeric value")
	}
}

func TestSetupLogging_UnsetKeepsStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	t.Setenv(wrapperlog.EnvKey, "")
	setupLogging()
	if logDest != nil {
		t.Fatal("expected no routing when env var unset")
	}
}

func TestWriteFatal_DualWritesWhenRouted(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	destR, destW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	logDest = destW

	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = errW
	defer func() { os.Stderr = origStderr }()

	writeFatal("boom: 42")

	destW.Close()
	errW.Close()
	destOut, _ := io.ReadAll(destR)
	errOut, _ := io.ReadAll(errR)
	if !strings.Contains(string(destOut), "boom: 42") {
		t.Errorf("routed destination missing message: %q", destOut)
	}
	if !strings.Contains(string(errOut), "boom: 42") {
		t.Errorf("stderr missing message: %q", errOut)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/agentsh-unixwrap/ -run 'TestSetupLogging|TestWriteFatal' -v`
Expected: FAIL — `setupLogging`, `logDest`, `writeFatal` undefined.

- [ ] **Step 3: Write the implementation**

`cmd/agentsh-unixwrap/logging.go`:

```go
//go:build linux && cgo

package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/agentsh/agentsh/internal/wrapperlog"
	"golang.org/x/sys/unix"
)

// logDest is the routed diagnostics destination; nil means stderr (no
// routing active). Set by setupLogging, consulted by writeFatal.
var logDest *os.File

// setupLogging routes the wrapper's diagnostics (default slog handler +
// stdlib log) to the inherited fd named by wrapperlog.EnvKey, so the
// per-exec "seccomp: filter loaded" line and friends land in the
// parent's log sink instead of the wrapped command's stderr (issue
// #415). Must run first thing in main(), before anything can log.
//
// Every failure path falls back to stderr (legacy behavior) — logging
// must never abort an exec.
func setupLogging() {
	val := os.Getenv(wrapperlog.EnvKey)
	// Strip unconditionally: syscall.Exec passes os.Environ() to the
	// wrapped command, and a stale fd number inherited by a NESTED
	// wrapper invocation (wrapped command → shell → shim → wrapper)
	// could point at an unrelated fd reused by the intermediate
	// process — the nested wrapper would write log lines onto it.
	_ = os.Unsetenv(wrapperlog.EnvKey)
	if val == "" {
		return
	}
	fd, err := strconv.Atoi(val)
	if err != nil || fd < 0 {
		log.Printf("warning: invalid %s=%q; wrapper diagnostics stay on stderr", wrapperlog.EnvKey, val)
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		log.Printf("warning: %s=%d is not a usable fd (%v); wrapper diagnostics stay on stderr", wrapperlog.EnvKey, fd, err)
		return
	}
	// Close-on-exec: the wrapped command must never inherit the log
	// destination. All wrapper logging happens before syscall.Exec, and
	// pipe-backed parents rely on this close for drain-goroutine EOF.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		log.Printf("warning: set FD_CLOEXEC on %s=%d: %v; wrapper diagnostics stay on stderr", wrapperlog.EnvKey, fd, err)
		return
	}
	f := os.NewFile(uintptr(fd), "wrapper-log")
	log.SetOutput(f)
	slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
	logDest = f
}

// fatalf replaces log.Fatalf: a user whose command dies must still see
// why on stderr even when diagnostics are routed elsewhere, and the
// routed sink (server log / state file) must record it too.
func fatalf(format string, args ...any) {
	writeFatal(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// writeFatal writes msg to the routed destination (when active) and
// always to stderr. Split from fatalf so the dual-write is testable
// without os.Exit.
func writeFatal(msg string) {
	if logDest != nil {
		fmt.Fprintln(logDest, msg)
	}
	fmt.Fprintln(os.Stderr, msg)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/agentsh-unixwrap/ -run 'TestSetupLogging|TestWriteFatal' -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/logging.go cmd/agentsh-unixwrap/logging_test.go
git commit -m "feat(#415): unixwrap setupLogging — route slog+stdlib log to inherited fd"
```

---

### Task 3: Wire `setupLogging` into wrapper `main()`

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`

- [ ] **Step 1: Call `setupLogging` first thing in `main()`**

At `main.go:30-34`, change:

```go
func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}
```

to:

```go
func main() {
	log.SetFlags(0)
	// Route diagnostics off the wrapped command's stderr before anything
	// can log (issue #415).
	setupLogging()
	if len(os.Args) < 3 || os.Args[1] != "--" {
		fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}
```

- [ ] **Step 2: Replace the remaining `log.Fatalf` call sites with `fatalf`**

13 call sites total in `main.go` (line numbers pre-edit): 33 (done above), 38, 44, 93, 121, 139, 159, 166, 182, 202, 215, 218, 257. Mechanical replacement of `log.Fatalf(` → `fatalf(` — arguments unchanged at every site, including the multi-line message at 139. `log.Printf` call sites stay as-is (they follow `log.SetOutput` automatically).

Verify none remain:

Run: `grep -n "log.Fatalf" cmd/agentsh-unixwrap/main.go`
Expected: no output.

- [ ] **Step 3: Build and run the package tests**

Run: `go build ./cmd/agentsh-unixwrap/ && go test ./cmd/agentsh-unixwrap/ -v`
Expected: build OK, all tests PASS.

- [ ] **Step 4: Confirm the #369 regression tests still pass un-adapted**

Run: `go test ./internal/netmonitor/unix/ -run 'TestInstallFilter' -v`
Expected: PASS (or SKIP on hosts where seccomp can't install — both fine; the point is no FAIL). These tests re-exec the test binary, never wrapper `main()`, so routing must not affect them.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "feat(#415): unixwrap main — activate log routing, dual-write fatals"
```

---

### Task 4: Server exec path — pipe + drain into server log

**Files:**
- Create: `internal/api/wrapper_log.go`
- Test: `internal/api/wrapper_log_test.go`
- Modify: `internal/api/exec.go` (`extraProcConfig` ~line 28, `startWrapperHandlers` ~line 771)
- Modify: `internal/api/core.go` (`buildWrapperSetup`, before the `return` at ~line 251)

- [ ] **Step 1: Write the failing drain test**

`internal/api/wrapper_log_test.go` (no build tag — pure `os.Pipe` + slog):

```go
package api

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer makes bytes.Buffer safe for the drain goroutine + test reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStartWrapperLogDrain_ForwardsLinesToLogger(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	done := startWrapperLogDrain(r, logger, "sess-1", "/bin/true")

	if _, err := w.WriteString("seccomp: filter loaded fd=8 wait_killable=true\nlandlock: restrictions applied\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close() // EOF → drain goroutine exits

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain goroutine did not finish after EOF")
	}

	out := buf.String()
	for _, want := range []string{
		"seccomp: filter loaded",
		"wait_killable=true",
		"landlock: restrictions applied",
		"session_id=sess-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("drained log missing %q, got:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestStartWrapperLogDrain -v`
Expected: FAIL — `startWrapperLogDrain` undefined.

- [ ] **Step 3: Implement the drain**

`internal/api/wrapper_log.go`:

```go
package api

import (
	"bufio"
	"log/slog"
	"os"
)

// startWrapperLogDrain forwards agentsh-unixwrap diagnostic lines from
// the wrapper log pipe into the server log (issue #415). The wrapper
// sets FD_CLOEXEC on its end, so EOF arrives when it execs the real
// command (or exits) — the goroutine is short-lived by construction.
// Lines are forwarded verbatim as an attr; no re-parsing or re-leveling,
// so "wait_killable=..." stays greppable at the default level.
//
// The returned channel closes when the drain finishes (test hook).
func startWrapperLogDrain(r *os.File, logger *slog.Logger, sessionID, command string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.Close()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			logger.Info("unixwrap", "session_id", sessionID, "command", command, "line", sc.Text())
		}
	}()
	return done
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestStartWrapperLogDrain -v`
Expected: PASS.

- [ ] **Step 5: Add the `extraProcConfig` fields**

In `internal/api/exec.go`, after the `blockList` field (~line 38), add:

```go
	// Wrapper log routing (issue #415): pipe carrying unixwrap
	// diagnostics into the server log. wrapperLogChild is the write end
	// inherited by the wrapper via extraFiles; the parent's copy is
	// closed in startWrapperHandlers so the drain goroutine sees EOF
	// when the wrapper execs (its own copy is CLOEXEC).
	wrapperLogParent *os.File
	wrapperLogChild  *os.File
```

- [ ] **Step 6: Close write end + start drain in `startWrapperHandlers`**

In `internal/api/exec.go:771`, `startWrapperHandlers` currently begins:

```go
func startWrapperHandlers(ctx context.Context, extra *extraProcConfig, pid, pgid int, ptraceReady chan<- error) {
	if extra == nil {
		return
	}
	if extra.notifyParentSock != nil {
```

Insert between the nil-check and the notify block:

```go
	// Wrapper log routing (issue #415): the child now owns its dup of
	// the write end; close ours so the drain goroutine gets EOF at the
	// wrapper's exec. Called from every post-start path (exec.go and
	// exec_stream.go, hybrid and wrapper-only), exactly once.
	if extra.wrapperLogChild != nil {
		_ = extra.wrapperLogChild.Close()
		extra.wrapperLogChild = nil
	}
	if extra.wrapperLogParent != nil {
		_ = startWrapperLogDrain(extra.wrapperLogParent, slog.Default(), extra.notifySessionID, extra.origCommand)
		extra.wrapperLogParent = nil
	}
```

(`slog` is already imported in exec.go.)

- [ ] **Step 7: Create the pipe in `buildWrapperSetup`**

In `internal/api/core.go`, after the signal-filter block (ends ~line 249) and immediately before `return &wrapperSetupResult{wrappedReq: wrappedReq, extraCfg: extraCfg}`, add:

```go
	// Wrapper log routing (issue #415): hand the wrapper a pipe for its
	// diagnostics (the "seccomp: filter loaded" line, landlock notices)
	// so they land in the server log instead of the wrapped command's
	// stderr. The fd number is the next ExtraFiles slot — 4 normally,
	// 5 when the signal socket is present. On pipe failure the env var
	// is omitted and the wrapper falls back to stderr (legacy behavior);
	// logging must never block an exec.
	if logR, logW, pipeErr := os.Pipe(); pipeErr == nil {
		fdStr := strconv.Itoa(3 + len(extraCfg.extraFiles))
		wrappedReq.Env[wrapperlog.EnvKey] = fdStr
		extraCfg.env[wrapperlog.EnvKey] = fdStr
		extraCfg.extraFiles = append(extraCfg.extraFiles, logW)
		extraCfg.wrapperLogParent = logR
		extraCfg.wrapperLogChild = logW
	} else {
		slog.Warn("wrapper log pipe unavailable; wrapper diagnostics will appear on command stderr",
			"session_id", sessionID, "error", pipeErr)
	}
```

Add the import `"github.com/agentsh/agentsh/internal/wrapperlog"` to core.go (`os`, `strconv`, `slog` are already imported).

- [ ] **Step 8: Build and test the package**

Run: `go build ./... && go test ./internal/api/ 2>&1 | tail -20`
Expected: build OK; package tests pass (modulo known local-env failures noted in the header).

- [ ] **Step 9: Commit**

```bash
git add internal/api/wrapper_log.go internal/api/wrapper_log_test.go internal/api/exec.go internal/api/core.go
git commit -m "feat(#415): server exec path — pipe wrapper diagnostics into server log"
```

---

### Task 5: Shim relay path — state-dir log file

**Files:**
- Modify: `internal/shim/kernelinstall/install_linux.go` (`runRelay` ~line 174, `assembleWrapperEnv` ~line 389, `filterShimInternalEnv` ~line 413)
- Test: `internal/shim/kernelinstall/install_linux_test.go`

- [ ] **Step 1: Write the failing env-hygiene tests**

Append to `install_linux_test.go` (match its existing build tag and package; add imports as needed — `strings`, `github.com/agentsh/agentsh/internal/wrapperlog`):

```go
func TestFilterShimInternalEnv_StripsWrapperLogFD(t *testing.T) {
	in := []string{"PATH=/bin", wrapperlog.EnvKey + "=7", "HOME=/root"}
	out := filterShimInternalEnv(in)
	for _, e := range out {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("inherited %s not stripped: %v", wrapperlog.EnvKey, out)
		}
	}
	if len(out) != 2 {
		t.Fatalf("unexpected env after strip: %v", out)
	}
}

func TestAssembleWrapperEnv_DropsWrapperLogFDFromWrapperEnv(t *testing.T) {
	env := assembleWrapperEnv(
		[]string{"PATH=/bin"},
		"",
		map[string]string{
			wrapperlog.EnvKey:        "9", // must NOT pass through — the relay sets its own
			"AGENTSH_SECCOMP_CONFIG": "{}",
		},
		nil,
	)
	for _, e := range env {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("server-supplied %s leaked into wrapper env: %v", wrapperlog.EnvKey, env)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shim/kernelinstall/ -run 'WrapperLogFD' -v`
Expected: FAIL — `TestFilterShimInternalEnv_StripsWrapperLogFD` fails (key passes through); the `assembleWrapperEnv` test fails (key forwarded from wrapperEnv map).

- [ ] **Step 3: Implement the env hygiene**

In `filterShimInternalEnv` (line ~413), add the third prefix:

```go
func filterShimInternalEnv(env []string) []string {
	out := make([]string, 0, len(env))
	signalPrefix := signalSockFDKey + "="
	argv0Prefix := argv0EnvKey + "="
	logFDPrefix := wrapperlog.EnvKey + "="
	for _, e := range env {
		if strings.HasPrefix(e, signalPrefix) || strings.HasPrefix(e, argv0Prefix) || strings.HasPrefix(e, logFDPrefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
```

In `assembleWrapperEnv`'s wrapperEnv loop (line ~403), extend the skip:

```go
	for k, v := range wrapperEnv {
		if k == signalSockFDKey {
			slog.Debug("kernelinstall: stripping signal sock fd from wrapper env (shim mode limitation)")
			continue
		}
		if k == wrapperlog.EnvKey {
			// The relay is the wrapper's parent here and sets its own
			// authoritative log fd; a server-supplied value would point
			// at an fd that does not exist in this process (issue #415).
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
```

Add the import `"github.com/agentsh/agentsh/internal/wrapperlog"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/shim/kernelinstall/ -run 'WrapperLogFD' -v`
Expected: PASS.

- [ ] **Step 5: Wire the log file into `runRelay`**

In `runRelay`, after `env := assembleWrapperEnv(...)` (line ~201), add:

```go
	// Wrapper log routing (issue #415): point the wrapper's diagnostics
	// at the state-dir log file. The relay's own stderr IS the user's
	// terminal, so draining a pipe into our slog would put the noise
	// right back on screen; an O_APPEND file needs no drain goroutine
	// and keeps concurrent shim execs line-atomic. Debug (not Warn) on
	// failure for the same reason — the relay must not add stderr noise.
	logFile, logErr := wrapperlog.OpenStateLogFile()
	if logErr != nil {
		slog.Debug("kernelinstall: wrapper log file unavailable; wrapper diagnostics stay on stderr", "error", logErr)
	}
```

Change the `cmd` setup (lines ~210-217) from:

```go
	cmd := exec.Command(wrapperBin, wrapperArgs...)
	cmd.Args[0] = filepath.Base(wrapperBin)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// ExtraFiles[0] becomes fd 3 in the child (0=stdin,1=stdout,2=stderr,3=ExtraFiles[0])
	cmd.ExtraFiles = []*os.File{childFile}
```

to:

```go
	cmd := exec.Command(wrapperBin, wrapperArgs...)
	cmd.Args[0] = filepath.Base(wrapperBin)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// ExtraFiles[0] becomes fd 3 in the child (0=stdin,1=stdout,2=stderr,3=ExtraFiles[0])
	cmd.ExtraFiles = []*os.File{childFile}
	if logFile != nil {
		// ExtraFiles[1] = fd 4 — free in shim mode (the signal-filter
		// socketpair is deliberately not replicated here).
		cmd.ExtraFiles = append(cmd.ExtraFiles, logFile)
		cmd.Env = append(cmd.Env, wrapperlog.EnvKey+"=4")
	}
```

Update the start-failure cleanup (lines ~219-223) and the post-start close (line ~226):

```go
	if err := cmd.Start(); err != nil {
		parentFile.Close()
		childFile.Close()
		if logFile != nil {
			logFile.Close()
		}
		return Result{}, fmt.Errorf("start wrapper: %w", err)
	}

	// The wrapper owns childFile now; close our copy in the parent.
	childFile.Close()
	if logFile != nil {
		logFile.Close()
	}
```

- [ ] **Step 6: Write the relay wiring test (spec test item 4)**

Append to `install_linux_test.go`, reusing the package's fake-wrapper harness (`buildFakeWrapperPrintEnv`, `serveNotifySetupStatus`, `makeWrapInitHandler`, `baseParams` — see `TestInstall_StripsSignalSockFdFromPEnv` for the pattern):

```go
// TestInstall_PassesWrapperLogFDAndCreatesStateLogFile verifies the
// issue #415 relay wiring end-to-end: runRelay opens the state-dir log
// file, passes it as ExtraFiles[1], and exports AGENTSH_WRAPPER_LOG_FD=4
// to the wrapper. XDG_STATE_HOME is redirected to a temp dir so the test
// owns the state-dir location.
func TestInstall_PassesWrapperLogFDAndCreatesStateLogFile(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	wrapperBin := buildFakeWrapperPrintEnv(t)

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
		WrapperEnv:    map[string]string{"FAKE_WRAPPER": "1"},
	}
	handler, _ := makeWrapInitHandler(200, wrapResp)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	p.Env = []string{"HOME=/tmp"}

	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()
	p.Env = append(p.Env, "FAKE_ENV_OUT="+outPath)

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}

	envOutput, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read wrapper env output: %v", err)
	}
	if !strings.Contains(string(envOutput), wrapperlog.EnvKey+"=4") {
		t.Errorf("wrapper env missing %s=4:\n%s", wrapperlog.EnvKey, envOutput)
	}

	logPath := filepath.Join(stateHome, "agentsh", "logs", "unixwrap.log")
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("state-dir log file not created at %s: %v", logPath, err)
	}
}
```

Run: `go test ./internal/shim/kernelinstall/ -run TestInstall_PassesWrapperLogFD -v`
Expected: PASS.

- [ ] **Step 7: Build and run the package tests**

Run: `go build ./... && go test ./internal/shim/kernelinstall/`
Expected: build OK, tests pass.

- [ ] **Step 8: Commit**

```bash
git add internal/shim/kernelinstall/install_linux.go internal/shim/kernelinstall/install_linux_test.go
git commit -m "feat(#415): shim relay — wrapper diagnostics to state-dir log file"
```

---

### Task 6: `agentsh wrap` CLI path — state-dir log file

**Files:**
- Modify: `internal/cli/wrap_linux.go` (`platformSetupWrap`, extraFiles assembly ~line 160)

- [ ] **Step 1: Wire the log file in**

In `wrap_linux.go`, the current extraFiles assembly (lines ~160-163):

```go
	extraFiles := []*os.File{childFile}
	if hasSignalSocket {
		extraFiles = append(extraFiles, signalChildFile)
	}
```

becomes:

```go
	extraFiles := []*os.File{childFile}
	if hasSignalSocket {
		extraFiles = append(extraFiles, signalChildFile)
	}
	// Wrapper log routing (issue #415): the CLI's stderr is the user's
	// terminal, so route wrapper diagnostics to the state-dir log file.
	// fd number = next ExtraFiles slot (4, or 5 with the signal socket).
	// Silent stderr fallback on failure — adding our own warning here
	// would reintroduce the exact noise this removes. wrap.go closes
	// every extraFiles entry after Start, so no extra cleanup is needed.
	if logFile, err := wrapperlog.OpenStateLogFile(); err == nil {
		env = append(env, fmt.Sprintf("%s=%d", wrapperlog.EnvKey, 3+len(extraFiles)))
		extraFiles = append(extraFiles, logFile)
	}
```

Add the import `"github.com/agentsh/agentsh/internal/wrapperlog"` (`fmt` is already imported).

- [ ] **Step 2: Build and run the package tests**

Run: `go build ./... && go test ./internal/cli/`
Expected: build OK, tests pass.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/wrap_linux.go
git commit -m "feat(#415): agentsh wrap CLI — wrapper diagnostics to state-dir log file"
```

---

### Task 7: Integration test — clean stderr + diagnostic in server log

**Files:**
- Create: `internal/integration/wrapper_log_routing_test.go`

Reuses this package's existing harness: `buildSeccompBinaries`, `startWrapSeccompServerContainer`, `writeFile`, `mustMkdir`, `wrapStrongTestConfigYAML`, `wrapTestPolicyYAML`, `testAPIKeysYAML` (see `agentsh_wrap_linux_test.go`). The config already sets `logging.output: stdout`, so the server log is the container log.

- [ ] **Step 1: Write the test**

```go
//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestExecPath_WrapperLogRoutedOffCommandStderr is the end-to-end
// acceptance test for issue #415: a wrapped command's stderr must not
// carry the per-exec "seccomp: filter loaded" wrapper diagnostic, and
// that diagnostic must instead appear in the server log (drained from
// the wrapper log pipe) at the default level.
func TestExecPath_WrapperLogRoutedOffCommandStderr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	agentshBin, unixwrapBin := buildSeccompBinaries(t)
	temp := t.TempDir()

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapStrongTestConfigYAML)
	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	ctr, endpoint, cleanup := startWrapSeccompServerContainer(t, ctx, agentshBin, unixwrapBin, configPath, keysPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "agent-default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Cleanup(func() {
		if err := cli.DestroySession(context.Background(), sess.ID); err != nil {
			t.Logf("DestroySession: %v", err)
		}
	})

	execCtx, execCancel := context.WithTimeout(ctx, 30*time.Second)
	res, execErr := cli.Exec(execCtx, sess.ID, types.ExecRequest{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo STDERR_MARKER >&2"},
	})
	execCancel()
	if execErr != nil {
		if errors.Is(execErr, context.DeadlineExceeded) || strings.Contains(execErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify appears unreliable in this environment (exec timeout)")
		}
		t.Fatalf("Exec: %v", execErr)
	}
	if res.Result.ExitCode != 0 {
		t.Skipf("seccomp-user-notify may not be active in this environment (exit=%d, stderr=%q)", res.Result.ExitCode, res.Result.Stderr)
	}

	// (a) The command's own stderr arrives intact and uncontaminated.
	if !strings.Contains(res.Result.Stderr, "STDERR_MARKER") {
		t.Fatalf("command stderr lost: %q", res.Result.Stderr)
	}
	if strings.Contains(res.Result.Stderr, "seccomp: filter loaded") {
		t.Fatalf("wrapper diagnostic leaked onto command stderr (issue #415 regression):\n%s", res.Result.Stderr)
	}

	// (b) The diagnostic landed in the server log instead, at default
	// level (logging.level=info in the test config). The drained line
	// is embedded as the `line` attr of the server's "unixwrap" record;
	// the substring survives TextHandler quoting.
	logsCtx, logsCancel := context.WithTimeout(ctx, 30*time.Second)
	defer logsCancel()
	logsReader, err := ctr.Logs(logsCtx)
	if err != nil {
		t.Fatalf("container logs: %v", err)
	}
	defer logsReader.Close()
	logBytes, err := io.ReadAll(logsReader)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	serverLog := string(logBytes)
	if !strings.Contains(serverLog, "seccomp: filter loaded") {
		t.Fatalf("wait_killable diagnostic missing from server log (acceptance criterion #2)\nserver log:\n%s", serverLog)
	}
	if !strings.Contains(serverLog, "wait_killable") {
		t.Fatalf("wait_killable field missing from drained diagnostic\nserver log:\n%s", serverLog)
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test -tags integration ./internal/integration/ -run TestExecPath_WrapperLogRoutedOffCommandStderr -v -timeout 10m`
Expected: PASS (or SKIP on hosts where seccomp user-notify is unreliable — the probe-skip pattern matches the package's existing tests). Requires Docker.

- [ ] **Step 3: Commit**

```bash
git add internal/integration/wrapper_log_routing_test.go
git commit -m "test(#415): integration — clean wrapped stderr, diagnostic drained to server log"
```

---

### Task 8: Final verification

- [ ] **Step 1: Full build, both platforms**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (CLAUDE.md pre-commit requirement).

- [ ] **Step 2: Full test suite**

Run: `go test ./... 2>&1 | grep -v "^ok" | head -40`
Expected: no FAILs beyond the known local-env failures listed in the header notes and known flake families (`TestStore_*EmitsTransportLossOnWire`). In particular `./internal/netmonitor/unix/` (the #369 regression tests) and `./cmd/agentsh-unixwrap/` must pass.

- [ ] **Step 3: Manual smoke test (acceptance criterion #1)**

```bash
go build -o /tmp/agentsh ./cmd/agentsh && go build -o /tmp/agentsh-unixwrap ./cmd/agentsh-unixwrap
# In a running session (or via agentsh wrap), confirm:
#   agentsh detect --output json   → stderr starts with '{', no "seccomp: filter loaded" prefix
# and the server log (or ~/.local/state/agentsh/logs/unixwrap.log for
# shim/CLI paths) contains the wait_killable line.
```

Expected: clean machine-readable stderr; diagnostic present in the routed destination.

- [ ] **Step 4: Run roborev on the branch, fix findings above low**

- [ ] **Step 5: Final commit (if any fixups) and hand off**

Use superpowers:finishing-a-development-branch — PR referencing issue #415.
