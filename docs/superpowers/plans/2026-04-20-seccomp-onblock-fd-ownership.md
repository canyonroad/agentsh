# Seccomp On-Block FD Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the flaky `TestSeccompOnBlock_LogAndKill` integration failure by making the notify-socket handoff in `startWrappedChild` use unambiguous `*os.File` ownership throughout the receive and ACK path.

**Architecture:** Keep the fix local to `internal/integration/seccomp_onblock_test.go`. First add a deterministic GC-pressure regression harness that reproduces the current fd lifetime bug in a subprocess. Then refactor `startWrappedChild` so the socketpair ends are wrapped once, the parent end is used for both `RecvFD` and the ACK write, and no raw fd writes occur after ownership has moved to `*os.File`.

**Tech Stack:** Go 1.22+, Linux integration tests, stdlib `os/exec`, `runtime`, `runtime/debug`, `golang.org/x/sys/unix`, existing `require` assertions.

**Spec:** `docs/superpowers/specs/2026-04-20-seccomp-onblock-fd-ownership-design.md`

---

## File Structure

**Modify:**
- `internal/integration/seccomp_onblock_test.go` — owns the flaky helper, the `log_and_kill` integration tests, and the new GC-pressure regression harness.

---

### Task 1: Add a GC-pressure regression harness for the flaky handoff

**Files:**
- Modify: `internal/integration/seccomp_onblock_test.go`

- [ ] **Step 1: Add the subprocess-backed regression test and required import**

Update the import block in `internal/integration/seccomp_onblock_test.go` to add `runtime/debug`:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"testing"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)
```

Then add this constant and test just above `TestSeccompOnBlock_Errno`:

```go
const seccompOnBlockGCPressureEnv = "AGENTSH_TEST_SECCOMP_ONBLOCK_GC_PRESSURE"

func TestSeccompOnBlock_LogAndKill_GCPressure(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`

	if os.Getenv(seccompOnBlockGCPressureEnv) == "1" {
		oldGCPercent := debug.SetGCPercent(1)
		oldMemLimit := debug.SetMemoryLimit(64 << 20)
		defer debug.SetGCPercent(oldGCPercent)
		defer debug.SetMemoryLimit(oldMemLimit)

		for i := 0; i < 25; i++ {
			runtime.GC()

			st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
			require.NoErrorf(t, err, "iteration %d", i)
			require.Truef(t, st.Signaled(), "iteration %d", i)
			require.Equalf(t, syscall.SIGKILL, st.Signal(), "iteration %d", i)
			require.Lenf(t, events, 1, "iteration %d", i)

			runtime.GC()
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSeccompOnBlock_LogAndKill_GCPressure$")
	cmd.Env = append(os.Environ(), seccompOnBlockGCPressureEnv+"=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Run())
}
```

- [ ] **Step 2: Run the new regression test and confirm it fails on the current helper**

Run:

```bash
go test -tags=integration ./internal/integration -run '^TestSeccompOnBlock_LogAndKill_GCPressure$' -count=1
```

Expected:

- command exits non-zero
- output includes one of the current handshake failures:
  - `ACK: invalid argument`
  - `RecvFD: bad file descriptor`
  - `ACK handshake failed: expected 1 ACK byte, got 0`

---

### Task 2: Refactor `startWrappedChild` to use single-owner `*os.File` handles

**Files:**
- Modify: `internal/integration/seccomp_onblock_test.go`

- [ ] **Step 1: Replace mixed raw-fd and `*os.File` ownership with file-handle ownership**

In `startWrappedChild`, replace the socketpair setup and notify-handshake block with:

```go
	// socketpair for notify fd handoff (only meaningful in log/log_and_kill).
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("socketpair: %w", err)
	}

	parentEnd := os.NewFile(uintptr(sp[0]), "parent-end")
	childEnd := os.NewFile(uintptr(sp[1]), "child-end")
	defer parentEnd.Close()
	// childEnd will be dup'd into the wrapper via ExtraFiles (fd 3); we keep
	// our copy alive until after cmd.Start so the fd survives the fork.
	defer childEnd.Close()
```

and later:

```go
	if hasNotify {
		// Receive the notify fd from the wrapper.
		recvd, rerr := unixmon.RecvFD(parentEnd)
		if rerr != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return 0, nil, fmt.Errorf("RecvFD: %w", rerr)
		}
		notifyFile = recvd

		// ACK so the wrapper proceeds to exec.
		if _, werr := parentEnd.Write([]byte{1}); werr != nil {
			_ = notifyFile.Close()
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return 0, nil, fmt.Errorf("ACK: %w", werr)
		}

		serveDone = make(chan struct{})
		go func() {
			defer close(serveDone)
			unixmon.ServeNotifyWithExecve(ctx, notifyFile, "test-session", nil, emitter, nil, nil, bl)
		}()
	}
```

Remove these old lines entirely:

```go
	parentFD := sp[0]
	childFD := sp[1]
	defer unix.Close(parentFD)
	childEnd := os.NewFile(uintptr(childFD), "child-end")
```

and:

```go
		parentEnd := os.NewFile(uintptr(parentFD), "parent-end")
		// parentEnd shares the fd with parentFD; do NOT double-close.
```

and:

```go
		if _, werr := unix.Write(parentFD, []byte{1}); werr != nil {
```

- [ ] **Step 2: Run the new GC-pressure regression test and verify it passes**

Run:

```bash
go test -tags=integration ./internal/integration -run '^TestSeccompOnBlock_LogAndKill_GCPressure$' -count=1
```

Expected:

- command exits zero
- test output shows `ok  	github.com/agentsh/agentsh/internal/integration`

- [ ] **Step 3: Re-run the original stress reproduction command**

Run:

```bash
GOGC=1 GOMEMLIMIT=64MiB go test -tags=integration ./internal/integration -run '^TestSeccompOnBlock_LogAndKill$' -count=50
```

Expected:

- command exits zero
- no occurrences of `ACK: invalid argument`
- no occurrences of `RecvFD: bad file descriptor`
- no occurrences of `ACK handshake failed: expected 1 ACK byte, got 0`

---

### Task 3: Run focused integration coverage and repository-level safety checks

**Files:**
- Modify: `internal/integration/seccomp_onblock_test.go`

- [ ] **Step 1: Run the surrounding `on_block` integration tests**

Run:

```bash
go test -tags=integration ./internal/integration -run 'TestSeccompOnBlock_(Errno|Kill|Log|LogAndKill|LogAndKill_GCPressure|LogAndKill_ConcurrentCalls)$' -count=1
```

Expected:

- command exits zero
- all six `TestSeccompOnBlock_*` tests pass

- [ ] **Step 2: Run normal repository verification**

Run:

```bash
go test ./... -count=1
GOOS=windows go build ./...
```

Expected:

- both commands exit zero
- no new failures outside the integration test file

- [ ] **Step 3: Commit the fix**

Run:

```bash
git add internal/integration/seccomp_onblock_test.go
git commit -m "test(integration): fix seccomp on_block fd ownership"
```

Expected:

- commit succeeds with only the integration test file staged

---

## Self-Review

- Spec coverage: the plan covers the local helper refactor, keeps the scope inside `internal/integration/seccomp_onblock_test.go`, and adds GC-sensitive regression coverage plus the focused verification commands called for in the spec.
- Placeholder scan: no `TODO`, `TBD`, or vague “handle appropriately” steps remain; each code-changing step includes explicit code and commands.
- Type consistency: the plan uses one new constant name, `seccompOnBlockGCPressureEnv`, keeps `startWrappedChild` unchanged at the signature level, and uses `parentEnd.Write` consistently as the single-owner ACK path.
