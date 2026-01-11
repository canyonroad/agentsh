# Signal Filter Runtime Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the signal filter into the runtime supervisor so signal rules are enforced during command execution.

**Architecture:** Mirror the unix socket notify pattern: extend wrapper config → install filter in wrapper → send FD to parent → run handler loop in parent goroutine. The signal registry tracks process tree, handler evaluates signals against policy, responds allow/deny.

**Tech Stack:** Go, seccomp user-notify, unix socketpair, SCM_RIGHTS

---

## Task 1: Extend Wrapper Config for Signal Filter

Add signal filter configuration to both the API's config struct and the wrapper's config.

**Files:**
- Modify: `internal/api/core.go:27-32`
- Modify: `cmd/agentsh-unixwrap/config.go:11-15`

**Step 1: Write failing test for wrapper config parsing**

Create `cmd/agentsh-unixwrap/config_signal_test.go`:

```go
//go:build linux && cgo

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigWithSignal(t *testing.T) {
	os.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":true,"signal_filter_enabled":true}`)
	defer os.Unsetenv("AGENTSH_SECCOMP_CONFIG")

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.True(t, cfg.SignalFilterEnabled)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go test ./cmd/agentsh-unixwrap/... -run TestLoadConfigWithSignal -v`
Expected: FAIL with "cfg.SignalFilterEnabled undefined"

**Step 3: Add SignalFilterEnabled to wrapper config**

Modify `cmd/agentsh-unixwrap/config.go`:

```go
// WrapperConfig is the configuration passed via AGENTSH_SECCOMP_CONFIG env var.
type WrapperConfig struct {
	UnixSocketEnabled   bool     `json:"unix_socket_enabled"`
	BlockedSyscalls     []string `json:"blocked_syscalls"`
	SignalFilterEnabled bool     `json:"signal_filter_enabled"`
}
```

**Step 4: Add SignalFilterEnabled to API's seccompWrapperConfig**

Modify `internal/api/core.go`:

```go
// seccompWrapperConfig is passed to the agentsh-unixwrap wrapper via
// AGENTSH_SECCOMP_CONFIG environment variable to configure seccomp-bpf filtering.
type seccompWrapperConfig struct {
	UnixSocketEnabled   bool     `json:"unix_socket_enabled"`
	BlockedSyscalls     []string `json:"blocked_syscalls"`
	SignalFilterEnabled bool     `json:"signal_filter_enabled"`
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go test ./cmd/agentsh-unixwrap/... -run TestLoadConfigWithSignal -v`
Expected: PASS

**Step 6: Commit**

```bash
git add cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/config_signal_test.go internal/api/core.go
git commit -m "feat(signal): add signal filter config to wrapper"
```

---

## Task 2: Install Signal Filter in Wrapper

Add signal filter installation to the wrapper, sending the notify FD back to the server.

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`

**Step 1: Write failing test for signal filter installation**

Create `cmd/agentsh-unixwrap/signal_test.go`:

```go
//go:build linux && cgo

package main

import (
	"testing"

	"github.com/agentsh/agentsh/internal/signal"
)

func TestSignalFilterAvailable(t *testing.T) {
	// This just verifies the signal package is importable and has the expected functions
	cfg := signal.DefaultSignalFilterConfig()
	if !cfg.Enabled {
		t.Error("DefaultSignalFilterConfig should be enabled")
	}
	if len(cfg.Syscalls) == 0 {
		t.Error("DefaultSignalFilterConfig should have syscalls")
	}
}
```

**Step 2: Run test to verify it passes (signal package already exists)**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go test ./cmd/agentsh-unixwrap/... -run TestSignalFilterAvailable -v`
Expected: PASS

**Step 3: Add signal filter installation to wrapper main**

Modify `cmd/agentsh-unixwrap/main.go` - add import and installation:

```go
import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/signal"
	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}

	sockFD, err := notifySockFD()
	if err != nil {
		log.Fatalf("notify fd: %v", err)
	}

	// Load config from environment.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Resolve syscall names to numbers.
	blockedNrs, skipped := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	// Build filter config.
	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled: cfg.UnixSocketEnabled,
		BlockedSyscalls:   blockedNrs,
	}

	// Install seccomp filter for unix sockets.
	filt, err := unixmon.InstallFilterWithConfig(filterCfg)
	if errors.Is(err, unixmon.ErrUnsupported) {
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("install seccomp filter: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()

	// Send unix socket notify fd to server over socketpair.
	if notifFD >= 0 {
		if err := sendFD(sockFD, notifFD); err != nil {
			log.Fatalf("send fd: %v", err)
		}
	}

	// Install signal filter if enabled.
	var sigFilter *signal.SignalFilter
	if cfg.SignalFilterEnabled {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err = signal.InstallSignalFilter(sigCfg)
		if err != nil {
			// Signal filter is optional - log and continue
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			// Send signal notify fd to server
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(sockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
	}

	_ = unix.Close(sockFD)

	// Exec the real command.
	cmd := os.Args[2]
	args := os.Args[2:]
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}
```

**Step 4: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./cmd/agentsh-unixwrap/...`
Expected: PASS (no errors)

**Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go cmd/agentsh-unixwrap/signal_test.go
git commit -m "feat(signal): install signal filter in wrapper"
```

---

## Task 3: Add Signal Handler to API

Create the signal handler that mirrors the notify handler pattern.

**Files:**
- Create: `internal/api/signal_handler_linux.go`
- Create: `internal/api/signal_handler_stub.go`

**Step 1: Write the signal handler for Linux**

Create `internal/api/signal_handler_linux.go`:

```go
//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"os"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/signal"
	"github.com/agentsh/agentsh/pkg/types"
)

// signalEmitterAdapter adapts the API's event store/broker to the signal handler's EventEmitter interface.
type signalEmitterAdapter struct {
	store     eventStore
	broker    eventBroker
	sessionID string
	commandID func() string
}

func (a *signalEmitterAdapter) Emit(ctx context.Context, eventType types.EventType, data map[string]interface{}) {
	ev := types.Event{
		ID:        "sig-" + a.commandID(),
		Timestamp: time.Now().UTC(),
		Type:      string(eventType),
		SessionID: a.sessionID,
		CommandID: a.commandID(),
		Fields:    data,
	}
	if a.store != nil {
		_ = a.store.AppendEvent(ctx, ev)
	}
	if a.broker != nil {
		a.broker.Publish(ev)
	}
}

// startSignalHandler receives the signal filter notify fd from the parent socket and
// starts the signal handler loop in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
func startSignalHandler(ctx context.Context, parentSock *os.File, sessID string, supervisorPID int,
	engine *signal.Engine, registry *signal.PIDRegistry,
	store eventStore, broker eventBroker, commandIDFunc func() string) {

	if parentSock == nil || engine == nil {
		return
	}

	// Receive the signal filter fd from the wrapper process
	signalFD, err := unixmon.RecvFD(parentSock)
	if err != nil {
		slog.Debug("failed to receive signal fd", "error", err)
		_ = parentSock.Close()
		return
	}
	_ = parentSock.Close()

	if signalFD == nil {
		return
	}

	emitter := &signalEmitterAdapter{
		store:     store,
		broker:    broker,
		sessionID: sessID,
		commandID: commandIDFunc,
	}
	handler := signal.NewHandler(engine, registry, emitter)

	// Start the signal handler loop in a goroutine
	go func() {
		defer signalFD.Close()
		serveSignalNotify(ctx, signalFD, handler)
	}()
}

// serveSignalNotify runs the signal notification loop.
func serveSignalNotify(ctx context.Context, fd *os.File, handler *signal.Handler) {
	// Create a SignalFilter from the fd
	filter := signal.NewSignalFilterFromFD(int(fd.Fd()))
	if filter == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := filter.Receive()
		if err != nil {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}
			// Transient error - continue
			slog.Debug("signal filter receive", "error", err)
			continue
		}

		sigCtx := signal.ExtractSignalContext(req)
		dec := handler.Handle(ctx, sigCtx)

		// Respond based on decision
		allow := dec.Action == signal.DecisionAllow ||
			dec.Action == signal.DecisionAudit ||
			dec.Action == signal.DecisionAbsorb // Absorb allows but doesn't deliver

		var errno int32 = 0
		if !allow {
			errno = 1 // EPERM
		}

		if err := filter.Respond(req.ID, allow, errno); err != nil {
			slog.Debug("signal filter respond", "error", err)
		}
	}
}
```

**Step 2: Create stub for non-Linux**

Create `internal/api/signal_handler_stub.go`:

```go
//go:build !linux || !cgo

package api

import (
	"context"
	"os"

	"github.com/agentsh/agentsh/internal/signal"
)

// startSignalHandler is a no-op on non-Linux platforms.
func startSignalHandler(ctx context.Context, parentSock *os.File, sessID string, supervisorPID int,
	engine *signal.Engine, registry *signal.PIDRegistry,
	store eventStore, broker eventBroker, commandIDFunc func() string) {
	// Signal interception not supported on this platform
}
```

**Step 3: Add NewSignalFilterFromFD to signal package**

Create `internal/signal/seccomp_linux.go` addition (add after existing code):

```go
// NewSignalFilterFromFD creates a SignalFilter from an existing file descriptor.
// This is used by the parent process to wrap an FD received from the child.
func NewSignalFilterFromFD(fd int) *SignalFilter {
	if fd < 0 {
		return nil
	}
	return &SignalFilter{fd: seccomp.ScmpFd(fd)}
}
```

Add to `internal/signal/seccomp_stub.go`:

```go
// NewSignalFilterFromFD creates a SignalFilter from an existing file descriptor.
func NewSignalFilterFromFD(fd int) *SignalFilter {
	return nil
}
```

**Step 4: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./internal/api/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/api/signal_handler_linux.go internal/api/signal_handler_stub.go internal/signal/seccomp_linux.go internal/signal/seccomp_stub.go
git commit -m "feat(signal): add signal handler for API"
```

---

## Task 4: Add Signal Fields to extraProcConfig

Extend the extraProcConfig struct to hold signal-related configuration.

**Files:**
- Modify: `internal/api/exec.go:25-33`

**Step 1: Add signal fields to extraProcConfig**

Modify `internal/api/exec.go`:

```go
type extraProcConfig struct {
	extraFiles       []*os.File
	env              map[string]string
	notifyParentSock *os.File       // Parent socket to receive seccomp notify fd (Linux only)
	notifySessionID  string         // Session ID for notify handler
	notifyStore      eventStore     // Event store for notify handler
	notifyBroker     eventBroker    // Event broker for notify handler
	notifyPolicy     *policy.Engine // Policy engine for notify handler

	// Signal filter fields
	signalParentSock *os.File           // Parent socket to receive signal filter fd
	signalEngine     *signal.Engine     // Signal policy engine
	signalRegistry   *signal.PIDRegistry // Process registry for signal classification
	signalCommandID  func() string      // Function to get current command ID
}
```

**Step 2: Add signal import**

Add to imports in `internal/api/exec.go`:

```go
import (
	// ... existing imports ...
	"github.com/agentsh/agentsh/internal/signal"
)
```

**Step 3: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./internal/api/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/api/exec.go
git commit -m "feat(signal): add signal fields to extraProcConfig"
```

---

## Task 5: Start Signal Handler in runCommandWithResources

Wire up the signal handler start call in the command execution flow.

**Files:**
- Modify: `internal/api/exec.go:185-190`

**Step 1: Add signal handler startup after notify handler**

Modify `internal/api/exec.go` after line 189 (after `startNotifyHandler` call):

```go
		// Start unix socket notify handler if configured (Linux only).
		// The handler receives the notify fd from the wrapper and runs until ctx is cancelled.
		if extra != nil && extra.notifyParentSock != nil {
			startNotifyHandler(ctx, extra.notifyParentSock, extra.notifySessionID, extra.notifyPolicy, extra.notifyStore, extra.notifyBroker)
		}

		// Start signal filter handler if configured (Linux only).
		// The handler receives the signal filter fd from the wrapper and runs until ctx is cancelled.
		if extra != nil && extra.signalParentSock != nil && extra.signalEngine != nil {
			// Register the spawned process in the signal registry
			if extra.signalRegistry != nil {
				extra.signalRegistry.Register(cmd.Process.Pid, pgid, req.Command)
			}
			startSignalHandler(ctx, extra.signalParentSock, extra.notifySessionID, cmd.Process.Pid,
				extra.signalEngine, extra.signalRegistry,
				extra.notifyStore, extra.notifyBroker, extra.signalCommandID)
		}
```

**Step 2: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./internal/api/...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/api/exec.go
git commit -m "feat(signal): start signal handler in runCommandWithResources"
```

---

## Task 6: Wire Signal Filter in Core Exec Flow

Configure the signal filter when the policy has signal rules.

**Files:**
- Modify: `internal/api/core.go:670-700` (in the exec wrapper setup section)

**Step 1: Add signal filter configuration to wrapper setup**

Find the section where seccompCfg is created (around line 679) and extend it:

```go
			// Pass seccomp configuration to the wrapper
			seccompCfg := seccompWrapperConfig{
				UnixSocketEnabled:   a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
				BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
				SignalFilterEnabled: a.policy != nil && a.policy.SignalEngine() != nil,
			}
```

**Step 2: Create signal registry and add to extraCfg**

After the extraCfg creation, add signal configuration:

```go
			extraCfg = &extraProcConfig{
				extraFiles:       []*os.File{sp.child},
				env:              extraEnv,
				notifyParentSock: sp.parent,
				notifySessionID:  sess.ID,
				notifyStore:      a.store,
				notifyBroker:     a.broker,
				notifyPolicy:     a.policy,
			}

			// Add signal filter config if policy has signal rules
			if a.policy != nil && a.policy.SignalEngine() != nil {
				// Create a second socket pair for signal filter fd
				sigSP, err := newSocketPair()
				if err == nil {
					extraCfg.extraFiles = append(extraCfg.extraFiles, sigSP.child)
					extraCfg.signalParentSock = sigSP.parent
					extraCfg.signalEngine = a.policy.SignalEngine()
					extraCfg.signalRegistry = signal.NewPIDRegistryWithUID(sess.ID, os.Getpid(), os.Getuid())
					extraCfg.signalCommandID = func() string { return sess.CurrentCommandID() }
				}
			}
```

**Step 3: Add signal import to core.go**

Add to imports:

```go
import (
	// ... existing imports ...
	"github.com/agentsh/agentsh/internal/signal"
)
```

**Step 4: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./internal/api/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/api/core.go
git commit -m "feat(signal): wire signal filter into core exec flow"
```

---

## Task 7: Handle Second FD in Wrapper

Update wrapper to handle sending two FDs (unix socket notify + signal filter).

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`

**Step 1: Refactor wrapper to send FDs sequentially**

The wrapper sends unix socket FD first, then signal FD. The server receives them in the same order. Update the wrapper to close socket after sending both:

```go
func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}

	sockFD, err := notifySockFD()
	if err != nil {
		log.Fatalf("notify fd: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	blockedNrs, skipped := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled: cfg.UnixSocketEnabled,
		BlockedSyscalls:   blockedNrs,
	}

	filt, err := unixmon.InstallFilterWithConfig(filterCfg)
	if errors.Is(err, unixmon.ErrUnsupported) {
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("install seccomp filter: %v", err)
	}
	defer filt.Close()

	// Send unix socket notify fd first
	notifFD := filt.NotifFD()
	if notifFD >= 0 {
		if err := sendFD(sockFD, notifFD); err != nil {
			log.Fatalf("send unix fd: %v", err)
		}
	}

	// Install and send signal filter fd if enabled
	if cfg.SignalFilterEnabled {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err := signal.InstallSignalFilter(sigCfg)
		if err != nil {
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(sockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
	}

	_ = unix.Close(sockFD)

	cmd := os.Args[2]
	args := os.Args[2:]
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}
```

**Step 2: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./cmd/agentsh-unixwrap/...`
Expected: PASS

**Step 3: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "feat(signal): handle multiple FDs in wrapper"
```

---

## Task 8: Update Notify Handler to Use Separate Socket

The unix socket and signal filter need separate socket pairs for receiving their FDs.

**Files:**
- Modify: `internal/api/core.go` (wrapper setup section)

**Step 1: Create separate socket pairs**

Update the wrapper setup to use two socket pairs - one for unix socket notify, one for signal filter:

The key insight: each filter sends its FD over the socket. If we send both over one socket, the receiver can distinguish them by order. But cleaner is to have separate socket pairs.

Actually, looking at the code more carefully, the current implementation only has one socketpair and passes it as ExtraFiles[0] (fd 3). The wrapper reads AGENTSH_NOTIFY_SOCK_FD to know which fd to use.

For simplicity, let's use a single socketpair and have the wrapper send both FDs over it. The server receives them in order (unix notify first, signal filter second).

Update `internal/api/core.go` to receive both FDs from the same socket:

```go
// In the extraProcConfig setup, both handlers use the same parent socket
// but we need to receive the FDs in sequence

extraCfg = &extraProcConfig{
    extraFiles:       []*os.File{sp.child},
    env:              extraEnv,
    notifyParentSock: sp.parent,
    notifySessionID:  sess.ID,
    notifyStore:      a.store,
    notifyBroker:     a.broker,
    notifyPolicy:     a.policy,
}

// Signal filter shares the same socket - FDs sent in sequence
if a.policy != nil && a.policy.SignalEngine() != nil {
    extraCfg.signalParentSock = nil // Will receive from same socket as notify
    extraCfg.signalEngine = a.policy.SignalEngine()
    extraCfg.signalRegistry = signal.NewPIDRegistryWithUID(sess.ID, os.Getpid(), os.Getuid())
    extraCfg.signalCommandID = func() string { return sess.CurrentCommandID() }
}
```

Actually, this is getting complex. Let me simplify: use two separate socket pairs.

**Step 2: Update with two socket pairs approach**

```go
// Create unix socket pair for notify fd
sp, err := newSocketPair()
if err != nil {
    return req, fmt.Errorf("create socket pair: %w", err)
}
extraFiles := []*os.File{sp.child}
envFD := 3

// Create signal socket pair if signal rules exist
var sigSP *socketPair
signalEnabled := a.policy != nil && a.policy.SignalEngine() != nil
if signalEnabled {
    sigSP, err = newSocketPair()
    if err != nil {
        _ = sp.Close()
        return req, fmt.Errorf("create signal socket pair: %w", err)
    }
    extraFiles = append(extraFiles, sigSP.child)
}

wrappedReq.Env["AGENTSH_NOTIFY_SOCK_FD"] = strconv.Itoa(envFD)
if signalEnabled {
    wrappedReq.Env["AGENTSH_SIGNAL_SOCK_FD"] = strconv.Itoa(envFD + 1)
}

// Pass seccomp configuration
seccompCfg := seccompWrapperConfig{
    UnixSocketEnabled:   a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
    BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
    SignalFilterEnabled: signalEnabled,
}
```

This requires updating the wrapper to read AGENTSH_SIGNAL_SOCK_FD too.

**Step 3: Commit partial progress**

```bash
git add internal/api/core.go
git commit -m "wip(signal): add separate socket pair for signal filter"
```

---

## Task 9: Update Wrapper to Use Separate Signal Socket

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`

**Step 1: Add signal socket FD reader**

```go
func signalSockFD() (int, error) {
	val := os.Getenv("AGENTSH_SIGNAL_SOCK_FD")
	if val == "" {
		return -1, nil // Signal socket not configured
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return -1, fmt.Errorf("invalid AGENTSH_SIGNAL_SOCK_FD=%q", val)
	}
	return n, nil
}
```

**Step 2: Update main to use separate sockets**

```go
func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}

	notifySockFD, err := notifySockFD()
	if err != nil {
		log.Fatalf("notify fd: %v", err)
	}

	signalSockFD, err := signalSockFD()
	if err != nil {
		log.Fatalf("signal fd: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// ... existing unix socket filter setup ...

	// Send unix socket notify fd
	if notifFD >= 0 {
		if err := sendFD(notifySockFD, notifFD); err != nil {
			log.Fatalf("send unix fd: %v", err)
		}
	}
	_ = unix.Close(notifySockFD)

	// Install and send signal filter fd if enabled
	if cfg.SignalFilterEnabled && signalSockFD >= 0 {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err := signal.InstallSignalFilter(sigCfg)
		if err != nil {
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(signalSockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
		_ = unix.Close(signalSockFD)
	}

	// Exec the real command
	cmd := os.Args[2]
	args := os.Args[2:]
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}
```

**Step 3: Verify build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./cmd/agentsh-unixwrap/...`
Expected: PASS

**Step 4: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "feat(signal): use separate socket for signal filter fd"
```

---

## Task 10: Write Integration Test

Create an integration test that verifies signal interception works end-to-end.

**Files:**
- Create: `internal/api/signal_integration_test.go`

**Step 1: Write integration test**

```go
//go:build linux && cgo && integration

package api

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalFilterIntegration(t *testing.T) {
	if !signal.IsSignalSupportAvailable() {
		t.Skip("signal interception not available")
	}

	// This test verifies the signal handler can be started
	// Full e2e testing requires the wrapper which needs root

	engine, err := signal.NewEngine([]signal.SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL", "SIGTERM"},
			Target:   signal.TargetSpec{Type: "external"},
			Decision: "deny",
		},
	})
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test", 1234)
	handler := signal.NewHandler(engine, registry, nil)

	// Evaluate a signal context
	ctx := signal.SignalContext{
		PID:       1234,
		TargetPID: 9999, // External
		Signal:    15,   // SIGTERM
	}
	dec := handler.Evaluate(ctx)
	assert.Equal(t, signal.DecisionDeny, dec.Action)
}
```

**Step 2: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go test ./internal/api/... -run TestSignalFilterIntegration -v -tags integration`
Expected: PASS (or skip if not available)

**Step 3: Commit**

```bash
git add internal/api/signal_integration_test.go
git commit -m "test(signal): add integration test for signal filter"
```

---

## Task 11: Run Full Test Suite and Verify

**Step 1: Run all tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go test ./... -v 2>&1 | tail -50`
Expected: All tests pass

**Step 2: Verify Windows cross-compilation**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && GOOS=windows go build ./...`
Expected: PASS

**Step 3: Verify build**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-runtime && go build ./...`
Expected: PASS

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Extend wrapper config | core.go, config.go |
| 2 | Install signal filter in wrapper | main.go |
| 3 | Add signal handler to API | signal_handler_linux.go, signal_handler_stub.go |
| 4 | Add signal fields to extraProcConfig | exec.go |
| 5 | Start signal handler in runCommandWithResources | exec.go |
| 6 | Wire signal filter in core exec flow | core.go |
| 7 | Handle second FD in wrapper | main.go |
| 8 | Update core for separate socket | core.go |
| 9 | Update wrapper for separate socket | main.go |
| 10 | Write integration test | signal_integration_test.go |
| 11 | Run full test suite | - |
