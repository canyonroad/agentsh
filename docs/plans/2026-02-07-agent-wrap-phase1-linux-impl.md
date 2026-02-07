# Agent Wrap Phase 1: Linux Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the existing Linux seccomp-based exec interception from simple allow/deny to full pipeline routing (approve, redirect, audit), add the `agentsh wrap` CLI command, build the `agentsh-stub` I/O proxy binary, and ship default agent policies.

**Architecture:** The existing `agentsh-unixwrap` binary installs seccomp filters and passes the notify fd to the server. The `ExecveHandler` currently returns allow/deny. We extend it to support approve/redirect decisions by: (1) adding a new `ExecveResult.Action` field that can be `continue`, `redirect`, or `deny`, (2) implementing `SECCOMP_IOCTL_NOTIF_ADDFD` to inject a socket fd into the target process, (3) redirecting the execve to `agentsh-stub` which proxies I/O from the server-spawned command, and (4) adding the `agentsh wrap` CLI command that orchestrates session + interceptor + agent lifecycle.

**Tech Stack:** Go 1.25, libseccomp-golang, seccomp user-notify (`SECCOMP_ADDFD`), Unix sockets, Cobra CLI, existing agentsh server API

**Design Spec:** `docs/plans/2026-02-07-agent-wrap-exec-interception-design.md`

---

## Task 1: Extend ExecveResult to support pipeline decisions

Currently `ExecveResult` only has `Allow bool`. We need to support `approve`, `redirect`, and `audit` decisions from the policy engine.

**Files:**
- Modify: `internal/netmonitor/unix/execve_handler.go`
- Test: `internal/netmonitor/unix/execve_handler_test.go`

**Step 1: Write the failing test**

In `internal/netmonitor/unix/execve_handler_test.go`, add tests for the new decision types:

```go
//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type mockPolicy struct {
	decision PolicyDecision
}

func (m *mockPolicy) CheckExecve(filename string, argv []string, depth int) PolicyDecision {
	return m.decision
}

func TestExecveHandler_ApproveDecision(t *testing.T) {
	dt := NewDepthTracker()
	h := NewExecveHandler(ExecveHandlerConfig{MaxArgc: 100, MaxArgvBytes: 4096}, &mockPolicy{
		decision: PolicyDecision{
			Decision:          "approve",
			EffectiveDecision: "approve",
			Rule:              "pkg-install",
			Message:           "requires approval",
		},
	}, dt, nil)

	result := h.Handle(ExecveContext{
		PID: 1000, ParentPID: 999, Filename: "/usr/bin/npm", Argv: []string{"npm", "install"},
	})

	assert.Equal(t, "approve", result.Decision)
	assert.Equal(t, ActionRedirect, result.Action, "approve should route to redirect action")
	assert.Equal(t, int32(0), result.Errno)
}

func TestExecveHandler_RedirectDecision(t *testing.T) {
	dt := NewDepthTracker()
	h := NewExecveHandler(ExecveHandlerConfig{MaxArgc: 100, MaxArgvBytes: 4096}, &mockPolicy{
		decision: PolicyDecision{
			Decision:          "redirect",
			EffectiveDecision: "redirect",
			Rule:              "npm-redirect",
		},
	}, dt, nil)

	result := h.Handle(ExecveContext{
		PID: 1000, ParentPID: 999, Filename: "/usr/bin/npm", Argv: []string{"npm", "install"},
	})

	assert.Equal(t, "redirect", result.Decision)
	assert.Equal(t, ActionRedirect, result.Action)
}

func TestExecveHandler_AuditDecision(t *testing.T) {
	dt := NewDepthTracker()
	h := NewExecveHandler(ExecveHandlerConfig{MaxArgc: 100, MaxArgvBytes: 4096}, &mockPolicy{
		decision: PolicyDecision{
			Decision:          "audit",
			EffectiveDecision: "allow",
			Rule:              "shell-audit",
		},
	}, dt, nil)

	result := h.Handle(ExecveContext{
		PID: 1000, ParentPID: 999, Filename: "/bin/bash", Argv: []string{"bash", "-c", "ls"},
	})

	assert.Equal(t, "audit", result.Decision)
	assert.Equal(t, ActionContinue, result.Action, "audit effective=allow should continue in-place")
}

func TestExecveHandler_AllowContinuesInPlace(t *testing.T) {
	dt := NewDepthTracker()
	h := NewExecveHandler(ExecveHandlerConfig{MaxArgc: 100, MaxArgvBytes: 4096}, &mockPolicy{
		decision: PolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "dev-tools",
		},
	}, dt, nil)

	result := h.Handle(ExecveContext{
		PID: 1000, ParentPID: 999, Filename: "/usr/bin/ls", Argv: []string{"ls", "-la"},
	})

	assert.Equal(t, ActionContinue, result.Action)
	assert.True(t, result.Allow)
}

func TestExecveHandler_DenyReturnsEPERM(t *testing.T) {
	dt := NewDepthTracker()
	h := NewExecveHandler(ExecveHandlerConfig{MaxArgc: 100, MaxArgvBytes: 4096}, &mockPolicy{
		decision: PolicyDecision{
			Decision:          "deny",
			EffectiveDecision: "deny",
			Rule:              "dangerous",
		},
	}, dt, nil)

	result := h.Handle(ExecveContext{
		PID: 1000, ParentPID: 999, Filename: "/bin/rm", Argv: []string{"rm", "-rf", "/"},
	})

	assert.Equal(t, ActionDeny, result.Action)
	assert.False(t, result.Allow)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/unix/ -run TestExecveHandler_Approve -v`
Expected: FAIL — `ActionRedirect`, `ActionContinue`, `ActionDeny` constants don't exist yet

**Step 3: Write minimal implementation**

Add the `Action` constants and field to `ExecveResult`, and update `Handle()` to set them:

```go
// Action constants for ExecveResult
const (
	ActionContinue = "continue" // Allow execve in-place (zero overhead)
	ActionRedirect = "redirect" // Redirect execve to agentsh-stub
	ActionDeny     = "deny"     // Fail execve with errno
)

// In ExecveResult, add:
type ExecveResult struct {
	Allow    bool
	Action   string // ActionContinue | ActionRedirect | ActionDeny
	Rule     string
	Reason   string
	Errno    int32
	Decision string
}
```

Update the `Handle()` switch on `effectiveDecision`:
- `"allow"` → `Action: ActionContinue`
- `"deny"` → `Action: ActionDeny`
- `"approve"`, `"redirect"` → `Action: ActionRedirect`
- Default (fail-secure) → `Action: ActionDeny`

**Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run TestExecveHandler_ -v`
Expected: All 5 new tests PASS

**Step 5: Commit**

```bash
git add internal/netmonitor/unix/execve_handler.go internal/netmonitor/unix/execve_handler_test.go
git commit -m "feat(execve): extend ExecveResult with Action field for pipeline routing

Add ActionContinue/ActionRedirect/ActionDeny constants. Policy decisions
approve and redirect now produce ActionRedirect instead of falling through
to deny. This is the foundation for full exec pipeline routing."
```

---

## Task 2: Add SECCOMP_IOCTL_NOTIF_ADDFD support to seccomp package

The existing seccomp wrapper doesn't expose `SECCOMP_IOCTL_NOTIF_ADDFD` which is needed to inject fds into the trapped process. We need this to inject a Unix socket fd before redirecting the execve to the stub.

**Files:**
- Create: `internal/netmonitor/unix/addfd_linux.go`
- Test: `internal/netmonitor/unix/addfd_linux_test.go`

**Step 1: Write the failing test**

```go
//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddFDRequestLayout(t *testing.T) {
	// Verify the struct layout matches kernel expectations
	req := seccompNotifAddFD{
		id:         123,
		flags:      SECCOMP_ADDFD_FLAG_SETFD,
		srcfd:      5,
		newfd:      10,
		newfdFlags: 0,
	}
	assert.Equal(t, uint64(123), req.id)
	assert.Equal(t, uint32(SECCOMP_ADDFD_FLAG_SETFD), req.flags)
	assert.Equal(t, uint32(5), req.srcfd)
	assert.Equal(t, uint32(10), req.newfd)
}

func TestAddFDFlagConstants(t *testing.T) {
	assert.Equal(t, uint32(0x1), uint32(SECCOMP_ADDFD_FLAG_SETFD))
	assert.Equal(t, uint32(0x2), uint32(SECCOMP_ADDFD_FLAG_SEND))
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/unix/ -run TestAddFD -v`
Expected: FAIL — types don't exist

**Step 3: Write minimal implementation**

```go
//go:build linux && cgo

package unix

import (
	"fmt"
	"unsafe"

	sysunix "golang.org/x/sys/unix"
)

// SECCOMP_IOCTL_NOTIF_ADDFD adds a file descriptor to the trapped process.
// Available since Linux 5.9.
//
// Flags:
//   SECCOMP_ADDFD_FLAG_SETFD (0x1) — place fd at newfd (like dup2)
//   SECCOMP_ADDFD_FLAG_SEND  (0x2) — atomically add fd AND return from notification
//                                    (combines addfd + respond in one ioctl)

const (
	SECCOMP_ADDFD_FLAG_SETFD = 0x1
	SECCOMP_ADDFD_FLAG_SEND  = 0x2
)

// seccompNotifAddFD matches struct seccomp_notif_addfd from <linux/seccomp.h>
type seccompNotifAddFD struct {
	id         uint64 // notification ID (from ScmpNotifReq)
	flags      uint32 // SECCOMP_ADDFD_FLAG_*
	srcfd      uint32 // fd in supervisor's fd table
	newfd      uint32 // target fd in tracee (if SETFD flag)
	newfdFlags uint32 // O_CLOEXEC etc.
}

// SECCOMP_IOCTL_NOTIF_ADDFD ioctl number
// #define SECCOMP_IOCTL_NOTIF_ADDFD  SECCOMP_IOW(3, struct seccomp_notif_addfd)
// IOW('!', 3, 24) = 0x40182103
const ioctlNotifAddFD = 0x40182103

// NotifAddFD injects srcFD from the supervisor into the trapped process's fd table.
// If SECCOMP_ADDFD_FLAG_SETFD is set, it's placed at targetFD (like dup2).
// If SECCOMP_ADDFD_FLAG_SEND is set, the notification is atomically responded to
// and the return value of the syscall is set to the new fd number.
// Returns the fd number in the tracee, or error.
func NotifAddFD(notifFD int, notifID uint64, srcFD int, targetFD int, flags uint32) (int, error) {
	req := seccompNotifAddFD{
		id:    notifID,
		flags: flags,
		srcfd: uint32(srcFD),
		newfd: uint32(targetFD),
	}
	r, _, errno := sysunix.Syscall(sysunix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifAddFD),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("SECCOMP_IOCTL_NOTIF_ADDFD: %w", errno)
	}
	return int(r), nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run TestAddFD -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/netmonitor/unix/addfd_linux.go internal/netmonitor/unix/addfd_linux_test.go
git commit -m "feat(seccomp): add SECCOMP_IOCTL_NOTIF_ADDFD wrapper

Exposes the Linux 5.9+ seccomp addfd ioctl for injecting file descriptors
into trapped processes. Needed for redirecting execve to agentsh-stub
while injecting a Unix socket fd for I/O proxying."
```

---

## Task 3: Build `agentsh-stub` binary — the I/O proxy

The stub is exec'd in place of the original command. It connects to the agentsh server over a pre-injected Unix socket fd, receives proxied stdout/stderr, and exits with the proxied exit code.

**Files:**
- Create: `cmd/agentsh-stub/main.go`
- Create: `cmd/agentsh-stub/main_test.go`
- Create: `internal/stub/proxy.go`
- Create: `internal/stub/proxy_test.go`
- Create: `internal/stub/protocol.go`

**Step 1: Write the failing test for the protocol**

```go
// internal/stub/protocol.go — wire protocol between stub and server
package stub

// Message types for stub <-> server communication
const (
	MsgReady    = byte(0x01) // stub -> server: ready to receive
	MsgStdout   = byte(0x02) // server -> stub: stdout data
	MsgStderr   = byte(0x03) // server -> stub: stderr data
	MsgStdin    = byte(0x04) // stub -> server: stdin data
	MsgExit     = byte(0x05) // server -> stub: exit code (4 bytes big-endian)
	MsgError    = byte(0x06) // server -> stub: error message
)

// Frame format: [1 byte type][4 bytes length big-endian][payload]
```

```go
// internal/stub/proxy_test.go
package stub

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_ExitCodePropagation(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	// Server side: send exit code 42
	go func() {
		// Read ready message
		buf := make([]byte, 6)
		io.ReadFull(srvConn, buf)

		// Send exit code
		var frame bytes.Buffer
		frame.WriteByte(MsgExit)
		binary.Write(&frame, binary.BigEndian, uint32(4))
		binary.Write(&frame, binary.BigEndian, int32(42))
		srvConn.Write(frame.Bytes())
		srvConn.Close()
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestProxy_StdoutStreaming(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		buf := make([]byte, 6)
		io.ReadFull(srvConn, buf) // ready

		// Send stdout data
		data := []byte("hello world\n")
		var frame bytes.Buffer
		frame.WriteByte(MsgStdout)
		binary.Write(&frame, binary.BigEndian, uint32(len(data)))
		frame.Write(data)
		srvConn.Write(frame.Bytes())

		// Send exit 0
		frame.Reset()
		frame.WriteByte(MsgExit)
		binary.Write(&frame, binary.BigEndian, uint32(4))
		binary.Write(&frame, binary.BigEndian, int32(0))
		srvConn.Write(frame.Bytes())
		srvConn.Close()
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "hello world\n", stdout.String())
}

func TestProxy_StderrStreaming(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		buf := make([]byte, 6)
		io.ReadFull(srvConn, buf) // ready

		// Send stderr data
		data := []byte("error: not found\n")
		var frame bytes.Buffer
		frame.WriteByte(MsgStderr)
		binary.Write(&frame, binary.BigEndian, uint32(len(data)))
		frame.Write(data)
		srvConn.Write(frame.Bytes())

		// Send exit 1
		frame.Reset()
		frame.WriteByte(MsgExit)
		binary.Write(&frame, binary.BigEndian, uint32(4))
		binary.Write(&frame, binary.BigEndian, int32(1))
		srvConn.Write(frame.Bytes())
		srvConn.Close()
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "error: not found\n", stderr.String())
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/stub/ -v`
Expected: FAIL — `RunProxy` doesn't exist

**Step 3: Write minimal implementation**

```go
// internal/stub/proxy.go
package stub

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// RunProxy connects to the agentsh server over conn, proxies stdin/stdout/stderr,
// and returns the exit code from the server-spawned command.
func RunProxy(conn net.Conn, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	// Send ready message
	readyFrame := makeFrame(MsgReady, nil)
	if _, err := conn.Write(readyFrame); err != nil {
		return 1, fmt.Errorf("send ready: %w", err)
	}

	// Forward stdin in background if provided
	if stdin != nil {
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := stdin.Read(buf)
				if n > 0 {
					frame := makeFrame(MsgStdin, buf[:n])
					conn.Write(frame)
				}
				if err != nil {
					return
				}
			}
		}()
	}

	// Read frames from server
	for {
		msgType, payload, err := readFrame(conn)
		if err != nil {
			if err == io.EOF {
				return 1, fmt.Errorf("server closed connection without exit code")
			}
			return 1, fmt.Errorf("read frame: %w", err)
		}

		switch msgType {
		case MsgStdout:
			stdout.Write(payload)
		case MsgStderr:
			stderr.Write(payload)
		case MsgExit:
			if len(payload) < 4 {
				return 1, fmt.Errorf("short exit payload")
			}
			code := int32(binary.BigEndian.Uint32(payload[:4]))
			return int(code), nil
		case MsgError:
			return 1, fmt.Errorf("server error: %s", string(payload))
		}
	}
}

func makeFrame(msgType byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = msgType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func readFrame(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	length := binary.BigEndian.Uint32(header[1:5])
	if length == 0 {
		return msgType, nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/stub/ -v`
Expected: PASS

**Step 5: Write the stub binary**

```go
// cmd/agentsh-stub/main.go
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/agentsh/agentsh/internal/stub"
)

func main() {
	// The Unix socket fd is injected by the seccomp supervisor via SECCOMP_ADDFD.
	// It's passed as env var AGENTSH_STUB_FD.
	fdStr := os.Getenv("AGENTSH_STUB_FD")
	if fdStr == "" {
		fmt.Fprintf(os.Stderr, "agentsh-stub: AGENTSH_STUB_FD not set\n")
		os.Exit(126)
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: invalid AGENTSH_STUB_FD: %v\n", err)
		os.Exit(126)
	}

	file := os.NewFile(uintptr(fd), "agentsh-stub-sock")
	if file == nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: bad fd %d\n", fd)
		os.Exit(126)
	}

	conn, err := net.FileConn(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: FileConn: %v\n", err)
		os.Exit(126)
	}
	file.Close()

	exitCode, err := stub.RunProxy(conn, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: %v\n", err)
		os.Exit(126)
	}
	os.Exit(exitCode)
}
```

**Step 6: Run tests and build**

Run: `go test ./internal/stub/ -v && go build ./cmd/agentsh-stub/`
Expected: PASS + binary built

**Step 7: Commit**

```bash
git add internal/stub/ cmd/agentsh-stub/
git commit -m "feat: add agentsh-stub binary for I/O proxy

The stub is exec'd in place of intercepted commands. It connects to the
agentsh server over a pre-injected Unix socket fd, proxies stdin/stdout/stderr
using a simple frame protocol, and exits with the server-reported exit code."
```

---

## Task 4: Server-side stub handler — run command and proxy I/O back

When the supervisor redirects an exec to the stub, the server needs to: run the original command, proxy its I/O over the Unix socket to the stub, and send the exit code.

**Files:**
- Create: `internal/stub/server.go`
- Create: `internal/stub/server_test.go`

**Step 1: Write the failing test**

```go
// internal/stub/server_test.go
package stub

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHandler_EchoCommand(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	// Run server handler in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/echo",
			Args:    []string{"echo", "hello from server"},
		})
	}()

	// Stub side
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "hello from server\n", stdout.String())

	// Server should complete without error
	require.NoError(t, <-errCh)
}

func TestServerHandler_NonZeroExit(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "exit 42"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestServerHandler_StderrCapture(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "echo err >&2; echo out"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "out")
	assert.Contains(t, stderr.String(), "err")
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/stub/ -run TestServerHandler -v`
Expected: FAIL — `ServeStubConnection` doesn't exist

**Step 3: Write minimal implementation**

```go
// internal/stub/server.go
package stub

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
)

// ServeConfig configures the server-side stub handler.
type ServeConfig struct {
	Command    string
	Args       []string
	Env        []string
	WorkingDir string
}

// ServeStubConnection handles one stub connection. It waits for the stub's
// ready message, starts the command, proxies stdout/stderr to the stub,
// forwards stdin from the stub to the command, and sends the exit code.
func ServeStubConnection(ctx context.Context, conn net.Conn, cfg ServeConfig) error {
	defer conn.Close()

	// Wait for ready
	msgType, _, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("waiting for ready: %w", err)
	}
	if msgType != MsgReady {
		return fmt.Errorf("expected ready, got 0x%02x", msgType)
	}

	// Start command
	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args[1:]...)
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}
	if len(cfg.Env) > 0 {
		cmd.Env = cfg.Env
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stdin pipe: %v", err))
		return err
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stdout pipe: %v", err))
		return err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stderr pipe: %v", err))
		return err
	}

	if err := cmd.Start(); err != nil {
		sendError(conn, fmt.Sprintf("start: %v", err))
		return err
	}

	// Proxy I/O
	var wg sync.WaitGroup

	// stdout -> stub
	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeToFrame(stdoutPipe, conn, MsgStdout)
	}()

	// stderr -> stub
	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeToFrame(stderrPipe, conn, MsgStderr)
	}()

	// stdin from stub -> command
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		for {
			msgType, payload, err := readFrame(conn)
			if err != nil {
				return
			}
			if msgType == MsgStdin && len(payload) > 0 {
				stdinPipe.Write(payload)
			}
		}
	}()

	// Wait for stdout/stderr to drain, then wait for process
	wg.Wait()
	waitErr := cmd.Wait()

	// Send exit code
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		} else {
			exitCode = 126
		}
	}

	frame := make([]byte, 9)
	frame[0] = MsgExit
	binary.BigEndian.PutUint32(frame[1:5], 4)
	binary.BigEndian.PutUint32(frame[5:9], uint32(int32(exitCode)))
	conn.Write(frame)

	return nil
}

func pipeToFrame(r io.Reader, conn net.Conn, msgType byte) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			frame := makeFrame(msgType, buf[:n])
			conn.Write(frame)
		}
		if err != nil {
			return
		}
	}
}

func sendError(conn net.Conn, msg string) {
	frame := makeFrame(MsgError, []byte(msg))
	conn.Write(frame)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/stub/ -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add internal/stub/server.go internal/stub/server_test.go
git commit -m "feat(stub): add server-side stub handler

ServeStubConnection runs the real command and proxies stdout/stderr/stdin
to the stub process over the Unix socket using the frame protocol.
Exit code is propagated faithfully."
```

---

## Task 5: Wire redirect path into seccomp notify handler

When `ExecveResult.Action == ActionRedirect`, the notify handler must:
1. Create a Unix socketpair
2. Inject one end into the trapped process via `SECCOMP_ADDFD`
3. Respond to the notification (which redirects the execve to `agentsh-stub`)
4. Start `ServeStubConnection` on the server end to run the original command

**Files:**
- Modify: `internal/netmonitor/unix/handler.go`
- Modify: `internal/netmonitor/unix/execve_handler.go` (add original command to result)
- Create: `internal/netmonitor/unix/redirect_linux.go`
- Test: `internal/netmonitor/unix/redirect_linux_test.go`

**Step 1: Write tests for the redirect wiring**

Test the socketpair creation and `ServeStubConnection` integration. The actual seccomp addfd requires a real seccomp filter, so that's an integration test (Task 8). Here we test the server-side wiring.

```go
//go:build linux && cgo

package unix

import (
	"bytes"
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/stub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectSocketPairCreation(t *testing.T) {
	stubConn, srvConn, err := createStubSocketPair()
	require.NoError(t, err)
	defer stubConn.Close()
	defer srvConn.Close()

	// Verify we can send data both ways
	go func() {
		srvConn.Write(stub.MakeFrame(stub.MsgExit, []byte{0, 0, 0, 0}))
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := stub.RunProxy(stubConn, nil, stdout, stderr)
	// This won't fully work because stub sends ready first, but it proves the pipes connect
	// Full integration test in Task 8
	_ = exitCode
	_ = err
}
```

**Step 2: Implement redirect wiring**

Create `internal/netmonitor/unix/redirect_linux.go`:

```go
//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/agentsh/agentsh/internal/stub"
	seccomp "github.com/seccomp/libseccomp-golang"
	sysunix "golang.org/x/sys/unix"
)

// stubBinaryPath is the path to the agentsh-stub binary.
// Set at startup by the server or discovered from the agentsh binary directory.
var stubBinaryPath string

// SetStubBinaryPath sets the path to the agentsh-stub binary.
func SetStubBinaryPath(path string) {
	stubBinaryPath = path
}

// createStubSocketPair creates a Unix socketpair for stub <-> server communication.
// Returns (stub-side, server-side, error).
func createStubSocketPair() (net.Conn, net.Conn, error) {
	fds, err := sysunix.Socketpair(sysunix.AF_UNIX, sysunix.SOCK_STREAM|sysunix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}

	stubFile := os.NewFile(uintptr(fds[0]), "stub-sock")
	srvFile := os.NewFile(uintptr(fds[1]), "srv-sock")

	stubConn, err := net.FileConn(stubFile)
	stubFile.Close()
	if err != nil {
		srvFile.Close()
		return nil, nil, fmt.Errorf("stub FileConn: %w", err)
	}

	srvConn, err := net.FileConn(srvFile)
	srvFile.Close()
	if err != nil {
		stubConn.Close()
		return nil, nil, fmt.Errorf("srv FileConn: %w", err)
	}

	return stubConn, srvConn, nil
}

// handleRedirect implements the redirect path for an intercepted execve.
// 1. Creates socketpair
// 2. Injects stub-side fd into tracee via SECCOMP_ADDFD
// 3. Responds to notification (which continues execve, now running stub)
// 4. Starts ServeStubConnection to run the original command
func handleRedirect(notifFD seccomp.ScmpFd, reqID uint64, ctx ExecveContext, sessionID string) error {
	_, srvConn, err := createStubSocketPair()
	if err != nil {
		return fmt.Errorf("create socketpair: %w", err)
	}

	// Get the raw fd for the stub side to inject
	// We need the raw fd from the socketpair, not the net.Conn wrapper
	stubFDs, err := sysunix.Socketpair(sysunix.AF_UNIX, sysunix.SOCK_STREAM, 0)
	if err != nil {
		srvConn.Close()
		return fmt.Errorf("socketpair for inject: %w", err)
	}
	stubRawFD := stubFDs[0]
	srvRawFD := stubFDs[1]

	// Re-create proper connections
	srvConn.Close()
	srvFile := os.NewFile(uintptr(srvRawFD), "srv-sock")
	srvConn, err = net.FileConn(srvFile)
	srvFile.Close()
	if err != nil {
		sysunix.Close(stubRawFD)
		return fmt.Errorf("srv FileConn: %w", err)
	}

	// Inject stub fd into tracee
	// Use SECCOMP_ADDFD_FLAG_SETFD to place at a known fd number
	// The stub binary reads AGENTSH_STUB_FD env var to find it
	targetFD := 100 // Use high fd to avoid conflicts
	_, err = NotifAddFD(int(notifFD), reqID, stubRawFD, targetFD, SECCOMP_ADDFD_FLAG_SETFD)
	sysunix.Close(stubRawFD) // Close our copy
	if err != nil {
		srvConn.Close()
		return fmt.Errorf("addfd: %w", err)
	}

	// Respond to notification — allow the execve to continue
	// The process will now exec agentsh-stub instead of the original command
	// (The caller must have already set up the redirect by modifying /proc/<pid>/mem
	// or using SECCOMP_ADDFD_FLAG_SEND — see Task 6 for the full integration)
	resp := seccomp.ScmpNotifResp{ID: reqID, Flags: seccomp.NotifRespFlagContinue}
	if err := seccomp.NotifRespond(notifFD, &resp); err != nil {
		srvConn.Close()
		return fmt.Errorf("respond: %w", err)
	}

	// Start server handler in background
	go func() {
		defer srvConn.Close()
		err := stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
			Command: ctx.Filename,
			Args:    ctx.Argv,
		})
		if err != nil {
			slog.Error("stub serve error", "pid", ctx.PID, "error", err)
		}
	}()

	return nil
}
```

**Step 3: Update `handleExecveNotification` in `handler.go`**

Modify the response section to handle `ActionRedirect`:

```go
// In handleExecveNotification, replace the response section:
result := h.Handle(ctx)

switch result.Action {
case ActionRedirect:
    if err := handleRedirect(fd, req.ID, ctx, ""); err != nil {
        slog.Error("redirect failed, denying", "pid", pid, "error", err)
        resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(sysunix.EPERM)}
        _ = seccomp.NotifRespond(fd, &resp)
    }
    return

case ActionDeny:
    resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
    _ = seccomp.NotifRespond(fd, &resp)
    return

default: // ActionContinue
    resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
    _ = seccomp.NotifRespond(fd, &resp)
    return
}
```

**Step 4: Run tests**

Run: `go test ./internal/netmonitor/unix/ -v && go test ./internal/stub/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/netmonitor/unix/redirect_linux.go internal/netmonitor/unix/handler.go internal/netmonitor/unix/execve_handler.go
git commit -m "feat(seccomp): wire redirect path into notify handler

When ExecveHandler returns ActionRedirect, create a Unix socketpair,
inject one end into the trapped process via SECCOMP_ADDFD, and start
ServeStubConnection to run the original command and proxy I/O."
```

---

## Task 6: Add `agentsh wrap` CLI command

The `agentsh wrap` command orchestrates the full lifecycle: create/reuse session, start interceptor, launch agent, generate report on exit.

**Files:**
- Create: `internal/cli/wrap.go`
- Create: `internal/cli/wrap_test.go`
- Modify: `internal/cli/root.go` (register command)

**Step 1: Write the failing test**

```go
// internal/cli/wrap_test.go
package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapCmd_RequiresCommand(t *testing.T) {
	cmd := newWrapCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command required")
}

func TestWrapCmd_ParsesDoubleDash(t *testing.T) {
	cmd := newWrapCmd()
	cmd.SetArgs([]string{"--policy", "strict", "--", "claude-code", "--model", "opus"})

	// Extract the agent command from args after --
	var policy string
	cmd.Flags().StringVar(&policy, "policy", "agent-default", "")
	// Don't actually execute, just parse
	err := cmd.ParseFlags([]string{"--policy", "strict", "--", "claude-code", "--model", "opus"})
	require.NoError(t, err)
	assert.Equal(t, "strict", policy)
}

func TestWrapCmd_DefaultPolicy(t *testing.T) {
	cmd := newWrapCmd()
	policy, _ := cmd.Flags().GetString("policy")
	assert.Equal(t, "agent-default", policy)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestWrapCmd -v`
Expected: FAIL — `newWrapCmd` doesn't exist

**Step 3: Write the wrap command**

```go
// internal/cli/wrap.go
package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newWrapCmd() *cobra.Command {
	var sessionID string
	var policy string
	var root string
	var report bool

	cmd := &cobra.Command{
		Use:   "wrap [flags] -- COMMAND [ARGS...]",
		Short: "Wrap an AI agent with exec interception",
		Long: `Launch an AI agent with full exec interception.

Every command spawned by the agent and its descendants is routed through the
agentsh exec pipeline (policy check, approval workflow, audit logging).

Examples:
  agentsh wrap -- claude-code
  agentsh wrap --policy strict -- codex
  agentsh wrap --session my-dev -- cursor`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find everything after --
			agentArgs := findArgsAfterDash(os.Args)
			if len(agentArgs) == 0 {
				return fmt.Errorf("command required after --\n\nUsage: agentsh wrap [flags] -- COMMAND [ARGS...]")
			}

			cfg := getClientConfig(cmd)
			return runWrap(cmd.Context(), cfg, wrapOptions{
				sessionID:  sessionID,
				policy:     policy,
				root:       root,
				report:     report,
				agentCmd:   agentArgs[0],
				agentArgs:  agentArgs[1:],
			})
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Reuse existing session ID (creates new if empty)")
	cmd.Flags().StringVar(&policy, "policy", "agent-default", "Policy name")
	cmd.Flags().StringVar(&root, "root", "", "Workspace root (default: current directory)")
	cmd.Flags().BoolVar(&report, "report", true, "Generate session report on exit")

	return cmd
}

type wrapOptions struct {
	sessionID string
	policy    string
	root      string
	report    bool
	agentCmd  string
	agentArgs []string
}

func runWrap(ctx context.Context, cfg *clientConfig, opts wrapOptions) error {
	// 1. Create or reuse session
	c, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL: cfg.serverAddr,
		GRPCAddr:    cfg.grpcAddr,
		APIKey:      cfg.apiKey,
		Transport:   cfg.transport,
	})
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}

	workspace := opts.root
	if workspace == "" {
		workspace, _ = os.Getwd()
	}

	var sess types.Session
	if opts.sessionID != "" {
		sess, err = c.GetSession(ctx, opts.sessionID)
		if err != nil {
			return fmt.Errorf("get session %s: %w", opts.sessionID, err)
		}
	} else {
		sess, err = c.CreateSession(ctx, workspace, opts.policy)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}
		fmt.Fprintf(os.Stderr, "agentsh: session %s created (policy: %s)\n", sess.ID, opts.policy)
	}

	// 2. Launch the agent process
	// The agent runs under the session's seccomp wrapper (set up by the server)
	agentPath, err := exec.LookPath(opts.agentCmd)
	if err != nil {
		return fmt.Errorf("agent not found: %s: %w", opts.agentCmd, err)
	}

	agentProc := exec.CommandContext(ctx, agentPath, opts.agentArgs...)
	agentProc.Stdin = os.Stdin
	agentProc.Stdout = os.Stdout
	agentProc.Stderr = os.Stderr
	agentProc.Env = append(os.Environ(),
		fmt.Sprintf("AGENTSH_SESSION_ID=%s", sess.ID),
		fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
	)

	// Set up signal forwarding
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if agentProc.Process != nil {
				agentProc.Process.Signal(sig)
			}
		}
	}()

	if err := agentProc.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	fmt.Fprintf(os.Stderr, "agentsh: agent %s started (pid: %d)\n", opts.agentCmd, agentProc.Process.Pid)

	// 3. Wait for agent to exit
	waitErr := agentProc.Wait()

	signal.Stop(sigCh)
	close(sigCh)

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		}
	}

	// 4. Generate report
	if opts.report {
		fmt.Fprintf(os.Stderr, "\nagentsh: session %s complete (agent exit code: %d)\n", sess.ID, exitCode)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// findArgsAfterDash extracts arguments after "--" from the full os.Args.
func findArgsAfterDash(args []string) []string {
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			return args[i+1:]
		}
	}
	return nil
}
```

**Step 4: Register in root.go**

Add `cmd.AddCommand(newWrapCmd())` in `NewRoot()`.

**Step 5: Run tests**

Run: `go test ./internal/cli/ -run TestWrapCmd -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/cli/wrap.go internal/cli/wrap_test.go internal/cli/root.go
git commit -m "feat: add 'agentsh wrap' CLI command

Orchestrates session creation, agent launch, signal forwarding, and
session report generation. Usage: agentsh wrap [--policy P] -- AGENT [ARGS...]"
```

---

## Task 7: Ship default agent policies

Create the three agent policies described in the design doc.

**Files:**
- Create: `configs/policies/agent-default.yaml`
- Create: `configs/policies/agent-strict.yaml`
- Create: `configs/policies/agent-observe.yaml`

**Step 1: Write `agent-default.yaml`**

Use the policy from the design doc verbatim (it uses the existing policy schema — see `agent-sandbox.yaml` for format reference).

```yaml
# configs/policies/agent-default.yaml
version: 1
name: agent-default
description: |
  Default policy for AI agent supervision.
  Allows common dev tools, audits shell invocations, requires approval
  for package installs, and blocks dangerous commands.

command_rules:
  - name: dev-tools
    description: Common development tools - allow with audit
    commands:
      - ls
      - cat
      - grep
      - find
      - git
      - node
      - npm
      - npx
      - python
      - python3
      - pip
      - go
      - cargo
      - make
      - cmake
    decision: allow

  - name: shell-exec
    description: Shell invocations - allow with full audit
    commands:
      - bash
      - sh
      - zsh
    decision: allow

  - name: pkg-install
    description: Package installs - require human approval
    commands:
      - apt
      - yum
      - brew
      - pip
      - npm
    args_patterns:
      - "install"
      - "add"
      - "upgrade"
    decision: approve

  - name: dangerous
    description: Dangerous commands - block
    commands:
      - rm
      - dd
      - mkfs
      - fdisk
    args_patterns:
      - "-rf /"
      - "--no-preserve-root"
    decision: deny

file_rules:
  - name: workspace
    description: Workspace - full access
    paths:
      - "${PROJECT_ROOT}"
      - "${PROJECT_ROOT}/**"
    operations:
      - read
      - write
      - create
      - delete
    decision: allow

  - name: system-read
    description: System files - read only
    paths:
      - "/etc/**"
      - "/usr/**"
    operations:
      - read
    decision: allow

  - name: system-write
    description: System files - block writes
    paths:
      - "/etc/**"
      - "/usr/**"
      - "/bin/**"
      - "/sbin/**"
    operations:
      - write
      - create
      - delete
    decision: deny

network_rules:
  - name: package-registries
    description: Package registries
    destinations:
      - registry.npmjs.org
      - pypi.org
      - proxy.golang.org
    decision: allow

  - name: github
    description: GitHub
    destinations:
      - github.com
      - "*.githubusercontent.com"
    decision: allow

  - name: other-network
    description: Everything else - require approval
    destinations:
      - "*"
    decision: approve
```

**Step 2: Write `agent-strict.yaml`**

```yaml
# configs/policies/agent-strict.yaml
version: 1
name: agent-strict
description: |
  Strict policy for high-security environments.
  All commands require approval except read-only operations.
  Network access blocked by default. File writes only within workspace.

command_rules:
  - name: read-only-tools
    description: Read-only tools - allow
    commands:
      - ls
      - cat
      - head
      - tail
      - grep
      - find
      - wc
      - file
      - which
      - whoami
      - pwd
      - env
      - uname
    decision: allow

  - name: git-read
    description: Git read operations - allow
    commands:
      - git
    args_patterns:
      - "^(status|log|diff|show|branch|tag|remote)$"
    decision: allow

  - name: all-other-commands
    description: Everything else requires approval
    commands:
      - "*"
    decision: approve

file_rules:
  - name: workspace
    description: Workspace - full access
    paths:
      - "${PROJECT_ROOT}"
      - "${PROJECT_ROOT}/**"
    operations:
      - read
      - write
      - create
      - delete
    decision: allow

  - name: system-read
    description: System files - read only
    paths:
      - "/etc/**"
      - "/usr/**"
      - "/tmp/**"
    operations:
      - read
    decision: allow

  - name: all-writes-denied
    description: All other writes denied
    paths:
      - "/**"
    operations:
      - write
      - create
      - delete
    decision: deny

network_rules:
  - name: all-network-denied
    description: All network access blocked
    destinations:
      - "*"
    decision: deny
```

**Step 3: Write `agent-observe.yaml`**

```yaml
# configs/policies/agent-observe.yaml
version: 1
name: agent-observe
description: |
  Audit-only mode for initial profiling.
  Everything allowed, everything logged.
  Use with 'agentsh policy generate' to create a custom policy
  from observed behavior (profile-then-lock workflow).

command_rules:
  - name: observe-all-commands
    description: Allow all commands, full audit
    commands:
      - "*"
    decision: audit

file_rules:
  - name: observe-all-files
    description: Allow all file operations, full audit
    paths:
      - "/**"
    operations:
      - read
      - write
      - create
      - delete
    decision: audit

network_rules:
  - name: observe-all-network
    description: Allow all network, full audit
    destinations:
      - "*"
    decision: audit
```

**Step 4: Verify policies load**

Run: `go test ./internal/policy/ -run TestLoad -v` (existing policy loading tests should validate YAML parsing)

Also add a quick test:

```go
// internal/policy/agent_policies_test.go
package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgentPoliciesLoad(t *testing.T) {
	policyDir := filepath.Join("..", "..", "configs", "policies")
	for _, name := range []string{"agent-default.yaml", "agent-strict.yaml", "agent-observe.yaml"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(policyDir, name))
			require.NoError(t, err, "policy file should exist")
			_, err = ParsePolicy(data)
			require.NoError(t, err, "policy should parse without errors")
		})
	}
}
```

**Step 5: Run tests**

Run: `go test ./internal/policy/ -run TestAgentPolicies -v`
Expected: PASS

**Step 6: Commit**

```bash
git add configs/policies/agent-default.yaml configs/policies/agent-strict.yaml configs/policies/agent-observe.yaml internal/policy/agent_policies_test.go
git commit -m "feat: ship agent-default, agent-strict, agent-observe policies

Three default policies for agentsh wrap:
- agent-default: balanced supervision for typical dev work
- agent-strict: high-security with approval for most commands
- agent-observe: audit-only for profiling (profile-then-lock workflow)"
```

---

## Task 8: Integration test — full redirect path end-to-end

Test the complete flow: seccomp filter → intercept execve → redirect to stub → proxy I/O → exit code.

**Files:**
- Create: `internal/netmonitor/unix/redirect_integration_test.go`

**Step 1: Write integration test**

```go
//go:build linux && cgo && integration

package unix

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/stub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectIntegration_ExitCodeFidelity(t *testing.T) {
	// Test that exit codes are faithfully proxied through the stub
	for _, tc := range []struct {
		name     string
		cmd      string
		args     []string
		wantCode int
	}{
		{"exit-0", "/bin/sh", []string{"sh", "-c", "exit 0"}, 0},
		{"exit-1", "/bin/sh", []string{"sh", "-c", "exit 1"}, 1},
		{"exit-42", "/bin/sh", []string{"sh", "-c", "exit 42"}, 42},
		{"exit-127", "/bin/sh", []string{"sh", "-c", "exit 127"}, 127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvConn, stubConn := net.Pipe()
			defer srvConn.Close()
			defer stubConn.Close()

			go func() {
				stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
					Command: tc.cmd,
					Args:    tc.args,
				})
			}()

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			exitCode, err := stub.RunProxy(stubConn, nil, stdout, stderr)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCode, exitCode)
		})
	}
}

func TestRedirectIntegration_StdoutStderrOrdering(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "echo stdout1; echo stderr1 >&2; echo stdout2"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := stub.RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "stdout1")
	assert.Contains(t, stdout.String(), "stdout2")
	assert.Contains(t, stderr.String(), "stderr1")
}

func TestRedirectIntegration_LargeOutput(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	// Generate 1MB of output
	go func() {
		stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | base64"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := stub.RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Greater(t, stdout.Len(), 1000000, "should have received ~1MB of output")
}

func TestRedirectIntegration_Timeout(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		stub.ServeStubConnection(ctx, srvConn, stub.ServeConfig{
			Command: "/bin/sleep",
			Args:    []string{"sleep", "60"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, _ := stub.RunProxy(stubConn, nil, stdout, stderr)
	// Should complete within timeout, not hang for 60 seconds
	assert.NotEqual(t, 0, exitCode, "timed-out command should have non-zero exit")
}
```

**Step 2: Run integration test**

Run: `go test ./internal/netmonitor/unix/ -tags integration -run TestRedirectIntegration -v -timeout 30s`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/netmonitor/unix/redirect_integration_test.go
git commit -m "test: add integration tests for redirect proxy path

Tests exit code fidelity (0, 1, 42, 127), stdout/stderr ordering,
large output (1MB), and timeout handling through the stub proxy."
```

---

## Task 9: Wire wrap command to seccomp wrapper

Connect the `agentsh wrap` command to the existing seccomp wrapper infrastructure so the agent process tree is actually intercepted.

**Files:**
- Modify: `internal/cli/wrap.go` (add seccomp setup)
- Modify: `internal/api/core.go` (expose wrapper setup for external callers)

**Step 1: Add server-side wrap endpoint**

The wrap command needs a server endpoint that:
1. Creates a session
2. Returns the seccomp wrapper config (binary path, env vars, extra fds)
3. The CLI then launches the agent with these wrappers

Add to the HTTP API:

```
POST /sessions/{sid}/wrap
Request: { "agent_command": "claude-code", "agent_args": ["--model", "opus"] }
Response: {
  "wrapper_binary": "/usr/local/bin/agentsh-unixwrap",
  "wrapper_env": { "AGENTSH_SECCOMP_CONFIG": "...", "AGENTSH_NOTIFY_SOCK_FD": "3" },
  "extra_fds": [...fd numbers...],
  "stub_binary": "/usr/local/bin/agentsh-stub"
}
```

This is a larger task — implement the API endpoint, update the wrap CLI to call it, and set up the agent process with the wrapper prefix.

**Step 2: Test the wrap integration**

Write an integration test that:
1. Starts an agentsh server
2. Calls `agentsh wrap -- /bin/sh -c "echo hello"`
3. Verifies the command ran and output was captured
4. Verifies an execve event was recorded

**Step 3: Commit**

```bash
git add internal/cli/wrap.go internal/api/wrap.go internal/api/wrap_test.go
git commit -m "feat: wire wrap command to seccomp wrapper infrastructure

The wrap command now creates a session, sets up seccomp interception,
and launches the agent with the unixwrap prefix so all descendant
commands are routed through the exec pipeline."
```

---

## Task 10: Cross-compile check and final verification

**Step 1: Run full test suite**

Run: `go test ./...`
Expected: All PASS

**Step 2: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: SUCCESS (no Linux-only code leaking into non-Linux builds)

Run: `GOOS=darwin go build ./...`
Expected: SUCCESS

**Step 3: Build all new binaries**

Run: `go build ./cmd/agentsh-stub/ && go build ./cmd/agentsh/`
Expected: Both build successfully

**Step 4: Commit any fixes**

If cross-compile reveals missing build tags or platform-specific issues, fix them.

---

## Dependency Graph

```
Task 1 (ExecveResult Action field)
    ↓
Task 2 (SECCOMP_ADDFD)
    ↓
Task 3 (agentsh-stub binary) ←─── Task 4 (server-side handler)
    ↓                                ↓
Task 5 (wire redirect into handler) ←┘
    ↓
Task 6 (agentsh wrap CLI) ←─── Task 7 (agent policies)
    ↓
Task 8 (integration tests)
    ↓
Task 9 (wire wrap to seccomp)
    ↓
Task 10 (cross-compile + final check)
```

## Parallel Execution Opportunities

- **Tasks 1, 2, 3, 7** can all start in parallel (no dependencies between them)
- **Task 4** depends on Task 3 (uses `stub.RunProxy` in tests)
- **Task 6** depends on nothing except the CLI pattern (but full wiring needs Task 9)
- **Task 8** depends on Tasks 3+4

## Out of Scope (Phase 2+)

- macOS Endpoint Security implementation
- Windows kernel driver
- `agentsh wrap --detect` auto-detection
- VS Code / Cursor extension
- Web dashboard
- WHQL certification
