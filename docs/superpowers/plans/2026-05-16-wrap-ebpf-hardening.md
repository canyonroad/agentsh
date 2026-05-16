# Wrap eBPF Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `agentsh wrap` so wrapped agents receive session network proxy env and, on Linux, cannot exec the real agent until cgroup/eBPF setup has succeeded or explicitly degraded according to config.

**Architecture:** Keep proxy env injection in the CLI wrap launch path. Add a small Linux-only notify handoff helper package so the CLI, shim relay, and API agree on sending the seccomp notify fd plus wrapper PID metadata and receiving a server setup status. On the server, apply the existing cgroup/eBPF setup to the wrapper PID before acknowledging the wrapper, and clean it up when the notify handler exits.

**Tech Stack:** Go, Unix domain sockets with `SCM_RIGHTS`, cgroup v2 manager, existing cgroup eBPF connect/sendmsg programs, existing `agentsh-unixwrap` ACK handshake.

---

## File Structure

- Create `internal/wraphandoff/handoff_linux.go`
  - Linux-only helper for forwarding notify fds with wrapper PID metadata and one-byte server status.

- Create `internal/wraphandoff/handoff_linux_test.go`
  - Unit tests for metadata round trip, legacy fd-only receive, and status read/write behavior.

- Modify `internal/cli/wrap.go`
  - Keep `sess.ProxyURL` in `runWrap`.
  - Add and call a CLI env helper that injects network proxy variables.
  - Change `wrapLaunchConfig.postStart` to receive the wrapper child PID.

- Modify `internal/cli/wrap_linux.go`
  - Forward wrapper PID metadata to the server.
  - Wait for server setup success before ACKing `agentsh-unixwrap`.
  - Keep signal fd forwarding on the legacy no-status path.

- Modify `internal/cli/wrap_test.go`
  - Add proxy env helper tests.
  - Update postStart signature expectations where needed.

- Modify `internal/shim/kernelinstall/install_linux.go`
  - Use the same handoff helper for the shim notify relay.
  - Wait for server success before ACKing the wrapper.

- Modify `internal/shim/kernelinstall/install_linux_test.go`
  - Add server-reject coverage proving the shim does not ACK the wrapper.

- Modify `internal/api/wrap.go`
  - Receive notify fd metadata.
  - Reject required pre-ACK cgroup/eBPF setup when no wrapper PID is available.
  - Write server setup status to the CLI/shim relay.

- Modify `internal/api/wrap_linux.go`
  - Add cleanup support to `startNotifyHandlerForWrap`.
  - Apply cgroup/eBPF setup before the server success status is written.

- Modify `internal/api/wrap_linux_test.go`
  - Add metadata, server status, pre-ACK ordering, missing PID, and cleanup tests.

- Modify `internal/api/cgroups.go`
  - Treat eBPF-enabled setup as requiring a concrete cgroup, even when resource limits are empty.

- Modify or create `internal/api/cgroups_test.go`
  - Add focused tests for eBPF requiring a concrete cgroup.

- Modify `docs/ebpf.md`
  - Document `agentsh wrap` coverage and the cgroups requirement.

---

### Task 1: Add CLI Network Proxy Env For Wrap

**Files:**
- Modify: `internal/cli/wrap.go`
- Modify: `internal/cli/wrap_test.go`

- [ ] **Step 1: Write failing proxy env helper tests**

Add these helpers near the existing `buildWrapEnv` tests in `internal/cli/wrap_test.go`:

```go
func envSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}
```

Add `strings` to the import block:

```go
import (
	"bytes"
	"context"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

Add these tests:

```go
func TestAppendWrapNetworkProxyEnv_AddsSessionProxyVars(t *testing.T) {
	env := appendWrapNetworkProxyEnv([]string{"PATH=/usr/bin"}, "http://127.0.0.1:18081")
	got := envSliceToMap(env)

	for _, key := range []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
	} {
		assert.Equal(t, "http://127.0.0.1:18081", got[key], key)
	}
	assert.Contains(t, got["NO_PROXY"], "localhost")
	assert.Contains(t, got["NO_PROXY"], "127.0.0.1")
	assert.Equal(t, got["NO_PROXY"], got["no_proxy"])
}

func TestAppendWrapNetworkProxyEnv_ReplacesInheritedProxyVars(t *testing.T) {
	env := appendWrapNetworkProxyEnv([]string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://stale",
		"https_proxy=http://stale",
		"NO_PROXY=example.test",
	}, "http://127.0.0.1:18081")
	got := envSliceToMap(env)

	assert.Equal(t, "http://127.0.0.1:18081", got["HTTP_PROXY"])
	assert.Equal(t, "http://127.0.0.1:18081", got["https_proxy"])
	assert.Contains(t, got["NO_PROXY"], "example.test")
	assert.Contains(t, got["NO_PROXY"], "localhost")
	assert.Contains(t, got["NO_PROXY"], "127.0.0.1")
}

func TestAppendWrapNetworkProxyEnv_NoProxyWhenSessionProxyEmpty(t *testing.T) {
	env := appendWrapNetworkProxyEnv([]string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://host-proxy",
	}, "")
	got := envSliceToMap(env)

	assert.Equal(t, "http://host-proxy", got["HTTP_PROXY"])
	assert.Equal(t, "/usr/bin", got["PATH"])
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
go test ./internal/cli -run 'TestAppendWrapNetworkProxyEnv' -count=1
```

Expected: compile failure because `appendWrapNetworkProxyEnv` does not exist.

- [ ] **Step 3: Implement the proxy env helper**

Add this helper after `buildWrapEnv` in `internal/cli/wrap.go`:

```go
func appendWrapNetworkProxyEnv(base []string, proxyURL string) []string {
	if strings.TrimSpace(proxyURL) == "" {
		return base
	}

	const noProxyDefault = "localhost,127.0.0.1"
	proxyKeys := map[string]struct{}{
		"HTTP_PROXY":  {},
		"HTTPS_PROXY": {},
		"ALL_PROXY":   {},
		"http_proxy":  {},
		"https_proxy": {},
		"all_proxy":   {},
		"NO_PROXY":    {},
		"no_proxy":    {},
	}

	out := make([]string, 0, len(base)+8)
	noProxy := ""
	for _, e := range base {
		key, val, found := strings.Cut(e, "=")
		if !found {
			out = append(out, e)
			continue
		}
		if strings.EqualFold(key, "NO_PROXY") {
			if noProxy == "" {
				noProxy = val
			}
			continue
		}
		if _, ok := proxyKeys[key]; ok {
			continue
		}
		out = append(out, e)
	}

	if noProxy == "" {
		noProxy = noProxyDefault
	} else {
		if !strings.Contains(noProxy, "localhost") {
			if !strings.HasSuffix(noProxy, ",") {
				noProxy += ","
			}
			noProxy += "localhost"
		}
		if !strings.Contains(noProxy, "127.0.0.1") {
			if !strings.HasSuffix(noProxy, ",") {
				noProxy += ","
			}
			noProxy += "127.0.0.1"
		}
	}

	out = append(out,
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("ALL_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("all_proxy=%s", proxyURL),
		fmt.Sprintf("NO_PROXY=%s", noProxy),
		fmt.Sprintf("no_proxy=%s", noProxy),
	)
	return out
}
```

- [ ] **Step 4: Wire the helper into `runWrap`**

In `internal/cli/wrap.go`, after this existing block:

```go
	sessID := sess.ID
	workspaceMount := sess.WorkspaceMount
	llmProxyURL := sess.LLMProxyURL
```

change it to:

```go
	sessID := sess.ID
	workspaceMount := sess.WorkspaceMount
	networkProxyURL := sess.ProxyURL
	llmProxyURL := sess.LLMProxyURL
```

Then, after the direct/wrapper `agentProc` is created and before the FUSE mount env block, add:

```go
	agentProc.Env = appendWrapNetworkProxyEnv(agentProc.Env, networkProxyURL)
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
go test ./internal/cli -run 'TestAppendWrapNetworkProxyEnv|TestBuildWrapEnv' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/wrap.go internal/cli/wrap_test.go
git commit -m "fix(wrap): inject network proxy env"
```

---

### Task 2: Add Linux Notify Handoff Helper

**Files:**
- Create: `internal/wraphandoff/handoff_linux.go`
- Create: `internal/wraphandoff/handoff_linux_test.go`

- [ ] **Step 1: Write failing handoff tests**

Create `internal/wraphandoff/handoff_linux_test.go`:

```go
//go:build linux

package wraphandoff

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func socketPairConns(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "handoff.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	clientCh := make(chan *net.UnixConn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := net.Dial("unix", path)
		if err != nil {
			errCh <- err
			return
		}
		clientCh <- c.(*net.UnixConn)
	}()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	var clientConn *net.UnixConn
	select {
	case clientConn = <-clientCh:
	case err := <-errCh:
		t.Fatalf("dial: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for client dial")
	}

	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	return clientConn, serverConn.(*net.UnixConn)
}

func TestNotifyHandoffRoundTripWithWrapperPID(t *testing.T) {
	client, server := socketPairConns(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	go func() {
		_ = SendNotifyFD(client, int(r.Fd()), Metadata{WrapperPID: 4321})
	}()

	fd, meta, hasMeta, err := RecvNotifyFD(server)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	if !hasMeta {
		t.Fatal("expected metadata")
	}
	if meta.WrapperPID != 4321 {
		t.Fatalf("WrapperPID = %d, want 4321", meta.WrapperPID)
	}
}

func TestSetupStatusRoundTrip(t *testing.T) {
	client, server := socketPairConns(t)

	go func() {
		_ = WriteStatus(server, true)
	}()
	if err := ReadStatus(client); err != nil {
		t.Fatalf("read success status: %v", err)
	}

	go func() {
		_ = WriteStatus(server, false)
	}()
	if err := ReadStatus(client); err == nil {
		t.Fatal("expected reject status error")
	}
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
go test ./internal/wraphandoff -count=1
```

Expected: package or symbol missing errors.

- [ ] **Step 3: Implement the helper**

Create `internal/wraphandoff/handoff_linux.go`:

```go
//go:build linux

package wraphandoff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	protocolMagic byte = 0xA7
	StatusReject  byte = 0
	StatusOK      byte = 1
)

type Metadata struct {
	WrapperPID int
}

func SendNotifyFD(conn *net.UnixConn, notifyFD int, meta Metadata) error {
	if conn == nil {
		return errors.New("nil unix connection")
	}
	if notifyFD < 0 {
		return fmt.Errorf("invalid notify fd %d", notifyFD)
	}
	payload := make([]byte, 5)
	payload[0] = protocolMagic
	binary.LittleEndian.PutUint32(payload[1:], uint32(meta.WrapperPID))
	rights := unix.UnixRights(notifyFD)
	_, _, err := conn.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		return fmt.Errorf("send notify fd: %w", err)
	}
	return nil
}

func RecvNotifyFD(conn *net.UnixConn) (*os.File, Metadata, bool, error) {
	if conn == nil {
		return nil, Metadata{}, false, errors.New("nil unix connection")
	}

	buf := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, Metadata{}, false, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return nil, Metadata{}, false, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, Metadata{}, false, fmt.Errorf("parse control message: %w", err)
	}
	fd := -1
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			fd = fds[0]
			break
		}
	}
	if fd < 0 {
		return nil, Metadata{}, false, errors.New("no fd in control message")
	}

	meta := Metadata{}
	hasMeta := n >= 5 && buf[0] == protocolMagic
	if hasMeta {
		meta.WrapperPID = int(binary.LittleEndian.Uint32(buf[1:5]))
	}
	return os.NewFile(uintptr(fd), "wrap-notif-fd"), meta, hasMeta, nil
}

func WriteStatus(w io.Writer, ok bool) error {
	if w == nil {
		return errors.New("nil writer")
	}
	b := StatusReject
	if ok {
		b = StatusOK
	}
	_, err := w.Write([]byte{b})
	return err
}

func ReadStatus(r io.Reader) error {
	if r == nil {
		return errors.New("nil reader")
	}
	buf := []byte{0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read setup status: %w", err)
	}
	switch buf[0] {
	case StatusOK:
		return nil
	case StatusReject:
		return errors.New("server rejected wrap setup")
	default:
		return fmt.Errorf("unexpected setup status byte %d", buf[0])
	}
}
```

- [ ] **Step 4: Run helper tests**

Run:

```bash
go test ./internal/wraphandoff -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wraphandoff/handoff_linux.go internal/wraphandoff/handoff_linux_test.go
git commit -m "internal: add wrap notify handoff protocol"
```

---

### Task 3: Make CLI Notify Forwarding Wait For Server Setup

**Files:**
- Modify: `internal/cli/wrap.go`
- Modify: `internal/cli/wrap_linux.go`
- Modify: `internal/cli/wrap_test.go`

- [ ] **Step 1: Update the launch config shape**

In `internal/cli/wrap.go`, change:

```go
	postStart   func()    // Called after the process starts (e.g., to forward notify fd)
```

to:

```go
	postStart   func(childPID int) // Called after process start to forward notify fd with child PID
```

Then change the call site in `runWrap` from:

```go
		if wrapCfg.postStart != nil {
			go wrapCfg.postStart()
		}
```

to:

```go
		if wrapCfg.postStart != nil {
			go wrapCfg.postStart(agentProc.Process.Pid)
		}
```

- [ ] **Step 2: Update Linux forwarder to send PID and wait for status**

In `internal/cli/wrap_linux.go`, add the import:

```go
	"github.com/agentsh/agentsh/internal/wraphandoff"
```

Change the notify `postStart` closure from:

```go
		postStart: func() {
```

to:

```go
		postStart: func(childPID int) {
```

Inside that closure, replace:

```go
			if err := forwardNotifyFD(notifySocket, notifyFD); err != nil {
				slog.Error("wrap: failed to forward notify fd to server", "error", err, "session_id", sessID)
				return
			}
			slog.Info("wrap: notify fd forwarded to server", "session_id", sessID, "socket", notifySocket)
```

with:

```go
			if err := forwardNotifyFDWithPID(notifySocket, notifyFD, childPID); err != nil {
				slog.Error("wrap: failed to forward notify fd to server", "error", err, "session_id", sessID)
				return
			}
			slog.Info("wrap: notify fd accepted by server", "session_id", sessID, "socket", notifySocket, "wrapper_pid", childPID)
```

Keep the existing wrapper ACK write after this block.

- [ ] **Step 3: Add PID-aware forward helper**

In `internal/cli/wrap_linux.go`, replace the existing `forwardNotifyFD` helper with two helpers:

```go
func forwardNotifyFDWithPID(socketPath string, notifyFD int, wrapperPID int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	if err := wraphandoff.SendNotifyFD(unixConn, notifyFD, wraphandoff.Metadata{WrapperPID: wrapperPID}); err != nil {
		return err
	}
	if err := wraphandoff.ReadStatus(unixConn); err != nil {
		return err
	}
	return nil
}

func forwardNotifyFD(socketPath string, notifyFD int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	file, err := unixConn.File()
	if err != nil {
		return fmt.Errorf("get file from connection: %w", err)
	}
	defer file.Close()

	rights := unix.UnixRights(notifyFD)
	if err := unix.Sendmsg(int(file.Fd()), []byte{0}, rights, nil, 0); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}
	return nil
}
```

The legacy `forwardNotifyFD` remains for signal fd forwarding.

- [ ] **Step 4: Add focused CLI forwarder tests**

Add Linux-only tests in `internal/cli/wrap_linux_test.go`. If the file does not exist, create it:

```go
//go:build linux

package cli

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/wraphandoff"
)

func TestForwardNotifyFDWithPIDWaitsForServerOK(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()
		unixConn := conn.(*net.UnixConn)
		fd, meta, hasMeta, err := wraphandoff.RecvNotifyFD(unixConn)
		if err != nil {
			t.Errorf("recv notify fd: %v", err)
			return
		}
		_ = fd.Close()
		if !hasMeta || meta.WrapperPID != 2468 {
			t.Errorf("metadata = %+v, hasMeta=%v", meta, hasMeta)
			return
		}
		_ = wraphandoff.WriteStatus(unixConn, true)
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468); err != nil {
		t.Fatalf("forward: %v", err)
	}
	<-serverDone
}

func TestForwardNotifyFDWithPIDRejectStatusReturnsError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		_ = wraphandoff.WriteStatus(unixConn, false)
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468); err == nil {
		t.Fatal("expected reject status error")
	}
}
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
go test ./internal/cli -run 'TestForwardNotifyFDWithPID|TestSetupWrapInterception|TestWrapLaunchConfig' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/wrap.go internal/cli/wrap_linux.go internal/cli/wrap_linux_test.go internal/cli/wrap_test.go
git commit -m "fix(wrap): wait for server notify setup"
```

---

### Task 4: Update Shim Relay To Use Server Setup Status

**Files:**
- Modify: `internal/shim/kernelinstall/install_linux.go`
- Modify: `internal/shim/kernelinstall/install_linux_test.go`

- [ ] **Step 1: Update shim forward helper to send wrapper PID**

In `internal/shim/kernelinstall/install_linux.go`, add:

```go
	"github.com/agentsh/agentsh/internal/wraphandoff"
```

Replace:

```go
	if fwdErr := forwardNotifyFD(notifySocket, notifyFD); fwdErr != nil {
```

with:

```go
	if fwdErr := forwardNotifyFDWithPID(notifySocket, notifyFD, cmd.Process.Pid); fwdErr != nil {
```

Replace the existing `forwardNotifyFD` helper with:

```go
func forwardNotifyFDWithPID(socketPath string, notifyFD int, wrapperPID int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	if err := wraphandoff.SendNotifyFD(unixConn, notifyFD, wraphandoff.Metadata{WrapperPID: wrapperPID}); err != nil {
		return err
	}
	if err := wraphandoff.ReadStatus(unixConn); err != nil {
		return err
	}
	return nil
}
```

- [ ] **Step 2: Add shim server-reject test**

Add a test near `TestInstall_RelayForwardFail_NoACK_ResultFailClosed` in `internal/shim/kernelinstall/install_linux_test.go`:

```go
func TestInstall_RelayServerReject_NoACK_ResultFailClosed(t *testing.T) {
	wrapperBin := buildFakeWrapperNoACKExit(t)

	notifyDir := t.TempDir()
	notifySocket := filepath.Join(notifyDir, "notify.sock")
	ln, err := net.Listen("unix", notifySocket)
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		_ = wraphandoff.WriteStatus(unixConn, false)
	}()

	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySocket,
		WrapperEnv:    map[string]string{},
	}
	handler, _ := makeWrapInitHandler(200, wrapResp)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Fatalf("expected ResultFailClosed, got %v (reason: %s)", res.Action, res.Reason)
	}
	if !strings.Contains(res.Reason, "server rejected wrap setup") {
		t.Fatalf("expected server rejection in reason, got %q", res.Reason)
	}
}
```

Add imports if missing:

```go
	"net"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/wraphandoff"
```

- [ ] **Step 3: Run focused shim tests**

Run:

```bash
go test ./internal/shim/kernelinstall -run 'TestInstall_RelayForwardFail_NoACK_ResultFailClosed|TestInstall_RelayServerReject_NoACK_ResultFailClosed' -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/shim/kernelinstall/install_linux.go internal/shim/kernelinstall/install_linux_test.go
git commit -m "fix(shim): wait for wrap setup status"
```

---

### Task 5: Server Receives Wrapper PID And Applies Pre-ACK Cgroup Setup

**Files:**
- Modify: `internal/api/wrap.go`
- Modify: `internal/api/wrap_linux.go`
- Modify: `internal/api/wrap_linux_test.go`

- [ ] **Step 1: Add cgroup setup hook and helper**

In `internal/api/wrap.go`, near `startNotifyHandlerForWrapHook`, add:

```go
	wrapCgroupSetupForNotifyHook = defaultWrapCgroupSetupForNotify
```

Add this helper near `acceptNotifyFD`:

```go
func wrapNeedsCgroupBeforeAck(a *App, s *session.Session) bool {
	if a == nil || a.cfg == nil {
		return false
	}
	if a.cfg.Sandbox.Network.EBPF.Required {
		return true
	}
	if !a.cfg.Sandbox.Cgroups.Enabled {
		return false
	}
	if a.cfg.Sandbox.Network.EBPF.Enabled || a.cfg.Sandbox.Network.EBPF.Enforce {
		return true
	}
	engine := a.policyEngineFor(s)
	if engine == nil {
		return false
	}
	lim := engine.Limits()
	return lim.MaxMemoryMB > 0 || lim.CPUQuotaPercent > 0 || lim.PidsMax > 0
}

func defaultWrapCgroupSetupForNotify(ctx context.Context, a *App, s *session.Session, sessionID string, wrapperPID int) (func() error, error) {
	if !wrapNeedsCgroupBeforeAck(a, s) {
		return nil, nil
	}
	if wrapperPID <= 0 {
		return nil, fmt.Errorf("wrap cgroup setup requires wrapper pid")
	}
	if a.cfg.Sandbox.Network.EBPF.Required && !a.cfg.Sandbox.Cgroups.Enabled {
		return nil, fmt.Errorf("ebpf required but sandbox.cgroups.enabled=false")
	}
	if !a.cfg.Sandbox.Cgroups.Enabled {
		return nil, nil
	}

	engine := a.policyEngineFor(s)
	lim := policy.Limits{}
	if engine != nil {
		lim = engine.Limits()
	}
	cmdID := "wrap-" + uuid.NewString()
	em := storeEmitter{store: a.store, broker: a.broker}
	return applyCgroupV2(ctx, em, a, sessionID, cmdID, wrapperPID, lim, a.metrics, engine)
}
```

Ensure `internal/api/wrap.go` imports `github.com/google/uuid` and already has `fmt`, `context`, `session`, and `policy` available. If `policy` is not imported in this file, add:

```go
	"github.com/agentsh/agentsh/internal/policy"
```

- [ ] **Step 2: Change notify handler signature to accept cleanup**

In `internal/api/wrap_linux.go`, change:

```go
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
```

to:

```go
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) {
```

Inside the goroutine, after the existing `defer notifyFD.Close()`, add:

```go
		if cleanup != nil {
			defer func() {
				if err := cleanup(); err != nil {
					slog.Warn("wrap: cgroup cleanup failed", "session_id", sessionID, "error", err)
				}
			}()
		}
```

Update the Windows and other platform stubs to accept the same `cleanup func() error` argument.

- [ ] **Step 3: Use the new handoff receive path in `acceptNotifyFD`**

In `internal/api/wrap.go`, add:

```go
	"github.com/agentsh/agentsh/internal/wraphandoff"
```

Replace the block that calls `unixConn.File()` and `recvFDFromConn(file)` with:

```go
	notifyFD, meta, hasMeta, err := wraphandoff.RecvNotifyFD(unixConn)
	if err != nil {
		slog.Debug("wrap: failed to receive notify fd", "session_id", sessionID, "error", err)
		_ = wraphandoff.WriteStatus(unixConn, false)
		return
	}
	if notifyFD == nil {
		slog.Debug("wrap: received nil notify fd", "session_id", sessionID)
		_ = wraphandoff.WriteStatus(unixConn, false)
		return
	}

	wrapperPID := notifyPeerPID
	if hasMeta && meta.WrapperPID > 0 {
		wrapperPID = meta.WrapperPID
	}

	var cleanup func() error
	if wrapNeedsCgroupBeforeAck(a, s) {
		if !hasMeta || meta.WrapperPID <= 0 {
			_ = notifyFD.Close()
			_ = wraphandoff.WriteStatus(unixConn, false)
			slog.Warn("wrap: rejecting notify setup without wrapper pid", "session_id", sessionID)
			return
		}
		cleanup, err = wrapCgroupSetupForNotifyHook(ctx, a, s, sessionID, wrapperPID)
		if err != nil {
			_ = notifyFD.Close()
			_ = wraphandoff.WriteStatus(unixConn, false)
			slog.Warn("wrap: cgroup setup failed before wrapper ACK", "session_id", sessionID, "wrapper_pid", wrapperPID, "error", err)
			return
		}
	}

	slog.Info("wrap: received notify fd", "session_id", sessionID, "fd", notifyFD.Fd(), "wrapper_pid", wrapperPID)

	startNotifyHandlerForWrapHook(ctx, notifyFD, sessionID, a, execveEnabled, wrapperPID, s, cleanup)
	if err := wraphandoff.WriteStatus(unixConn, true); err != nil {
		slog.Debug("wrap: failed to write setup status", "session_id", sessionID, "error", err)
	}
```

Remove the old `startNotifyHandlerForWrapHook(ctx, notifyFD, sessionID, a, execveEnabled, notifyPeerPID, s)` call.

- [ ] **Step 4: Update test hook signatures**

In `internal/api/wrap_linux_test.go`, update `withNotifyHandoffHook`:

```go
func withNotifyHandoffHook(t *testing.T) chan struct{} {
	t.Helper()

	called := make(chan struct{})
	prev := startNotifyHandlerForWrapHook
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) {
		if cleanup != nil {
			_ = cleanup()
		}
		if notifyFD != nil {
			_ = notifyFD.Close()
		}
		close(called)
	}
	t.Cleanup(func() {
		startNotifyHandlerForWrapHook = prev
	})
	return called
}
```

- [ ] **Step 5: Add server metadata and ordering tests**

Add this test to `internal/api/wrap_linux_test.go`:

```go
func TestAcceptNotifyFD_UsesMetadataWrapperPIDForCgroupBeforeAck(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	prevSetup := wrapCgroupSetupForNotifyHook
	prevStart := startNotifyHandlerForWrapHook
	setupCalled := make(chan int, 1)
	startCalled := make(chan struct{})
	wrapCgroupSetupForNotifyHook = func(ctx context.Context, a *App, s *session.Session, sessionID string, wrapperPID int) (func() error, error) {
		setupCalled <- wrapperPID
		return func() error { return nil }, nil
	}
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) {
		_ = notifyFD.Close()
		if cleanup != nil {
			_ = cleanup()
		}
		close(startCalled)
	}
	t.Cleanup(func() {
		wrapCgroupSetupForNotifyHook = prevSetup
		startNotifyHandlerForWrapHook = prevStart
	})

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn := dialUnixConn(t, socketPath)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	if err := wraphandoff.SendNotifyFD(conn, int(pipeR.Fd()), wraphandoff.Metadata{WrapperPID: 7777}); err != nil {
		t.Fatalf("send handoff: %v", err)
	}
	if err := wraphandoff.ReadStatus(conn); err != nil {
		t.Fatalf("read status: %v", err)
	}

	if got := <-setupCalled; got != 7777 {
		t.Fatalf("cgroup setup pid = %d, want 7777", got)
	}
	<-startCalled
	waitForTestDone(t, done)
}
```

Add this rejection test:

```go
func TestAcceptNotifyFD_RejectsMissingMetadataWhenEBPFRequired(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	called := withNotifyHandoffHook(t)
	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn := dialUnixConn(t, socketPath)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	sendFDOverUnixConn(t, conn, int(pipeR.Fd()))
	if err := wraphandoff.ReadStatus(conn); err == nil {
		t.Fatal("expected server rejection status")
	}

	select {
	case <-called:
		t.Fatal("notify handler should not start")
	default:
	}
	waitForTestDone(t, done)
}
```

Add imports if missing:

```go
	"github.com/agentsh/agentsh/internal/wraphandoff"
```

- [ ] **Step 6: Run focused API tests**

Run:

```bash
go test ./internal/api -run 'TestAcceptNotifyFD' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_linux.go internal/api/wrap_windows.go internal/api/wrap_other.go internal/api/wrap_linux_test.go
git commit -m "fix(wrap): attach cgroup before wrapper ack"
```

---

### Task 6: Require Concrete Cgroup For eBPF Setup

**Files:**
- Modify: `internal/api/cgroups.go`
- Modify or create: `internal/api/cgroups_test.go`

- [ ] **Step 1: Write failing tests for eBPF with no cgroup manager**

Create `internal/api/cgroups_test.go` if it does not exist:

```go
package api

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestApplyCgroupV2_EBPFEnabledRequiresCgroupManager(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := NewApp(
		cfg,
		session.NewManager(1),
		composite.New(mockEventStore{}, nil),
		nil,
		events.NewBroker(),
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected error when ebpf is enabled without cgroup manager")
	}
	var unavailable *limits.CgroupUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected CgroupUnavailableError, got %T: %v", err, err)
	}
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
go test ./internal/api -run 'TestApplyCgroupV2_EBPFEnabledRequiresCgroupManager' -count=1
```

Expected: FAIL because current code returns a no-op cleanup when limits are empty.

- [ ] **Step 3: Update `applyCgroupV2`**

In `internal/api/cgroups.go`, after `cgLimits` is built, add:

```go
	needsConcreteCgroup := !cgLimits.IsEmpty() || ebpfEnabled
```

Replace:

```go
	if app.cgroupMgr == nil {
		if cgLimits.IsEmpty() {
			return func() error { return nil }, nil
		}
		return nil, &limits.CgroupUnavailableError{
			Reason: "cgroup manager not initialized",
			Limits: cgLimits,
		}
	}
```

with:

```go
	if app.cgroupMgr == nil {
		if !needsConcreteCgroup {
			return func() error { return nil }, nil
		}
		return nil, &limits.CgroupUnavailableError{
			Reason: "cgroup manager not initialized",
			Limits: cgLimits,
		}
	}
```

Replace:

```go
	// If unavailable mode allowed us (empty limits), cg is nil. Treat as no-op.
	if cg == nil {
		return func() error { return nil }, nil
	}
```

with:

```go
	// If unavailable mode allowed us with no concrete cgroup need, treat as no-op.
	if cg == nil {
		if needsConcreteCgroup {
			return nil, &limits.CgroupUnavailableError{
				Reason: "cgroup manager returned no cgroup",
				Limits: cgLimits,
			}
		}
		return func() error { return nil }, nil
	}
```

- [ ] **Step 4: Run focused cgroup tests**

Run:

```bash
go test ./internal/api -run 'TestApplyCgroupV2_EBPFEnabledRequiresCgroupManager|TestEBPF' -count=1
```

Expected: PASS or eBPF integration tests skip when unsupported.

- [ ] **Step 5: Commit**

```bash
git add internal/api/cgroups.go internal/api/cgroups_test.go
git commit -m "fix(ebpf): require cgroup for ebpf setup"
```

---

### Task 7: Document Wrap eBPF Semantics

**Files:**
- Modify: `docs/ebpf.md`

- [ ] **Step 1: Update eBPF docs**

In `docs/ebpf.md`, after the "Enforcement model" section, add:

```markdown
## `agentsh wrap`

On Linux, `agentsh wrap` attaches the wrapped agent process tree to cgroup eBPF before `agentsh-unixwrap` is acknowledged and allowed to exec the real agent. This protects wrapped subprocesses even when they remove `HTTP_PROXY`, `HTTPS_PROXY`, or related proxy environment variables.

This requires `sandbox.cgroups.enabled: true`. If `sandbox.network.ebpf.required: true` and cgroups or eBPF setup cannot complete, wrap setup fails before the real agent starts.

Domain rules are still enforced by resolving literal domains to IP/port map entries in userspace. eBPF does not match domain strings in the kernel. Wildcard domains, shared CDN IPs, cached DNS answers, hosts-file entries, and DNS-over-HTTPS keep the same caveats described above.
```

- [ ] **Step 2: Run docs grep to verify wording**

Run:

```bash
rg -n "agentsh wrap|sandbox.cgroups.enabled|domain strings" docs/ebpf.md
```

Expected: output includes the new `agentsh wrap` section and cgroups requirement.

- [ ] **Step 3: Commit**

```bash
git add docs/ebpf.md
git commit -m "docs: describe wrap ebpf coverage"
```

---

### Task 8: Full Verification

**Files:**
- No source changes unless verification exposes a regression.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./internal/wraphandoff ./internal/cli ./internal/api ./internal/shim/kernelinstall -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full Go tests**

Run:

```bash
go test ./...
```

Expected: PASS. If long-running integration tests skip due missing platform capabilities, confirm the skip message is expected.

- [ ] **Step 3: Verify Windows compilation**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS.

- [ ] **Step 4: Verify macOS compilation**

Run:

```bash
GOOS=darwin go build ./...
```

Expected: PASS.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat HEAD
```

Expected: only files from this plan are modified. Existing unrelated dirty files from before this work should remain untouched and should not be included in commits.

- [ ] **Step 6: Optional privileged eBPF smoke test**

Run only on a Linux host with writable cgroup v2 and eBPF permissions:

```bash
go test ./internal/api -run TestEBPFConnectEventFlow -count=1
```

Expected: PASS or skip with a clear eBPF/cgroup capability message.

- [ ] **Step 7: Final commit if verification required changes**

If verification forced fixes, commit them:

```bash
git add internal/wraphandoff internal/cli internal/api internal/shim/kernelinstall docs/ebpf.md
git commit -m "test: verify wrap ebpf hardening"
```

Skip this commit if there were no additional changes after Task 7.

---

## Plan Self-Review

- Spec coverage: the plan covers proxy env injection, PID metadata handoff, server setup status, pre-ACK cgroup/eBPF attach, cleanup, cgroup requirement tightening, docs, and verification.
- Placeholder scan: no steps use unresolved markers or open-ended test instructions without code.
- Type consistency: `wraphandoff.Metadata`, `SendNotifyFD`, `RecvNotifyFD`, `WriteStatus`, and `ReadStatus` are introduced before other tasks use them.
- Scope: DNS syscall interception is excluded, matching the approved design.
