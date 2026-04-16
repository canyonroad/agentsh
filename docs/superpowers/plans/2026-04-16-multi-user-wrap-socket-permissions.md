# Multi-User Wrap Socket Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix notify socket permissions so `agentsh wrap` works when the server runs as root and the CLI runs as an unprivileged user, with per-caller isolation via chown and SO_PEERCRED verification.

**Architecture:** Add `CallerUID` to the wrap-init protocol. Server chowns the temp directory + sockets to the caller's UID (falls back to relaxed `0711`/`0666` if not root). On accept, the server verifies the connecting process's UID via kernel-provided SO_PEERCRED credentials.

**Tech Stack:** Go, Unix domain sockets, `os.Chown`/`os.Chmod`, `unix.GetsockoptUcred` (SO_PEERCRED)

---

## File Map

- **Modify:** `pkg/types/sessions.go:126-129` — add `CallerUID` field to `WrapInitRequest`
- **Modify:** `internal/cli/wrap.go:296-299` — set `CallerUID` in wrap-init call
- **Modify:** `internal/api/wrap.go:55-263` — add `secureNotifyDir`/`secureSocket` helpers, wire into `wrapInitCore` ptrace + seccomp paths, thread `expectedUID` into accept goroutines
- **Modify:** `internal/api/wrap.go:410-504` — add `expectedUID` param to `acceptNotifyFD`/`acceptSignalFD`, add UID verification
- **Modify:** `internal/api/wrap_linux.go:211-228` — rename `getConnPeerPID` → `getConnPeerCreds`, return `peerCreds` struct
- **Modify:** `internal/api/wrap_linux.go:233-306` — add `expectedUID` param to `acceptPtracePID`, add UID verification
- **Modify:** `internal/api/wrap_windows.go:42-48` — update `getConnPeerPID` → `getConnPeerCreds` stub, update `acceptPtracePID` signature
- **Modify:** `internal/api/wrap_other.go:39-45` — same stub updates
- **Modify:** `internal/api/wrap_test.go` — existing tests pass CallerUID, add new permission tests

---

### Task 1: Add CallerUID to WrapInitRequest

**Files:**
- Modify: `pkg/types/sessions.go:126-129`
- Modify: `internal/cli/wrap.go:296-299`
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write failing test — CallerUID round-trips through wrapInitCore**

Add to `internal/api/wrap_test.go`:

```go
func TestWrapInit_CallerUIDPassedThrough(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    1000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected 200, got %d", code)
	}
	if resp.NotifySocket == "" {
		t.Error("expected notify socket path")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run TestWrapInit_CallerUIDPassedThrough -v`
Expected: compilation error — `CallerUID` field does not exist on `WrapInitRequest`.

- [ ] **Step 3: Add CallerUID field to WrapInitRequest**

In `pkg/types/sessions.go`, change:

```go
type WrapInitRequest struct {
	AgentCommand string   `json:"agent_command"`
	AgentArgs    []string `json:"agent_args,omitempty"`
}
```

to:

```go
type WrapInitRequest struct {
	AgentCommand string   `json:"agent_command"`
	AgentArgs    []string `json:"agent_args,omitempty"`
	CallerUID    int      `json:"caller_uid,omitempty"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run TestWrapInit_CallerUIDPassedThrough -v`
Expected: PASS

- [ ] **Step 5: Set CallerUID in CLI wrap**

In `internal/cli/wrap.go`, change the wrap-init call at line ~296:

```go
	wrapResp, err := c.WrapInit(ctx, sessID, types.WrapInitRequest{
		AgentCommand: agentPath,
		AgentArgs:    agentArgs,
	})
```

to:

```go
	wrapResp, err := c.WrapInit(ctx, sessID, types.WrapInitRequest{
		AgentCommand: agentPath,
		AgentArgs:    agentArgs,
		CallerUID:    os.Getuid(),
	})
```

Add `"os"` to imports if not already present.

- [ ] **Step 6: Verify build**

Run: `cd /home/eran/work/agentsh && go build ./...`
Expected: clean build

- [ ] **Step 7: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./...`
Expected: all tests pass

- [ ] **Step 8: Commit**

```bash
git add pkg/types/sessions.go internal/cli/wrap.go internal/api/wrap_test.go
git commit -m "feat(wrap): add CallerUID to WrapInitRequest for multi-user socket permissions"
```

---

### Task 2: Add secureNotifyDir and secureSocket helpers

**Files:**
- Modify: `internal/api/wrap.go` (add helpers near the top, before `wrapInitCore`)
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write failing tests for the helpers**

Add to `internal/api/wrap_test.go`:

```go
func TestSecureNotifyDir_ChownSuccess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix permissions")
	}

	dir := t.TempDir()
	uid := os.Getuid()

	// When callerUID matches current user, chown succeeds (we own it)
	chownOK := secureNotifyDir(dir, uid)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("expected 0700, got %04o", info.Mode().Perm())
	}
	// chown to ourselves should succeed (even without root)
	if !chownOK {
		t.Error("expected chownOK=true when chowning to self")
	}
}

func TestSecureNotifyDir_CallerUIDZero_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix permissions")
	}

	dir := t.TempDir()
	chownOK := secureNotifyDir(dir, 0)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0711 {
		t.Errorf("expected 0711, got %04o", info.Mode().Perm())
	}
	if chownOK {
		t.Error("expected chownOK=false for callerUID=0")
	}
}

func TestSecureSocket_ChownOK(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix permissions")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	secureSocket(sockPath, os.Getuid(), true)

	// Socket should NOT be world-connectable (no 0666)
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	// When chownOK, we don't chmod to 0666
	if info.Mode().Perm()&0066 == 0066 {
		t.Error("socket should not be world-connectable when chown succeeded")
	}
}

func TestSecureSocket_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix permissions")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	secureSocket(sockPath, 0, false)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0666 {
		t.Errorf("expected 0666, got %04o", info.Mode().Perm())
	}
}
```

Add `"net"` to the test file imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestSecureNotifyDir|TestSecureSocket" -v`
Expected: compilation error — `secureNotifyDir` and `secureSocket` are undefined.

- [ ] **Step 3: Implement the helpers**

Add to `internal/api/wrap.go`, after the imports and before `wrapInit`:

```go
// secureNotifyDir sets ownership and permissions on the notify socket directory
// for multi-user wrap. If callerUID > 0, it attempts to chown the directory to
// the caller so only they can traverse it (0700). If chown fails (server is not
// root) or callerUID is 0 (old client), it falls back to 0711 (traverse-only).
// Returns true if chown succeeded, false if fallback permissions were applied.
func secureNotifyDir(dir string, callerUID int) bool {
	if callerUID > 0 {
		if err := os.Chown(dir, callerUID, -1); err != nil {
			slog.Debug("wrap: chown notify dir failed, using permissive fallback",
				"dir", dir, "uid", callerUID, "error", err)
			os.Chmod(dir, 0711)
			return false
		}
		os.Chmod(dir, 0700)
		return true
	}
	os.Chmod(dir, 0711)
	return false
}

// secureSocket sets ownership and permissions on a notify socket after creation.
// If chownOK (directory chown succeeded), it chowns the socket to the caller.
// Otherwise, it chmods the socket to 0666 so any local user can connect.
func secureSocket(socketPath string, callerUID int, chownOK bool) {
	if chownOK && callerUID > 0 {
		if err := os.Chown(socketPath, callerUID, -1); err != nil {
			slog.Debug("wrap: chown socket failed, using permissive fallback",
				"path", socketPath, "uid", callerUID, "error", err)
			os.Chmod(socketPath, 0666)
		}
		return
	}
	os.Chmod(socketPath, 0666)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestSecureNotifyDir|TestSecureSocket" -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Verify full build + existing tests**

Run: `cd /home/eran/work/agentsh && go build ./... && go test ./internal/api/ -v`
Expected: clean build, all tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_test.go
git commit -m "feat(wrap): add secureNotifyDir/secureSocket helpers for multi-user permissions"
```

---

### Task 3: Wire helpers into wrapInitCore

**Files:**
- Modify: `internal/api/wrap.go:76-111` (ptrace path)
- Modify: `internal/api/wrap.go:194-257` (seccomp path)
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write failing test — notify socket directory uses 0711 fallback for CallerUID=0**

Add to `internal/api/wrap_test.go`:

```go
func TestWrapInit_NotifyDirPermissions_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// CallerUID=0 simulates an old client — should get permissive fallback
	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check the notify socket's parent directory has 0711
	notifyDir := filepath.Dir(resp.NotifySocket)
	info, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if info.Mode().Perm() != 0711 {
		t.Errorf("expected dir perm 0711 for CallerUID=0, got %04o", info.Mode().Perm())
	}

	// Check the notify socket has 0666
	sockInfo, err := os.Stat(resp.NotifySocket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if sockInfo.Mode().Perm() != 0666 {
		t.Errorf("expected socket perm 0666 for CallerUID=0, got %04o", sockInfo.Mode().Perm())
	}
}

func TestWrapInit_NotifyDirPermissions_CallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Use our own UID so chown succeeds without root
	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    os.Getuid(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	info, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("expected dir perm 0700 for CallerUID=%d, got %04o", os.Getuid(), info.Mode().Perm())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestWrapInit_NotifyDirPermissions" -v`
Expected: FAIL — directory is still 0700 (hardcoded), not 0711.

- [ ] **Step 3: Wire secureNotifyDir + secureSocket into the ptrace path**

In `internal/api/wrap.go`, in the ptrace path (starting at line ~76), replace:

```go
		notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
		if err != nil {
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
		if err := os.Chmod(notifyDir, 0700); err != nil {
			os.RemoveAll(notifyDir)
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
```

with:

```go
		notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
		if err != nil {
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
		chownOK := secureNotifyDir(notifyDir, req.CallerUID)
```

Then after `net.Listen("unix", notifySocketPath)` (line ~105), before the `go a.acceptPtracePID` call, add:

```go
		secureSocket(notifySocketPath, req.CallerUID, chownOK)
```

- [ ] **Step 4: Wire secureNotifyDir + secureSocket into the seccomp path**

In the seccomp path (starting at line ~198), replace:

```go
	notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	if err := os.Chmod(notifyDir, 0700); err != nil {
		os.RemoveAll(notifyDir)
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
```

with:

```go
	notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	chownOK := secureNotifyDir(notifyDir, req.CallerUID)
```

Then after `net.Listen("unix", notifySocketPath)` (line ~226), before `go a.acceptNotifyFD`, add:

```go
	secureSocket(notifySocketPath, req.CallerUID, chownOK)
```

And after `signalListener, err := net.Listen("unix", signalSocketPath)` (line ~248), inside the `if signalFilterEnabled` block, after the `net.Listen` success path and before `go a.acceptSignalFD`, add:

```go
			secureSocket(signalSocketPath, req.CallerUID, chownOK)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestWrapInit_NotifyDirPermissions" -v`
Expected: both tests PASS

- [ ] **Step 6: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -v`
Expected: all tests pass (existing tests use CallerUID=0, so they get fallback behavior — still functional)

- [ ] **Step 7: Cross-compile check**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`
Expected: clean build

- [ ] **Step 8: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_test.go
git commit -m "feat(wrap): wire secureNotifyDir/secureSocket into wrapInitCore paths"
```

---

### Task 4: Extend getConnPeerPID to getConnPeerCreds

**Files:**
- Modify: `internal/api/wrap_linux.go:211-228`
- Modify: `internal/api/wrap_windows.go:42-44`
- Modify: `internal/api/wrap_other.go:39-41`
- Modify: `internal/api/wrap.go:434-439` (call site in `acceptNotifyFD`)
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write failing test for getConnPeerCreds**

Add to `internal/api/wrap_test.go`:

```go
func TestGetConnPeerCreds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Connect from this process
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		connCh <- c
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn := <-connCh
	defer serverConn.Close()

	unixConn, ok := serverConn.(*net.UnixConn)
	if !ok {
		t.Fatal("not a unix conn")
	}

	creds := getConnPeerCreds(unixConn)
	if creds.PID <= 0 {
		t.Errorf("expected PID > 0, got %d", creds.PID)
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Errorf("expected UID %d, got %d", os.Getuid(), creds.UID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run TestGetConnPeerCreds -v`
Expected: compilation error — `getConnPeerCreds` undefined, returns wrong type.

- [ ] **Step 3: Implement getConnPeerCreds on Linux**

In `internal/api/wrap_linux.go`, replace `getConnPeerPID` (lines 211-228):

```go
// peerCreds holds the peer process credentials from SO_PEERCRED.
type peerCreds struct {
	PID int
	UID uint32
}

// getConnPeerCreds extracts the peer process PID and UID from a Unix connection.
func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		slog.Debug("getConnPeerCreds: failed to get syscall conn", "error", err)
		return peerCreds{}
	}
	var creds peerCreds
	rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			slog.Debug("getConnPeerCreds: GetsockoptUcred failed", "error", err)
		} else {
			creds.PID = int(ucred.Pid)
			creds.UID = ucred.Uid
		}
	})
	return creds
}
```

- [ ] **Step 4: Update Windows stub**

In `internal/api/wrap_windows.go`, replace:

```go
func getConnPeerPID(conn *net.UnixConn) int {
	return 0
}
```

with:

```go
type peerCreds struct {
	PID int
	UID uint32
}

func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	return peerCreds{}
}
```

- [ ] **Step 5: Update Other stub**

In `internal/api/wrap_other.go`, replace:

```go
func getConnPeerPID(conn *net.UnixConn) int {
	return 0
}
```

with:

```go
type peerCreds struct {
	PID int
	UID uint32
}

func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	return peerCreds{}
}
```

- [ ] **Step 6: Update call site in acceptNotifyFD**

In `internal/api/wrap.go`, in `acceptNotifyFD` (~line 434-439), replace:

```go
	// Get wrapper PID from socket credentials for depth tracking
	wrapperPID := getConnPeerPID(unixConn)
	if wrapperPID > 0 {
		slog.Debug("wrap: got wrapper PID from socket credentials",
			"wrapper_pid", wrapperPID, "session_id", sessionID)
	}
```

with:

```go
	// Get wrapper credentials from socket for depth tracking and UID verification
	creds := getConnPeerCreds(unixConn)
	wrapperPID := creds.PID
	if wrapperPID > 0 {
		slog.Debug("wrap: got wrapper credentials from socket",
			"wrapper_pid", wrapperPID, "wrapper_uid", creds.UID, "session_id", sessionID)
	}
```

- [ ] **Step 7: Run test and verify it passes**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run TestGetConnPeerCreds -v`
Expected: PASS

- [ ] **Step 8: Cross-compile check**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: clean build on all platforms

- [ ] **Step 9: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -v`
Expected: all tests pass

- [ ] **Step 10: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_linux.go internal/api/wrap_windows.go internal/api/wrap_other.go internal/api/wrap_test.go
git commit -m "refactor(wrap): rename getConnPeerPID to getConnPeerCreds, return PID+UID"
```

---

### Task 5: Add SO_PEERCRED UID verification to accept functions

**Files:**
- Modify: `internal/api/wrap.go:410` (`acceptNotifyFD` signature + verification)
- Modify: `internal/api/wrap.go:467` (`acceptSignalFD` signature + verification)
- Modify: `internal/api/wrap_linux.go:233` (`acceptPtracePID` signature + verification)
- Modify: `internal/api/wrap_windows.go:46` (`acceptPtracePID` stub signature)
- Modify: `internal/api/wrap_other.go:43` (`acceptPtracePID` stub signature)
- Modify: `internal/api/wrap.go` (goroutine call sites to pass `expectedUID`)
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write failing test — UID verification rejects mismatched UID**

Add to `internal/api/wrap_test.go`:

```go
func TestAcceptNotifyFD_RejectsWrongUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	// expectedUID=99999 won't match our real UID
	app, mgr := newTestAppForWrap(t, &config.Config{})
	_ = mgr
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), ln, sockPath, "test-session", nil, false, 99999)
	}()

	// Connect — should be rejected
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The server should close the connection without reading
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed by server")
	}
	conn.Close()
	<-done
}

func TestAcceptNotifyFD_AcceptsCorrectUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	// expectedUID=0 means no check (old client)
	app, _ := newTestAppForWrap(t, &config.Config{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), ln, sockPath, "test-session", nil, false, 0)
	}()

	// Connect — should be accepted (UID check skipped)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Send a byte to unblock recvmsg (it will fail to parse fd, but that's fine —
	// we're testing that the connection was accepted, not fd forwarding)
	conn.Write([]byte{0})
	conn.Close()
	<-done
}
```

Add `"context"` and `"time"` to the test file imports if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestAcceptNotifyFD" -v`
Expected: compilation error — `acceptNotifyFD` doesn't accept `expectedUID` parameter.

- [ ] **Step 3: Add expectedUID to acceptNotifyFD**

In `internal/api/wrap.go`, change the `acceptNotifyFD` signature:

```go
func (a *App) acceptNotifyFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, execveEnabled bool) {
```

to:

```go
func (a *App) acceptNotifyFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, execveEnabled bool, expectedUID int) {
```

After the `getConnPeerCreds` call and before `file, err := unixConn.File()`, add the UID verification:

```go
	// Verify connecting process UID matches expected caller
	if expectedUID > 0 && creds.UID != uint32(expectedUID) {
		slog.Warn("wrap: rejected notify connection from unexpected UID",
			"expected_uid", expectedUID, "actual_uid", creds.UID,
			"pid", creds.PID, "session_id", sessionID)
		return
	}
```

Update the goroutine call site in `wrapInitCore` (seccomp path, ~line 233):

```go
	go a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled, req.CallerUID)
```

- [ ] **Step 4: Add expectedUID to acceptSignalFD**

Change the `acceptSignalFD` signature:

```go
func (a *App) acceptSignalFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session) {
```

to:

```go
func (a *App) acceptSignalFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, expectedUID int) {
```

After `listener.Accept()` succeeds and the `*net.UnixConn` type assertion, add UID verification. Insert after `unixConn, ok := conn.(*net.UnixConn)` and before `file, err := unixConn.File()`:

```go
	// Verify connecting process UID matches expected caller
	if expectedUID > 0 {
		creds := getConnPeerCreds(unixConn)
		if creds.UID != uint32(expectedUID) {
			slog.Warn("wrap: rejected signal connection from unexpected UID",
				"expected_uid", expectedUID, "actual_uid", creds.UID,
				"pid", creds.PID, "session_id", sessionID)
			return
		}
	}
```

Update the goroutine call site (~line 255):

```go
			go a.acceptSignalFD(ctx, signalListener, signalSocketPath, sessionID, s, req.CallerUID)
```

- [ ] **Step 5: Add expectedUID to acceptPtracePID on Linux**

In `internal/api/wrap_linux.go`, change the `acceptPtracePID` signature:

```go
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string) {
```

to:

```go
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string, expectedUID int) {
```

After `conn, err := listener.Accept()` succeeds (~line 242), before the read deadline, add:

```go
	// Verify connecting process UID matches expected caller
	if expectedUID > 0 {
		if unixConn, ok := conn.(*net.UnixConn); ok {
			creds := getConnPeerCreds(unixConn)
			if creds.UID != uint32(expectedUID) {
				slog.Warn("ptrace wrap: rejected connection from unexpected UID",
					"expected_uid", expectedUID, "actual_uid", creds.UID,
					"pid", creds.PID, "session_id", sessionID)
				conn.Close()
				return
			}
		}
	}
```

- [ ] **Step 6: Update acceptPtracePID stubs**

In `internal/api/wrap_windows.go`, change:

```go
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string) {
```

to:

```go
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string, expectedUID int) {
```

In `internal/api/wrap_other.go`, make the same signature change.

- [ ] **Step 7: Update ptrace goroutine call site**

In `internal/api/wrap.go`, in the ptrace path (~line 111), change:

```go
		go a.acceptPtracePID(ctx, listener, notifySocketPath, sessionID)
```

to:

```go
		go a.acceptPtracePID(ctx, listener, notifySocketPath, sessionID, req.CallerUID)
```

- [ ] **Step 8: Run the UID verification tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestAcceptNotifyFD" -v`
Expected: both tests PASS

- [ ] **Step 9: Cross-compile check**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: clean build

- [ ] **Step 10: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./... -count=1`
Expected: all tests pass

- [ ] **Step 11: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_linux.go internal/api/wrap_windows.go internal/api/wrap_other.go internal/api/wrap_test.go
git commit -m "feat(wrap): add SO_PEERCRED UID verification on notify socket accept"
```

---

### Task 6: Final validation

**Files:** none (verification only)

- [ ] **Step 1: Full build and test**

Run: `cd /home/eran/work/agentsh && go build ./... && go test ./... -count=1`
Expected: all pass

- [ ] **Step 2: Cross-compile**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: clean build on all platforms

- [ ] **Step 3: Verify the complete permission flow manually**

Run the new tests specifically to confirm the full chain works:

```bash
cd /home/eran/work/agentsh
go test ./internal/api/ -run "TestWrapInit_CallerUID|TestWrapInit_NotifyDirPermissions|TestSecureNotifyDir|TestSecureSocket|TestGetConnPeerCreds|TestAcceptNotifyFD" -v
```

Expected: all tests PASS
