# macOS ESF + Network Extension Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Apple's Endpoint Security Framework and Network Extension for TierEnterprise macOS support.

**Architecture:** Go policy socket server receives queries from Swift XPC service, which bridges to the System Extension containing ESF client and NE providers. Graceful fallback to FUSE-T when entitlements unavailable.

**Tech Stack:** Go 1.21+, Swift 5.9+, Xcode 15+, EndpointSecurity.framework, NetworkExtension.framework

---

## Phase 1: Go Policy Socket Server

This phase creates the Go-side Unix socket handler that receives policy queries from the Swift XPC bridge. **Testable on Linux** - no macOS or entitlements needed.

### Task 1: Define Policy Socket Protocol Types

**Files:**
- Create: `internal/platform/darwin/xpc/protocol.go`
- Test: `internal/platform/darwin/xpc/protocol_test.go`

**Step 1: Write the failing test**

```go
// internal/platform/darwin/xpc/protocol_test.go
package xpc

import (
	"encoding/json"
	"testing"
)

func TestPolicyRequest_File_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypeFile,
		Path:      "/workspace/test.txt",
		Operation: "read",
		PID:       1234,
		SessionID: "session-abc",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypeFile {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypeFile)
	}
	if decoded.Path != "/workspace/test.txt" {
		t.Errorf("path: got %q, want %q", decoded.Path, "/workspace/test.txt")
	}
}

func TestPolicyResponse_Marshal(t *testing.T) {
	resp := PolicyResponse{
		Allow:   true,
		Rule:    "allow-workspace",
		Message: "",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.Allow {
		t.Error("expected allow=true")
	}
	if decoded.Rule != "allow-workspace" {
		t.Errorf("rule: got %q, want %q", decoded.Rule, "allow-workspace")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/... -v`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// internal/platform/darwin/xpc/protocol.go
package xpc

// RequestType identifies the type of policy check.
type RequestType string

const (
	RequestTypeFile    RequestType = "file"
	RequestTypeNetwork RequestType = "network"
	RequestTypeCommand RequestType = "command"
	RequestTypeSession RequestType = "session"
	RequestTypeEvent   RequestType = "event"
)

// PolicyRequest is sent from the XPC bridge to the Go policy server.
type PolicyRequest struct {
	Type      RequestType `json:"type"`
	Path      string      `json:"path,omitempty"`      // file path or command path
	Operation string      `json:"operation,omitempty"` // read, write, delete, exec
	PID       int32       `json:"pid"`
	SessionID string      `json:"session_id,omitempty"`

	// Network-specific fields
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Domain string `json:"domain,omitempty"`

	// Command-specific fields
	Args []string `json:"args,omitempty"`

	// Event emission
	EventData []byte `json:"event_data,omitempty"`
}

// PolicyResponse is returned from the Go policy server.
type PolicyResponse struct {
	Allow     bool   `json:"allow"`
	Rule      string `json:"rule,omitempty"`
	Message   string `json:"message,omitempty"`
	SessionID string `json:"session_id,omitempty"` // for session lookups
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/darwin/xpc/
git commit -m "feat(darwin): add XPC policy protocol types"
```

---

### Task 2: Implement Policy Socket Server

**Files:**
- Create: `internal/platform/darwin/xpc/server.go`
- Test: `internal/platform/darwin/xpc/server_test.go`

**Step 1: Write the failing test**

```go
// internal/platform/darwin/xpc/server_test.go
package xpc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockPolicyEngine implements a simple allow-all policy for testing.
type mockPolicyEngine struct{}

func (m *mockPolicyEngine) CheckFile(path, op string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) CheckNetwork(ip string, port int, domain string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) CheckCommand(cmd string, args []string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) ResolveSession(pid int32) string {
	if pid == 1234 {
		return "session-test"
	}
	return ""
}

func TestServer_HandleFileRequest(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "policy.sock")

	srv := NewServer(sockPath, &mockPolicyEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	// Connect and send request
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := PolicyRequest{
		Type:      RequestTypeFile,
		Path:      "/test/file.txt",
		Operation: "read",
		PID:       1234,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Allow {
		t.Error("expected allow=true")
	}
	if resp.Rule != "test-allow" {
		t.Errorf("rule: got %q, want %q", resp.Rule, "test-allow")
	}
}

func TestServer_HandleSessionRequest(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "policy.sock")

	srv := NewServer(sockPath, &mockPolicyEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := PolicyRequest{
		Type: RequestTypeSession,
		PID:  1234,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.SessionID != "session-test" {
		t.Errorf("session_id: got %q, want %q", resp.SessionID, "session-test")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestServer`
Expected: FAIL - NewServer undefined

**Step 3: Write minimal implementation**

```go
// internal/platform/darwin/xpc/server.go
package xpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// PolicyHandler handles policy queries from the XPC bridge.
type PolicyHandler interface {
	CheckFile(path, op string) (allow bool, rule string)
	CheckNetwork(ip string, port int, domain string) (allow bool, rule string)
	CheckCommand(cmd string, args []string) (allow bool, rule string)
	ResolveSession(pid int32) (sessionID string)
}

// Server listens on a Unix socket for policy queries.
type Server struct {
	sockPath string
	handler  PolicyHandler
	listener net.Listener
	mu       sync.Mutex
	running  bool
}

// NewServer creates a new policy socket server.
func NewServer(sockPath string, handler PolicyHandler) *Server {
	return &Server{
		sockPath: sockPath,
		handler:  handler,
	}
}

// Run starts the server and blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Remove existing socket
	os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	// Set socket permissions (readable only by root)
	if err := os.Chmod(s.sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod: %w", err)
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req PolicyRequest
		if err := decoder.Decode(&req); err != nil {
			return // Connection closed or error
		}

		resp := s.handleRequest(&req)
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) handleRequest(req *PolicyRequest) PolicyResponse {
	switch req.Type {
	case RequestTypeFile:
		allow, rule := s.handler.CheckFile(req.Path, req.Operation)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeNetwork:
		allow, rule := s.handler.CheckNetwork(req.IP, req.Port, req.Domain)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeCommand:
		allow, rule := s.handler.CheckCommand(req.Path, req.Args)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeSession:
		sessionID := s.handler.ResolveSession(req.PID)
		return PolicyResponse{Allow: sessionID != "", SessionID: sessionID}

	case RequestTypeEvent:
		// Events are fire-and-forget, always acknowledge
		return PolicyResponse{Allow: true}

	default:
		return PolicyResponse{Allow: true, Message: "unknown request type"}
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestServer`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/darwin/xpc/server.go internal/platform/darwin/xpc/server_test.go
git commit -m "feat(darwin): add XPC policy socket server"
```

---

### Task 3: Create Policy Handler Adapter

**Files:**
- Create: `internal/platform/darwin/xpc/handler.go`
- Test: `internal/platform/darwin/xpc/handler_test.go`

**Step 1: Write the failing test**

```go
// internal/platform/darwin/xpc/handler_test.go
package xpc

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestPolicyAdapter_CheckFile_Allow(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/test/file.txt", "read")

	if !allow {
		t.Error("expected allow=true")
	}
	if rule != "allow-all" {
		t.Errorf("rule: got %q, want %q", rule, "allow-all")
	}
}

func TestPolicyAdapter_CheckFile_Deny(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-secrets", Paths: []string{"/etc/passwd"}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/etc/passwd", "read")

	if allow {
		t.Error("expected allow=false")
	}
	if rule != "deny-secrets" {
		t.Errorf("rule: got %q, want %q", rule, "deny-secrets")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestPolicyAdapter`
Expected: FAIL - NewPolicyAdapter undefined

**Step 3: Write minimal implementation**

```go
// internal/platform/darwin/xpc/handler.go
package xpc

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// SessionResolver looks up session ID for a process.
type SessionResolver interface {
	SessionForPID(pid int32) string
}

// PolicyAdapter adapts the policy.Engine to the PolicyHandler interface.
type PolicyAdapter struct {
	engine   *policy.Engine
	sessions SessionResolver
}

// NewPolicyAdapter creates a new policy adapter.
func NewPolicyAdapter(engine *policy.Engine, sessions SessionResolver) *PolicyAdapter {
	return &PolicyAdapter{
		engine:   engine,
		sessions: sessions,
	}
}

// CheckFile evaluates file access policy.
func (a *PolicyAdapter) CheckFile(path, op string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	dec := a.engine.CheckFile(path, op)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckNetwork evaluates network access policy.
func (a *PolicyAdapter) CheckNetwork(ip string, port int, domain string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	// Use domain if provided, otherwise use IP
	target := domain
	if target == "" {
		target = ip
	}
	dec := a.engine.CheckNetwork(target, port)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckCommand evaluates command execution policy.
func (a *PolicyAdapter) CheckCommand(cmd string, args []string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	dec := a.engine.CheckCommand(cmd, args)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// ResolveSession looks up the session ID for a process.
func (a *PolicyAdapter) ResolveSession(pid int32) string {
	if a.sessions == nil {
		return ""
	}
	return a.sessions.SessionForPID(pid)
}

// Compile-time interface check
var _ PolicyHandler = (*PolicyAdapter)(nil)
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestPolicyAdapter`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/darwin/xpc/handler.go internal/platform/darwin/xpc/handler_test.go
git commit -m "feat(darwin): add policy adapter for XPC handler"
```

---

### Task 4: Add Session Process Tracker

**Files:**
- Create: `internal/platform/darwin/xpc/sessions.go`
- Test: `internal/platform/darwin/xpc/sessions_test.go`

**Step 1: Write the failing test**

```go
// internal/platform/darwin/xpc/sessions_test.go
package xpc

import (
	"testing"
	"time"
)

func TestSessionTracker_RegisterAndLookup(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0) // root process
	tracker.RegisterProcess("session-1", 101, 100) // child

	if sid := tracker.SessionForPID(100); sid != "session-1" {
		t.Errorf("pid 100: got %q, want %q", sid, "session-1")
	}
	if sid := tracker.SessionForPID(101); sid != "session-1" {
		t.Errorf("pid 101: got %q, want %q", sid, "session-1")
	}
	if sid := tracker.SessionForPID(999); sid != "" {
		t.Errorf("pid 999: got %q, want empty", sid)
	}
}

func TestSessionTracker_ParentWalk(t *testing.T) {
	tracker := NewSessionTracker()

	// Register root process
	tracker.RegisterProcess("session-1", 100, 0)

	// Simulate fork chain: 100 -> 101 -> 102 -> 103
	tracker.SetParent(101, 100)
	tracker.SetParent(102, 101)
	tracker.SetParent(103, 102)

	// Should find session via parent walk
	if sid := tracker.SessionForPID(103); sid != "session-1" {
		t.Errorf("pid 103: got %q, want %q", sid, "session-1")
	}

	// Verify caching - 103 should now be cached
	if sid := tracker.SessionForPID(103); sid != "session-1" {
		t.Errorf("pid 103 cached: got %q, want %q", sid, "session-1")
	}
}

func TestSessionTracker_ProcessExit(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0)
	tracker.RegisterProcess("session-1", 101, 100)

	tracker.UnregisterProcess(101)

	if sid := tracker.SessionForPID(101); sid != "" {
		t.Errorf("pid 101 after exit: got %q, want empty", sid)
	}
	// Root process should still be tracked
	if sid := tracker.SessionForPID(100); sid != "session-1" {
		t.Errorf("pid 100: got %q, want %q", sid, "session-1")
	}
}

func TestSessionTracker_SessionEnd(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0)
	tracker.RegisterProcess("session-1", 101, 100)

	tracker.EndSession("session-1")

	if sid := tracker.SessionForPID(100); sid != "" {
		t.Errorf("pid 100 after session end: got %q, want empty", sid)
	}
	if sid := tracker.SessionForPID(101); sid != "" {
		t.Errorf("pid 101 after session end: got %q, want empty", sid)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestSessionTracker`
Expected: FAIL - NewSessionTracker undefined

**Step 3: Write minimal implementation**

```go
// internal/platform/darwin/xpc/sessions.go
package xpc

import (
	"sync"
)

const maxParentWalkDepth = 10

// SessionTracker tracks which processes belong to which sessions.
type SessionTracker struct {
	mu sync.RWMutex

	// pid -> sessionID (direct registration or cached from parent walk)
	pidToSession map[int32]string

	// pid -> parent pid (for parent walk)
	pidToParent map[int32]int32

	// sessionID -> set of pids (for cleanup on session end)
	sessionToPids map[string]map[int32]struct{}
}

// NewSessionTracker creates a new session tracker.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		pidToSession:  make(map[int32]string),
		pidToParent:   make(map[int32]int32),
		sessionToPids: make(map[string]map[int32]struct{}),
	}
}

// RegisterProcess adds a process to a session.
func (t *SessionTracker) RegisterProcess(sessionID string, pid, ppid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pidToSession[pid] = sessionID
	if ppid > 0 {
		t.pidToParent[pid] = ppid
	}

	if t.sessionToPids[sessionID] == nil {
		t.sessionToPids[sessionID] = make(map[int32]struct{})
	}
	t.sessionToPids[sessionID][pid] = struct{}{}
}

// SetParent records a parent-child relationship (from fork events).
func (t *SessionTracker) SetParent(pid, ppid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pidToParent[pid] = ppid
}

// UnregisterProcess removes a process (on exit).
func (t *SessionTracker) UnregisterProcess(pid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sessionID := t.pidToSession[pid]
	delete(t.pidToSession, pid)
	delete(t.pidToParent, pid)

	if sessionID != "" && t.sessionToPids[sessionID] != nil {
		delete(t.sessionToPids[sessionID], pid)
	}
}

// EndSession removes all processes for a session.
func (t *SessionTracker) EndSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pids := t.sessionToPids[sessionID]
	for pid := range pids {
		delete(t.pidToSession, pid)
		delete(t.pidToParent, pid)
	}
	delete(t.sessionToPids, sessionID)
}

// SessionForPID returns the session ID for a process, walking parents if needed.
func (t *SessionTracker) SessionForPID(pid int32) string {
	t.mu.RLock()

	// Fast path: direct lookup
	if sessionID, ok := t.pidToSession[pid]; ok {
		t.mu.RUnlock()
		return sessionID
	}

	// Slow path: walk parent chain
	current := pid
	visited := make([]int32, 0, maxParentWalkDepth)

	for i := 0; i < maxParentWalkDepth; i++ {
		ppid, ok := t.pidToParent[current]
		if !ok || ppid <= 0 {
			break
		}

		visited = append(visited, current)

		if sessionID, ok := t.pidToSession[ppid]; ok {
			t.mu.RUnlock()

			// Cache the result for all visited pids
			t.mu.Lock()
			for _, v := range visited {
				t.pidToSession[v] = sessionID
				if t.sessionToPids[sessionID] == nil {
					t.sessionToPids[sessionID] = make(map[int32]struct{})
				}
				t.sessionToPids[sessionID][v] = struct{}{}
			}
			t.mu.Unlock()

			return sessionID
		}

		current = ppid
	}

	t.mu.RUnlock()
	return ""
}

// Compile-time interface check
var _ SessionResolver = (*SessionTracker)(nil)
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/... -v -run TestSessionTracker`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/darwin/xpc/sessions.go internal/platform/darwin/xpc/sessions_test.go
git commit -m "feat(darwin): add session process tracker for XPC"
```

---

### Task 5: Add CLI Commands for System Extension Management

**Files:**
- Create: `internal/platform/darwin/sysext.go`
- Modify: `cmd/agentsh/main.go` (add sysext subcommand)

**Step 1: Create sysext command structure**

```go
// internal/platform/darwin/sysext.go
//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// SysExtStatus represents the state of the System Extension.
type SysExtStatus struct {
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Version     string `json:"version,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	ExtensionID string `json:"extension_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SysExtManager manages the agentsh System Extension lifecycle.
type SysExtManager struct {
	bundlePath string
	bundleID   string
}

// NewSysExtManager creates a new System Extension manager.
func NewSysExtManager() *SysExtManager {
	// Find the app bundle - either we're running from it or it's adjacent
	execPath, _ := os.Executable()
	bundlePath := findAppBundle(execPath)

	return &SysExtManager{
		bundlePath: bundlePath,
		bundleID:   "com.agentsh.sysext",
	}
}

// findAppBundle locates the AgentSH.app bundle.
func findAppBundle(execPath string) string {
	// If running from within .app bundle
	if idx := filepath.Index(execPath, ".app/"); idx >= 0 {
		return execPath[:idx+4]
	}

	// Check common locations
	candidates := []string{
		"/Applications/AgentSH.app",
		filepath.Join(filepath.Dir(execPath), "AgentSH.app"),
		filepath.Join(filepath.Dir(execPath), "..", "AgentSH.app"),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}

	return ""
}

// Status returns the current System Extension status.
func (m *SysExtManager) Status() (*SysExtStatus, error) {
	status := &SysExtStatus{
		BundleID: m.bundleID,
	}

	if m.bundlePath == "" {
		status.Error = "AgentSH.app bundle not found"
		return status, nil
	}

	// Check if extension is installed via systemextensionsctl
	out, err := exec.Command("systemextensionsctl", "list").Output()
	if err != nil {
		status.Error = fmt.Sprintf("systemextensionsctl: %v", err)
		return status, nil
	}

	output := string(out)
	if contains(output, m.bundleID) {
		status.Installed = true
		if contains(output, "activated enabled") {
			status.Running = true
		}
	}

	return status, nil
}

// Install requests installation of the System Extension.
func (m *SysExtManager) Install() error {
	if m.bundlePath == "" {
		return fmt.Errorf("AgentSH.app bundle not found; install it first")
	}

	// The actual installation is triggered by OSSystemExtensionManager in Swift
	// This Go code just validates prerequisites
	extPath := filepath.Join(m.bundlePath, "Contents", "Library", "SystemExtensions",
		m.bundleID+".systemextension")

	if _, err := os.Stat(extPath); err != nil {
		return fmt.Errorf("System Extension not found at %s", extPath)
	}

	fmt.Println("System Extension installation will require user approval.")
	fmt.Println("A system dialog will appear asking for permission.")

	// In the real implementation, this would use NSWorkspace to launch
	// the app with an argument that triggers the Swift installation code
	return fmt.Errorf("not implemented: requires Swift integration")
}

// Uninstall removes the System Extension.
func (m *SysExtManager) Uninstall() error {
	return fmt.Errorf("not implemented: requires Swift integration")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

**Step 2: Create stub for non-darwin**

```go
// internal/platform/darwin/sysext_stub.go
//go:build !darwin

package darwin

import "fmt"

type SysExtStatus struct {
	Error string `json:"error"`
}

type SysExtManager struct{}

func NewSysExtManager() *SysExtManager {
	return &SysExtManager{}
}

func (m *SysExtManager) Status() (*SysExtStatus, error) {
	return &SysExtStatus{Error: "System Extensions are only available on macOS"}, nil
}

func (m *SysExtManager) Install() error {
	return fmt.Errorf("System Extensions are only available on macOS")
}

func (m *SysExtManager) Uninstall() error {
	return fmt.Errorf("System Extensions are only available on macOS")
}
```

**Step 3: Commit**

```bash
git add internal/platform/darwin/sysext.go internal/platform/darwin/sysext_stub.go
git commit -m "feat(darwin): add System Extension manager scaffolding"
```

---

## Phase 2: Xcode Project Setup

This phase creates the Swift project structure. **Requires macOS with Xcode.**

### Task 6: Create Xcode Project Structure

**Files:**
- Create: `macos/AgentSH.xcodeproj/` (Xcode project)
- Create: `macos/AgentSH/` (main app target placeholder)
- Create: `macos/SysExt/` (System Extension target)
- Create: `macos/XPCService/` (XPC Service target)

**Step 1: Create directory structure**

```bash
mkdir -p macos/AgentSH
mkdir -p macos/SysExt
mkdir -p macos/XPCService
```

**Step 2: Create placeholder Info.plist files**

```xml
<!-- macos/AgentSH/Info.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.agentsh.app</string>
    <key>CFBundleName</key>
    <string>AgentSH</string>
    <key>CFBundleExecutable</key>
    <string>agentsh</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
```

```xml
<!-- macos/SysExt/Info.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.agentsh.sysext</string>
    <key>CFBundleName</key>
    <string>AgentSH System Extension</string>
    <key>CFBundleExecutable</key>
    <string>com.agentsh.sysext</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>SYSX</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NetworkExtension</key>
    <dict>
        <key>NEProviderClasses</key>
        <dict>
            <key>com.apple.networkextension.filter-data</key>
            <string>$(PRODUCT_MODULE_NAME).FilterDataProvider</string>
            <key>com.apple.networkextension.dns-proxy</key>
            <string>$(PRODUCT_MODULE_NAME).DNSProxyProvider</string>
        </dict>
    </dict>
    <key>NSEndpointSecurityEarlyBoot</key>
    <false/>
</dict>
</plist>
```

**Step 3: Create entitlements files**

```xml
<!-- macos/SysExt/SysExt.entitlements -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- ESF requires Apple approval - submit business justification -->
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
    <!-- Network Extension is a standard capability since Nov 2016 - enable in Xcode -->
    <!-- Use -systemextension suffix for Developer ID distribution -->
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>content-filter-provider-systemextension</string>
        <string>dns-proxy-systemextension</string>
    </array>
</dict>
</plist>
```

**Step 4: Commit**

```bash
git add macos/
git commit -m "feat(darwin): add Xcode project structure for System Extension"
```

---

### Task 7: Implement XPC Protocol (Swift)

**Files:**
- Create: `macos/Shared/XPCProtocol.swift`

**Step 1: Write XPC protocol**

```swift
// macos/Shared/XPCProtocol.swift
import Foundation

/// Protocol for communication between System Extension and XPC Service.
@objc protocol AgentshXPCProtocol {
    /// Check if a file operation is allowed.
    func checkFile(
        path: String,
        operation: String,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Check if a network connection is allowed.
    func checkNetwork(
        ip: String,
        port: Int,
        domain: String?,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Check if a command execution is allowed.
    func checkCommand(
        executable: String,
        args: [String],
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Resolve session ID for a process.
    func resolveSession(
        pid: pid_t,
        reply: @escaping (String?) -> Void
    )

    /// Emit an event to the agentsh server.
    func emitEvent(
        event: Data,
        reply: @escaping (Bool) -> Void
    )
}

/// XPC Service identifier.
let xpcServiceIdentifier = "com.agentsh.xpc"
```

**Step 2: Commit**

```bash
git add macos/Shared/
git commit -m "feat(darwin): add XPC protocol definition (Swift)"
```

---

### Task 8: Implement XPC Service Bridge

**Files:**
- Create: `macos/XPCService/main.swift`
- Create: `macos/XPCService/XPCServiceDelegate.swift`
- Create: `macos/XPCService/PolicyBridge.swift`

**Step 1: Write XPC Service main**

```swift
// macos/XPCService/main.swift
import Foundation

let delegate = XPCServiceDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()

RunLoop.main.run()
```

**Step 2: Write XPC Service delegate**

```swift
// macos/XPCService/XPCServiceDelegate.swift
import Foundation

class XPCServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let bridge = PolicyBridge()

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        newConnection.exportedObject = bridge
        newConnection.resume()
        return true
    }
}
```

**Step 3: Write Policy Bridge**

```swift
// macos/XPCService/PolicyBridge.swift
import Foundation

/// Bridges XPC calls to the Go policy server via Unix socket.
class PolicyBridge: NSObject, AgentshXPCProtocol {
    private let socketPath = "/var/run/agentsh/policy.sock"
    private let timeout: TimeInterval = 5.0

    func checkFile(
        path: String,
        operation: String,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "file",
            "path": path,
            "operation": operation,
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    func checkNetwork(
        ip: String,
        port: Int,
        domain: String?,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "network",
            "ip": ip,
            "port": port,
            "domain": domain ?? "",
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    func checkCommand(
        executable: String,
        args: [String],
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "command",
            "path": executable,
            "args": args,
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    func resolveSession(pid: pid_t, reply: @escaping (String?) -> Void) {
        let request: [String: Any] = [
            "type": "session",
            "pid": pid
        ]
        sendRequest(request) { response in
            let sessionID = response["session_id"] as? String
            reply(sessionID?.isEmpty == true ? nil : sessionID)
        }
    }

    func emitEvent(event: Data, reply: @escaping (Bool) -> Void) {
        let request: [String: Any] = [
            "type": "event",
            "event_data": event.base64EncodedString()
        ]
        sendRequest(request) { _ in
            reply(true)
        }
    }

    // MARK: - Socket Communication

    private func sendRequest(
        _ request: [String: Any],
        completion: @escaping ([String: Any]) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else {
                completion(["allow": true])
                return
            }

            do {
                let response = try self.sendSync(request)
                DispatchQueue.main.async {
                    completion(response)
                }
            } catch {
                // Fail-open: allow on error
                NSLog("PolicyBridge error: \(error)")
                DispatchQueue.main.async {
                    completion(["allow": true, "rule": "error-failopen"])
                }
            }
        }
    }

    private func sendSync(_ request: [String: Any]) throws -> [String: Any] {
        // Create Unix socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw BridgeError.socketCreation
        }
        defer { close(fd) }

        // Connect
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            socketPath.withCString { cstr in
                strcpy(ptr, cstr)
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, addrLen)
            }
        }

        guard result == 0 else {
            throw BridgeError.connectionFailed
        }

        // Set timeout
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Send request
        let requestData = try JSONSerialization.data(withJSONObject: request)
        var dataWithNewline = requestData
        dataWithNewline.append(0x0A) // newline

        let written = dataWithNewline.withUnsafeBytes { ptr in
            write(fd, ptr.baseAddress, ptr.count)
        }
        guard written == dataWithNewline.count else {
            throw BridgeError.writeFailed
        }

        // Read response
        var buffer = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(fd, &buffer, buffer.count)
        guard bytesRead > 0 else {
            throw BridgeError.readFailed
        }

        let responseData = Data(bytes: buffer, count: bytesRead)
        guard let response = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw BridgeError.invalidResponse
        }

        return response
    }

    enum BridgeError: Error {
        case socketCreation
        case connectionFailed
        case writeFailed
        case readFailed
        case invalidResponse
    }
}
```

**Step 4: Commit**

```bash
git add macos/XPCService/
git commit -m "feat(darwin): implement XPC Service bridge to Go policy server"
```

---

### Task 9: Implement ESF Client

**Files:**
- Create: `macos/SysExt/ESFClient.swift`
- Create: `macos/SysExt/main.swift`

**Step 1: Write ESF Client**

```swift
// macos/SysExt/ESFClient.swift
import Foundation
import EndpointSecurity

/// Handles Endpoint Security Framework events.
class ESFClient {
    private var client: OpaquePointer?
    private let xpc: NSXPCConnection
    private var xpcProxy: AgentshXPCProtocol?

    init() {
        // Connect to XPC Service
        xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
        xpc.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        xpc.resume()

        xpcProxy = xpc.remoteObjectProxyWithErrorHandler { error in
            NSLog("XPC error: \(error)")
        } as? AgentshXPCProtocol
    }

    func start() -> Bool {
        var client: OpaquePointer?

        let result = es_new_client(&client) { [weak self] _, event in
            self?.handleEvent(event)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            NSLog("Failed to create ES client: \(result.rawValue)")
            return false
        }

        self.client = client

        // Subscribe to AUTH events (blocking)
        let authEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC
        ]

        // Subscribe to NOTIFY events (observation)
        let notifyEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK
        ]

        let allEvents = authEvents + notifyEvents
        let subscribeResult = es_subscribe(client!, allEvents, UInt32(allEvents.count))

        guard subscribeResult == ES_RETURN_SUCCESS else {
            NSLog("Failed to subscribe: \(subscribeResult.rawValue)")
            es_delete_client(client!)
            self.client = nil
            return false
        }

        NSLog("ESF client started successfully")
        return true
    }

    func stop() {
        if let client = client {
            es_delete_client(client)
            self.client = nil
        }
        xpc.invalidate()
    }

    private func handleEvent(_ event: UnsafePointer<es_message_t>) {
        let message = event.pointee
        let pid = audit_token_to_pid(message.process.pointee.audit_token)

        switch message.event_type {
        // AUTH events - must respond
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleAuthOpen(message, pid: pid)
        case ES_EVENT_TYPE_AUTH_CREATE:
            handleAuthCreate(message, pid: pid)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            handleAuthUnlink(message, pid: pid)
        case ES_EVENT_TYPE_AUTH_RENAME:
            handleAuthRename(message, pid: pid)
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleAuthExec(message, pid: pid)

        // NOTIFY events - no response needed
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleNotifyFork(message, pid: pid)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleNotifyExit(message, pid: pid)
        default:
            break
        }
    }

    // MARK: - AUTH Handlers

    private func handleAuthOpen(_ message: es_message_t, pid: pid_t) {
        guard let client = client else { return }
        let path = String(cString: message.event.open.file.pointee.path.data)

        xpcProxy?.checkFile(path: path, operation: "read", pid: pid, sessionID: nil) { allow, _ in
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, &message, result, false)
        }
    }

    private func handleAuthCreate(_ message: es_message_t, pid: pid_t) {
        guard let client = client else { return }
        // Similar pattern - extract path, check policy, respond
        es_respond_auth_result(client, &message, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthUnlink(_ message: es_message_t, pid: pid_t) {
        guard let client = client else { return }
        es_respond_auth_result(client, &message, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthRename(_ message: es_message_t, pid: pid_t) {
        guard let client = client else { return }
        es_respond_auth_result(client, &message, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthExec(_ message: es_message_t, pid: pid_t) {
        guard let client = client else { return }
        let execPath = String(cString: message.event.exec.target.pointee.executable.pointee.path.data)

        xpcProxy?.checkCommand(executable: execPath, args: [], pid: pid, sessionID: nil) { allow, _ in
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, &message, result, false)
        }
    }

    // MARK: - NOTIFY Handlers

    private func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
        // Track parent-child relationship for session scoping
        let childPid = audit_token_to_pid(message.event.fork.child.pointee.audit_token)
        NSLog("Fork: \(pid) -> \(childPid)")
    }

    private func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
        NSLog("Exit: \(pid)")
    }
}
```

**Step 2: Write System Extension main**

```swift
// macos/SysExt/main.swift
import Foundation
import NetworkExtension

class ExtensionMain: NSObject, OSSystemExtensionRequestDelegate {
    private var esfClient: ESFClient?
    private var filterProvider: FilterDataProvider?
    private var dnsProvider: DNSProxyProvider?

    override init() {
        super.init()

        // Start ESF client
        esfClient = ESFClient()
        if !esfClient!.start() {
            NSLog("Failed to start ESF client")
        }

        // Network Extension providers are started by the system
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        NSLog("Extension request finished: \(result.rawValue)")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        NSLog("Extension request failed: \(error)")
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("Extension needs user approval")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

// Entry point
let main = ExtensionMain()
dispatchMain()
```

**Step 3: Commit**

```bash
git add macos/SysExt/
git commit -m "feat(darwin): implement ESF client for System Extension"
```

---

### Task 10: Implement Network Extension Providers

**Files:**
- Create: `macos/SysExt/FilterDataProvider.swift`
- Create: `macos/SysExt/DNSProxyProvider.swift`

**Step 1: Write Filter Data Provider**

```swift
// macos/SysExt/FilterDataProvider.swift
import NetworkExtension

class FilterDataProvider: NEFilterDataProvider {
    private var xpc: NSXPCConnection?
    private var xpcProxy: AgentshXPCProtocol?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Connect to XPC Service
        xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
        xpc?.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        xpc?.resume()

        xpcProxy = xpc?.remoteObjectProxyWithErrorHandler { error in
            NSLog("XPC error: \(error)")
        } as? AgentshXPCProtocol

        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        xpc?.invalidate()
        xpc = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }

        let ip = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0
        let pid = socketFlow.sourceAppAuditToken.map { audit_token_to_pid($0) } ?? 0

        // For now, allow and check async
        // In production, use .needRules() and respond later
        xpcProxy?.checkNetwork(ip: ip, port: port, domain: nil, pid: pid, sessionID: nil) { allow, _ in
            if !allow {
                NSLog("Would block: \(ip):\(port) from pid \(pid)")
            }
        }

        return .allow()
    }

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }
}
```

**Step 2: Write DNS Proxy Provider**

```swift
// macos/SysExt/DNSProxyProvider.swift
import NetworkExtension

class DNSProxyProvider: NEDNSProxyProvider {
    private var xpc: NSXPCConnection?
    private var xpcProxy: AgentshXPCProtocol?

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        // Connect to XPC Service
        xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
        xpc?.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        xpc?.resume()

        xpcProxy = xpc?.remoteObjectProxyWithErrorHandler { error in
            NSLog("XPC error: \(error)")
        } as? AgentshXPCProtocol

        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        xpc?.invalidate()
        xpc = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // DNS flows come through here
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleDNSFlow(udpFlow)
            return true
        }
        return false
    }

    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: nil) { error in
            if let error = error {
                NSLog("DNS flow open error: \(error)")
                return
            }
            self.readAndProcessDNS(flow)
        }
    }

    private func readAndProcessDNS(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { datagrams, endpoints, error in
            guard let datagrams = datagrams, let endpoints = endpoints, error == nil else {
                return
            }

            for (datagram, endpoint) in zip(datagrams, endpoints) {
                // Parse DNS query, extract domain
                // Check policy
                // Forward or block
                self.forwardDNS(datagram, to: endpoint, via: flow)
            }
        }
    }

    private func forwardDNS(_ datagram: Data, to endpoint: NWEndpoint, via flow: NEAppProxyUDPFlow) {
        // In production: parse query, check policy, forward to upstream or return NXDOMAIN
        flow.writeDatagrams([datagram], sentBy: [endpoint]) { error in
            if let error = error {
                NSLog("DNS write error: \(error)")
            }
        }
    }
}
```

**Step 3: Commit**

```bash
git add macos/SysExt/FilterDataProvider.swift macos/SysExt/DNSProxyProvider.swift
git commit -m "feat(darwin): implement Network Extension providers"
```

---

## Phase 3: Build and Packaging

### Task 11: Add Makefile Targets

**Files:**
- Modify: `Makefile`

**Step 1: Add macOS enterprise build targets**

```makefile
# Add to Makefile

.PHONY: build-macos-enterprise build-swift assemble-bundle sign-bundle

# Build Go binary for macOS
build-macos-go:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o build/AgentSH.app/Contents/MacOS/agentsh ./cmd/agentsh
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o build/AgentSH-amd64.app/Contents/MacOS/agentsh ./cmd/agentsh

# Build Swift components (requires Xcode)
build-swift:
	xcodebuild -project macos/AgentSH.xcodeproj -scheme SysExt -configuration Release
	xcodebuild -project macos/AgentSH.xcodeproj -scheme XPCService -configuration Release

# Assemble app bundle
assemble-bundle: build-macos-go build-swift
	mkdir -p build/AgentSH.app/Contents/{Library/SystemExtensions,XPCServices,Resources}
	cp macos/AgentSH/Info.plist build/AgentSH.app/Contents/
	cp -r build/Release/com.agentsh.sysext.systemextension build/AgentSH.app/Contents/Library/SystemExtensions/
	cp -r build/Release/com.agentsh.xpc.xpc build/AgentSH.app/Contents/XPCServices/

# Sign bundle (requires signing identity)
sign-bundle:
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/SysExt/SysExt.entitlements \
		build/AgentSH.app/Contents/Library/SystemExtensions/com.agentsh.sysext.systemextension
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app/Contents/XPCServices/com.agentsh.xpc.xpc
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app

# Full enterprise build
build-macos-enterprise: assemble-bundle sign-bundle
	@echo "Enterprise build complete: build/AgentSH.app"
```

**Step 2: Commit**

```bash
git add Makefile
git commit -m "feat(darwin): add Makefile targets for enterprise build"
```

---

### Task 12: Add Integration Test Scaffolding

**Files:**
- Create: `internal/platform/darwin/xpc/integration_test.go`

**Step 1: Write integration test**

```go
// internal/platform/darwin/xpc/integration_test.go
//go:build integration && darwin

package xpc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestIntegration_FullPolicyFlow(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create real policy
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-etc", Paths: []string{"/etc/**"}, Operations: []string{"write"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Start server
	sockPath := "/tmp/agentsh-test-policy.sock"
	tracker := NewSessionTracker()
	tracker.RegisterProcess("session-test", 12345, 0)

	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	defer os.Remove(sockPath)

	// Test file allow
	t.Run("file_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/home/user/test.txt",
			Operation: "read",
			PID:       12345,
		})
		if !resp.Allow {
			t.Error("expected allow")
		}
	})

	// Test file deny
	t.Run("file_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/etc/passwd",
			Operation: "write",
			PID:       12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
		if resp.Rule != "deny-etc" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "deny-etc")
		}
	})

	// Test command deny
	t.Run("command_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeCommand,
			Path: "/bin/rm",
			Args: []string{"-rf", "/"},
			PID:  12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
	})

	// Test session lookup
	t.Run("session_lookup", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeSession,
			PID:  12345,
		})
		if resp.SessionID != "session-test" {
			t.Errorf("session: got %q, want %q", resp.SessionID, "session-test")
		}
	})
}

func sendTestRequest(t *testing.T, sockPath string, req PolicyRequest) PolicyResponse {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return resp
}
```

**Step 2: Commit**

```bash
git add internal/platform/darwin/xpc/integration_test.go
git commit -m "test(darwin): add XPC integration test scaffolding"
```

---

## Summary

### Phase 1 (Go - testable everywhere):
1. Define XPC protocol types
2. Implement policy socket server
3. Create policy handler adapter
4. Add session process tracker
5. Add sysext CLI commands

### Phase 2 (Swift - requires macOS + Xcode):
6. Create Xcode project structure
7. Implement XPC protocol (Swift)
8. Implement XPC Service bridge
9. Implement ESF client
10. Implement Network Extension providers

### Phase 3 (Build/Package):
11. Add Makefile targets
12. Add integration test scaffolding

### Post-Implementation:
- Apply for ESF entitlement from Apple (requires business justification)
- Enable Network Extension capability in Xcode (standard capability - no approval needed)
- Set up signing certificates
- Configure notarization
- Add CI pipeline for entitled builds
