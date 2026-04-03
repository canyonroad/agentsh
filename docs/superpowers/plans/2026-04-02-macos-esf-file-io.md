# macOS ESF File I/O Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete end-to-end file I/O event capture on macOS via ESF, achieving parity with Linux's seccomp/FUSE file event tracking.

**Architecture:** The sysext opens a persistent event stream connection to the Go policy socket server. All ESF AUTH decisions and NOTIFY events are forwarded as fire-and-forget JSON. The Go server resolves PID to command_id, builds types.Event objects, and stores them in SQLite via the existing async batch writer.

**Tech Stack:** Go (policysock server, event handler), Swift (ESF sysext, PolicySocketClient), SQLite (event store)

**Spec:** `docs/superpowers/specs/2026-04-02-macos-esf-file-io-design.md`

---

## File Structure

**New Go files:**
- `internal/platform/darwin/policysock/command_resolver.go` -- PID to command_id concurrent map
- `internal/platform/darwin/policysock/command_resolver_test.go` -- tests
- `internal/platform/darwin/policysock/esf_event_handler.go` -- concrete EventHandler implementation
- `internal/platform/darwin/policysock/esf_event_handler_test.go` -- tests

**Modified Go files:**
- `internal/platform/darwin/policysock/server.go` -- event stream mode in handleConn
- `internal/platform/darwin/policysock/protocol.go` -- add RequestTypeEventStreamInit constant
- `internal/server/policysock_darwin.go` -- wire EventHandler + CommandResolver
- `internal/server/server.go` -- add cmdResolver field
- `internal/api/exec.go` -- register PID to command_id after cmd.Start()

**Modified Swift files:**
- `macos/AgentSH/PolicySocketClient.swift` -- persistent event stream connection + ring buffer
- `macos/AgentSH/ESFClient.swift` -- forward AUTH decisions, fork/exit, SETATTR

---

### Task 1: CommandResolver -- PID to Command_ID Mapping

**Files:**
- Create: `internal/platform/darwin/policysock/command_resolver.go`
- Create: `internal/platform/darwin/policysock/command_resolver_test.go`

- [ ] **Step 1: Write the test file**

Create `internal/platform/darwin/policysock/command_resolver_test.go`:

```go
//go:build darwin

package policysock

import (
	"testing"
)

func TestCommandResolver_RegisterAndLookup(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")

	got := cr.CommandForPID(100)
	if got != "cmd-abc" {
		t.Errorf("CommandForPID(100) = %q, want %q", got, "cmd-abc")
	}
}

func TestCommandResolver_UnknownPID(t *testing.T) {
	cr := NewCommandResolver()

	got := cr.CommandForPID(999)
	if got != "" {
		t.Errorf("CommandForPID(999) = %q, want empty", got)
	}
}

func TestCommandResolver_RegisterFork(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")
	cr.RegisterFork(100, 101)

	got := cr.CommandForPID(101)
	if got != "cmd-abc" {
		t.Errorf("CommandForPID(101) = %q, want %q", got, "cmd-abc")
	}
}

func TestCommandResolver_ForkUnknownParent(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterFork(999, 1000)

	got := cr.CommandForPID(1000)
	if got != "" {
		t.Errorf("CommandForPID(1000) = %q, want empty", got)
	}
}

func TestCommandResolver_Unregister(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")
	cr.UnregisterPID(100)

	got := cr.CommandForPID(100)
	if got != "" {
		t.Errorf("CommandForPID(100) after unregister = %q, want empty", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/policysock/ -run TestCommandResolver -v`
Expected: FAIL -- `NewCommandResolver` undefined

- [ ] **Step 3: Implement CommandResolver**

Create `internal/platform/darwin/policysock/command_resolver.go`:

```go
//go:build darwin

package policysock

import "sync"

// CommandResolver maps process PIDs to command IDs.
// Thread-safe for concurrent reads and writes.
type CommandResolver struct {
	mu   sync.RWMutex
	pids map[int32]string // PID -> command_id
}

// NewCommandResolver creates a new empty resolver.
func NewCommandResolver() *CommandResolver {
	return &CommandResolver{pids: make(map[int32]string)}
}

// RegisterCommand associates a PID with a command ID.
// Called by the exec handler after cmd.Start().
func (cr *CommandResolver) RegisterCommand(pid int32, commandID string) {
	cr.mu.Lock()
	cr.pids[pid] = commandID
	cr.mu.Unlock()
}

// RegisterFork associates a child PID with the same command ID as its parent.
// If the parent PID is unknown, the child is not registered.
func (cr *CommandResolver) RegisterFork(parentPID, childPID int32) {
	cr.mu.Lock()
	if cmdID, ok := cr.pids[parentPID]; ok {
		cr.pids[childPID] = cmdID
	}
	cr.mu.Unlock()
}

// UnregisterPID removes a PID from the resolver.
func (cr *CommandResolver) UnregisterPID(pid int32) {
	cr.mu.Lock()
	delete(cr.pids, pid)
	cr.mu.Unlock()
}

// CommandForPID returns the command ID for a PID, or empty string if unknown.
func (cr *CommandResolver) CommandForPID(pid int32) string {
	cr.mu.RLock()
	cmdID := cr.pids[pid]
	cr.mu.RUnlock()
	return cmdID
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -run TestCommandResolver -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS (file has `//go:build darwin` tag)

- [ ] **Step 6: Commit**

```bash
git add internal/platform/darwin/policysock/command_resolver.go internal/platform/darwin/policysock/command_resolver_test.go
git commit -m "feat(darwin): add CommandResolver for PID to command_id mapping"
```

---

### Task 2: ESFEventHandler -- Process ESF Events into types.Event

**Files:**
- Create: `internal/platform/darwin/policysock/esf_event_handler.go`
- Create: `internal/platform/darwin/policysock/esf_event_handler_test.go`

- [ ] **Step 1: Write the test file**

Create `internal/platform/darwin/policysock/esf_event_handler_test.go`:

```go
//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// fakeEventStore captures events for testing.
type fakeEventStore struct {
	events []types.Event
}

func (f *fakeEventStore) AppendEvent(_ context.Context, ev types.Event) error {
	f.events = append(f.events, ev)
	return nil
}

func TestESFEventHandler_FileOpen(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(1234, "cmd-test-123")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_open",
		"path":       "/workspace/secret.txt",
		"operation":  "read",
		"pid":        1234,
		"session_id": "session-abc",
		"decision":   "allow",
		"rule":       "allow-workspace-read",
		"timestamp":  "2026-04-02T16:34:08Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	if len(store.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(store.events))
	}

	ev := store.events[0]
	if ev.Type != "file_open" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_open")
	}
	if ev.Path != "/workspace/secret.txt" {
		t.Errorf("Path = %q, want %q", ev.Path, "/workspace/secret.txt")
	}
	if ev.SessionID != "session-abc" {
		t.Errorf("SessionID = %q, want %q", ev.SessionID, "session-abc")
	}
	if ev.CommandID != "cmd-test-123" {
		t.Errorf("CommandID = %q, want %q", ev.CommandID, "cmd-test-123")
	}
	if ev.Source != "esf" {
		t.Errorf("Source = %q, want %q", ev.Source, "esf")
	}
	if ev.Operation != "read" {
		t.Errorf("Operation = %q, want %q", ev.Operation, "read")
	}
}

func TestESFEventHandler_FileRename(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_rename",
		"path":       "/workspace/old.txt",
		"path2":      "/workspace/new.txt",
		"pid":        100,
		"session_id": "session-abc",
		"decision":   "allow",
		"rule":       "allow-workspace",
		"timestamp":  "2026-04-02T16:35:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Type != "file_rename" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_rename")
	}
	if ev.Fields["path2"] != "/workspace/new.txt" {
		t.Errorf("Fields[path2] = %v, want %q", ev.Fields["path2"], "/workspace/new.txt")
	}
}

func TestESFEventHandler_ProcessFork(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-parent")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "process_fork",
		"pid":        100,
		"child_pid":  101,
		"session_id": "session-abc",
		"timestamp":  "2026-04-02T16:36:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	// Fork should register child PID, not store an event
	if len(store.events) != 0 {
		t.Errorf("expected 0 stored events for fork, got %d", len(store.events))
	}
	if cr.CommandForPID(101) != "cmd-parent" {
		t.Errorf("child PID command = %q, want %q", cr.CommandForPID(101), "cmd-parent")
	}
}

func TestESFEventHandler_ProcessExit(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-test")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "process_exit",
		"pid":        100,
		"session_id": "session-abc",
		"timestamp":  "2026-04-02T16:37:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	if cr.CommandForPID(100) != "" {
		t.Errorf("PID should be unregistered after exit, got %q", cr.CommandForPID(100))
	}
}

func TestESFEventHandler_NotifyEvent(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_write",
		"path":       "/workspace/modified.txt",
		"operation":  "close_modified",
		"pid":        200,
		"session_id": "session-def",
		"decision":   "observed",
		"timestamp":  "2026-04-02T16:38:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Type != "file_write" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_write")
	}
	if ev.Policy == nil || ev.Policy.Decision != "observed" {
		t.Errorf("expected decision 'observed'")
	}
}

func TestESFEventHandler_ActionField(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_delete",
		"path":       "/workspace/important.txt",
		"operation":  "delete",
		"pid":        300,
		"session_id": "session-ghi",
		"decision":   "deny",
		"rule":       "soft-delete-rule",
		"action":     "soft_delete",
		"timestamp":  "2026-04-02T16:39:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Fields["action"] != "soft_delete" {
		t.Errorf("Fields[action] = %v, want %q", ev.Fields["action"], "soft_delete")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/policysock/ -run TestESFEventHandler -v`
Expected: FAIL -- `NewESFEventHandler` undefined

- [ ] **Step 3: Implement ESFEventHandler**

Create `internal/platform/darwin/policysock/esf_event_handler.go`:

```go
//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// esfEventStore is the subset of store.EventStore needed by ESFEventHandler.
type esfEventStore interface {
	AppendEvent(ctx context.Context, ev types.Event) error
}

// ESFEventHandler processes ESF events from the sysext and stores them.
type ESFEventHandler struct {
	store       esfEventStore
	cmdResolver *CommandResolver
	tracker     *SessionTracker
}

// NewESFEventHandler creates a handler that processes ESF events.
func NewESFEventHandler(store esfEventStore, cmdResolver *CommandResolver, tracker *SessionTracker) *ESFEventHandler {
	return &ESFEventHandler{
		store:       store,
		cmdResolver: cmdResolver,
		tracker:     tracker,
	}
}

// esfEvent is the JSON structure sent by the Swift sysext.
type esfEvent struct {
	Type      string `json:"type"`
	EventType string `json:"event_type"`
	Path      string `json:"path"`
	Path2     string `json:"path2,omitempty"`
	Operation string `json:"operation"`
	PID       int32  `json:"pid"`
	ChildPID  int32  `json:"child_pid,omitempty"`
	SessionID string `json:"session_id"`
	Decision  string `json:"decision"`
	Rule      string `json:"rule"`
	Action    string `json:"action,omitempty"`
	Timestamp string `json:"timestamp"`
}

// HandleESFEvent implements the EventHandler interface.
func (h *ESFEventHandler) HandleESFEvent(ctx context.Context, payload []byte) error {
	var ev esfEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return fmt.Errorf("unmarshal esf event: %w", err)
	}

	switch ev.EventType {
	case "process_fork":
		h.cmdResolver.RegisterFork(ev.PID, ev.ChildPID)
		return nil
	case "process_exit":
		h.cmdResolver.UnregisterPID(ev.PID)
		return nil
	}

	// Resolve command ID from PID
	commandID := h.cmdResolver.CommandForPID(ev.PID)

	// Resolve session ID -- prefer payload, fall back to tracker
	sessionID := ev.SessionID
	if sessionID == "" {
		sessionID = h.tracker.SessionForPID(ev.PID)
	}

	// Parse timestamp
	ts, err := time.Parse(time.RFC3339, ev.Timestamp)
	if err != nil {
		ts = time.Now()
	}

	// Build types.Event
	event := types.Event{
		ID:        uuid.NewString(),
		Timestamp: ts,
		Type:      ev.EventType,
		SessionID: sessionID,
		CommandID: commandID,
		Source:    "esf",
		PID:      int(ev.PID),
		Path:     ev.Path,
		Operation: ev.Operation,
		Fields:   make(map[string]any),
	}

	// Policy info
	if ev.Decision != "" {
		event.Policy = &types.PolicyInfo{
			Decision: ev.Decision,
			Rule:     ev.Rule,
		}
	}

	// Extra fields
	if ev.Path2 != "" {
		event.Fields["path2"] = ev.Path2
	}
	if ev.Action != "" {
		event.Fields["action"] = ev.Action
	}

	if err := h.store.AppendEvent(ctx, event); err != nil {
		slog.Warn("failed to store ESF event", "type", ev.EventType, "error", err)
		return err
	}

	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -run TestESFEventHandler -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/platform/darwin/policysock/esf_event_handler.go internal/platform/darwin/policysock/esf_event_handler_test.go
git commit -m "feat(darwin): add ESFEventHandler for processing sysext file events"
```

---

### Task 3: Event Stream Mode in policysock Server

**Files:**
- Modify: `internal/platform/darwin/policysock/server.go` -- handleConn and new handleEventStream method
- Modify: `internal/platform/darwin/policysock/protocol.go` -- add RequestTypeEventStreamInit
- Create or modify: `internal/platform/darwin/policysock/server_test.go` -- stream mode test

- [ ] **Step 1: Add RequestTypeEventStreamInit constant**

In `internal/platform/darwin/policysock/protocol.go`, add to the request type constants:

```go
RequestTypeEventStreamInit RequestType = "event_stream_init"
```

- [ ] **Step 2: Write a test for the stream mode**

Create or add to `internal/platform/darwin/policysock/server_test.go`:

```go
//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type mockPolicyHandler struct{}

func (m *mockPolicyHandler) CheckFile(path, op string) (bool, string) { return true, "" }
func (m *mockPolicyHandler) CheckNetwork(ip string, port int, domain string) (bool, string) {
	return true, ""
}
func (m *mockPolicyHandler) CheckCommand(cmd string, args []string) (bool, string) {
	return true, ""
}
func (m *mockPolicyHandler) ResolveSession(pid int32) string { return "" }

type mockESFEventHandler struct {
	mu     sync.Mutex
	events [][]byte
}

func (m *mockESFEventHandler) HandleESFEvent(_ context.Context, payload []byte) error {
	m.mu.Lock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	m.events = append(m.events, cp)
	m.mu.Unlock()
	return nil
}

func (m *mockESFEventHandler) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestServer_EventStream(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	handler := &mockPolicyHandler{}
	srv := NewServer(sockPath, handler)

	mock := &mockESFEventHandler{}
	srv.SetEventHandler(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()
	if err := srv.StartErr(); err != nil {
		t.Fatalf("server start: %v", err)
	}

	// Connect and send event_stream_init
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send init
	initMsg, _ := json.Marshal(map[string]any{"type": "event_stream_init"})
	initMsg = append(initMsg, '\n')
	conn.Write(initMsg)

	// Read ack
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	var ack map[string]any
	if err := json.Unmarshal(buf[:n], &ack); err != nil {
		t.Fatalf("unmarshal ack: %v (raw: %s)", err, buf[:n])
	}
	if ack["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", ack)
	}

	// Send file events
	for i := 0; i < 3; i++ {
		ev, _ := json.Marshal(map[string]any{
			"type":       "file_event",
			"event_type": "file_open",
			"path":       "/test",
			"pid":        100 + i,
			"session_id": "sess-1",
			"timestamp":  "2026-04-02T00:00:00Z",
		})
		ev = append(ev, '\n')
		conn.Write(ev)
	}

	// Close connection to signal EOF
	conn.Close()

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	if mock.count() != 3 {
		t.Errorf("expected 3 events, got %d", mock.count())
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/policysock/ -run TestServer_EventStream -v`
Expected: FAIL -- server does not handle event_stream_init

- [ ] **Step 4: Modify handleConn in server.go**

In `server.go`, modify the `handleConn` method to detect event stream init as the first message. Add a `handleEventStream` method:

The key change: after decoding the first `PolicyRequest`, check if `req.Type == RequestTypeEventStreamInit`. If so, send an ack response and enter `handleEventStream` which reads events in a loop.

```go
// In handleConn, after decoding the first request:
if req.Type == RequestTypeEventStreamInit {
	enc.Encode(map[string]any{"status": "ok"})
	s.handleEventStream(dec)
	return
}
// ... existing request-response handling continues

// New method:
func (s *Server) handleEventStream(dec *json.Decoder) {
	s.mu.RLock()
	eh := s.eventHandler
	s.mu.RUnlock()

	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return // EOF or error -- stream closed
		}
		if eh != nil {
			if err := eh.HandleESFEvent(context.Background(), []byte(raw)); err != nil {
				slog.Warn("event stream: handler error", "error", err)
			}
		}
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -run TestServer_EventStream -v`
Expected: PASS

- [ ] **Step 6: Run all policysock tests**

Run: `go test ./internal/platform/darwin/policysock/ -v`
Expected: PASS (no regressions)

- [ ] **Step 7: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/platform/darwin/policysock/server.go internal/platform/darwin/policysock/protocol.go internal/platform/darwin/policysock/server_test.go
git commit -m "feat(darwin): add event stream mode to policysock server"
```

---

### Task 4: Wire EventHandler and CommandResolver into Server

**Files:**
- Modify: `internal/server/policysock_darwin.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: Add cmdResolver field to Server struct**

In `internal/server/server.go`, add to the Server struct:

```go
// cmdResolver is set on darwin to resolve PID to command_id for ESF events.
// Nil on non-darwin platforms.
cmdResolver interface {
	RegisterCommand(pid int32, commandID string)
}
```

- [ ] **Step 2: Wire EventHandler in policysock_darwin.go**

In `startPolicySocket`, after creating the tracker and adapter, create the ESFEventHandler and CommandResolver. Call `psrv.SetEventHandler(eventHandler)`. Store the resolver in `s.cmdResolver`.

See the spec component 8 for exact wiring. The key additions:

```go
cmdResolver := policysock.NewCommandResolver()
eventHandler := policysock.NewESFEventHandler(s.store, cmdResolver, tracker)
psrv.SetEventHandler(eventHandler)
s.cmdResolver = cmdResolver
```

Note: `s.store` must match the `esfEventStore` interface (has `AppendEvent`). Check that the server's store field type satisfies this -- it should, since `composite.Store` implements `store.EventStore`.

- [ ] **Step 3: Build and test**

Run: `go build ./... && go test ./internal/server/ -v`
Expected: PASS

- [ ] **Step 4: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS (cmdResolver interface is in server.go, not darwin-specific)

- [ ] **Step 5: Commit**

```bash
git add internal/server/server.go internal/server/policysock_darwin.go
git commit -m "feat(darwin): wire ESFEventHandler and CommandResolver into server"
```

---

### Task 5: Register PID to Command_ID in Exec Handler

**Files:**
- Modify: `internal/api/exec.go` -- add cmdResolver to extraProcConfig, register after cmd.Start()

- [ ] **Step 1: Add cmdResolver to extraProcConfig**

In `internal/api/exec.go`, find the `extraProcConfig` struct and add:

```go
cmdResolver interface {
	RegisterCommand(pid int32, commandID string)
}
```

- [ ] **Step 2: Register PID after cmd.Start()**

In `runCommandWithResources`, after `s.SetCurrentProcessPID(cmd.Process.Pid)` (around line 281-283):

```go
if extra != nil && extra.cmdResolver != nil {
	extra.cmdResolver.RegisterCommand(int32(cmd.Process.Pid), cmdID)
}
```

- [ ] **Step 3: Wire cmdResolver when constructing extraProcConfig**

Find where `extraProcConfig` is constructed (likely in `internal/api/app.go` or `internal/api/core.go`) and pass the server's `cmdResolver` through. This may require adding a `cmdResolver` field to `App` or accessing it from the server.

- [ ] **Step 4: Build and test**

Run: `go build ./... && go test ./internal/api/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/api/exec.go internal/api/app.go
git commit -m "feat: register PID to command_id for ESF file event attribution"
```

---

### Task 6: Swift -- Persistent Event Stream Connection

**Files:**
- Modify: `macos/AgentSH/PolicySocketClient.swift`

- [ ] **Step 1: Add event stream properties**

Add to `PolicySocketClient`:

```swift
// Event stream persistent connection
private var streamFD: Int32 = -1
private let streamQueue = DispatchQueue(label: "ai.canyonroad.agentsh.eventstream")
private var eventBuffer: [[String: Any]] = []
private let maxBufferSize = 1024
private var reconnectDelay: TimeInterval = 1.0
private let maxReconnectDelay: TimeInterval = 30.0
private var streamConnected = false
```

- [ ] **Step 2: Implement connectEventStream()**

Add `connectEventStream()` method that:
1. Opens a Unix socket connection to `socketPath`
2. Validates server code signing (reuse `validateServer(fd:)`)
3. Sends `{"type": "event_stream_init"}` with newline
4. Reads ack response `{"status": "ok"}`
5. Stores fd as `streamFD`, sets `streamConnected = true`
6. Flushes any buffered events
7. On failure, calls `scheduleReconnect()`

- [ ] **Step 3: Implement sendEvent() with ring buffer**

Add `sendEvent(_ event: [String: Any])` method that:
1. If connected, writes event as newline-delimited JSON to `streamFD`
2. If write fails, closes connection, buffers event, schedules reconnect
3. If not connected, buffers event (drop oldest if buffer exceeds `maxBufferSize`, log warning)

- [ ] **Step 4: Implement reconnect logic**

Add `scheduleReconnect()` with exponential backoff (1s, 2s, 4s, ... capped at 30s). Reset delay on successful connect.

- [ ] **Step 5: Call connectEventStream from connectWhenReady**

In the existing `connectWhenReady()`, add `connectEventStream()` call.

- [ ] **Step 6: Commit**

```bash
git add macos/AgentSH/PolicySocketClient.swift
git commit -m "feat(darwin): add persistent event stream connection with ring buffer"
```

---

### Task 7: Swift -- Forward AUTH Decisions from ESFClient

**Files:**
- Modify: `macos/AgentSH/ESFClient.swift`

- [ ] **Step 1: Add sendFileEvent helper method**

Add a private helper that builds the event JSON dict and calls `PolicySocketClient.shared.sendEvent()`:

```swift
private func sendFileEvent(
    eventType: String,
    path: String,
    operation: String,
    pid: pid_t,
    sessionID: String?,
    decision: String,
    rule: String?,
    action: String? = nil,
    extraFields: [String: Any]? = nil
)
```

- [ ] **Step 2: Add forwarding to handleAuthOpen**

After the `es_respond_flags_result` call, send a `file_open` event. Determine operation (read/write/readwrite) from `event.pointee.event.open.fflag` checking `FFLAGS_READ` and `FFLAGS_WRITE` bits.

- [ ] **Step 3: Add forwarding to handleAuthCreate**

After `es_respond_auth_result`, send a `file_create` event.

- [ ] **Step 4: Add forwarding to handleAuthUnlink**

After `es_respond_auth_result`, send a `file_delete` event. Include `action: "soft_delete"` if the rule action was soft_delete.

- [ ] **Step 5: Add forwarding to handleAuthRename**

After `es_respond_auth_result`, send a `file_rename` event with `path2` for the destination.

- [ ] **Step 6: Switch handleNotifyClose to use sendEvent**

Replace the existing `PolicySocketClient.shared.send(...)` (base64-encoded event_data path) with `sendFileEvent(eventType: "file_write", ...)`. Remove the old base64 encoding.

- [ ] **Step 7: Commit**

```bash
git add macos/AgentSH/ESFClient.swift
git commit -m "feat(darwin): forward all AUTH file decisions to Go server via event stream"
```

---

### Task 8: Swift -- Forward Fork/Exit Events for Command Resolution

**Files:**
- Modify: `macos/AgentSH/ESFClient.swift`

- [ ] **Step 1: Add fork event forwarding to handleNotifyFork**

After the existing `SessionPolicyCache.shared.addPID(...)` call, add:

```swift
PolicySocketClient.shared.sendEvent([
    "type": "file_event",
    "event_type": "process_fork",
    "pid": pid,
    "child_pid": childPid,
    "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
    "timestamp": ISO8601DateFormatter().string(from: Date())
])
```

- [ ] **Step 2: Add exit event forwarding to handleNotifyExit**

After the existing cleanup, add:

```swift
PolicySocketClient.shared.sendEvent([
    "type": "file_event",
    "event_type": "process_exit",
    "pid": pid,
    "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
    "timestamp": ISO8601DateFormatter().string(from: Date())
])
```

Note: Send exit event before removing PID from session cache so `sessionForPID` still works.

- [ ] **Step 3: Commit**

```bash
git add macos/AgentSH/ESFClient.swift
git commit -m "feat(darwin): forward fork/exit events for command_id resolution"
```

---

### Task 9: Swift -- NOTIFY_SETATTR Support (macOS 26+)

**Files:**
- Modify: `macos/AgentSH/ESFClient.swift`

- [ ] **Step 1: Add SETATTR to subscription list**

In the ESF event subscription (around line 65-76), add SETATTR gated for macOS 26:

```swift
if #available(macOS 26.0, *) {
    let setAttrEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_SETATTR]
    es_subscribe(client, setAttrEvents, UInt32(setAttrEvents.count))
}
```

If `ES_EVENT_TYPE_NOTIFY_SETATTR` does not compile on current SDK, wrap with appropriate `#if` compilation guard.

- [ ] **Step 2: Add SETATTR handler**

In the event switch, add (gated with `if #available(macOS 26.0, *)`):

```swift
@available(macOS 26.0, *)
private func handleNotifySetattr(_ message: es_message_t, pid: pid_t) {
    let sessionID = SessionPolicyCache.shared.sessionForPID(pid)
    guard let sessionID = sessionID else { return }

    let path = String(cString: message.event.setattr.target.pointee.path.data)
    let attr = message.event.setattr.attrlist

    if attr.commonattr & UInt32(ATTR_CMN_OWNERID) != 0 ||
       attr.commonattr & UInt32(ATTR_CMN_GRPID) != 0 {
        sendFileEvent(eventType: "file_chown", path: path, operation: "chown",
                      pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
    }

    if attr.commonattr & UInt32(ATTR_CMN_ACCESSMASK) != 0 {
        sendFileEvent(eventType: "file_chmod", path: path, operation: "chmod",
                      pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
    }
}
```

- [ ] **Step 3: Remove the TODO comment**

Delete the existing TODO at lines 234-235 about SETATTR.

- [ ] **Step 4: Commit**

```bash
git add macos/AgentSH/ESFClient.swift
git commit -m "feat(darwin): add NOTIFY_SETATTR support for chmod/chown events (macOS 26+)"
```

---

### Task 10: Documentation

**Files:**
- Modify or create docs for policy actions, architecture, README

- [ ] **Step 1: Document file rule actions on macOS**

Create or update policy documentation explaining macOS-specific behavior:
- `allow` -- operation permitted, event logged
- `deny` -- operation blocked, event logged
- `redirect` -- blocked at ESF, guidance tells agent to use alternative path
- `soft_delete` -- deletion blocked, file preserved, guidance explains why
- `approve` -- blocked at ESF, approval flow triggered (future), event logged

Explain differences from Linux where FUSE/seccomp can transparently intercept.

- [ ] **Step 2: Document event stream architecture**

Update architecture docs with:
- Two connection types (request-response + event stream)
- Event stream lifecycle (init handshake, persistent connection, ring buffer, reconnect)
- Event flow diagram

- [ ] **Step 3: Update README**

Add macOS file I/O section explaining ESF-based monitoring model and limitations.

- [ ] **Step 4: Commit**

```bash
git add docs/ README.md
git commit -m "docs: add macOS ESF file I/O architecture and policy documentation"
```

---

### Task 11: Build, Sign, Notarize, and E2E Test

**Files:**
- No new files -- build and test the complete system

- [ ] **Step 1: Build and test Go**

```bash
go build ./...
go test ./...
GOOS=windows go build ./...
```

- [ ] **Step 2: Build macOS app bundle**

Build the Xcode project with updated Swift code. Sign and notarize.

- [ ] **Step 3: Install, activate, start server**

```bash
# Install new build, run activate-extension
/Applications/AgentSH.app/Contents/MacOS/agentsh activate-extension
# Start server
/Applications/AgentSH.app/Contents/MacOS/agentsh server
```

- [ ] **Step 4: Create session and run file operations**

```bash
mkdir -p /tmp/agentsh-e2e-fileio
curl -s -X POST http://127.0.0.1:18080/api/v1/sessions \
  -H 'Content-Type: application/json' \
  -d '{"name":"file-io-test","workspace":"/tmp/agentsh-e2e-fileio"}'

SESSION_ID="<from response>"

# Write, read, delete, rename
curl -s -X POST "http://127.0.0.1:18080/api/v1/sessions/$SESSION_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"command":"sh","args":["-c","echo hello > /tmp/agentsh-e2e-fileio/test.txt"]}'

curl -s -X POST "http://127.0.0.1:18080/api/v1/sessions/$SESSION_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"command":"cat","args":["/tmp/agentsh-e2e-fileio/test.txt"]}'

curl -s -X POST "http://127.0.0.1:18080/api/v1/sessions/$SESSION_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"command":"rm","args":["/tmp/agentsh-e2e-fileio/test.txt"]}'

curl -s -X POST "http://127.0.0.1:18080/api/v1/sessions/$SESSION_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"command":"sh","args":["-c","echo data > /tmp/agentsh-e2e-fileio/a.txt && mv /tmp/agentsh-e2e-fileio/a.txt /tmp/agentsh-e2e-fileio/b.txt"]}'
```

- [ ] **Step 5: Query SQLite for file events**

```bash
sqlite3 data/events.db "
SELECT type, path, operation, policy_decision, command_id
FROM events
WHERE session_id='$SESSION_ID' AND type LIKE 'file_%'
ORDER BY ts_unix_ns;
"
```

Expected: `file_open`, `file_create`, `file_write`, `file_delete`, `file_rename` events with correct paths and command_id attribution.

- [ ] **Step 6: Commit any fixes**

```bash
git commit -m "test: verify ESF file I/O events end-to-end"
```
