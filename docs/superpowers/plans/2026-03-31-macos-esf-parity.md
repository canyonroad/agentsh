# macOS ESF & Network Extension Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring macOS enforcement and auditing to parity with Linux using ESF for file/exec and Network Extension for network, with a local policy cache and Darwin notification-based invalidation.

**Architecture:** Two enforcement pillars (ESF + Network Extension), both session-scoped. A `SessionPolicyCache` in the SysExt provides fast-path decisions from glob-matched rules, with XPC fallback to the Go policy server. Darwin notifications trigger cache refresh on policy changes.

**Tech Stack:** Swift (ESF, NetworkExtension, Darwin notify API), Go (policy engine, XPC Unix socket server, cgo for notify_post), EndpointSecurity C library

**Spec:** `docs/superpowers/specs/2026-03-31-macos-esf-parity-design.md`

---

### Task 1: Go-Side Protocol Extensions

Add new request types and fields to the XPC protocol so the Swift side can call them.

**Files:**
- Modify: `internal/platform/darwin/xpc/protocol.go:3-30` (request type constants), `internal/platform/darwin/xpc/protocol.go:33-78` (PolicyRequest struct)
- Test: `internal/platform/darwin/xpc/protocol_test.go` (new)

- [ ] **Step 1: Write test for new request type constants and PolicyRequest fields**

```go
// internal/platform/darwin/xpc/protocol_test.go
package xpc

import (
	"encoding/json"
	"testing"
)

func TestRequestTypeFetchPolicySnapshot(t *testing.T) {
	if RequestTypeFetchPolicySnapshot != "fetch_policy_snapshot" {
		t.Fatalf("expected fetch_policy_snapshot, got %s", RequestTypeFetchPolicySnapshot)
	}
}

func TestPolicyRequestDepthField(t *testing.T) {
	req := PolicyRequest{
		Type:  RequestTypeExecCheck,
		Path:  "/usr/bin/curl",
		Depth: 3,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Depth != 3 {
		t.Fatalf("expected depth 3, got %d", decoded.Depth)
	}
}

func TestPolicyRequestVersionField(t *testing.T) {
	req := PolicyRequest{
		Type:    RequestTypeFetchPolicySnapshot,
		SessionID: "session-abc",
		Version: 42,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 42 {
		t.Fatalf("expected version 42, got %d", decoded.Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/ -run TestRequestTypeFetchPolicySnapshot -v`
Expected: FAIL — `RequestTypeFetchPolicySnapshot` undefined

- [ ] **Step 3: Add new constants and fields to protocol.go**

In `internal/platform/darwin/xpc/protocol.go`, add to the request type constants block (after line ~29):

```go
RequestTypeFetchPolicySnapshot RequestType = "fetch_policy_snapshot"
```

Add to the `PolicyRequest` struct (after the existing fields):

```go
// Exec depth tracking
Depth int `json:"depth,omitempty"`

// Policy snapshot versioning
Version uint64 `json:"version,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/ -run "TestRequestType|TestPolicyRequest" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/xpc/protocol.go internal/platform/darwin/xpc/protocol_test.go
git commit -m "feat(darwin/xpc): add fetch_policy_snapshot request type, depth and version fields"
```

---

### Task 2: Go-Side Policy Snapshot Builder

Add `BuildPolicySnapshot` method to `PolicyAdapter` that projects the policy engine's rules into a flat cache format.

**Files:**
- Modify: `internal/platform/darwin/xpc/handler.go:16-19` (PolicyAdapter struct)
- Create: `internal/platform/darwin/xpc/snapshot.go`
- Test: `internal/platform/darwin/xpc/snapshot_test.go`

- [ ] **Step 1: Write test for BuildPolicySnapshot**

```go
// internal/platform/darwin/xpc/snapshot_test.go
package xpc

import (
	"encoding/json"
	"testing"
)

func TestPolicySnapshotResponse_JSON(t *testing.T) {
	snap := PolicySnapshotResponse{
		Version:   1,
		SessionID: "session-abc",
		FileRules: []SnapshotFileRule{
			{Pattern: "/home/user/project/**", Operations: []string{"read", "write", "create"}, Action: "allow"},
			{Pattern: "/etc/shadow", Operations: []string{"read"}, Action: "deny"},
		},
		NetworkRules: []SnapshotNetworkRule{
			{Pattern: "*.evil.com", Ports: []int{}, Action: "deny"},
		},
		DNSRules: []SnapshotDNSRule{
			{Pattern: "*.evil.com", Action: "nxdomain"},
		},
		Defaults: SnapshotDefaults{File: "allow", Network: "allow", DNS: "allow"},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 {
		t.Fatalf("expected version 1, got %d", decoded.Version)
	}
	if len(decoded.FileRules) != 2 {
		t.Fatalf("expected 2 file rules, got %d", len(decoded.FileRules))
	}
	if decoded.FileRules[1].Action != "deny" {
		t.Fatalf("expected deny, got %s", decoded.FileRules[1].Action)
	}
	if decoded.Defaults.DNS != "allow" {
		t.Fatalf("expected allow, got %s", decoded.Defaults.DNS)
	}
}

func TestPolicySnapshotResponse_EmptyForMatchingVersion(t *testing.T) {
	snap := PolicySnapshotResponse{}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("expected valid JSON even for empty snapshot")
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 0 {
		t.Fatalf("expected version 0, got %d", decoded.Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/ -run TestPolicySnapshot -v`
Expected: FAIL — `PolicySnapshotResponse` undefined

- [ ] **Step 3: Write snapshot types and builder**

```go
// internal/platform/darwin/xpc/snapshot.go
package xpc

// PolicySnapshotResponse is the flattened policy cache sent to the Swift SysExt.
type PolicySnapshotResponse struct {
	Version      uint64              `json:"version"`
	SessionID    string              `json:"session_id"`
	FileRules    []SnapshotFileRule  `json:"file_rules"`
	NetworkRules []SnapshotNetworkRule `json:"network_rules"`
	DNSRules     []SnapshotDNSRule   `json:"dns_rules"`
	Defaults     SnapshotDefaults    `json:"defaults"`
}

type SnapshotFileRule struct {
	Pattern    string   `json:"pattern"`
	Operations []string `json:"operations"`
	Action     string   `json:"action"`
}

type SnapshotNetworkRule struct {
	Pattern  string `json:"pattern"`
	Ports    []int  `json:"ports"`
	Protocol string `json:"protocol,omitempty"`
	Action   string `json:"action"`
}

type SnapshotDNSRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
}

type SnapshotDefaults struct {
	File    string `json:"file"`
	Network string `json:"network"`
	DNS     string `json:"dns"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/xpc/ -run TestPolicySnapshot -v`
Expected: PASS

- [ ] **Step 5: Add optional snapshot fields to PolicyResponse**

In `protocol.go`, add to the `PolicyResponse` struct so snapshot data can flow through the existing response encoding:

```go
// Policy snapshot fields (returned by fetch_policy_snapshot)
SnapshotVersion      uint64              `json:"snapshot_version,omitempty"`
SnapshotSessionID    string              `json:"snapshot_session_id,omitempty"`
FileRules            []SnapshotFileRule  `json:"file_rules,omitempty"`
NetworkRules         []SnapshotNetworkRule `json:"network_rules,omitempty"`
DNSRules             []SnapshotDNSRule   `json:"dns_rules,omitempty"`
Defaults             *SnapshotDefaults   `json:"defaults,omitempty"`
```

Move the snapshot types from `snapshot.go` into `protocol.go` (they are part of the protocol), or keep in `snapshot.go` — either way they must be in the same package.

- [ ] **Step 6: Implement BuildPolicySnapshot on PolicyAdapter**

Add to `handler.go`:

```go
// BuildPolicySnapshot projects the policy engine's rules into the flat cache format.
func (a *PolicyAdapter) BuildPolicySnapshot(sessionID string, clientVersion uint64) PolicyResponse {
	if a.engine == nil {
		return PolicyResponse{Allow: true}
	}

	// Get current rules from the policy engine
	snapshot := a.engine.BuildSnapshot()
	if snapshot.Version <= clientVersion {
		return PolicyResponse{Allow: true} // Client is up to date
	}

	var fileRules []SnapshotFileRule
	for _, r := range snapshot.FileRules {
		fileRules = append(fileRules, SnapshotFileRule{
			Pattern:    r.Pattern,
			Operations: r.Operations,
			Action:     r.Action,
		})
	}

	var networkRules []SnapshotNetworkRule
	for _, r := range snapshot.NetworkRules {
		networkRules = append(networkRules, SnapshotNetworkRule{
			Pattern:  r.Pattern,
			Ports:    r.Ports,
			Protocol: r.Protocol,
			Action:   r.Action,
		})
	}

	var dnsRules []SnapshotDNSRule
	for _, r := range snapshot.DNSRules {
		dnsRules = append(dnsRules, SnapshotDNSRule{
			Pattern: r.Pattern,
			Action:  r.Action,
		})
	}

	defaults := SnapshotDefaults{
		File:    snapshot.Defaults.File,
		Network: snapshot.Defaults.Network,
		DNS:     snapshot.Defaults.DNS,
	}

	return PolicyResponse{
		Allow:             true,
		SnapshotVersion:   snapshot.Version,
		SnapshotSessionID: sessionID,
		FileRules:         fileRules,
		NetworkRules:      networkRules,
		DNSRules:          dnsRules,
		Defaults:          &defaults,
	}
}
```

**Pre-requisite:** This requires adding a `BuildSnapshot()` method to `policy.Engine` that returns the current rules in a flat format. Add to `internal/policy/engine.go`:

```go
// SnapshotData is the flat projection of policy rules for the Swift cache.
type SnapshotData struct {
	Version      uint64
	FileRules    []SnapshotFileRule
	NetworkRules []SnapshotNetworkRule
	DNSRules     []SnapshotDNSRule
	Defaults     SnapshotDefaults
}

type SnapshotFileRule struct {
	Pattern    string
	Operations []string
	Action     string
}

type SnapshotNetworkRule struct {
	Pattern  string
	Ports    []int
	Protocol string
	Action   string
}

type SnapshotDNSRule struct {
	Pattern string
	Action  string
}

type SnapshotDefaults struct {
	File    string
	Network string
	DNS     string
}

// BuildSnapshot projects the engine's current rules into a flat format
// suitable for the macOS SysExt policy cache.
func (e *Engine) BuildSnapshot() SnapshotData {
	// Project from e.policy.File, e.policy.Network, e.policy.DNS
	// into the flat SnapshotData format.
	// Implementation depends on Engine's internal rule representation.
	// Each rule type maps: pattern + operations/ports + action.
}
```

The exact field access depends on `Engine`'s internal structure — the implementer should inspect `internal/policy/engine.go` and map existing rule types to the snapshot format.

- [ ] **Step 7: Commit**

```bash
git add internal/platform/darwin/xpc/snapshot.go internal/platform/darwin/xpc/snapshot_test.go internal/platform/darwin/xpc/protocol.go internal/platform/darwin/xpc/handler.go
git commit -m "feat(darwin/xpc): add PolicySnapshotResponse types and BuildPolicySnapshot implementation"
```

---

### Task 3: Go-Side Event Handler and Server Routing

Wire `emitEvent` to decode payloads and store events. Add `fetch_policy_snapshot` routing. Add `EventHandler` interface to server.

**Files:**
- Modify: `internal/platform/darwin/xpc/server.go:14-52` (interfaces), `internal/platform/darwin/xpc/server.go:249-306` (routing)
- Modify: `internal/platform/darwin/xpc/handler.go`
- Test: `internal/platform/darwin/xpc/server_test.go` (may already exist — check and extend)

- [ ] **Step 1: Write test for event handler interface and snapshot routing**

```go
// internal/platform/darwin/xpc/event_handler_test.go
package xpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

type mockEventHandler struct {
	events []types.Event
}

func (m *mockEventHandler) HandleESFEvent(ctx context.Context, payload []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	ev := types.Event{
		Type:      raw["type"].(string),
		Path:      raw["path"].(string),
		Source:    "esf",
		SessionID: raw["session_id"].(string),
	}
	m.events = append(m.events, ev)
	return nil
}

func TestDecodeESFEventPayload(t *testing.T) {
	payload := map[string]any{
		"type":       "file_write",
		"path":       "/tmp/test.txt",
		"operation":  "close_modified",
		"pid":        1234,
		"session_id": "session-abc",
		"timestamp":  "2026-03-31T10:00:00Z",
	}
	data, _ := json.Marshal(payload)
	encoded := base64.StdEncoding.EncodeToString(data)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	handler := &mockEventHandler{}
	if err := handler.HandleESFEvent(context.Background(), decoded); err != nil {
		t.Fatal(err)
	}
	if len(handler.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(handler.events))
	}
	if handler.events[0].Type != "file_write" {
		t.Fatalf("expected file_write, got %s", handler.events[0].Type)
	}
	if handler.events[0].Source != "esf" {
		t.Fatalf("expected esf source, got %s", handler.events[0].Source)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/xpc/ -run TestDecodeESFEventPayload -v`
Expected: May pass (uses mock only) — adjust if needed after checking types import

- [ ] **Step 3: Add EventHandler and SnapshotBuilder interfaces to server.go**

Add to `internal/platform/darwin/xpc/server.go` after the `SessionRegistrar` interface (~line 52):

```go
// EventHandler processes events emitted by the SysExt (ESF NOTIFY handlers).
type EventHandler interface {
	HandleESFEvent(ctx context.Context, payload []byte) error
}

// SnapshotBuilder projects the policy engine's rules into the flat cache format.
type SnapshotBuilder interface {
	BuildPolicySnapshot(sessionID string, clientVersion uint64) PolicyResponse
}
```

Add fields to `Server` struct:

```go
eventHandler    EventHandler
snapshotBuilder SnapshotBuilder
```

Add setter methods:

```go
func (s *Server) SetEventHandler(h EventHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventHandler = h
}

func (s *Server) SetSnapshotBuilder(b SnapshotBuilder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshotBuilder = b
}
```

Update `handleRequest` routing — change the `RequestTypeEvent` case (~line 267) from no-op to:

```go
case RequestTypeEvent:
	if s.eventHandler != nil && req.EventData != nil {
		// EventData is []byte — Go's json.Unmarshal already base64-decoded
		// the JSON string value, so req.EventData contains raw JSON bytes.
		_ = s.eventHandler.HandleESFEvent(context.Background(), req.EventData)
	}
	return PolicyResponse{Allow: true}
```

Add `fetch_policy_snapshot` routing to the switch (before the `default` case):

```go
case RequestTypeFetchPolicySnapshot:
	s.mu.Lock()
	sb := s.snapshotBuilder
	s.mu.Unlock()
	if sb != nil {
		return sb.BuildPolicySnapshot(req.SessionID, req.Version)
	}
	return PolicyResponse{Allow: true}
```

- [ ] **Step 3b: Add SessionID to PNACLCheckRequest**

In `server.go`, add to `PNACLCheckRequest` struct:

```go
SessionID string
```

In `handlePNACLCheck`, populate it from the request:

```go
pnaclReq := PNACLCheckRequest{
	// ... existing fields ...
	SessionID: req.SessionID,
}
```

Update the `PNACLHandler.CheckNetwork` interface to accept the new field — all implementations receive it via the struct.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/xpc/ -v`
Expected: PASS

- [ ] **Step 5: Verify cross-compilation**

Run: `GOOS=darwin go build ./internal/platform/darwin/xpc/`
Expected: Success

- [ ] **Step 6: Commit**

```bash
git add internal/platform/darwin/xpc/server.go internal/platform/darwin/xpc/event_handler_test.go
git commit -m "feat(darwin/xpc): add EventHandler and SnapshotBuilder interfaces, wire routing"
```

---

### Task 4: Darwin Notification Poster (Go cgo wrapper)

Add a cgo wrapper for `notify_post` so the Go server can signal the SysExt when policy changes.

**Files:**
- Create: `internal/platform/darwin/notify.go`
- Create: `internal/platform/darwin/notify_test.go`

- [ ] **Step 1: Write test**

```go
// internal/platform/darwin/notify_test.go
//go:build darwin

package darwin

import "testing"

func TestNotifyPolicyUpdated(t *testing.T) {
	// notify_post returns 0 on success
	// This posts a notification that nobody is listening for — harmless
	NotifyPolicyUpdated()
	// If we get here without a crash/panic, the cgo bridge works
}

func TestNotifyName(t *testing.T) {
	if PolicyUpdatedNotification != "ai.canyonroad.agentsh.policy-updated" {
		t.Fatalf("unexpected notification name: %s", PolicyUpdatedNotification)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/darwin/ -run TestNotify -v`
Expected: FAIL — `NotifyPolicyUpdated` undefined

- [ ] **Step 3: Write the cgo wrapper**

```go
// internal/platform/darwin/notify.go
//go:build darwin

package darwin

/*
#include <notify.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// PolicyUpdatedNotification is the Darwin notification name posted when
// policy changes. The Swift SysExt listens for this to refresh its cache.
const PolicyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// NotifyPolicyUpdated posts a Darwin notification to signal the SysExt
// that the policy cache should be refreshed. This is a fire-and-forget
// signal — the SysExt fetches the actual data via XPC.
func NotifyPolicyUpdated() {
	cname := C.CString(PolicyUpdatedNotification)
	defer C.free(unsafe.Pointer(cname))
	C.notify_post(cname)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/darwin/ -run TestNotify -v`
Expected: PASS

- [ ] **Step 5: Add session version counter**

Create `internal/platform/darwin/xpc/version.go`:

```go
package xpc

import "sync"

// SessionVersions tracks per-session monotonic version counters.
// Incremented on any policy change; the Swift SysExt uses version
// to detect stale caches.
type SessionVersions struct {
	mu       sync.Mutex
	versions map[string]uint64
}

func NewSessionVersions() *SessionVersions {
	return &SessionVersions{versions: make(map[string]uint64)}
}

func (sv *SessionVersions) Register(sessionID string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.versions[sessionID] = 1
}

func (sv *SessionVersions) Unregister(sessionID string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	delete(sv.versions, sessionID)
}

// IncrementAll bumps version for all active sessions.
// Called on any policy change.
func (sv *SessionVersions) IncrementAll() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	for id := range sv.versions {
		sv.versions[id]++
	}
}

func (sv *SessionVersions) Get(sessionID string) uint64 {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	return sv.versions[sessionID]
}
```

- [ ] **Step 6: Wire NotifyPolicyUpdated into policy watcher**

In the Go code that handles policy file changes (the fsnotify watcher), add after reloading the policy:

```go
// Signal SysExt to refresh its cache
sessionVersions.IncrementAll()
darwin.NotifyPolicyUpdated()
```

This requires passing `sessionVersions` and calling `NotifyPolicyUpdated()` wherever policy changes are processed. The exact integration point depends on the policy watcher's location — look for the fsnotify handler that calls `engine.Reload()` or similar.

- [ ] **Step 7: Verify it doesn't break cross-compilation**

Run: `GOOS=linux go build ./...`
Expected: Success (notify.go has `//go:build darwin` guard, version.go has no build tags)

- [ ] **Step 8: Commit**

```bash
git add internal/platform/darwin/notify.go internal/platform/darwin/notify_test.go internal/platform/darwin/xpc/version.go
git commit -m "feat(darwin): add notify_post wrapper, session version counter, and policy watcher wiring"
```

---

### Task 5: SessionPolicyCache.swift (New File)

The core local policy cache — data structures, glob matching, Darwin notification listener, snapshot fetch.

**Files:**
- Create: `macos/agentsh/SessionPolicyCache.swift`
- Modify: `macos/agentsh/agentsh.xcodeproj/project.pbxproj` (add to SysExt Sources)

- [ ] **Step 1: Write SessionPolicyCache.swift**

```swift
// macos/agentsh/SessionPolicyCache.swift
import Foundation

/// Darwin notification name posted by Go server when policy changes.
let policyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// MARK: - Rule Types

struct FileRule {
    let pattern: String
    let operations: Set<String>  // "read", "write", "create", "delete", "rename"
    let action: String           // "allow" or "deny"
}

struct NetworkRule {
    let pattern: String
    let ports: Set<Int>
    let proto: String?
    let action: String
}

struct DNSRule {
    let pattern: String
    let action: String  // "allow", "deny", "nxdomain"
}

struct PolicyDefaults {
    let file: String     // "allow" or "deny"
    let network: String
    let dns: String
}

// MARK: - Per-Session Cache Entry

class SessionCache {
    let sessionID: String
    let rootPID: pid_t
    var version: UInt64
    var sessionPIDs: Set<pid_t>
    var fileRules: [FileRule]
    var networkRules: [NetworkRule]
    var dnsRules: [DNSRule]
    var defaults: PolicyDefaults

    init(sessionID: String, rootPID: pid_t, version: UInt64,
         fileRules: [FileRule], networkRules: [NetworkRule],
         dnsRules: [DNSRule], defaults: PolicyDefaults) {
        self.sessionID = sessionID
        self.rootPID = rootPID
        self.version = version
        self.sessionPIDs = [rootPID]
        self.fileRules = fileRules
        self.networkRules = networkRules
        self.dnsRules = dnsRules
        self.defaults = defaults
    }
}

// MARK: - Policy Cache Manager

class SessionPolicyCache {
    static let shared = SessionPolicyCache()

    private var sessions: [String: SessionCache] = [:]  // sessionID -> cache
    private var pidToSession: [pid_t: String] = [:]      // fast PID -> sessionID lookup
    private var execDepths: [pid_t: Int] = [:]
    private let queue = DispatchQueue(label: "ai.canyonroad.agentsh.policycache",
                                       attributes: .concurrent)

    private var notifyToken: Int32 = 0

    private init() {
        startListeningForNotifications()
    }

    // MARK: - Session Lifecycle

    func registerSession(sessionID: String, rootPID: pid_t, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            self.sessions[sessionID] = snapshot
            self.pidToSession[rootPID] = sessionID
        }
    }

    func unregisterSession(sessionID: String) {
        queue.async(flags: .barrier) {
            guard let cache = self.sessions[sessionID] else { return }
            for pid in cache.sessionPIDs {
                self.pidToSession.removeValue(forKey: pid)
                self.execDepths.removeValue(forKey: pid)
            }
            self.sessions.removeValue(forKey: sessionID)
        }
    }

    var hasActiveSessions: Bool {
        queue.sync { !sessions.isEmpty }
    }

    // MARK: - PID Tracking (called from NOTIFY_FORK/EXIT)

    func addPID(_ childPID: pid_t, parentPID: pid_t) {
        queue.async(flags: .barrier) {
            guard let sessionID = self.pidToSession[parentPID],
                  let cache = self.sessions[sessionID] else { return }
            cache.sessionPIDs.insert(childPID)
            self.pidToSession[childPID] = sessionID
        }
    }

    func removePID(_ pid: pid_t) {
        queue.async(flags: .barrier) {
            if let sessionID = self.pidToSession.removeValue(forKey: pid) {
                self.sessions[sessionID]?.sessionPIDs.remove(pid)
            }
            self.execDepths.removeValue(forKey: pid)
        }
    }

    // MARK: - Session Membership

    /// Returns the sessionID for a PID, or nil if not in any session.
    func sessionForPID(_ pid: pid_t) -> String? {
        queue.sync { pidToSession[pid] }
    }

    /// Returns the SessionCache for a PID, or nil if not in any session.
    func cacheForPID(_ pid: pid_t) -> SessionCache? {
        queue.sync {
            guard let sid = pidToSession[pid] else { return nil }
            return sessions[sid]
        }
    }

    // MARK: - Exec Depth

    func recordExecDepth(pid: pid_t, parentPID: pid_t) -> Int {
        return queue.sync(flags: .barrier) {
            let parentDepth = execDepths[parentPID] ?? 0
            let depth = parentDepth + 1
            execDepths[pid] = depth
            return depth
        }
    }

    // MARK: - File Policy Evaluation

    enum CacheDecision {
        case allow
        case deny
        case fallthrough_  // No match, use default or XPC
    }

    func evaluateFile(path: String, operation: String, pid: pid_t) -> (CacheDecision, String?) {
        return queue.sync {
            guard let sid = pidToSession[pid],
                  let cache = sessions[sid] else {
                return (.allow, nil)  // Not in session
            }

            // Check deny rules first
            for rule in cache.fileRules where rule.action == "deny" {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    return (.deny, sid)
                }
            }

            // Rules requiring server-side logic -> XPC fallthrough
            for rule in cache.fileRules {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    if rule.action == "approve" || rule.action == "redirect" || rule.action == "soft_delete" {
                        return (.fallthrough_, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            // Apply default
            if cache.defaults.file == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    // MARK: - Network Policy Evaluation

    func evaluateNetwork(host: String, port: Int, pid: pid_t) -> (CacheDecision, String?) {
        return queue.sync {
            guard let sid = pidToSession[pid],
                  let cache = sessions[sid] else {
                return (.allow, nil)
            }

            for rule in cache.networkRules where rule.action == "deny" {
                if globMatch(pattern: rule.pattern, path: host) &&
                   (rule.ports.isEmpty || rule.ports.contains(port)) {
                    return (.deny, sid)
                }
            }

            for rule in cache.networkRules {
                if globMatch(pattern: rule.pattern, path: host) &&
                   (rule.ports.isEmpty || rule.ports.contains(port)) {
                    if rule.action == "approve" {
                        return (.fallthrough_, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            if cache.defaults.network == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    // MARK: - DNS Policy Evaluation (union of all sessions)

    func evaluateDNS(domain: String) -> String? {
        return queue.sync {
            if sessions.isEmpty { return nil }  // No sessions = passthrough

            for (_, cache) in sessions {
                for rule in cache.dnsRules where rule.action == "deny" || rule.action == "nxdomain" {
                    if globMatch(pattern: rule.pattern, path: domain) {
                        return rule.action
                    }
                }
            }

            // Strictest default wins
            for (_, cache) in sessions {
                if cache.defaults.dns == "deny" {
                    return "deny"
                }
            }

            return nil  // All defaults allow = passthrough
        }
    }

    // MARK: - Cache Update

    func updateSession(_ sessionID: String, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            guard let existing = self.sessions[sessionID] else { return }
            if snapshot.version <= existing.version { return }
            // Preserve sessionPIDs — they're maintained by fork/exit, not snapshot
            snapshot.sessionPIDs = existing.sessionPIDs
            self.sessions[sessionID] = snapshot
        }
    }

    func versionForSession(_ sessionID: String) -> UInt64 {
        queue.sync { sessions[sessionID]?.version ?? 0 }
    }

    func allSessionIDs() -> [String] {
        queue.sync { Array(sessions.keys) }
    }

    // MARK: - Darwin Notification Listener

    private func startListeningForNotifications() {
        let name = policyUpdatedNotification as CFString
        notify_register_dispatch(
            policyUpdatedNotification,
            &notifyToken,
            DispatchQueue.global(qos: .utility)
        ) { [weak self] _ in
            self?.handlePolicyUpdateNotification()
        }
    }

    private func handlePolicyUpdateNotification() {
        // Fetch updated snapshot for each active session via XPC
        let sessionIDs = allSessionIDs()
        for sessionID in sessionIDs {
            // The XPC fetch is done by ESFClient which holds the xpcProxy reference.
            // Post a local notification that ESFClient observes.
            NotificationCenter.default.post(
                name: .policyCacheNeedsRefresh,
                object: nil,
                userInfo: ["session_id": sessionID]
            )
        }
    }

    // MARK: - Glob Matching

    /// Simple glob matcher supporting * (single segment) and ** (recursive).
    /// Matches the Go policy engine's glob semantics.
    private func globMatch(pattern: String, path: String) -> Bool {
        // Use fnmatch for simple cases, handling ** manually
        if pattern.contains("**") {
            // Convert ** to regex-style matching
            let regexPattern = "^" + NSRegularExpression.escapedPattern(for: pattern)
                .replacingOccurrences(of: "\\*\\*", with: ".*")
                .replacingOccurrences(of: "\\*", with: "[^/]*")
            + "$"
            return (try? NSRegularExpression(pattern: regexPattern))?.firstMatch(
                in: path, range: NSRange(path.startIndex..., in: path)
            ) != nil
        }
        // Simple glob: use fnmatch
        return fnmatch(pattern, path, FNM_PATHNAME) == 0
    }
}

// MARK: - Snapshot Parsing

extension SessionCache {
    static func from(json: [String: Any], sessionID: String, rootPID: pid_t) -> SessionCache? {
        guard let version = json["version"] as? UInt64 ?? (json["version"] as? Int).map({ UInt64($0) }) else {
            return nil
        }

        var fileRules: [FileRule] = []
        if let rules = json["file_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let ops = r["operations"] as? [String],
                      let action = r["action"] as? String else { continue }
                fileRules.append(FileRule(pattern: pattern, operations: Set(ops), action: action))
            }
        }

        var networkRules: [NetworkRule] = []
        if let rules = json["network_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                let ports = (r["ports"] as? [Int]).map { Set($0) } ?? Set<Int>()
                let proto = r["protocol"] as? String
                networkRules.append(NetworkRule(pattern: pattern, ports: ports, proto: proto, action: action))
            }
        }

        var dnsRules: [DNSRule] = []
        if let rules = json["dns_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                dnsRules.append(DNSRule(pattern: pattern, action: action))
            }
        }

        let defs = json["defaults"] as? [String: String] ?? [:]
        let defaults = PolicyDefaults(
            file: defs["file"] ?? "allow",
            network: defs["network"] ?? "allow",
            dns: defs["dns"] ?? "allow"
        )

        return SessionCache(
            sessionID: sessionID, rootPID: rootPID, version: version,
            fileRules: fileRules, networkRules: networkRules,
            dnsRules: dnsRules, defaults: defaults
        )
    }
}

// MARK: - Notification Name

extension Notification.Name {
    static let policyCacheNeedsRefresh = Notification.Name("ai.canyonroad.agentsh.policyCacheNeedsRefresh")
}
```

- [ ] **Step 2: Add to Xcode project**

Open `macos/agentsh/agentsh.xcodeproj` in Xcode and drag `SessionPolicyCache.swift` into the SysExt group. Ensure it is added to the SysExt target's Sources build phase (check the target membership checkbox). Alternatively, manually edit `project.pbxproj` following the same pattern as `ESFClient.swift`:
1. Generate two new UUIDs (use `uuidgen | tr -d '-' | head -c 24`)
2. Add a `PBXFileReference` entry for `SessionPolicyCache.swift`
3. Add a `PBXBuildFile` entry referencing it
4. Add the file reference to the SysExt group's `children` array
5. Add the build file to the SysExt target's Sources build phase

- [ ] **Step 3: Build to verify compilation**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -target SysExt -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/agentsh/SessionPolicyCache.swift macos/agentsh/agentsh.xcodeproj/project.pbxproj
git commit -m "feat(darwin/sysext): add SessionPolicyCache with glob matching and Darwin notification listener"
```

---

### Task 6: XPC Protocol and PolicyBridge Extensions

Add `fetchPolicySnapshot` method and `sessionID` parameter to `checkNetworkPNACL`.

**Files:**
- Modify: `macos/agentsh/xpc/xpcProtocol.swift:68-79` (checkNetworkPNACL signature)
- Modify: `macos/agentsh/xpc/PolicyBridge.swift:167-206` (checkNetworkPNACL impl), `macos/agentsh/xpc/PolicyBridge.swift:155-163` (emitEvent)

- [ ] **Step 1: Add fetchPolicySnapshot to protocol**

In `xpcProtocol.swift`, add after the existing methods (before the closing brace of the protocol):

```swift
func fetchPolicySnapshot(
    sessionID: String,
    version: UInt64,
    reply: @escaping ([String: Any]) -> Void
)
```

Add `sessionID` parameter to `checkNetworkPNACL`:

```swift
func checkNetworkPNACL(
    ip: String,
    port: Int,
    protocol proto: String,
    domain: String?,
    pid: pid_t,
    bundleID: String?,
    executablePath: String?,
    processName: String?,
    parentPID: pid_t,
    sessionID: String?,           // NEW
    reply: @escaping (String, String?) -> Void
)
```

- [ ] **Step 2: Implement in PolicyBridge.swift**

Add `fetchPolicySnapshot` implementation:

```swift
func fetchPolicySnapshot(
    sessionID: String,
    version: UInt64,
    reply: @escaping ([String: Any]) -> Void
) {
    let request: [String: Any] = [
        "type": "fetch_policy_snapshot",
        "session_id": sessionID,
        "version": version
    ]
    sendRequest(request) { response in
        reply(response)
    }
}
```

Update `checkNetworkPNACL` in `PolicyBridge.swift` — add `sessionID: String?` parameter to the method signature and add it to the request dictionary:

```swift
func checkNetworkPNACL(
    ip: String,
    port: Int,
    protocol proto: String,
    domain: String?,
    pid: pid_t,
    bundleID: String?,
    executablePath: String?,
    processName: String?,
    parentPID: pid_t,
    sessionID: String?,           // NEW
    reply: @escaping (String, String?) -> Void
) {
    let request: [String: Any] = [
        "type": "pnacl_check",
        "ip": ip,
        "port": port,
        "protocol": proto,
        "domain": domain ?? "",
        "pid": pid,
        "bundle_id": bundleID ?? "",
        "executable_path": executablePath ?? "",
        "process_name": processName ?? "",
        "parent_pid": parentPID,
        "session_id": sessionID ?? ""           // NEW
    ]
    // ... rest unchanged ...
```

- [ ] **Step 3: Update all callers of checkNetworkPNACL**

In `FilterDataProvider.swift`, add `sessionID: nil` (for now) to all existing `checkNetworkPNACL` call sites. This will be updated to pass the real sessionID in Task 9.

- [ ] **Step 4: Build to verify compilation**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -scheme agentsh -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|warning:.*\.swift|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 5: Commit**

```bash
git add macos/agentsh/xpc/xpcProtocol.swift macos/agentsh/xpc/PolicyBridge.swift macos/agentsh/FilterDataProvider.swift
git commit -m "feat(darwin/xpc): add fetchPolicySnapshot, add sessionID to checkNetworkPNACL"
```

---

### Task 7: ESF AUTH Handler Wiring

Wire AUTH_CREATE, AUTH_UNLINK, AUTH_RENAME to policy checks. Retrofit AUTH_OPEN with session scoping and cache fast-path. Update subscription arrays.

**Files:**
- Modify: `macos/agentsh/ESFClient.swift:54-68` (subscriptions), `macos/agentsh/ESFClient.swift:227-256` (AUTH handlers), `macos/agentsh/ESFClient.swift:198-222` (switch), `macos/agentsh/ESFClient.swift:15-20` (state)

- [ ] **Step 1: Remove activeSessions and sessionQueue, use SessionPolicyCache**

Replace the `activeSessions` dictionary (line 19) and `sessionQueue` (line 20) with references to `SessionPolicyCache.shared`. Update `registerSession`, `unregisterSession`, `findSession` to delegate to the cache.

Update `handleNotifyFork` to also call `SessionPolicyCache.shared.addPID(childPid, parentPID: pid)`.

Update `handleNotifyExit` to also call `SessionPolicyCache.shared.removePID(pid)`.

- [ ] **Step 2: Remove NOTIFY_WRITE from subscription**

In `start()`, change the `notifyEvents` array — remove `NOTIFY_WRITE` but do NOT add `NOTIFY_SETATTR` yet (that comes in Task 8 alongside the handler implementation):

```swift
let notifyEvents: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_CLOSE,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_FORK
]
```

Remove the `case ES_EVENT_TYPE_NOTIFY_WRITE` from the `handleEvent` switch (and the empty `handleNotifyWrite` method).

- [ ] **Step 3: Retrofit AUTH_OPEN with session scoping and cache**

Replace the current `handleAuthOpen` body:

```swift
private func handleAuthOpen(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }

    let path = String(cString: event.pointee.event.open.file.pointee.path.data)

    // Cache fast-path
    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
        path: path, operation: "read", pid: pid)

    switch decision {
    case .allow:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    case .deny:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    case .fallthrough_:
        // XPC round-trip
        es_retain_message(event)
        xpcProxy?.checkFile(path: path, operation: "read", pid: pid, sessionID: sessionID) {
            [weak self] allow, _ in
            defer { es_release_message(event) }
            guard let client = self?.getClient() else { return }
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, event, result, false)
        }
    }
}
```

- [ ] **Step 4: Wire AUTH_CREATE**

```swift
private func handleAuthCreate(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }

    // Extract path based on destination_type
    let create = event.pointee.event.create
    let path: String
    if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        path = String(cString: create.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: create.destination.new_path.filename.data)
        path = dir + "/" + filename
    }

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
        path: path, operation: "create", pid: pid)

    switch decision {
    case .allow:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    case .deny:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    case .fallthrough_:
        es_retain_message(event)
        xpcProxy?.checkFile(path: path, operation: "create", pid: pid, sessionID: sessionID) {
            [weak self] allow, _ in
            defer { es_release_message(event) }
            guard let client = self?.getClient() else { return }
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, event, result, false)
        }
    }
}
```

- [ ] **Step 5: Wire AUTH_UNLINK**

```swift
private func handleAuthUnlink(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }
    let path = String(cString: event.pointee.event.unlink.target.pointee.path.data)

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
        path: path, operation: "delete", pid: pid)

    switch decision {
    case .allow:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    case .deny:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    case .fallthrough_:
        es_retain_message(event)
        xpcProxy?.checkFile(path: path, operation: "delete", pid: pid, sessionID: sessionID) {
            [weak self] allow, _ in
            defer { es_release_message(event) }
            guard let client = self?.getClient() else { return }
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, event, result, false)
        }
    }
}
```

- [ ] **Step 6: Wire AUTH_RENAME (two-path evaluation)**

```swift
private func handleAuthRename(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }
    let sourcePath = String(cString: event.pointee.event.rename.source.pointee.path.data)

    let rename = event.pointee.event.rename
    let destPath: String
    if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        destPath = String(cString: rename.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: rename.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: rename.destination.new_path.filename.data)
        destPath = dir + "/" + filename
    }

    // Evaluate both paths
    let (srcDecision, sessionID) = SessionPolicyCache.shared.evaluateFile(
        path: sourcePath, operation: "rename", pid: pid)
    let (dstDecision, _) = SessionPolicyCache.shared.evaluateFile(
        path: destPath, operation: "create", pid: pid)

    // If either is denied by cache, deny immediately
    if srcDecision == .deny || dstDecision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        return
    }
    if srcDecision == .allow && dstDecision == .allow {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    // Fallthrough — XPC for source then dest
    es_retain_message(event)
    xpcProxy?.checkFile(path: sourcePath, operation: "rename", pid: pid, sessionID: sessionID) {
        [weak self] srcAllow, _ in
        guard srcAllow else {
            defer { es_release_message(event) }
            guard let client = self?.getClient() else { return }
            es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
            return
        }
        self?.xpcProxy?.checkFile(path: destPath, operation: "create", pid: pid, sessionID: sessionID) {
            [weak self] dstAllow, _ in
            defer { es_release_message(event) }
            guard let client = self?.getClient() else { return }
            let result: es_auth_result_t = dstAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, event, result, false)
        }
    }
}
```

- [ ] **Step 7: Update AUTH_EXEC to use cache for session check and depth tracking**

In `handleAuthExec`, replace the `hasActiveSessions` and `findSession` checks with `SessionPolicyCache.shared`:

```swift
// Replace: let hasActiveSessions = sessionQueue.sync { !activeSessions.isEmpty }
let hasActiveSessions = SessionPolicyCache.shared.hasActiveSessions
if !hasActiveSessions {
    es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    return
}

// Replace: let sessionInfo = findSession(forPID: pid)
let sessionID = SessionPolicyCache.shared.sessionForPID(pid)
if sessionID == nil {
    es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    return
}

// Add depth tracking before the XPC call
let depth = SessionPolicyCache.shared.recordExecDepth(pid: pid, parentPID: parentPID)
```

Pass `depth` through `checkExecPipeline` — the existing `checkExecPipeline` XPC method does not have a depth parameter yet. For now, include it as part of the session context that flows through. The Go-side `PolicyRequest.Depth` field was added in Task 1.

- [ ] **Step 8: Build to verify compilation**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -target SysExt -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 9: Commit**

```bash
git add macos/agentsh/ESFClient.swift
git commit -m "feat(darwin/esf): wire AUTH_CREATE/UNLINK/RENAME, retrofit AUTH_OPEN with session scoping and cache"
```

---

### Task 8: ESF NOTIFY Handler Wiring (Auditing)

Wire NOTIFY_CLOSE and NOTIFY_SETATTR to emit events via XPC. Add NOTIFY_SETATTR subscription.

**Files:**
- Modify: `macos/agentsh/ESFClient.swift:54-68` (notifyEvents subscription), `macos/agentsh/ESFClient.swift:400-403` (handleNotifyClose), add handleNotifySetattr

- [ ] **Step 0: Add NOTIFY_SETATTR to subscription and switch**

In `start()`, add `ES_EVENT_TYPE_NOTIFY_SETATTR` to the `notifyEvents` array:

```swift
let notifyEvents: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_CLOSE,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_SETATTR
]
```

Add `case ES_EVENT_TYPE_NOTIFY_SETATTR` to the `handleEvent` switch:

```swift
case ES_EVENT_TYPE_NOTIFY_SETATTR:
    handleNotifySetattr(message, pid: pid)
```

- [ ] **Step 1: Wire handleNotifyClose**

```swift
private func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
    guard message.event.close.modified else { return }
    guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

    let path = String(cString: message.event.close.target.pointee.path.data)

    let payload: [String: Any] = [
        "type": "file_write",
        "path": path,
        "operation": "close_modified",
        "pid": Int(pid),
        "session_id": sessionID,
        "timestamp": ISO8601DateFormatter().string(from: Date())
    ]

    if let data = try? JSONSerialization.data(withJSONObject: payload) {
        xpcProxy?.emitEvent(event: data) { _ in }
    }
}
```

- [ ] **Step 2: Add handleNotifySetattr**

```swift
private func handleNotifySetattr(_ message: es_message_t, pid: pid_t) {
    guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

    let path = String(cString: message.event.setattr.target.pointee.path.data)

    // Determine what changed
    let attrList = message.event.setattr.attrlist
    let operation: String
    if attrList.commonattr & UInt32(ATTR_CMN_OWNERID) != 0 ||
       attrList.commonattr & UInt32(ATTR_CMN_GRPID) != 0 {
        operation = "chown"
    } else {
        operation = "chmod"
    }

    let payload: [String: Any] = [
        "type": "file_\(operation)",
        "path": path,
        "operation": operation,
        "pid": Int(pid),
        "session_id": sessionID,
        "timestamp": ISO8601DateFormatter().string(from: Date())
    ]

    if let data = try? JSONSerialization.data(withJSONObject: payload) {
        xpcProxy?.emitEvent(event: data) { _ in }
    }
}
```

- [ ] **Step 3: Build to verify**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -target SysExt -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/agentsh/ESFClient.swift
git commit -m "feat(darwin/esf): wire NOTIFY_CLOSE and NOTIFY_SETATTR event emission"
```

---

### Task 9: FilterDataProvider Session Scoping

Add session scoping to the network extension's filter data provider.

**Files:**
- Modify: `macos/agentsh/FilterDataProvider.swift:64-152` (handleNewFlow), `macos/agentsh/FilterDataProvider.swift:157-204` (audit-only mode), `macos/agentsh/FilterDataProvider.swift:209-346` (blocking mode)

- [ ] **Step 1: Add session check at the top of flow handling**

In the flow handling method, after extracting PID from audit token (~line 110), add:

```swift
// Session scoping: auto-allow if PID is not in any active session
guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
    return .allow()
}

// Cache fast-path: check network rules
let (cacheDecision, _) = SessionPolicyCache.shared.evaluateNetwork(
    host: hostname ?? remoteIP, port: remotePort, pid: pid)

switch cacheDecision {
case .allow:
    return .allow()
case .deny:
    return .drop()
case .fallthrough_:
    break  // Continue to XPC check
}
```

- [ ] **Step 2: Pass sessionID to checkNetworkPNACL calls**

Update all `checkNetworkPNACL` calls to pass `sessionID: sessionID` instead of `sessionID: nil`. This applies to both the audit-only and blocking mode code paths.

- [ ] **Step 3: Build to verify**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -scheme agentsh -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/agentsh/FilterDataProvider.swift
git commit -m "feat(darwin/ne): add session scoping and cache fast-path to FilterDataProvider"
```

---

### Task 10: DNS Filtering in DNSProxyProvider

Add DNS query parsing, policy evaluation, and NXDOMAIN synthesis.

**Files:**
- Modify: `macos/agentsh/DNSProxyProvider.swift:53-80`

- [ ] **Step 1: Add DNS wire format parser**

Add a helper function to extract the domain name from a DNS query datagram:

```swift
/// Parse domain name from DNS query wire format.
/// DNS header is 12 bytes, then QNAME as length-prefixed labels.
private func parseDNSQueryDomain(_ datagram: Data) -> String? {
    guard datagram.count > 12 else { return nil }

    var offset = 12  // Skip DNS header
    var labels: [String] = []

    while offset < datagram.count {
        let length = Int(datagram[offset])
        if length == 0 { break }  // Root label = end
        offset += 1
        guard offset + length <= datagram.count else { return nil }
        let label = datagram[offset..<offset+length]
        if let str = String(bytes: label, encoding: .ascii) {
            labels.append(str)
        }
        offset += length
    }

    return labels.isEmpty ? nil : labels.joined(separator: ".")
}

/// Synthesize a DNS NXDOMAIN response from a query datagram.
private func synthesizeNXDOMAIN(_ query: Data) -> Data? {
    guard query.count >= 12 else { return nil }
    var response = query
    // Set QR bit (response) and RCODE=3 (NXDOMAIN)
    // Byte 2: QR=1 (0x80) | Opcode (keep) | AA=0 | TC=0 | RD (keep)
    response[2] = (query[2] & 0x79) | 0x80  // Set QR, preserve Opcode and RD
    // Byte 3: RA=1 (0x80) | Z=0 | RCODE=3 (0x03)
    response[3] = 0x83
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    response[6] = 0; response[7] = 0
    response[8] = 0; response[9] = 0
    response[10] = 0; response[11] = 0
    // Truncate to header + question only
    // Find end of question section (skip QNAME + QTYPE + QCLASS = 4 bytes)
    var offset = 12
    while offset < response.count {
        let length = Int(response[offset])
        if length == 0 { offset += 1; break }
        offset += 1 + length
    }
    offset += 4  // QTYPE (2) + QCLASS (2)
    return response.prefix(offset)
}
```

- [ ] **Step 2: Update readAndProcessDNS to check policy**

Replace the `forwardDNS` call path:

```swift
private func readAndProcessDNS(_ flow: NEAppProxyUDPFlow) {
    flow.readDatagrams { [weak self] tuples, error in
        guard let self = self else { return }

        guard let tuples = tuples, error == nil else {
            if let error = error {
                NSLog("DNS read error: \(error)")
            }
            return
        }

        for (datagram, endpoint) in tuples {
            if let domain = self.parseDNSQueryDomain(datagram),
               let dnsAction = SessionPolicyCache.shared.evaluateDNS(domain: domain) {
                // Policy says deny or nxdomain
                if let nxdomain = self.synthesizeNXDOMAIN(datagram) {
                    flow.writeDatagrams([(nxdomain, endpoint)]) { error in
                        if let error = error {
                            NSLog("DNS NXDOMAIN write error: \(error)")
                        }
                    }
                }
            } else {
                // Allow — forward unchanged
                self.forwardDNS(datagram, to: endpoint, via: flow)
            }
        }

        // Continue reading
        self.readAndProcessDNS(flow)
    }
}
```

- [ ] **Step 3: Build to verify**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -target SysExt -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/agentsh/DNSProxyProvider.swift
git commit -m "feat(darwin/dns): add DNS query parsing, policy evaluation, and NXDOMAIN synthesis"
```

---

### Task 11: ESFClient Cache Refresh Wiring

Connect ESFClient to the Darwin notification-triggered cache refresh cycle. When `SessionPolicyCache` receives a notification, ESFClient fetches the new snapshot via XPC and updates the cache.

**Files:**
- Modify: `macos/agentsh/ESFClient.swift` (init, registerSession, add observer)

- [ ] **Step 1: Add NotificationCenter observer in ESFClient.init**

```swift
NotificationCenter.default.addObserver(
    forName: .policyCacheNeedsRefresh,
    object: nil,
    queue: nil
) { [weak self] notification in
    guard let sessionID = notification.userInfo?["session_id"] as? String else { return }
    self?.refreshCacheForSession(sessionID)
}
```

- [ ] **Step 2: Add refreshCacheForSession method**

```swift
private func refreshCacheForSession(_ sessionID: String) {
    let currentVersion = SessionPolicyCache.shared.versionForSession(sessionID)
    xpcProxy?.fetchPolicySnapshot(sessionID: sessionID, version: currentVersion) { response in
        // Empty response means version matches, no update needed
        guard let version = response["version"] as? UInt64 ?? (response["version"] as? Int).map({ UInt64($0) }),
              version > 0 else { return }
        guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
        guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
            NSLog("ESFClient: failed to parse policy snapshot for session \(sessionID)")
            return
        }
        SessionPolicyCache.shared.updateSession(sessionID, snapshot: snapshot)
        NSLog("ESFClient: updated cache for session \(sessionID) to version \(version)")
    }
}
```

- [ ] **Step 3: Update registerSession to fetch initial snapshot**

```swift
func registerSession(rootPID: pid_t, sessionID: String) {
    // Fetch initial policy snapshot
    xpcProxy?.fetchPolicySnapshot(sessionID: sessionID, version: 0) { [weak self] response in
        guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
            NSLog("ESFClient: failed to fetch initial snapshot for session \(sessionID)")
            // Register with empty cache — will XPC fallback for all decisions
            let emptySnapshot = SessionCache(
                sessionID: sessionID, rootPID: rootPID, version: 0,
                fileRules: [], networkRules: [], dnsRules: [],
                defaults: PolicyDefaults(file: "allow", network: "allow", dns: "allow"))
            SessionPolicyCache.shared.registerSession(
                sessionID: sessionID, rootPID: rootPID, snapshot: emptySnapshot)
            return
        }
        SessionPolicyCache.shared.registerSession(
            sessionID: sessionID, rootPID: rootPID, snapshot: snapshot)
        NSLog("ESFClient: registered session \(sessionID) with policy version \(snapshot.version)")
    }
}
```

- [ ] **Step 4: Update unregisterSession**

```swift
func unregisterSession(rootPID: pid_t) {
    // Find sessionID before removing
    if let sessionID = SessionPolicyCache.shared.sessionForPID(rootPID) {
        SessionPolicyCache.shared.unregisterSession(sessionID: sessionID)
        NSLog("ESFClient: unregistered session \(sessionID)")
    }
}
```

- [ ] **Step 5: Build to verify**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -target SysExt -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|BUILD'`
Expected: BUILD SUCCEEDED

- [ ] **Step 6: Commit**

```bash
git add macos/agentsh/ESFClient.swift
git commit -m "feat(darwin/esf): wire cache refresh from Darwin notifications and initial snapshot fetch"
```

---

### Task 12: Go-Side Cross-Compilation and Full Test Suite

Verify all Go changes compile cross-platform and all tests pass.

**Files:**
- All Go files modified in Tasks 1-4

- [ ] **Step 1: Run full Go test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 2: Verify macOS cross-compilation**

Run: `GOOS=darwin go build ./...`
Expected: Success

- [ ] **Step 3: Verify Windows cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Success (darwin-specific files have build tags)

- [ ] **Step 4: Verify Linux cross-compilation**

Run: `GOOS=linux go build ./...`
Expected: Success

- [ ] **Step 5: Full Xcode build**

Run: `xcodebuild -project macos/agentsh/agentsh.xcodeproj -scheme agentsh -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'error:|warning:.*\.swift|BUILD'`
Expected: BUILD SUCCEEDED, zero Swift warnings

- [ ] **Step 6: Commit and push**

```bash
git push origin feat/endpoint-security-entitlements
```
