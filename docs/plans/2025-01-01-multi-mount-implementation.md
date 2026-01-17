# Multi-Mount Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable agentsh to mount multiple filesystem paths with independent policies per mount.

**Architecture:** Mount profiles define collections of paths to mount, each with its own policy file. Sessions can use a profile instead of a single workspace+policy. Policy evaluation routes file checks to the appropriate mount's policy, then the base policy.

**Tech Stack:** Go, YAML config, go-fuse, existing policy engine

---

## Task 1: Add MountProfile Types to Config

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestMountProfileParsing(t *testing.T) {
	yaml := `
mount_profiles:
  agent-profile:
    base_policy: "default"
    mounts:
      - path: "/home/user/workspace"
        policy: "workspace-rw"
      - path: "/home/user/.config"
        policy: "config-readonly"
`
	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if len(cfg.MountProfiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(cfg.MountProfiles))
	}
	p := cfg.MountProfiles["agent-profile"]
	if p.BasePolicy != "default" {
		t.Errorf("expected base_policy=default, got %s", p.BasePolicy)
	}
	if len(p.Mounts) != 2 {
		t.Errorf("expected 2 mounts, got %d", len(p.Mounts))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -run TestMountProfileParsing -v`
Expected: FAIL with "undefined: config.LoadFromBytes" or missing field

**Step 3: Add MountProfile types to config.go**

Add after line ~240 (after `PoliciesConfig`):

```go
// MountProfile defines a collection of mounts with policies.
type MountProfile struct {
	BasePolicy string      `yaml:"base_policy"`
	Mounts     []MountSpec `yaml:"mounts"`
}

// MountSpec defines a single mount point with its policy.
type MountSpec struct {
	Path   string `yaml:"path"`
	Policy string `yaml:"policy"`
}
```

Add to `Config` struct:

```go
MountProfiles map[string]MountProfile `yaml:"mount_profiles"`
```

Add `LoadFromBytes` function:

```go
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config/... -run TestMountProfileParsing -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add MountProfile types for multi-mount support"
```

---

## Task 2: Add Profile Field to API Types

**Files:**
- Modify: `pkg/types/sessions.go`

**Step 1: Add Profile field to CreateSessionRequest**

In `pkg/types/sessions.go`, update `CreateSessionRequest`:

```go
type CreateSessionRequest struct {
	ID        string `json:"id,omitempty"`
	Workspace string `json:"workspace,omitempty"`  // Optional if Profile is set
	Policy    string `json:"policy,omitempty"`
	Profile   string `json:"profile,omitempty"`    // NEW: mount profile name
}
```

**Step 2: Add Profile and Mounts to Session**

Update `Session` struct:

```go
type Session struct {
	ID        string       `json:"id"`
	State     SessionState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	Workspace string       `json:"workspace"`
	Policy    string       `json:"policy"`
	Profile   string       `json:"profile,omitempty"`  // NEW
	Mounts    []MountInfo  `json:"mounts,omitempty"`   // NEW
	Cwd       string       `json:"cwd"`
}

// MountInfo describes an active mount in a session.
type MountInfo struct {
	Path       string `json:"path"`
	Policy     string `json:"policy"`
	MountPoint string `json:"mount_point"`
}
```

**Step 3: Run tests to verify nothing broke**

Run: `go test ./pkg/types/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add pkg/types/sessions.go
git commit -m "feat(types): add Profile and Mounts fields to session types"
```

---

## Task 3: Add ResolvedMount Type to Session Package

**Files:**
- Create: `internal/session/mount.go`
- Test: `internal/session/mount_test.go`

**Step 1: Write the failing test**

Create `internal/session/mount_test.go`:

```go
package session

import (
	"testing"
)

func TestFindMount(t *testing.T) {
	mounts := []ResolvedMount{
		{Path: "/home/user", Policy: "base"},
		{Path: "/home/user/workspace", Policy: "workspace"},
		{Path: "/home/user/.config", Policy: "config"},
	}

	tests := []struct {
		path     string
		wantPath string
		wantNil  bool
	}{
		{"/home/user/workspace/file.txt", "/home/user/workspace", false},
		{"/home/user/.config/app.json", "/home/user/.config", false},
		{"/home/user/other/file.txt", "/home/user", false},
		{"/etc/passwd", "", true},
	}

	for _, tt := range tests {
		m := FindMount(mounts, tt.path)
		if tt.wantNil {
			if m != nil {
				t.Errorf("FindMount(%q) = %v, want nil", tt.path, m.Path)
			}
		} else {
			if m == nil {
				t.Errorf("FindMount(%q) = nil, want %q", tt.path, tt.wantPath)
			} else if m.Path != tt.wantPath {
				t.Errorf("FindMount(%q) = %q, want %q", tt.path, m.Path, tt.wantPath)
			}
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/... -run TestFindMount -v`
Expected: FAIL with "undefined: ResolvedMount"

**Step 3: Create mount.go with ResolvedMount and FindMount**

Create `internal/session/mount.go`:

```go
package session

import (
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// ResolvedMount represents an active mount with its loaded policy.
type ResolvedMount struct {
	Path         string         // Absolute path that was mounted
	Policy       string         // Policy name
	MountPoint   string         // Where FUSE mounted it
	PolicyEngine *policy.Engine // Loaded policy engine for this mount
	Unmount      func() error   // Function to unmount
}

// FindMount finds the mount that covers the given path using longest prefix match.
// Returns nil if no mount covers the path.
func FindMount(mounts []ResolvedMount, path string) *ResolvedMount {
	var best *ResolvedMount
	for i := range mounts {
		if strings.HasPrefix(path, mounts[i].Path) {
			// Ensure it's a proper path prefix (not just string prefix)
			if len(path) == len(mounts[i].Path) || path[len(mounts[i].Path)] == '/' {
				if best == nil || len(mounts[i].Path) > len(best.Path) {
					best = &mounts[i]
				}
			}
		}
	}
	return best
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/... -run TestFindMount -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/session/mount.go internal/session/mount_test.go
git commit -m "feat(session): add ResolvedMount type and FindMount function"
```

---

## Task 4: Add Mounts Field to Session Struct

**Files:**
- Modify: `internal/session/manager.go`

**Step 1: Add fields to Session struct**

In `internal/session/manager.go`, add to `Session` struct after line ~56:

```go
// Multi-mount support
Profile string          // Profile name if using multi-mount
Mounts  []ResolvedMount // Active mounts (empty if legacy single-mount)
```

**Step 2: Update Snapshot() to include new fields**

Update the `Snapshot()` method:

```go
func (s *Session) Snapshot() types.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var mounts []types.MountInfo
	for _, m := range s.Mounts {
		mounts = append(mounts, types.MountInfo{
			Path:       m.Path,
			Policy:     m.Policy,
			MountPoint: m.MountPoint,
		})
	}

	return types.Session{
		ID:        s.ID,
		State:     s.State,
		CreatedAt: s.CreatedAt,
		Workspace: s.Workspace,
		Policy:    s.Policy,
		Profile:   s.Profile,
		Mounts:    mounts,
		Cwd:       s.Cwd,
	}
}
```

**Step 3: Add cleanup for mounts**

Update the `cleanup()` method to unmount all mounts:

```go
func (s *Session) cleanup() {
	// Close network namespace
	s.CloseNetNS()

	// Close proxy
	s.CloseProxy()

	// Unmount all mounts (multi-mount)
	for i := range s.Mounts {
		if s.Mounts[i].Unmount != nil {
			_ = s.Mounts[i].Unmount()
		}
	}

	// Unmount workspace (legacy single-mount)
	s.UnmountWorkspace()
}
```

**Step 4: Run tests**

Run: `go test ./internal/session/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/session/manager.go
git commit -m "feat(session): add Profile and Mounts fields to Session struct"
```

---

## Task 5: Create Multi-Mount Policy Checker

**Files:**
- Create: `internal/session/policy_router.go`
- Test: `internal/session/policy_router_test.go`

**Step 1: Write the failing test**

Create `internal/session/policy_router_test.go`:

```go
package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestPolicyRouter_CheckFile(t *testing.T) {
	// Create a simple allow policy
	allowPolicy, _ := policy.Load([]byte(`
version: 1
name: allow-all
file_rules:
  - name: allow
    paths: ["/**"]
    operations: [read, write]
    decision: allow
`))

	// Create a deny-write policy
	denyWritePolicy, _ := policy.Load([]byte(`
version: 1
name: deny-write
file_rules:
  - name: allow-read
    paths: ["/**"]
    operations: [read]
    decision: allow
  - name: deny-write
    paths: ["/**"]
    operations: [write]
    decision: deny
`))

	mounts := []ResolvedMount{
		{Path: "/workspace", PolicyEngine: policy.NewEngine(allowPolicy)},
		{Path: "/config", PolicyEngine: policy.NewEngine(denyWritePolicy)},
	}

	router := NewPolicyRouter(nil, mounts)

	tests := []struct {
		path   string
		op     string
		want   types.Decision
	}{
		{"/workspace/file.txt", "read", types.DecisionAllow},
		{"/workspace/file.txt", "write", types.DecisionAllow},
		{"/config/app.json", "read", types.DecisionAllow},
		{"/config/app.json", "write", types.DecisionDeny},
		{"/unmounted/file.txt", "read", types.DecisionDeny}, // unmounted = deny
	}

	for _, tt := range tests {
		dec := router.CheckFile(tt.path, tt.op)
		if dec.EffectiveDecision != tt.want {
			t.Errorf("CheckFile(%q, %q) = %v, want %v", tt.path, tt.op, dec.EffectiveDecision, tt.want)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/... -run TestPolicyRouter -v`
Expected: FAIL with "undefined: NewPolicyRouter"

**Step 3: Create policy_router.go**

Create `internal/session/policy_router.go`:

```go
package session

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// PolicyRouter routes policy checks to the appropriate mount's policy engine.
type PolicyRouter struct {
	basePolicy *policy.Engine
	mounts     []ResolvedMount
}

// NewPolicyRouter creates a policy router with base policy and mount-specific policies.
func NewPolicyRouter(basePolicy *policy.Engine, mounts []ResolvedMount) *PolicyRouter {
	return &PolicyRouter{
		basePolicy: basePolicy,
		mounts:     mounts,
	}
}

// CheckFile checks file access against the appropriate mount policy, then base policy.
func (r *PolicyRouter) CheckFile(path, op string) policy.Decision {
	mount := FindMount(r.mounts, path)
	if mount == nil {
		// Unmounted path - deny by default
		return policy.Decision{
			PolicyDecision:    types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              "unmounted-path",
			Message:           "path is not covered by any mount",
		}
	}

	// Check mount policy first
	if mount.PolicyEngine != nil {
		dec := mount.PolicyEngine.CheckFile(path, op)
		if dec.EffectiveDecision == types.DecisionDeny {
			return dec
		}
	}

	// Check base policy
	if r.basePolicy != nil {
		return r.basePolicy.CheckFile(path, op)
	}

	// No policies - allow
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}

// CheckCommand delegates to base policy (mounts don't affect commands).
func (r *PolicyRouter) CheckCommand(cmd string, args []string) policy.Decision {
	if r.basePolicy != nil {
		return r.basePolicy.CheckCommand(cmd, args)
	}
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}

// CheckNetwork delegates to base policy (mounts don't affect network).
func (r *PolicyRouter) CheckNetwork(domain string, port int) policy.Decision {
	if r.basePolicy != nil {
		return r.basePolicy.CheckNetwork(domain, port)
	}
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/... -run TestPolicyRouter -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/session/policy_router.go internal/session/policy_router_test.go
git commit -m "feat(session): add PolicyRouter for multi-mount policy evaluation"
```

---

## Task 6: Add CreateWithProfile to Session Manager

**Files:**
- Modify: `internal/session/manager.go`
- Test: `internal/session/manager_test.go`

**Step 1: Write the failing test**

Add to `internal/session/manager_test.go`:

```go
func TestCreateWithProfile(t *testing.T) {
	m := NewManager(10)

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
		{Path: "/config", Policy: "config-readonly"},
	}

	s, err := m.CreateWithProfile("test-id", "my-profile", "default", mounts)
	if err != nil {
		t.Fatalf("CreateWithProfile: %v", err)
	}

	if s.Profile != "my-profile" {
		t.Errorf("Profile = %q, want %q", s.Profile, "my-profile")
	}
	if len(s.Mounts) != 2 {
		t.Errorf("len(Mounts) = %d, want 2", len(s.Mounts))
	}
	if s.Policy != "default" {
		t.Errorf("Policy = %q, want %q", s.Policy, "default")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/... -run TestCreateWithProfile -v`
Expected: FAIL with "undefined: CreateWithProfile"

**Step 3: Add CreateWithProfile method**

Add to `internal/session/manager.go`:

```go
// CreateWithProfile creates a session with multiple mounts from a profile.
func (m *Manager) CreateWithProfile(id, profile, basePolicy string, mounts []ResolvedMount) (*Session, error) {
	if len(mounts) == 0 {
		return nil, fmt.Errorf("at least one mount is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("max sessions reached")
	}

	if id == "" {
		id = "session-" + uuid.NewString()
	} else if !sessionIDRe.MatchString(id) {
		return nil, ErrInvalidSessionID
	}
	if _, ok := m.sessions[id]; ok {
		return nil, ErrSessionExists
	}

	// Use first mount as the "primary" workspace for legacy compatibility
	primaryWorkspace := mounts[0].Path

	now := time.Now().UTC()
	s := &Session{
		ID:           id,
		State:        types.SessionStateReady,
		CreatedAt:    now,
		LastActivity: now,
		Workspace:    primaryWorkspace,
		Policy:       basePolicy,
		Profile:      profile,
		Mounts:       mounts,
		Cwd:          "/workspace",
		Env:          map[string]string{},
	}
	m.sessions[id] = s
	return s, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/... -run TestCreateWithProfile -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/session/manager.go internal/session/manager_test.go
git commit -m "feat(session): add CreateWithProfile for multi-mount sessions"
```

---

## Task 7: Add Profile Resolution to API Core

**Files:**
- Modify: `internal/api/core.go`
- Modify: `internal/api/app.go`

**Step 1: Add profile resolution helper**

Add to `internal/api/core.go` before `createSessionCore`:

```go
// resolveProfile looks up a mount profile and validates it.
func (a *App) resolveProfile(profileName string) (*config.MountProfile, error) {
	if a.cfg.MountProfiles == nil {
		return nil, fmt.Errorf("no mount profiles configured")
	}
	profile, ok := a.cfg.MountProfiles[profileName]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", profileName)
	}
	if len(profile.Mounts) == 0 {
		return nil, fmt.Errorf("profile %q has no mounts", profileName)
	}
	return &profile, nil
}

// setupProfileMounts creates FUSE mounts for all paths in a profile.
func (a *App) setupProfileMounts(ctx context.Context, s *session.Session, profile *config.MountProfile) ([]session.ResolvedMount, error) {
	var mounts []session.ResolvedMount

	mountBase := a.cfg.Sandbox.FUSE.MountBaseDir
	if mountBase == "" {
		mountBase = a.cfg.Sessions.BaseDir
	}

	for i, spec := range profile.Mounts {
		// Validate path exists
		if _, err := os.Stat(spec.Path); err != nil {
			// Cleanup already-created mounts
			for _, m := range mounts {
				if m.Unmount != nil {
					_ = m.Unmount()
				}
			}
			return nil, fmt.Errorf("mount path %q: %w", spec.Path, err)
		}

		// Load the mount's policy
		var policyEngine *policy.Engine
		if spec.Policy != "" {
			p, err := a.policyLoader.Load(spec.Policy)
			if err != nil {
				for _, m := range mounts {
					if m.Unmount != nil {
						_ = m.Unmount()
					}
				}
				return nil, fmt.Errorf("load policy %q for mount %q: %w", spec.Policy, spec.Path, err)
			}
			policyEngine = policy.NewEngine(p)
		}

		// Create mount point
		mountPoint := filepath.Join(mountBase, s.ID, fmt.Sprintf("mount-%d", i))

		// Create FUSE mount
		if a.cfg.Sandbox.FUSE.Enabled && a.platform != nil {
			fs := a.platform.Filesystem()
			if fs != nil && fs.Available() {
				eventChan := make(chan platform.IOEvent, 1000)
				go a.processIOEvents(ctx, eventChan)

				fsCfg := platform.FSConfig{
					SourcePath: spec.Path,
					MountPoint: mountPoint,
					SessionID:  s.ID,
					CommandIDFunc: func() string {
						return s.CurrentCommandID()
					},
					PolicyEngine: platform.NewPolicyAdapter(policyEngine),
					EventChannel: eventChan,
				}

				m, err := fs.Mount(fsCfg)
				if err != nil {
					close(eventChan)
					// Log but continue - mount failure shouldn't block session
					a.logMountFailure(ctx, s.ID, spec.Path, mountPoint, err)
					continue
				}

				mounts = append(mounts, session.ResolvedMount{
					Path:         spec.Path,
					Policy:       spec.Policy,
					MountPoint:   mountPoint,
					PolicyEngine: policyEngine,
					Unmount: func() error {
						close(eventChan)
						return m.Close()
					},
				})
			}
		}
	}

	return mounts, nil
}

func (a *App) logMountFailure(ctx context.Context, sessionID, path, mountPoint string, err error) {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "fuse_mount_failed",
		SessionID: sessionID,
		Fields: map[string]any{
			"mount_point": mountPoint,
			"source_path": path,
			"error":       err.Error(),
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
}
```

**Step 2: Update createSessionCore to handle profiles**

Modify `createSessionCore` to check for profile first:

```go
func (a *App) createSessionCore(ctx context.Context, req types.CreateSessionRequest) (types.Session, int, error) {
	// Handle profile-based session creation
	if req.Profile != "" {
		return a.createSessionWithProfile(ctx, req)
	}

	// Existing single-workspace logic...
	// (keep the rest of the function as-is)
}

func (a *App) createSessionWithProfile(ctx context.Context, req types.CreateSessionRequest) (types.Session, int, error) {
	profile, err := a.resolveProfile(req.Profile)
	if err != nil {
		return types.Session{}, http.StatusBadRequest, err
	}

	basePolicy := profile.BasePolicy
	if basePolicy == "" {
		basePolicy = a.cfg.Policies.Default
	}

	// Create session with profile
	var s *session.Session
	if req.ID != "" {
		s, err = a.sessions.CreateWithProfile(req.ID, req.Profile, basePolicy, nil)
	} else {
		s, err = a.sessions.CreateWithProfile("", req.Profile, basePolicy, nil)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, session.ErrSessionExists) {
			code = http.StatusConflict
		}
		return types.Session{}, code, err
	}

	// Emit session_created event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "session_created",
		SessionID: s.ID,
		Fields: map[string]any{
			"profile":     req.Profile,
			"base_policy": basePolicy,
			"mounts":      len(profile.Mounts),
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	// Setup FUSE mounts for all paths in profile
	mounts, err := a.setupProfileMounts(ctx, s, profile)
	if err != nil {
		// Cleanup session on mount failure
		a.sessions.Destroy(s.ID)
		return types.Session{}, http.StatusInternalServerError, err
	}

	// Update session with resolved mounts
	s.Mounts = mounts

	return s.Snapshot(), http.StatusCreated, nil
}
```

**Step 3: Add policyLoader field to App struct**

In `internal/api/app.go`, add to `App` struct:

```go
policyLoader *policy.Loader
```

And wire it up in the constructor.

**Step 4: Run tests**

Run: `go test ./internal/api/... -v`
Expected: PASS (may need to mock policyLoader)

**Step 5: Commit**

```bash
git add internal/api/core.go internal/api/app.go
git commit -m "feat(api): add profile-based session creation with multi-mount"
```

---

## Task 8: Add /profiles API Endpoint

**Files:**
- Modify: `internal/api/routes.go` (or wherever routes are defined)
- Create: `internal/api/profiles.go`

**Step 1: Create profiles handler**

Create `internal/api/profiles.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
)

type ProfilesResponse struct {
	Profiles []ProfileInfo `json:"profiles"`
}

type ProfileInfo struct {
	Name       string      `json:"name"`
	BasePolicy string      `json:"base_policy"`
	Mounts     []MountInfo `json:"mounts"`
}

type MountInfo struct {
	Path   string `json:"path"`
	Policy string `json:"policy"`
}

func (a *App) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	var profiles []ProfileInfo

	for name, p := range a.cfg.MountProfiles {
		var mounts []MountInfo
		for _, m := range p.Mounts {
			mounts = append(mounts, MountInfo{
				Path:   m.Path,
				Policy: m.Policy,
			})
		}
		profiles = append(profiles, ProfileInfo{
			Name:       name,
			BasePolicy: p.BasePolicy,
			Mounts:     mounts,
		})
	}

	resp := ProfilesResponse{Profiles: profiles}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
```

**Step 2: Register route**

Add to routes:

```go
r.HandleFunc("/api/v1/profiles", a.handleListProfiles).Methods("GET")
```

**Step 3: Run tests**

Run: `go test ./internal/api/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/api/profiles.go internal/api/routes.go
git commit -m "feat(api): add GET /profiles endpoint to list mount profiles"
```

---

## Task 9: Add Built-in System Mounts

**Files:**
- Create: `internal/config/system_mounts.go`
- Test: `internal/config/system_mounts_test.go`

**Step 1: Write the failing test**

Create `internal/config/system_mounts_test.go`:

```go
package config

import (
	"runtime"
	"testing"
)

func TestGetSystemMounts(t *testing.T) {
	mounts := GetSystemMounts()

	if len(mounts) == 0 {
		t.Error("expected at least some system mounts")
	}

	// All mounts should have the system-readonly policy
	for _, m := range mounts {
		if m.Policy != "system-readonly" {
			t.Errorf("mount %q has policy %q, want system-readonly", m.Path, m.Policy)
		}
	}

	// Check for expected paths based on OS
	switch runtime.GOOS {
	case "linux":
		found := false
		for _, m := range mounts {
			if m.Path == "/usr" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected /usr in Linux system mounts")
		}
	case "darwin":
		found := false
		for _, m := range mounts {
			if m.Path == "/usr" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected /usr in Darwin system mounts")
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -run TestGetSystemMounts -v`
Expected: FAIL with "undefined: GetSystemMounts"

**Step 3: Create system_mounts.go**

Create `internal/config/system_mounts.go`:

```go
package config

import (
	"os"
	"runtime"
	"strings"
)

// GetSystemMounts returns the built-in read-only system mounts for the current platform.
func GetSystemMounts() []MountSpec {
	switch runtime.GOOS {
	case "linux":
		return linuxSystemMounts()
	case "darwin":
		return darwinSystemMounts()
	case "windows":
		return windowsSystemMounts()
	default:
		return minimalSystemMounts()
	}
}

func linuxSystemMounts() []MountSpec {
	mounts := []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/lib", Policy: "system-readonly"},
		{Path: "/lib64", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
		{Path: "/sbin", Policy: "system-readonly"},
		{Path: "/etc/hosts", Policy: "system-readonly"},
		{Path: "/etc/resolv.conf", Policy: "system-readonly"},
		{Path: "/etc/ssl/certs", Policy: "system-readonly"},
	}

	if isRunningInContainer() {
		mounts = append(mounts, MountSpec{
			Path: "/etc/alternatives", Policy: "system-readonly",
		})
	}

	return mounts
}

func darwinSystemMounts() []MountSpec {
	mounts := []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
		{Path: "/sbin", Policy: "system-readonly"},
		{Path: "/System/Library", Policy: "system-readonly"},
		{Path: "/etc/hosts", Policy: "system-readonly"},
		{Path: "/etc/resolv.conf", Policy: "system-readonly"},
	}

	// Add Homebrew paths if they exist
	if _, err := os.Stat("/opt/homebrew"); err == nil {
		mounts = append(mounts, MountSpec{Path: "/opt/homebrew", Policy: "system-readonly"})
	}
	if _, err := os.Stat("/usr/local/Cellar"); err == nil {
		mounts = append(mounts, MountSpec{Path: "/usr/local/Cellar", Policy: "system-readonly"})
	}

	return mounts
}

func windowsSystemMounts() []MountSpec {
	return []MountSpec{
		{Path: "C:\\Windows\\System32", Policy: "system-readonly"},
		{Path: "C:\\Program Files", Policy: "system-readonly"},
		{Path: "C:\\Program Files (x86)", Policy: "system-readonly"},
	}
}

func minimalSystemMounts() []MountSpec {
	return []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
	}
}

func isRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		return strings.Contains(s, "docker") || strings.Contains(s, "kubepods")
	}
	return false
}

// DetectEnvironment returns information about the current runtime environment.
type Environment struct {
	OS             string
	InContainer    bool
	InWSL          bool
	InDevContainer bool
}

func DetectEnvironment() Environment {
	env := Environment{OS: runtime.GOOS}

	env.InContainer = isRunningInContainer()

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			env.InWSL = strings.Contains(strings.ToLower(string(data)), "microsoft")
		}
	}

	env.InDevContainer = os.Getenv("REMOTE_CONTAINERS") != "" ||
		os.Getenv("CODESPACES") != ""

	return env
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config/... -run TestGetSystemMounts -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/system_mounts.go internal/config/system_mounts_test.go
git commit -m "feat(config): add platform-specific built-in system mounts"
```

---

## Task 10: Create system-readonly Policy File

**Files:**
- Create: `configs/policies/system-readonly.yaml`

**Step 1: Create the policy file**

Create `configs/policies/system-readonly.yaml`:

```yaml
version: 1
name: system-readonly
description: Built-in read-only policy for system paths

file_rules:
  - name: allow-readonly
    paths: ["/**"]
    operations: [read, stat, list, open, readlink]
    decision: allow

  - name: deny-write
    paths: ["/**"]
    operations: [write, create, delete, mkdir, rmdir, chmod, rename]
    decision: deny
    message: "system paths are read-only"
```

**Step 2: Commit**

```bash
git add configs/policies/system-readonly.yaml
git commit -m "feat(policies): add system-readonly policy for built-in mounts"
```

---

## Task 11: Integration Test for Multi-Mount

**Files:**
- Create: `internal/integration/multi_mount_test.go`

**Step 1: Create integration test**

Create `internal/integration/multi_mount_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestMultiMountProfile(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)

	// Create workspace-rw policy
	writeFile(t, filepath.Join(policiesDir, "workspace-rw.yaml"), `
version: 1
name: workspace-rw
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: [read, write, create, delete]
    decision: allow
`)

	// Create config-readonly policy
	writeFile(t, filepath.Join(policiesDir, "config-readonly.yaml"), `
version: 1
name: config-readonly
file_rules:
  - name: allow-read
    paths: ["/**"]
    operations: [read, stat, list]
    decision: allow
  - name: deny-write
    paths: ["/**"]
    operations: [write, create, delete]
    decision: deny
`)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	// Create config with mount profile
	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, `
server:
  http:
    addr: "0.0.0.0:18080"
auth:
  type: "api_key"
  api_key:
    keys_file: "/keys.yaml"
    header_name: "X-API-Key"
logging:
  level: "debug"
policies:
  dir: "/policies"
  default: "workspace-rw"
mount_profiles:
  test-profile:
    base_policy: "workspace-rw"
    mounts:
      - path: "/workspace"
        policy: "workspace-rw"
      - path: "/config"
        policy: "config-readonly"
sandbox:
  fuse:
    enabled: true
`)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "test.txt"), "hello")

	configDir := filepath.Join(temp, "config")
	mustMkdir(t, configDir)
	writeFile(t, filepath.Join(configDir, "settings.json"), `{"key": "value"}`)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// Create session with profile
	sess, err := cli.CreateSessionWithProfile(ctx, "test-profile")
	if err != nil {
		t.Fatalf("CreateSessionWithProfile: %v", err)
	}
	t.Logf("Created session: %s with profile: %s", sess.ID, sess.Profile)

	// Verify session has profile set
	if sess.Profile != "test-profile" {
		t.Errorf("expected profile=test-profile, got %s", sess.Profile)
	}

	// Test: read from workspace (should work)
	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/workspace/test.txt"},
	})
	if err != nil {
		t.Fatalf("Exec cat workspace: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("cat workspace should succeed, got exit %d", resp.Result.ExitCode)
	}

	// Test: read from config (should work)
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/config/settings.json"},
	})
	if err != nil {
		t.Fatalf("Exec cat config: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("cat config should succeed, got exit %d", resp.Result.ExitCode)
	}

	// Test: write to workspace (should work)
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "touch",
		Args:    []string{"/workspace/newfile.txt"},
	})
	if err != nil {
		t.Fatalf("Exec touch workspace: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("touch workspace should succeed, got exit %d", resp.Result.ExitCode)
	}

	// Test: write to config (should fail - readonly)
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "touch",
		Args:    []string{"/config/newfile.txt"},
	})
	// Either the exec returns an error or the exit code is non-zero
	if err == nil && resp.Result.ExitCode == 0 {
		t.Error("touch config should fail (readonly policy)")
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v", err)
	}
}
```

**Step 2: Add CreateSessionWithProfile to client**

Add to `internal/client/client.go`:

```go
func (c *Client) CreateSessionWithProfile(ctx context.Context, profile string) (*types.Session, error) {
	req := types.CreateSessionRequest{Profile: profile}
	// ... implement HTTP call
}
```

**Step 3: Run integration test**

Run: `go test -v -tags=integration ./internal/integration/... -run TestMultiMountProfile`

**Step 4: Commit**

```bash
git add internal/integration/multi_mount_test.go internal/client/client.go
git commit -m "test(integration): add multi-mount profile integration test"
```

---

## Task 12: Update Documentation

**Files:**
- Modify: `config.yml` (example config)
- Modify: `docs/spec.md` or relevant docs

**Step 1: Add mount_profiles example to config.yml**

Add to `config.yml`:

```yaml
# =============================================================================
# MOUNT PROFILES (for multi-mount sessions)
# =============================================================================

mount_profiles:
  # Example: Claude Code agent with protected config
  claude-agent:
    base_policy: "default"
    mounts:
      - path: "/home/user/workspace"
        policy: "workspace-rw"
      - path: "/home/user/.claude"
        policy: "config-readonly"
      - path: "/home/user/.config/claude-code"
        policy: "config-readonly"

  # Example: Restricted agent with minimal access
  restricted:
    base_policy: "minimal"
    mounts:
      - path: "/project"
        policy: "project-only"
```

**Step 2: Commit**

```bash
git add config.yml docs/
git commit -m "docs: add mount_profiles configuration examples"
```

---

## Summary

This plan implements multi-mount support in 12 tasks:

1. **Config types** - MountProfile and MountSpec in config.go
2. **API types** - Profile and Mounts fields in session types
3. **ResolvedMount** - Type for tracking active mounts with policies
4. **Session struct** - Add Profile and Mounts fields
5. **PolicyRouter** - Route file checks to appropriate mount policy
6. **CreateWithProfile** - Session manager method for profile-based creation
7. **API profile handling** - createSessionWithProfile and mount setup
8. **Profiles endpoint** - GET /profiles to list available profiles
9. **System mounts** - Platform-specific built-in read-only mounts
10. **system-readonly policy** - Policy file for built-in mounts
11. **Integration test** - End-to-end test for multi-mount
12. **Documentation** - Config examples and docs updates

Each task is independent and can be tested in isolation. The implementation follows TDD with tests before implementation.
