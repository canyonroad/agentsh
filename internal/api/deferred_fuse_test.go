package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

// --- mock types ---

type mockFSMount struct {
	path       string
	sourcePath string
	closed     atomic.Bool
}

func (m *mockFSMount) Path() string                { return m.path }
func (m *mockFSMount) SourcePath() string           { return m.sourcePath }
func (m *mockFSMount) Stats() platform.FSStats      { return platform.FSStats{} }
func (m *mockFSMount) Close() error                 { m.closed.Store(true); return nil }

type mockFilesystem struct {
	available      atomic.Bool
	recheckCalls   atomic.Int32
	mountCalls     atomic.Int32
	mountErr       error
	lastMount      *mockFSMount
	availableAfter int32 // become available after this many Recheck calls
}

func (m *mockFilesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	m.mountCalls.Add(1)
	if m.mountErr != nil {
		return nil, m.mountErr
	}
	mount := &mockFSMount{path: cfg.MountPoint, sourcePath: cfg.SourcePath}
	m.lastMount = mount
	return mount, nil
}

func (m *mockFilesystem) Unmount(mount platform.FSMount) error { return nil }

func (m *mockFilesystem) Available() bool { return m.available.Load() }

func (m *mockFilesystem) Recheck() {
	n := m.recheckCalls.Add(1)
	if m.availableAfter > 0 && n >= m.availableAfter {
		m.available.Store(true)
	}
}

func (m *mockFilesystem) Implementation() string { return "mock" }

type mockPlatform struct {
	fs *mockFilesystem
}

func (m *mockPlatform) Name() string                        { return "mock" }
func (m *mockPlatform) Capabilities() platform.Capabilities { return platform.Capabilities{} }
func (m *mockPlatform) Filesystem() platform.FilesystemInterceptor {
	if m.fs == nil {
		return nil
	}
	return m.fs
}
func (m *mockPlatform) Network() platform.NetworkInterceptor      { return nil }
func (m *mockPlatform) Sandbox() platform.SandboxManager          { return nil }
func (m *mockPlatform) Resources() platform.ResourceLimiter       { return nil }
func (m *mockPlatform) Initialize(_ context.Context, _ platform.Config) error { return nil }
func (m *mockPlatform) Shutdown(_ context.Context) error          { return nil }

// --- helpers ---

func newDeferredTestApp(t *testing.T, sessions *session.Manager, store *composite.Store) *App {
	t.Helper()
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = true
	cfg.Sandbox.FUSE.Deferred = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Default = "default"

	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)
}

func newDeferredTestSession(t *testing.T, mgr *session.Manager) *session.Session {
	t.Helper()
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := mgr.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- tests ---

func TestEnsureFUSEMount_AlreadyMounted(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	mfs.available.Store(true)
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	// Simulate already-mounted workspace
	s.SetWorkspaceMount("/some/mount/point")

	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 0 {
		t.Fatalf("expected no mount calls when already mounted, got %d", mfs.mountCalls.Load())
	}
}

func TestEnsureFUSEMount_NilPlatform(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	app.SetPlatformForTest(nil)

	// Should not panic
	app.ensureFUSEMount(context.Background(), s)
}

func TestEnsureFUSEMount_FUSEUnavailable(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	// available stays false
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 0 {
		t.Fatalf("expected no mount calls when FUSE unavailable, got %d", mfs.mountCalls.Load())
	}
	if s.WorkspaceMount != s.Workspace {
		t.Fatalf("expected WorkspaceMount unchanged (%q), got %q", s.Workspace, s.WorkspaceMount)
	}
}

func TestEnsureFUSEMount_FUSEAvailableAfterRecheck(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	// FUSE becomes available on the first Recheck call
	mfs.availableAfter = 1
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("expected 1 mount call after recheck, got %d", mfs.mountCalls.Load())
	}
	if s.WorkspaceMount == "" {
		t.Fatalf("expected WorkspaceMount to be set after successful mount")
	}
}

func TestEnsureFUSEMount_Success(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	mfs.available.Store(true)
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	app.ensureFUSEMount(context.Background(), s)

	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("expected 1 mount call, got %d", mfs.mountCalls.Load())
	}
	if s.WorkspaceMount == "" {
		t.Fatalf("expected WorkspaceMount to be set")
	}
	// Verify we can unmount
	if err := s.UnmountWorkspace(); err != nil {
		t.Fatalf("unexpected unmount error: %v", err)
	}
	if mfs.lastMount == nil || !mfs.lastMount.closed.Load() {
		t.Fatalf("expected mount to be closed after unmount")
	}
}

func TestEnsureFUSEMount_MountError(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	mfs.available.Store(true)
	mfs.mountErr = errors.New("fuse: permission denied")
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	app.ensureFUSEMount(context.Background(), s)

	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("expected 1 mount call, got %d", mfs.mountCalls.Load())
	}
	if s.WorkspaceMount != s.Workspace {
		t.Fatalf("expected WorkspaceMount unchanged after mount error (%q), got %q", s.Workspace, s.WorkspaceMount)
	}
}

func TestEnsureFUSEMount_Idempotent(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)

	app := newDeferredTestApp(t, mgr, store)
	mfs := &mockFilesystem{}
	mfs.available.Store(true)
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("first call: expected 1 mount, got %d", mfs.mountCalls.Load())
	}

	// Second call should be a no-op (already mounted)
	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("second call: expected still 1 mount, got %d", mfs.mountCalls.Load())
	}
}

func TestEnsureFUSEMount_NilPolicyAndEmitter(t *testing.T) {
	mgr := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := mgr.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Create minimal app with nil store/broker to test no-panic
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Sandbox.FUSE.Enabled = true
	cfg.Sandbox.FUSE.Deferred = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Policies.Default = "default"

	engine, _ := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
		},
	}, false)

	app := NewApp(cfg, mgr, store, engine, events.NewBroker(), nil, nil, nil, nil, nil)

	mfs := &mockFilesystem{}
	mfs.available.Store(true)
	app.SetPlatformForTest(&mockPlatform{fs: mfs})

	// Should not panic even with nil metrics
	app.ensureFUSEMount(context.Background(), s)
	if mfs.mountCalls.Load() != 1 {
		t.Fatalf("expected 1 mount call, got %d", mfs.mountCalls.Load())
	}
}

func TestMountFUSEForSession_DeferredEventField(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)
	s := newDeferredTestSession(t, mgr)
	broker := events.NewBroker()

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Sandbox.FUSE.Enabled = true
	cfg.Sandbox.FUSE.Deferred = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Policies.Default = "default"

	engine, _ := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
		},
	}, false)

	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, metrics.New(), nil)

	mfs := &mockFilesystem{}
	mfs.available.Store(true)

	// Subscribe to events
	ch := broker.Subscribe(s.ID, 10)
	defer broker.Unsubscribe(s.ID, ch)

	ok := app.mountFUSEForSession(context.Background(), fuseMountParams{
		session:  s,
		engine:   engine,
		fs:       mfs,
		deferred: true,
	})
	if !ok {
		t.Fatal("expected mountFUSEForSession to succeed")
	}

	// Drain the event channel to find fuse_mounted with deferred=true
	found := false
	timeout := time.After(2 * time.Second)
	for !found {
		select {
		case ev := <-ch:
			if ev.Type == "fuse_mounted" {
				if d, ok := ev.Fields["deferred"]; ok && d == true {
					found = true
				}
			}
		case <-timeout:
			t.Fatal("timed out waiting for fuse_mounted event with deferred=true")
		}
	}
}
