//go:build linux

package api

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/limits"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/cilium/ebpf"
)

type fakeCgroupManagerForAPITest struct {
	path     string
	mode     limits.CgroupMode // defaults to ModeNested when zero
	applyErr error             // when set, Apply returns this instead of a CgroupV2
}

func (m *fakeCgroupManagerForAPITest) Apply(name string, pid int, lim limits.CgroupV2Limits) (*limits.CgroupV2, error) {
	if m.applyErr != nil {
		return nil, m.applyErr
	}
	if err := os.MkdirAll(m.path, 0o755); err != nil {
		return nil, err
	}
	return &limits.CgroupV2{Path: m.path}, nil
}

func (m *fakeCgroupManagerForAPITest) Probe() *limits.CgroupProbeResult {
	mode := m.mode
	if mode == "" {
		mode = limits.ModeNested
	}
	return &limits.CgroupProbeResult{Mode: mode}
}

func newAppWithFakeCgroupManager(t *testing.T, cfg *config.Config, cgPath string) *App {
	t.Helper()
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
	app.cgroupMgr = &fakeCgroupManagerForAPITest{path: cgPath}
	return app
}

func withEBPFHooks(t *testing.T) {
	t.Helper()
	prevCheck := ebpfCheckSupport
	prevAttach := ebpfAttachConnectToCgroup
	prevStart := ebpfStartCollector
	prevCgroupID := ebpfCgroupID
	prevPopulate := ebpfPopulateAllowlist
	prevCleanup := ebpfCleanupAllowlist
	t.Cleanup(func() {
		ebpfCheckSupport = prevCheck
		ebpfAttachConnectToCgroup = prevAttach
		ebpfStartCollector = prevStart
		ebpfCgroupID = prevCgroupID
		ebpfPopulateAllowlist = prevPopulate
		ebpfCleanupAllowlist = prevCleanup
	})
}

func withDomainResolverHook(t *testing.T, fn func(string, time.Duration) ([]net.IP, time.Duration)) {
	t.Helper()
	prev := resolveDomainWithTTL
	resolveDomainWithTTL = fn
	t.Cleanup(func() {
		resolveDomainWithTTL = prev
	})
}

func networkPolicyEngineForCgroupTest(t *testing.T) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "cgroup-ebpf-test",
		NetworkRules: []policy.NetworkRule{{
			Name:     "allow-example",
			Domains:  []string{"example.test"},
			Ports:    []int{443},
			Decision: "allow",
		}},
	}, false, true)
	if err != nil {
		t.Fatalf("build policy engine: %v", err)
	}
	return engine
}

func TestApplyCgroupV2_CleansCgroupWhenRequiredEBPFUnsupported(t *testing.T) {
	withEBPFHooks(t)

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)

	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: false, Reason: "test unsupported"}
	}

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected required ebpf error")
	}
	if _, statErr := os.Stat(cgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected cgroup cleanup after required ebpf failure, stat err = %v", statErr)
	}
}

func TestApplyCgroupV2_CleansCgroupWhenRequiredAttachFails(t *testing.T) {
	withEBPFHooks(t)

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)

	var startCollectorCalls atomic.Int32
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		return nil, nil, errors.New("attach failed")
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		startCollectorCalls.Add(1)
		return nil, errors.New("collector should not start after attach failure")
	}

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected required ebpf attach error")
	}
	if !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("expected attach failure, got %v", err)
	}
	if got := startCollectorCalls.Load(); got != 0 {
		t.Fatalf("collector start calls = %d, want 0 after attach failure", got)
	}
	if _, statErr := os.Stat(cgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected cgroup cleanup after required attach failure, stat err = %v", statErr)
	}
}

func TestApplyCgroupV2_DetachesAndCleansCgroupWhenRequiredCollectorStartFails(t *testing.T) {
	withEBPFHooks(t)

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)

	var detachCalls atomic.Int32
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		return &ebpf.Collection{}, func() error {
			detachCalls.Add(1)
			return nil
		}, nil
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		return nil, errors.New("collector failed")
	}

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected required ebpf collector error")
	}
	if got := detachCalls.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
	if _, statErr := os.Stat(cgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected cgroup cleanup after required collector failure, stat err = %v", statErr)
	}
}

func TestApplyCgroupV2_CleansEBPFResourcesWhenOptionalEnforceCollectorStartFails(t *testing.T) {
	withEBPFHooks(t)
	withDomainResolverHook(t, func(domain string, maxTTL time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("203.0.113.10")}, time.Second
	})

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cfg.Sandbox.Network.EBPF.DNSRefreshSeconds = 1
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	engine := networkPolicyEngineForCgroupTest(t)

	var detachCalls atomic.Int32
	var populateCalls atomic.Int32
	var cleanupAllowlistCalls atomic.Int32
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		return &ebpf.Collection{}, func() error {
			detachCalls.Add(1)
			return nil
		}, nil
	}
	ebpfCgroupID = func(path string) (uint64, error) {
		return 42, nil
	}
	ebpfPopulateAllowlist = func(coll *ebpf.Collection, cgroupID uint64, allow []ebpftrace.AllowKey, allowCIDRs []ebpftrace.AllowCIDR, deny []ebpftrace.AllowKey, denyCIDRs []ebpftrace.AllowCIDR, defaultDeny bool) error {
		populateCalls.Add(1)
		return nil
	}
	ebpfCleanupAllowlist = func(coll *ebpf.Collection, cgroupID uint64) error {
		cleanupAllowlistCalls.Add(1)
		return nil
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		return nil, errors.New("collector failed")
	}

	cleanup, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, engine)
	if err != nil {
		t.Fatalf("optional collector failure should degrade without returning error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected cgroup cleanup function")
	}
	if got := populateCalls.Load(); got != 1 {
		t.Fatalf("populate calls = %d, want 1", got)
	}
	if got := cleanupAllowlistCalls.Load(); got != 1 {
		t.Fatalf("cleanup allowlist calls = %d, want 1 after optional collector failure", got)
	}
	if got := detachCalls.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
	if _, statErr := os.Stat(cgPath); statErr != nil {
		t.Fatalf("optional collector failure should leave cgroup for normal cleanup, stat err = %v", statErr)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestApplyCgroupV2_DetachesAndCleansCgroupWhenRequiredEnforceCgroupIDFails(t *testing.T) {
	withEBPFHooks(t)

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)

	var detachCalls atomic.Int32
	var cgroupIDCalls atomic.Int32
	var startCollectorCalls atomic.Int32
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		return &ebpf.Collection{}, func() error {
			detachCalls.Add(1)
			return nil
		}, nil
	}
	ebpfCgroupID = func(path string) (uint64, error) {
		cgroupIDCalls.Add(1)
		return 0, errors.New("cgroup id failed")
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		startCollectorCalls.Add(1)
		return nil, errors.New("collector should not start before enforcement setup")
	}

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected required ebpf enforcement error")
	}
	if !strings.Contains(err.Error(), "cgroup id failed") {
		t.Fatalf("expected cgroup id failure, got %v", err)
	}
	if got := cgroupIDCalls.Load(); got != 1 {
		t.Fatalf("cgroup id calls = %d, want 1", got)
	}
	if got := startCollectorCalls.Load(); got != 0 {
		t.Fatalf("collector start calls = %d, want 0 before enforcement setup succeeds", got)
	}
	if got := detachCalls.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
	if _, statErr := os.Stat(cgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected cgroup cleanup after required enforce setup failure, stat err = %v", statErr)
	}
}

func TestApplyCgroupV2_DetachesAndCleansCgroupWhenRequiredEnforcePopulateFails(t *testing.T) {
	withEBPFHooks(t)

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")
	app := newAppWithFakeCgroupManager(t, cfg, cgPath)

	var detachCalls atomic.Int32
	var populateCalls atomic.Int32
	var cleanupAllowlistCalls atomic.Int32
	var startCollectorCalls atomic.Int32
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		return &ebpf.Collection{}, func() error {
			detachCalls.Add(1)
			return nil
		}, nil
	}
	ebpfCgroupID = func(path string) (uint64, error) {
		return 42, nil
	}
	ebpfPopulateAllowlist = func(coll *ebpf.Collection, cgroupID uint64, allow []ebpftrace.AllowKey, allowCIDRs []ebpftrace.AllowCIDR, deny []ebpftrace.AllowKey, denyCIDRs []ebpftrace.AllowCIDR, defaultDeny bool) error {
		populateCalls.Add(1)
		return errors.New("populate failed")
	}
	ebpfCleanupAllowlist = func(coll *ebpf.Collection, cgroupID uint64) error {
		cleanupAllowlistCalls.Add(1)
		return nil
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		startCollectorCalls.Add(1)
		return nil, errors.New("collector should not start before enforcement setup")
	}

	_, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err == nil {
		t.Fatal("expected required ebpf enforcement error")
	}
	if !strings.Contains(err.Error(), "populate failed") {
		t.Fatalf("expected populate failure, got %v", err)
	}
	if got := populateCalls.Load(); got != 1 {
		t.Fatalf("populate calls = %d, want 1", got)
	}
	if got := startCollectorCalls.Load(); got != 0 {
		t.Fatalf("collector start calls = %d, want 0 before enforcement setup succeeds", got)
	}
	if got := cleanupAllowlistCalls.Load(); got != 1 {
		t.Fatalf("cleanup allowlist calls = %d, want 1", got)
	}
	if got := detachCalls.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
	if _, statErr := os.Stat(cgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected cgroup cleanup after required populate failure, stat err = %v", statErr)
	}
}

// TestApplyCgroupV2_AttachOnly_NoLimits_Succeeds verifies that when
// cgroups.enabled=false but ebpf.enabled=true the widened activation gate
// still proceeds, and a successful ModeAttachOnly Apply with no resource limits
// invokes ebpfAttachConnectToCgroup and returns a non-nil cleanup.
func TestApplyCgroupV2_AttachOnly_NoLimits_Succeeds(t *testing.T) {
	withEBPFHooks(t)

	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = false // widened gate: ebpf.enabled alone is sufficient
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	app.cgroupMgr.(*fakeCgroupManagerForAPITest).mode = limits.ModeAttachOnly

	var attachCalled string
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		attachCalled = path
		return &ebpf.Collection{}, func() error { return nil }, nil
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		return nil, errors.New("collector not needed in attach-only test")
	}

	cleanup, err := applyCgroupV2(context.Background(), storeEmitter{store: app.store, broker: app.broker}, app, "sess", "cmd", 1234, policy.Limits{}, nil, nil)
	if err != nil {
		t.Fatalf("applyCgroupV2: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup closure")
	}
	if attachCalled == "" {
		t.Errorf("ebpfAttachConnectToCgroup should have been called")
	}
	_ = cleanup()
}

// TestDefaultWrapCgroupSetup_AttachOnly_NoLimits_Succeeds verifies that when
// the probe mode is ModeAttachOnly and no resource limits are requested, the
// wrap cgroup setup succeeds and invokes the ebpf attach hook.
func TestDefaultWrapCgroupSetup_AttachOnly_NoLimits_Succeeds(t *testing.T) {
	withEBPFHooks(t)

	cgPath := filepath.Join(t.TempDir(), "agentsh-test-cgroup")

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	app.cgroupMgr.(*fakeCgroupManagerForAPITest).mode = limits.ModeAttachOnly

	var attachCalled string
	ebpfCheckSupport = func() ebpftrace.SupportStatus {
		return ebpftrace.SupportStatus{Supported: true}
	}
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		attachCalled = path
		return &ebpf.Collection{}, func() error { return nil }, nil
	}
	ebpfStartCollector = func(coll *ebpf.Collection, bufSize int) (*ebpftrace.Collector, error) {
		return nil, errors.New("collector not needed in attach-only test")
	}

	cleanup, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-1", 4242)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected cleanup closure, got nil")
	}
	if attachCalled == "" {
		t.Errorf("ebpfAttachConnectToCgroup should have been called")
	}
	_ = cleanup()
}

// TestDefaultWrapCgroupSetup_AttachOnly_LimitsRequested_Errors verifies that
// when the probe mode is ModeAttachOnly but the fake Apply returns
// CgroupResourceLimitsUnavailableError, the error propagates out.
func TestDefaultWrapCgroupSetup_AttachOnly_LimitsRequested_Errors(t *testing.T) {
	withEBPFHooks(t)

	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "controllers cannot be enabled: ENOTSUP",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	_, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-1", 4242)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var rlErr *limits.CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Errorf("error type: got %T, want *CgroupResourceLimitsUnavailableError", err)
	}
}

// TestDefaultWrapCgroupSetup_Unavailable_NotRequired_WarnContinues verifies
// that when the probe mode is ModeUnavailable and ebpf.required is false,
// the setup soft-fails: it returns a no-op cleanup and no error.
func TestDefaultWrapCgroupSetup_Unavailable_NotRequired_WarnContinues(t *testing.T) {
	withEBPFHooks(t)

	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	// ebpf.Required defaults false.

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeUnavailable
	fake.applyErr = &limits.CgroupUnavailableError{
		Reason: "probe unavailable: capability gap",
	}

	cleanup, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-2", 4242)
	if err != nil {
		t.Fatalf("expected nil error (soft fail), got %v", err)
	}
	if cleanup == nil {
		t.Errorf("expected a non-nil noop cleanup closure")
	}
	if cleanup != nil {
		_ = cleanup()
	}
}

// TestApplyCgroupV2_BestEffort_LimitsUnavailable_Degrades verifies that when
// best_effort=true and no eBPF flags are set, a CgroupResourceLimitsUnavailableError
// causes a degraded run (nil error, no-op cleanup) rather than a hard failure.
func TestApplyCgroupV2_BestEffort_LimitsUnavailable_Degrades(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = true
	// eBPF off — pure resource-limit case.

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	cleanup, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	if err != nil {
		t.Fatalf("expected degrade (nil err), got %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil no-op cleanup")
	}
	_ = cleanup()
}

// TestApplyCgroupV2_BestEffortDisabled_LimitsUnavailable_FailsClosed verifies
// that best_effort=false keeps the existing fail-closed behavior.
func TestApplyCgroupV2_BestEffortDisabled_LimitsUnavailable_FailsClosed(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = false

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	_, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	var rlErr *limits.CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Fatalf("expected typed error, got %T (%v)", err, err)
	}
}

// TestApplyCgroupV2_BestEffort_WithEBPF_FailsClosed verifies that when
// best_effort=true but eBPF is enabled, egress enforcement must stay strict
// and the error is still returned (fail closed).
func TestApplyCgroupV2_BestEffort_WithEBPF_FailsClosed(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = true
	cfg.Sandbox.Network.EBPF.Enabled = true // egress boundary present

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	_, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	if err == nil {
		t.Fatal("expected fail-closed with eBPF enabled, got nil")
	}
}

// TestDefaultWrapCgroupSetup_Unavailable_Required_HardFails verifies that
// when the probe mode is ModeUnavailable and ebpf.required is true, the
// CgroupUnavailableError propagates as a hard failure.
func TestDefaultWrapCgroupSetup_Unavailable_Required_HardFails(t *testing.T) {
	withEBPFHooks(t)

	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeUnavailable
	fake.applyErr = &limits.CgroupUnavailableError{Reason: "probe unavailable"}

	_, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-3", 4242)
	if err == nil {
		t.Fatalf("expected error under ebpf.required=true, got nil")
	}
	var unavailErr *limits.CgroupUnavailableError
	if !errors.As(err, &unavailErr) {
		t.Errorf("error type: got %T, want *CgroupUnavailableError", err)
	}
}
