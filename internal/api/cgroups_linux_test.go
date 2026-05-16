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
	path string
}

func (m *fakeCgroupManagerForAPITest) Apply(name string, pid int, lim limits.CgroupV2Limits) (*limits.CgroupV2, error) {
	if err := os.MkdirAll(m.path, 0o755); err != nil {
		return nil, err
	}
	return &limits.CgroupV2{Path: m.path}, nil
}

func (m *fakeCgroupManagerForAPITest) Probe() *limits.CgroupProbeResult {
	return &limits.CgroupProbeResult{Mode: limits.ModeNested}
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
