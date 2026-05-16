//go:build linux

package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

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
	t.Cleanup(func() {
		ebpfCheckSupport = prevCheck
		ebpfAttachConnectToCgroup = prevAttach
		ebpfStartCollector = prevStart
	})
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
		return nil, func() error {
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
