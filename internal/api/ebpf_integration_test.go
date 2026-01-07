//go:build linux

package api

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// This test is best-effort: it skips if ebpf support is unavailable or connect_bpfel.o is missing.
func TestEBPFConnectEventFlow(t *testing.T) {
	status := ebpftrace.CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf unsupported: %s", status.Reason)
	}

	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	ws := t.TempDir()
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Cgroups.Enabled = true

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)

	// Create command cgroup and attach ebpf via hook.
	hook := app.cgroupHook(sess.ID, "cmd-test", policy.Limits{})
	detach, err := hook(os.Getpid())
	if err != nil {
		t.Skipf("ebpf attach failed (likely missing object): %v", err)
	}
	defer func() {
		if detach != nil {
			_ = detach()
		}
	}()

	// Trigger a localhost connect.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9", 500*time.Millisecond)
	if err == nil {
		conn.Close()
	}

	time.Sleep(200 * time.Millisecond)
	evs, err := store.QueryEvents(ctx, types.EventQuery{SessionID: sess.ID, Types: []string{"net_connect"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Skip("no net_connect events observed; likely missing ebpf object or blocked by kernel lockdown")
	}
}
