//go:build linux && cgo && integration

package signal_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalInterceptionE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for seccomp")
	}

	if !signal.IsSignalSupportAvailable() {
		t.Skip("seccomp user notify not available")
	}

	// Create policy
	rules := []signal.SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL", "SIGTERM"},
			Target:   signal.TargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := signal.NewEngine(rules)
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test-session", os.Getpid())
	handler := signal.NewHandler(engine, registry, nil)

	// Start a child process
	cmd := exec.Command("sleep", "60")
	err = cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	registry.Register(cmd.Process.Pid, os.Getpid(), "sleep")

	// Test: signal to external should be denied
	decision := handler.Evaluate(signal.SignalContext{
		PID:       cmd.Process.Pid,
		TargetPID: 1, // init - external
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionDeny, decision.Action)

	// Test: signal to child should use default deny (no allow rule)
	decision = handler.Evaluate(signal.SignalContext{
		PID:       os.Getpid(),
		TargetPID: cmd.Process.Pid,
		Signal:    int(syscall.SIGTERM),
	})
	// Default deny since no allow rule
	assert.Equal(t, signal.DecisionDeny, decision.Action)
}
