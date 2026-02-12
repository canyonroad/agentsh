//go:build !linux || !cgo

package api

import (
	"context"
	"os"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// createExecveHandler is a no-op on non-Linux platforms.
func createExecveHandler(cfg config.ExecveConfig, pol *policy.Engine, approvalMgr *approvals.Manager) any {
	return nil
}

// startNotifyHandler is a no-op on non-Linux platforms or without CGO.
// Unix socket enforcement via seccomp user-notify is Linux-only.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig) {
	// Unix socket enforcement not available on this platform
	if parentSock != nil {
		_ = parentSock.Close()
	}
}
