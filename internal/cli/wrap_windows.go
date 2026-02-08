//go:build windows

package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap on Windows sets up driver-based exec interception.
// Like macOS, Windows uses a system-wide driver (agentsh.sys) for exec
// interception, so the agent runs directly without a wrapper binary.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
		fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
	)
	for k, v := range wrapResp.WrapperEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	if wrapResp.WrapperBinary == "" {
		// No wrapper needed on Windows — driver-based interception is system-wide.
		// The agent runs directly and the driver intercepts its execs.
		return &wrapLaunchConfig{
			command: agentPath,
			args:    agentArgs,
			env:     env,
			sysProcAttr: &syscall.SysProcAttr{
				CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
			},
		}, nil
	}

	// If the server returns a wrapper binary, prefix the agent command with it.
	wrapperArgs := append([]string{"--", agentPath}, agentArgs...)
	return &wrapLaunchConfig{
		command: wrapResp.WrapperBinary,
		args:    wrapperArgs,
		env:     env,
		sysProcAttr: &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		},
	}, nil
}
