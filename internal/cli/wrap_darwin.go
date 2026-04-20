//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap on macOS sets up ES-based interception.
// Unlike Linux (seccomp per-process), macOS ES is system-wide via the System Extension.
// The wrap command registers the session with the server, which configures the ESF client
// to intercept execs from this session's process tree.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	if wrapResp.WrapperBinary == "" {
		// No wrapper needed on macOS — ES interception is handled by System Extension.
		// The agent runs directly, and the ESF client intercepts its execs.
		env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)

		return &wrapLaunchConfig{
			command: agentPath,
			args:    agentArgs,
			env:     env,
			sysProcAttr: &syscall.SysProcAttr{
				Setpgid: true,
			},
		}, nil
	}

	// If the server returns a wrapper binary (e.g., agentsh-macwrap for sandboxing),
	// use it as the launch command.
	env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
	for k, v := range wrapResp.WrapperEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	wrapperArgs := append([]string{"--", agentPath}, agentArgs...)

	return &wrapLaunchConfig{
		command: wrapResp.WrapperBinary,
		args:    wrapperArgs,
		env:     env,
		sysProcAttr: &syscall.SysProcAttr{
			Setpgid: true,
		},
	}, nil
}
