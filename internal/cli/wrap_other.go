//go:build !linux && !darwin

package cli

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap returns an error on unsupported platforms since exec
// interception requires Linux (seccomp) or macOS (Endpoint Security).
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	return nil, fmt.Errorf("exec interception is only supported on Linux and macOS")
}
