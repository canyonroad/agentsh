//go:build !linux && !darwin && !windows

package cli

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap returns an error on unsupported platforms since exec
// interception requires Linux (seccomp), macOS (Endpoint Security), or Windows (driver).
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	return nil, fmt.Errorf("exec interception is only supported on Linux, macOS, and Windows")
}
