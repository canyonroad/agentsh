//go:build !linux

package cli

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap returns an error on non-Linux platforms since seccomp
// interception requires Linux.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	return nil, fmt.Errorf("seccomp interception is only supported on Linux")
}
