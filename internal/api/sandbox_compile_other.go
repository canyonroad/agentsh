//go:build !darwin || !cgo

package api

import "github.com/agentsh/agentsh/internal/policy"

func compileDarwinSandboxProfile(cfg *macSandboxWrapperConfig, engine *policy.Engine, workspace string) bool {
	return false
}
