package config

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/seccomp"
)

// ResolveBlockedFamilies converts YAML-typed entries into the engine-typed
// slice consumed by FilterConfigFromYAML / FamilyChecker. Empty Action
// defaults to errno. Returns an error if any entry has an unknown family or
// an invalid action string.
func ResolveBlockedFamilies(in []SandboxSeccompSocketFamilyConfig) ([]seccomp.BlockedFamily, error) {
	out := make([]seccomp.BlockedFamily, 0, len(in))
	for i, e := range in {
		nr, name, ok := seccomp.ParseFamily(e.Family)
		if !ok {
			return nil, fmt.Errorf("blocked_socket_families[%d]: invalid family %q", i, e.Family)
		}
		actionStr := e.Action
		if actionStr == "" {
			actionStr = string(seccomp.OnBlockErrno)
		}
		action, ok := seccomp.ParseOnBlock(actionStr)
		if !ok {
			return nil, fmt.Errorf("blocked_socket_families[%d]: invalid action %q", i, e.Action)
		}
		out = append(out, seccomp.BlockedFamily{
			Family: nr,
			Action: action,
			Name:   name,
		})
	}
	return out, nil
}
