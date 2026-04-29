package config

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/seccomp"
)

// ResolveBlockedFamilies converts YAML-typed entries into the engine-typed
// slice consumed by FilterConfigFromYAML / FamilyChecker. Empty Action
// defaults to errno. Caller should have run config validation first;
// this function returns an error if any entry fails to resolve, but it
// does not catch unknown-action strings (those degrade to errno via
// seccomp.ParseOnBlock).
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
		action, _ := seccomp.ParseOnBlock(actionStr)
		out = append(out, seccomp.BlockedFamily{
			Family: nr,
			Action: action,
			Name:   name,
		})
	}
	return out, nil
}
