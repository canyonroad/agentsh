package config

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/seccomp"
)

const afNetlinkFamily = 16

func ResolveSocketRules(in SandboxSeccompConfig) ([]seccomp.SocketRule, error) {
	effective, err := EffectiveSeccompRulesForConfig(in)
	if err != nil {
		return nil, err
	}
	return resolveSocketRuleConfigs(effective.SocketRules)
}

func resolveSocketRuleConfigs(configs []SandboxSeccompSocketRuleConfig) ([]seccomp.SocketRule, error) {
	out := make([]seccomp.SocketRule, 0, len(configs))
	seen := map[string]struct{}{}
	for i, e := range configs {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return nil, fmt.Errorf("socket_rules[%d].name: required", i)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate socket rule name %q", name)
		}
		seen[name] = struct{}{}

		family, familyName, ok := seccomp.ParseFamily(e.Family)
		if !ok {
			return nil, fmt.Errorf("socket_rules[%d].family: %q is not valid", i, e.Family)
		}
		actionStr := e.Action
		if actionStr == "" {
			actionStr = string(seccomp.OnBlockErrno)
		}
		action, ok := seccomp.ParseOnBlock(actionStr)
		if !ok {
			return nil, fmt.Errorf("socket_rules[%d].action: %q is not valid (allowed: errno, kill, log, log_and_kill)", i, e.Action)
		}
		rule := seccomp.SocketRule{Name: name, Family: family, FamilyName: familyName, Action: action}
		if e.Type != "" {
			typ, typName, ok := seccomp.ParseSocketType(e.Type)
			if !ok {
				return nil, fmt.Errorf("socket_rules[%d].type: %q is not valid", i, e.Type)
			}
			rule.Type = &typ
			rule.TypeName = typName
		}
		if e.Protocol != "" {
			proto, protoName, ok := seccomp.ParseSocketProtocol(e.Protocol)
			if !ok {
				return nil, fmt.Errorf("socket_rules[%d].protocol: %q is not valid", i, e.Protocol)
			}
			if strings.HasPrefix(protoName, "NETLINK_") && family != afNetlinkFamily {
				return nil, fmt.Errorf("socket_rules[%d].protocol: %q requires family AF_NETLINK", i, e.Protocol)
			}
			rule.Protocol = &proto
			rule.ProtocolName = protoName
		}
		out = append(out, rule)
	}
	return out, nil
}
