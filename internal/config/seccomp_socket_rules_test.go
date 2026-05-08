package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSandboxSeccompSocketRules_ParseYAML(t *testing.T) {
	data := []byte(`
sandbox:
  seccomp:
    socket_rules:
      - name: dirtyfrag-xfrm
        family: AF_NETLINK
        protocol: NETLINK_XFRM
        action: log_and_kill
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Len(t, cfg.Sandbox.Seccomp.SocketRules, 1)
	require.Equal(t, "dirtyfrag-xfrm", cfg.Sandbox.Seccomp.SocketRules[0].Name)
	require.Equal(t, "AF_NETLINK", cfg.Sandbox.Seccomp.SocketRules[0].Family)
	require.Equal(t, "NETLINK_XFRM", cfg.Sandbox.Seccomp.SocketRules[0].Protocol)
	require.Equal(t, "log_and_kill", cfg.Sandbox.Seccomp.SocketRules[0].Action)
}

func TestSandboxSeccompMitigationSets_ParseYAML(t *testing.T) {
	data := []byte(`
sandbox:
  seccomp:
    mitigation_sets:
      - dirtyfrag-conservative
    mitigation_dirs:
      - admin-mitigations
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Equal(t, []string{"dirtyfrag-conservative"}, cfg.Sandbox.Seccomp.MitigationSets)
	require.Equal(t, []string{"admin-mitigations"}, cfg.Sandbox.Seccomp.MitigationDirs)
}

func TestLoad_RejectsHardeningProfiles(t *testing.T) {
	_, err := loadFromString(t, `
sandbox:
  seccomp:
    hardening_profiles:
      - dirtyfrag-conservative
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sandbox.seccomp.hardening_profiles has been removed")
	require.Contains(t, err.Error(), "sandbox.seccomp.mitigation_sets")
}

func TestResolveSocketRules_DirtyFragMitigationSet(t *testing.T) {
	cfg := SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	}
	rules, err := ResolveSocketRules(cfg)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", rules[0].Name)
	require.Equal(t, "dirtyfrag-conservative-xfrm", rules[1].Name)
}

func TestResolveSocketRules_RejectsBadProtocol(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name:     "bad",
			Family:   "AF_NETLINK",
			Protocol: "NETLINK_XFRMM",
			Action:   "errno",
		}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `socket_rules[0].protocol`)
	require.Contains(t, err.Error(), "NETLINK_XFRMM")
}

func TestResolveSocketRules_RejectsNetlinkProtocolForNonNetlinkFamily(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name:     "bad-family-protocol",
			Family:   "AF_INET",
			Protocol: "NETLINK_XFRM",
			Action:   "errno",
		}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `socket_rules[0].protocol`)
	require.Contains(t, err.Error(), "NETLINK_XFRM")
	require.Contains(t, err.Error(), "AF_NETLINK")
}

func TestResolveSocketRules_AllowsNumericProtocolForNonNetlinkFamily(t *testing.T) {
	rules, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name:     "tcp",
			Family:   "AF_INET",
			Protocol: "6",
			Action:   "errno",
		}},
	})
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NotNil(t, rules[0].Protocol)
	require.Equal(t, 6, *rules[0].Protocol)
}

func TestResolveSocketRules_RejectsUnknownMitigationSet(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `mitigation_sets[0]`)
}

func TestResolveSocketRules_RejectsDuplicateNamesAfterMitigationSetExpansion(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name:     "dirtyfrag-conservative-xfrm",
			Family:   "AF_NETLINK",
			Protocol: "NETLINK_XFRM",
			Action:   "errno",
		}},
		MitigationSets: []string{"dirtyfrag-conservative"},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "duplicate socket rule name"), err.Error())
}

func TestValidateConfig_ValidatesSocketRules(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Seccomp.SocketRules = []SandboxSeccompSocketRuleConfig{{
		Name:   "bad-family",
		Family: "AF_NOT_REAL",
		Action: "errno",
	}}
	err := validateConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AF_NOT_REAL")
}
