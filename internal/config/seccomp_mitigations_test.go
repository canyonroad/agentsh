package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/stretchr/testify/require"
)

func TestEffectiveSeccompRules_BuiltInDirtyFrag(t *testing.T) {
	eff, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	})
	require.NoError(t, err)
	require.Len(t, eff.LoadedMitigations, 1)
	require.Equal(t, "dirtyfrag-conservative", eff.LoadedMitigations[0].ID)
	require.Equal(t, "builtin", eff.LoadedMitigations[0].Source)
	require.NotEmpty(t, eff.LoadedMitigations[0].Checksum)
	require.Len(t, eff.SocketRules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", eff.SocketRules[0].Name)
	require.Equal(t, "AF_RXRPC", eff.SocketRules[0].Family)
	require.Equal(t, "log_and_kill", eff.SocketRules[0].Action)
	require.Equal(t, "dirtyfrag-conservative-xfrm", eff.SocketRules[1].Name)
	require.Equal(t, "AF_NETLINK", eff.SocketRules[1].Family)
	require.Equal(t, "NETLINK_XFRM", eff.SocketRules[1].Protocol)
	require.Equal(t, "log_and_kill", eff.SocketRules[1].Action)
}

func TestEffectiveSeccompRules_IgnoresMitigationDirsForTask2(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dirtyfrag-conservative.yaml"), []byte("not: active\n"), 0o600))

	eff, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
		MitigationDirs: []string{dir},
	})
	require.NoError(t, err)
	require.Len(t, eff.LoadedMitigations, 1)
	require.Equal(t, "builtin", eff.LoadedMitigations[0].Source)
}

func TestResolveSocketRules_BuiltInDirtyFrag(t *testing.T) {
	rules, err := ResolveSocketRules(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	})
	require.NoError(t, err)
	require.Len(t, rules, 2)

	rxrpcFamily, _, ok := seccomp.ParseFamily("AF_RXRPC")
	require.True(t, ok)
	netlinkFamily, _, ok := seccomp.ParseFamily("AF_NETLINK")
	require.True(t, ok)
	xfrmProtocol, _, ok := seccomp.ParseSocketProtocol("NETLINK_XFRM")
	require.True(t, ok)

	require.Equal(t, rxrpcFamily, rules[0].Family)
	require.Equal(t, seccomp.OnBlockLogAndKill, rules[0].Action)
	require.Equal(t, netlinkFamily, rules[1].Family)
	require.NotNil(t, rules[1].Protocol)
	require.Equal(t, xfrmProtocol, *rules[1].Protocol)
	require.Equal(t, seccomp.OnBlockLogAndKill, rules[1].Action)
}

func TestEffectiveSeccompRules_RejectsUnknownMitigationSet(t *testing.T) {
	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `mitigation_sets[0]`)
	require.Contains(t, err.Error(), "dirtyfrag")
}

func TestEffectiveSeccompRules_RejectsDuplicateRequestedMitigationSet(t *testing.T) {
	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets:    []string{"dirtyfrag-conservative"},
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "duplicate mitigation set"), err.Error())
}
