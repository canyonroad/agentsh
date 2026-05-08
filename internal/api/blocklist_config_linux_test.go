//go:build linux && cgo

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

func TestBuildBlockListConfigFor_SocketRulesNotifyOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{
		{Name: "errno-rule", Family: "AF_NETLINK", Protocol: "NETLINK_AUDIT", Action: "errno"},
		{Name: "kill-rule", Family: "AF_NETLINK", Protocol: "NETLINK_GENERIC", Action: "kill"},
		{Name: "log-rule", Family: "AF_NETLINK", Protocol: "NETLINK_XFRM", Action: "log"},
		{Name: "log-and-kill-rule", Family: "AF_RXRPC", Action: "log_and_kill"},
	}

	app := &App{cfg: cfg}
	bl, ok := app.buildBlockListConfigFor("sess-socket-rules").(*unixmon.BlockListConfig)
	require.True(t, ok)
	require.NotNil(t, bl)

	require.Len(t, bl.SocketRules, 2)
	require.Equal(t, "log-rule", bl.SocketRules[0].Name)
	require.Equal(t, seccompkg.OnBlockLog, bl.SocketRules[0].Action)
	require.Equal(t, gounix.AF_NETLINK, bl.SocketRules[0].Family)
	require.NotNil(t, bl.SocketRules[0].Protocol)
	require.Equal(t, int(gounix.NETLINK_XFRM), *bl.SocketRules[0].Protocol)
	require.Equal(t, "log-and-kill-rule", bl.SocketRules[1].Name)
	require.Equal(t, seccompkg.OnBlockLogAndKill, bl.SocketRules[1].Action)
}

func TestBuildBlockListConfigFor_SocketRulesFromHardeningProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.HardeningProfiles = []string{"dirtyfrag-conservative"}

	app := &App{cfg: cfg}
	bl, ok := app.buildBlockListConfigFor("sess-dirtyfrag-profile").(*unixmon.BlockListConfig)
	require.True(t, ok)
	require.NotNil(t, bl)

	require.Len(t, bl.SocketRules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", bl.SocketRules[0].Name)
	require.Equal(t, seccompkg.OnBlockLogAndKill, bl.SocketRules[0].Action)
	require.Equal(t, "dirtyfrag-conservative-xfrm", bl.SocketRules[1].Name)
	require.Equal(t, seccompkg.OnBlockLogAndKill, bl.SocketRules[1].Action)
	require.NotNil(t, bl.SocketRules[1].Protocol)
	require.Equal(t, int(gounix.NETLINK_XFRM), *bl.SocketRules[1].Protocol)
}
