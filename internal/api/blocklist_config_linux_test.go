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

func TestBuildBlockListConfigFor_SocketRulesFromMitigationSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}

	app := &App{cfg: cfg}
	bl, ok := app.buildBlockListConfigFor("sess-dirtyfrag-mitigation").(*unixmon.BlockListConfig)
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

func TestBuildBlockListConfigFor_MitigationSetSyscallsAndFamilies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "log"
	addTestMitigationSet(t, cfg, "api-blocklist", `
version: 1
id: api-blocklist
seccomp:
  syscalls:
    block:
      - ptrace
  blocked_socket_families:
    - family: AF_ALG
      action: log
`)

	app := &App{cfg: cfg}
	bl, ok := app.buildBlockListConfigFor("sess-mitigation-blocklist").(*unixmon.BlockListConfig)
	require.True(t, ok)
	require.NotNil(t, bl)

	action, ok := bl.IsBlockListed(uint32(gounix.SYS_PTRACE))
	require.True(t, ok)
	require.Equal(t, seccompkg.OnBlockLog, action)

	family, ok := bl.FamilyBlockListed(uint32(gounix.SYS_SOCKET), uint64(gounix.AF_ALG))
	require.True(t, ok)
	require.Equal(t, "AF_ALG", family.Name)
	require.Equal(t, seccompkg.OnBlockLog, family.Action)

	family, ok = bl.FamilyBlockListed(uint32(gounix.SYS_SOCKETPAIR), uint64(gounix.AF_ALG))
	require.True(t, ok)
	require.Equal(t, "AF_ALG", family.Name)
	require.Equal(t, seccompkg.OnBlockLog, family.Action)
}
