package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapCmd_RequiresCommand(t *testing.T) {
	cmd := newWrapCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command required")
}

func TestWrapCmd_DefaultPolicy(t *testing.T) {
	cmd := newWrapCmd()
	policy, err := cmd.Flags().GetString("policy")
	require.NoError(t, err)
	assert.Equal(t, "agent-default", policy)
}

func TestWrapCmd_DefaultReport(t *testing.T) {
	cmd := newWrapCmd()
	report, err := cmd.Flags().GetBool("report")
	require.NoError(t, err)
	assert.True(t, report)
}

func TestWrapCmd_DefaultSessionEmpty(t *testing.T) {
	cmd := newWrapCmd()
	session, err := cmd.Flags().GetString("session")
	require.NoError(t, err)
	assert.Equal(t, "", session)
}

func TestWrapCmd_DefaultRootEmpty(t *testing.T) {
	cmd := newWrapCmd()
	root, err := cmd.Flags().GetString("root")
	require.NoError(t, err)
	assert.Equal(t, "", root)
}

func TestWrapCmd_ParsesFlags(t *testing.T) {
	cmd := newWrapCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Parse flags only (don't execute) to verify flag parsing works
	err := cmd.ParseFlags([]string{"--policy", "strict", "--session", "my-sess", "--root", "/tmp/work", "--report=false"})
	require.NoError(t, err)

	policy, _ := cmd.Flags().GetString("policy")
	assert.Equal(t, "strict", policy)

	session, _ := cmd.Flags().GetString("session")
	assert.Equal(t, "my-sess", session)

	root, _ := cmd.Flags().GetString("root")
	assert.Equal(t, "/tmp/work", root)

	report, _ := cmd.Flags().GetBool("report")
	assert.False(t, report)
}

func TestWrapCmd_CommandAfterDash(t *testing.T) {
	// Cobra treats everything after -- as args, not flags.
	// Verify flags before -- are parsed and everything after -- is treated as args.
	cmd := newWrapCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.ParseFlags([]string{"--policy", "strict", "--", "claude-code", "--model", "opus"})
	require.NoError(t, err)

	policy, _ := cmd.Flags().GetString("policy")
	assert.Equal(t, "strict", policy)

	// ArgsLenAtDash returns the index in Args where -- was found.
	// Everything from that index onward is after the dash separator.
	dashIdx := cmd.ArgsLenAtDash()
	allArgs := cmd.Flags().Args()
	assert.GreaterOrEqual(t, dashIdx, 0, "dash separator should be found")
	assert.Equal(t, []string{"claude-code", "--model", "opus"}, allArgs[dashIdx:])
}

func TestWrapCmd_UsageString(t *testing.T) {
	cmd := newWrapCmd()
	usage := cmd.UsageString()
	assert.Contains(t, usage, "wrap [flags] -- COMMAND [ARGS...]")
	assert.Contains(t, usage, "--policy")
	assert.Contains(t, usage, "--session")
	assert.Contains(t, usage, "--root")
	assert.Contains(t, usage, "--report")
}

func TestWrapCmd_ShortDescription(t *testing.T) {
	cmd := newWrapCmd()
	assert.Equal(t, "Wrap an AI agent with exec interception", cmd.Short)
}

func TestWrapCmd_RequiresCommandWithFlags(t *testing.T) {
	// Even with flags specified, if no command after --, it should error
	cmd := newWrapCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--policy", "strict"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command required")
}
