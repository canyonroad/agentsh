package cli

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
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

// mockWrapClient implements CLIClient for testing wrap interception setup.
type mockWrapClient struct {
	wrapInitCalled  bool
	wrapInitReq     types.WrapInitRequest
	wrapInitResp    types.WrapInitResponse
	wrapInitErr     error
	createSessCalled bool
	getSessionCalled bool
}

// Ensure mockWrapClient implements CLIClient at compile time.
var _ client.CLIClient = (*mockWrapClient)(nil)

func (m *mockWrapClient) WrapInit(ctx context.Context, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, error) {
	m.wrapInitCalled = true
	m.wrapInitReq = req
	return m.wrapInitResp, m.wrapInitErr
}

// Satisfy CLIClient interface (unused methods for this test)
func (m *mockWrapClient) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	m.createSessCalled = true
	return types.Session{ID: "test-session"}, nil
}
func (m *mockWrapClient) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	return types.Session{ID: id}, nil
}
func (m *mockWrapClient) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
	return types.Session{}, nil
}
func (m *mockWrapClient) ListSessions(ctx context.Context) ([]types.Session, error) {
	return nil, nil
}
func (m *mockWrapClient) GetSession(ctx context.Context, id string) (types.Session, error) {
	m.getSessionCalled = true
	return types.Session{ID: id}, nil
}
func (m *mockWrapClient) DestroySession(ctx context.Context, id string) error    { return nil }
func (m *mockWrapClient) PatchSession(ctx context.Context, id string, req types.SessionPatchRequest) (types.Session, error) {
	return types.Session{}, nil
}
func (m *mockWrapClient) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	return types.ExecResponse{}, nil
}
func (m *mockWrapClient) ExecStream(ctx context.Context, sessionID string, req types.ExecRequest) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockWrapClient) KillCommand(ctx context.Context, sessionID string, commandID string) error {
	return nil
}
func (m *mockWrapClient) QuerySessionEvents(ctx context.Context, sessionID string, q url.Values) ([]types.Event, error) {
	return nil, nil
}
func (m *mockWrapClient) SearchEvents(ctx context.Context, q url.Values) ([]types.Event, error) {
	return nil, nil
}
func (m *mockWrapClient) StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockWrapClient) OutputChunk(ctx context.Context, sessionID, commandID string, stream string, offset, limit int64) (map[string]any, error) {
	return nil, nil
}
func (m *mockWrapClient) ListApprovals(ctx context.Context) ([]map[string]any, error) { return nil, nil }
func (m *mockWrapClient) ResolveApproval(ctx context.Context, id string, decision string, reason string) error {
	return nil
}
func (m *mockWrapClient) PolicyTest(ctx context.Context, sessionID, operation, path string) (map[string]any, error) {
	return nil, nil
}
func (m *mockWrapClient) GetProxyStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return nil, nil
}
func (m *mockWrapClient) ListTaints(ctx context.Context, sessionID string) ([]types.TaintInfo, error) {
	return nil, nil
}
func (m *mockWrapClient) GetTaint(ctx context.Context, pid int) (*types.TaintInfo, error) {
	return nil, nil
}
func (m *mockWrapClient) GetTaintTrace(ctx context.Context, pid int) (*types.TaintTrace, error) {
	return nil, nil
}
func (m *mockWrapClient) WatchTaints(ctx context.Context, agentOnly bool, handler func(types.TaintEvent)) error {
	return nil
}

func TestSetupWrapInterception_CallsWrapInit(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("wrap interception requires Linux or macOS")
	}

	mc := &mockWrapClient{
		wrapInitResp: types.WrapInitResponse{
			WrapperBinary: "/bin/true",
			SeccompConfig: `{"unix_socket_enabled":true}`,
			NotifySocket:  "/tmp/agentsh-notify-test.sock",
			WrapperEnv: map[string]string{
				"AGENTSH_SECCOMP_CONFIG": `{"unix_socket_enabled":true}`,
			},
		},
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}

	lcfg, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", []string{"hello"}, cfg)
	require.NoError(t, err)
	require.NotNil(t, lcfg)

	// Verify WrapInit was called
	assert.True(t, mc.wrapInitCalled, "WrapInit should have been called")
	assert.Equal(t, "/bin/echo", mc.wrapInitReq.AgentCommand)
	assert.Equal(t, []string{"hello"}, mc.wrapInitReq.AgentArgs)

	// Verify the launch config
	assert.Equal(t, "/bin/true", lcfg.command, "command should be the wrapper binary")
	assert.Equal(t, []string{"--", "/bin/echo", "hello"}, lcfg.args, "args should be -- agent-cmd agent-args")
	assert.NotNil(t, lcfg.extraFiles, "extra files should be set (socket pair child)")
	assert.Len(t, lcfg.extraFiles, 1, "should have exactly one extra file (child socket)")
	assert.NotNil(t, lcfg.postStart, "postStart should be set")

	// Clean up
	for _, f := range lcfg.extraFiles {
		if f != nil {
			f.Close()
		}
	}
}

func TestSetupWrapInterception_EmptyWrapperBinary(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("empty wrapper binary is valid on macOS (ES interception)")
	}

	mc := &mockWrapClient{
		wrapInitResp: types.WrapInitResponse{
			WrapperBinary: "",
		},
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}

	_, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", nil, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty wrapper binary")
}

func TestSetupWrapInterception_WrapInitError(t *testing.T) {
	mc := &mockWrapClient{
		wrapInitErr: assert.AnError,
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}

	_, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", nil, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrap-init")
}

func TestWrapLaunchConfig_EnvContainsSessionAndWrapper(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("wrap interception requires Linux or macOS")
	}

	mc := &mockWrapClient{
		wrapInitResp: types.WrapInitResponse{
			WrapperBinary: "/bin/true",
			SeccompConfig: `{"unix_socket_enabled":true}`,
			NotifySocket:  "/tmp/agentsh-notify-test.sock",
			WrapperEnv: map[string]string{
				"AGENTSH_SECCOMP_CONFIG": `{"unix_socket_enabled":true}`,
			},
		},
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}

	lcfg, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", nil, cfg)
	require.NoError(t, err)
	require.NotNil(t, lcfg)

	// Check that the env contains required variables
	envMap := make(map[string]bool)
	for _, e := range lcfg.env {
		envMap[e] = true
	}
	assert.True(t, envMap["AGENTSH_SESSION_ID=test-session"], "env should contain AGENTSH_SESSION_ID")
	assert.True(t, envMap["AGENTSH_SERVER=http://127.0.0.1:18080"], "env should contain AGENTSH_SERVER")
	assert.True(t, envMap["AGENTSH_NOTIFY_SOCK_FD=3"], "env should contain AGENTSH_NOTIFY_SOCK_FD=3")

	// Clean up
	for _, f := range lcfg.extraFiles {
		if f != nil {
			f.Close()
		}
	}
}
