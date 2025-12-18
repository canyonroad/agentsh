package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentsh/agentsh/pkg/ptygrpc"
)

func TestExecPTYFlag_SelectsPTYPath(t *testing.T) {
	prev := execPTYRunner
	t.Cleanup(func() { execPTYRunner = prev })

	called := false
	execPTYRunner = func(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest) error {
		called = true
		return nil
	}

	root := NewRoot("test")
	root.SetArgs([]string{"exec", "--pty", "sess-1", "--", "echo", "hi"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if !called {
		t.Fatalf("expected PTY path to be selected when --pty is set")
	}
}

func TestExecPTYFlag_PassesTimeoutFromJSON(t *testing.T) {
	prev := execPTYRunner
	t.Cleanup(func() { execPTYRunner = prev })

	var got string
	execPTYRunner = func(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest) error {
		got = req.Timeout
		return nil
	}

	root := NewRoot("test")
	root.SetArgs([]string{
		"exec",
		"--pty",
		"--json", `{"command":"sh","args":["-c","echo hi"],"timeout":"123ms"}`,
		"sess-1",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if got != "123ms" {
		t.Fatalf("expected timeout to be propagated from JSON, got %q", got)
	}
}

func TestExecPTY_RawModeOnlyWhenTTY(t *testing.T) {
	makeRawCalled := 0
	restoreCalled := 0

	deps := ptyDeps{
		isTTY: func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) {
			makeRawCalled++
			return &ptyTermState{}, nil
		},
		restore: func(fd int, st *ptyTermState) error {
			restoreCalled++
			return nil
		},
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	prevGRPC := execPTYGRPCRunner
	t.Cleanup(func() { execPTYGRPCRunner = prevGRPC })
	execPTYGRPCRunner = func(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest, deps ptyDeps) error {
		// Ensure deps passed through.
		if deps.isTTY(0) != false {
			t.Fatalf("expected deps override")
		}
		return errors.New("stop")
	}

	err := execPTYWithDeps(context.Background(), &clientConfig{transport: "grpc"}, "sess-1", execPTYRequest{Command: "echo"}, deps)
	if err == nil {
		t.Fatalf("expected error")
	}
	if makeRawCalled != 0 {
		t.Fatalf("expected MakeRaw not called when not a tty, got %d", makeRawCalled)
	}
	if restoreCalled != 0 {
		t.Fatalf("expected Restore not called when not a tty, got %d", restoreCalled)
	}
}

func TestExecPTYWS_ContextCancelCloses(t *testing.T) {
	closed := make(chan struct{})
	srv := newHTTPTestServerOrSkip(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		// Read start message, then wait for client to disconnect.
		_, _, _ = c.ReadMessage()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				close(closed)
				return
			}
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := &clientConfig{serverAddr: srv.URL, transport: "http"}
	deps := ptyDeps{
		isTTY:   func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) { return nil, errors.New("unexpected raw") },
		restore: func(fd int, st *ptyTermState) error { return nil },
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	resCh := make(chan error, 1)
	go func() {
		resCh <- execPTYWS(ctx, cfg, "sess-1", execPTYRequest{Command: "sh"}, deps)
	}()

	select {
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("expected execPTYWS to return promptly on context cancel")
	case err := <-resCh:
		if err == nil {
			t.Fatalf("expected error on context cancel")
		}
	}

	select {
	case <-closed:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("expected server to observe client close")
	}
}

func TestExecPTYWS_PolicyDenied_DefaultsToExit126(t *testing.T) {
	srv := newHTTPTestServerOrSkip(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		// Start frame.
		_, _, _ = c.ReadMessage()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":403,"message":"command denied (approval required)"}`))
	}))

	cfg := &clientConfig{serverAddr: srv.URL, transport: "http"}
	deps := ptyDeps{
		isTTY:   func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) { return nil, errors.New("unexpected raw") },
		restore: func(fd int, st *ptyTermState) error { return nil },
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	err := execPTYWS(context.Background(), cfg, "sess-1", execPTYRequest{Command: "sh"}, deps)
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.Code() != 126 {
		t.Fatalf("expected exit 126, got %d", ee.Code())
	}
	if ee.Message() == "" {
		t.Fatalf("expected message to be set")
	}
}

func TestExecPTYWS_PolicyDenied_ModeErrorPreservesError(t *testing.T) {
	t.Setenv("AGENTSH_PTY_DENY_MODE", "error")

	srv := newHTTPTestServerOrSkip(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _, _ = c.ReadMessage()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":403,"message":"command denied by policy"}`))
	}))

	cfg := &clientConfig{serverAddr: srv.URL, transport: "http"}
	deps := ptyDeps{
		isTTY:   func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) { return nil, errors.New("unexpected raw") },
		restore: func(fd int, st *ptyTermState) error { return nil },
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	err := execPTYWS(context.Background(), cfg, "sess-1", execPTYRequest{Command: "sh"}, deps)
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		t.Fatalf("expected non-ExitError, got %T: %v", err, err)
	}
	if err.Error() != "command denied by policy" {
		t.Fatalf("expected policy message, got %q", err.Error())
	}
}

type denyPTYServer struct {
	ptygrpc.UnimplementedAgentshPTYServer
}

func (s *denyPTYServer) ExecPTY(stream ptygrpc.AgentshPTY_ExecPTYServer) error {
	_, _ = stream.Recv()
	return status.Error(codes.PermissionDenied, "command denied by policy")
}

type denyPTYServerImmediate struct {
	ptygrpc.UnimplementedAgentshPTYServer
}

func (s *denyPTYServerImmediate) ExecPTY(stream ptygrpc.AgentshPTY_ExecPTYServer) error {
	return status.Error(codes.PermissionDenied, "command denied by policy")
}

func TestExecPTYGRPC_PolicyDenied_DefaultsToExit126(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("grpc listen not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	g := grpc.NewServer()
	t.Cleanup(g.Stop)
	ptygrpc.RegisterAgentshPTYServer(g, &denyPTYServer{})
	go func() { _ = g.Serve(ln) }()

	cfg := &clientConfig{grpcAddr: ln.Addr().String(), transport: "grpc"}
	deps := ptyDeps{
		isTTY:   func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) { return nil, errors.New("unexpected raw") },
		restore: func(fd int, st *ptyTermState) error { return nil },
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = execPTYGRPC(ctx, cfg, "sess-1", execPTYRequest{Command: "sh"}, deps)
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.Code() != 126 {
		t.Fatalf("expected exit 126, got %d", ee.Code())
	}
}

func TestExecPTYGRPC_PolicyDeniedOnStart_DefaultsToExit126(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("grpc listen not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	g := grpc.NewServer()
	t.Cleanup(g.Stop)
	ptygrpc.RegisterAgentshPTYServer(g, &denyPTYServerImmediate{})
	go func() { _ = g.Serve(ln) }()

	cfg := &clientConfig{grpcAddr: ln.Addr().String(), transport: "grpc"}
	deps := ptyDeps{
		isTTY:   func(fd int) bool { return false },
		makeRaw: func(fd int) (*ptyTermState, error) { return nil, errors.New("unexpected raw") },
		restore: func(fd int, st *ptyTermState) error { return nil },
		getSize: func(fd int) (cols int, rows int, err error) { return 80, 24, nil },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = execPTYGRPC(ctx, cfg, "sess-1", execPTYRequest{Command: "sh"}, deps)
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.Code() != 126 {
		t.Fatalf("expected exit 126, got %d", ee.Code())
	}
}
