package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer srv.Close()

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
