package cli

import (
	"context"
	"errors"
	"testing"
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

