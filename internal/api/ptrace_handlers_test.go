//go:build linux

package api

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func newTestRouter(t *testing.T, trashPath string) (*ptraceHandlerRouter, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	router := &ptraceHandlerRouter{
		sessions:  mgr,
		store:     store,
		broker:    broker,
		trashPath: trashPath,
	}
	return router, mgr
}

func newSoftDeleteEngine(t *testing.T, workspace string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-soft-delete",
		FileRules: []policy.FileRule{
			{
				Name:       "soft-delete-workspace",
				Paths:      []string{workspace + "/**"},
				Operations: []string{"delete", "read", "write", "rmdir"},
				Decision:   "soft_delete",
				Message:    "Deletions go to trash",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestHandleFile_SoftDelete(t *testing.T) {
	workspace := t.TempDir()

	tests := []struct {
		name       string
		trashPath  string
		workspace  string
		operation  string
		path       string
		wantAction string
		wantAllow  bool
		wantErrno  int32
	}{
		{
			name:       "delete with configured trash returns soft-delete",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "delete",
			path:       workspace + "/file.txt",
			wantAction: "soft-delete",
		},
		{
			name:       "rmdir with configured trash returns soft-delete",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "rmdir",
			path:       workspace + "/subdir",
			wantAction: "soft-delete",
		},
		{
			name:       "non-delete op with soft_delete policy falls through to allow",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "read",
			path:       workspace + "/file.txt",
			wantAction: "allow",
			wantAllow:  true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, mgr := newTestRouter(t, tt.trashPath)
			sessID := fmt.Sprintf("test-session-%d", i)
			sess, err := mgr.CreateWithID(sessID, tt.workspace, "")
			if err != nil {
				t.Fatalf("CreateWithID: %v", err)
			}
			sess.SetPolicyEngine(newSoftDeleteEngine(t, tt.workspace))

			result := router.HandleFile(context.Background(), ptrace.FileContext{
				SessionID: sess.ID,
				PID:       1234,
				Path:      tt.path,
				Operation: tt.operation,
			})

			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
			if tt.wantErrno != 0 && result.Errno != tt.wantErrno {
				t.Errorf("Errno = %d, want %d", result.Errno, tt.wantErrno)
			}
			if result.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v", result.Allow, tt.wantAllow)
			}
		})
	}
}

func TestHandleFile_SoftDeleteNoTrashDir(t *testing.T) {
	// When trash path resolves to empty (no workspace), soft-delete denies.
	router, mgr := newTestRouter(t, "")
	workspace := t.TempDir()
	sess, err := mgr.CreateWithID("test-no-trash", workspace, "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	// Set workspace to empty after creation to simulate missing workspace.
	sess.Workspace = ""
	sess.SetPolicyEngine(newSoftDeleteEngine(t, workspace))

	result := router.HandleFile(context.Background(), ptrace.FileContext{
		SessionID: sess.ID,
		PID:       1234,
		Path:      workspace + "/file.txt",
		Operation: "delete",
	})

	if result.Action != "deny" {
		t.Errorf("Action = %q, want deny", result.Action)
	}
	if result.Errno != int32(syscall.EACCES) {
		t.Errorf("Errno = %d, want %d", result.Errno, int32(syscall.EACCES))
	}
}
