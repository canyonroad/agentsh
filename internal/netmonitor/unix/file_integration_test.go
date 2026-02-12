//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestFileHandler_FullPipeline exercises the complete routing pipeline:
// FileRequest -> policy check -> event emission -> result,
// covering all branches in a single test.
func TestFileHandler_FullPipeline(t *testing.T) {
	pol := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/workspace/src/main.go": {Decision: "allow", EffectiveDecision: "allow", Rule: "workspace-allow"},
			"/etc/shadow":            {Decision: "deny", EffectiveDecision: "deny", Rule: "system-deny"},
		},
	}
	emit := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(pol, registry, emit, true)

	// ── Test 1: Allowed open ──────────────────────────────────────────
	t.Run("allowed_open", func(t *testing.T) {
		emit.events = nil // reset

		req := FileRequest{
			PID:       100,
			Syscall:   int32(unix.SYS_OPENAT),
			Path:      "/workspace/src/main.go",
			Operation: "open",
			SessionID: "sess-1",
		}

		result := handler.Handle(req)

		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev := emit.events[0]
		assert.Equal(t, "seccomp", ev.Source, "Source must always be seccomp")
		assert.Equal(t, "file_open", ev.Type)
		assert.Equal(t, "/workspace/src/main.go", ev.Path)
		assert.Equal(t, "sess-1", ev.SessionID)
		assert.Equal(t, 100, ev.PID)
		assert.Equal(t, "allowed", ev.EffectiveAction)

		require.NotNil(t, ev.Policy)
		assert.Equal(t, "allow", string(ev.Policy.Decision))
		assert.Equal(t, "allow", string(ev.Policy.EffectiveDecision))
		assert.Equal(t, "workspace-allow", ev.Policy.Rule)
	})

	// ── Test 2: Denied open ───────────────────────────────────────────
	t.Run("denied_open", func(t *testing.T) {
		emit.events = nil

		req := FileRequest{
			PID:       101,
			Syscall:   int32(unix.SYS_OPENAT),
			Path:      "/etc/shadow",
			Operation: "open",
			SessionID: "sess-1",
		}

		result := handler.Handle(req)

		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)

		require.Len(t, emit.events, 1)
		ev := emit.events[0]
		assert.Equal(t, "seccomp", ev.Source)
		assert.Equal(t, "file_open", ev.Type)
		assert.Equal(t, "blocked", ev.EffectiveAction)

		require.NotNil(t, ev.Policy)
		assert.Equal(t, "deny", string(ev.Policy.Decision))
		assert.Equal(t, "deny", string(ev.Policy.EffectiveDecision))
		assert.Equal(t, "system-deny", ev.Policy.Rule)
	})

	// ── Test 3: FUSE overlap — audit-only ─────────────────────────────
	t.Run("fuse_overlap_audit_only", func(t *testing.T) {
		emit.events = nil

		// Register /workspace as a FUSE mount for this session.
		registry.Register("sess-1", "/workspace")
		defer registry.Deregister("sess-1", "/workspace")

		// Even though policy says allow, this tests FUSE overlap path:
		// the handler must return ActionContinue and let FUSE handle enforcement.
		req := FileRequest{
			PID:       102,
			Syscall:   int32(unix.SYS_OPENAT),
			Path:      "/workspace/src/main.go",
			Operation: "open",
			SessionID: "sess-1",
		}

		result := handler.Handle(req)

		assert.Equal(t, ActionContinue, result.Action,
			"FUSE overlap must always allow — FUSE handles enforcement")
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev := emit.events[0]
		assert.Equal(t, "seccomp", ev.Source)
		assert.Equal(t, "file_open", ev.Type)
	})

	// ── Test 4: Non-FUSE path still enforces after FUSE registration ──
	t.Run("non_fuse_path_still_enforces", func(t *testing.T) {
		emit.events = nil

		// Register /workspace under FUSE...
		registry.Register("sess-1", "/workspace")
		defer registry.Deregister("sess-1", "/workspace")

		// ...but /etc/shadow is NOT under /workspace, so full enforcement applies.
		req := FileRequest{
			PID:       103,
			Syscall:   int32(unix.SYS_OPENAT),
			Path:      "/etc/shadow",
			Operation: "open",
			SessionID: "sess-1",
		}

		result := handler.Handle(req)

		assert.Equal(t, ActionDeny, result.Action,
			"/etc/shadow is not under FUSE mount — must enforce deny")
		assert.Equal(t, int32(unix.EACCES), result.Errno)

		require.Len(t, emit.events, 1)
		ev := emit.events[0]
		assert.Equal(t, "seccomp", ev.Source)
		assert.Equal(t, "blocked", ev.EffectiveAction)
	})

	// ── Test 5: FUSE overlap with would-deny path — shadow deny ───────
	t.Run("fuse_overlap_shadow_deny", func(t *testing.T) {
		emit.events = nil

		// Policy denies /etc/shadow, but if it were under a FUSE mount
		// we'd still allow. We set up a FUSE mount covering /etc for this sub-test.
		registry.Register("sess-1", "/etc")
		defer registry.Deregister("sess-1", "/etc")

		req := FileRequest{
			PID:       104,
			Syscall:   int32(unix.SYS_OPENAT),
			Path:      "/etc/shadow",
			Operation: "open",
			SessionID: "sess-1",
		}

		result := handler.Handle(req)

		assert.Equal(t, ActionContinue, result.Action,
			"under FUSE mount — must allow even when policy says deny")
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev := emit.events[0]
		assert.Equal(t, "seccomp", ev.Source)

		// shadow_deny should be set because policy would deny but FUSE overrides.
		require.NotNil(t, ev.Fields)
		shadowDeny, ok := ev.Fields["shadow_deny"]
		require.True(t, ok, "expected shadow_deny field")
		assert.Equal(t, true, shadowDeny)
	})
}

// TestFileHandler_OperationMapping verifies that syscall numbers and flags
// map to the same operation strings the FUSE layer produces.
func TestFileHandler_OperationMapping(t *testing.T) {
	tests := []struct {
		name      string
		syscall   int32
		flags     uint32
		wantOp    string
		wantType  string // "file_" + wantOp
		wantSysc  string // fileSyscallName output
	}{
		{
			name:     "openat_read",
			syscall:  int32(unix.SYS_OPENAT),
			flags:    0,
			wantOp:   "open",
			wantType: "file_open",
			wantSysc: "openat",
		},
		{
			name:     "openat_O_CREAT",
			syscall:  int32(unix.SYS_OPENAT),
			flags:    unix.O_CREAT,
			wantOp:   "create",
			wantType: "file_create",
			wantSysc: "openat",
		},
		{
			name:     "openat_O_WRONLY",
			syscall:  int32(unix.SYS_OPENAT),
			flags:    unix.O_WRONLY,
			wantOp:   "write",
			wantType: "file_write",
			wantSysc: "openat",
		},
		{
			name:     "unlinkat_delete",
			syscall:  int32(unix.SYS_UNLINKAT),
			flags:    0,
			wantOp:   "delete",
			wantType: "file_delete",
			wantSysc: "unlinkat",
		},
		{
			name:     "unlinkat_AT_REMOVEDIR",
			syscall:  int32(unix.SYS_UNLINKAT),
			flags:    unix.AT_REMOVEDIR,
			wantOp:   "rmdir",
			wantType: "file_rmdir",
			wantSysc: "unlinkat",
		},
		{
			name:     "mkdirat",
			syscall:  int32(unix.SYS_MKDIRAT),
			flags:    0,
			wantOp:   "mkdir",
			wantType: "file_mkdir",
			wantSysc: "mkdirat",
		},
		{
			name:     "renameat2",
			syscall:  int32(unix.SYS_RENAMEAT2),
			flags:    0,
			wantOp:   "rename",
			wantType: "file_rename",
			wantSysc: "renameat2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify syscallToOperation mapping
			gotOp := syscallToOperation(tt.syscall, tt.flags)
			assert.Equal(t, tt.wantOp, gotOp, "operation mismatch")

			// Verify fileSyscallName mapping
			gotSysc := fileSyscallName(tt.syscall)
			assert.Equal(t, tt.wantSysc, gotSysc, "syscall name mismatch")

			// Wire through FileHandler and verify event Type = "file_" + operation
			pol := &mockFilePolicy{
				decisions: map[string]FilePolicyDecision{
					"/test/path": {Decision: "allow", EffectiveDecision: "allow", Rule: "test"},
				},
			}
			emit := &mockFileEmitter{}
			handler := NewFileHandler(pol, NewMountRegistry(), emit, true)

			req := FileRequest{
				PID:       200,
				Syscall:   tt.syscall,
				Path:      "/test/path",
				Operation: gotOp,
				Flags:     tt.flags,
				SessionID: "sess-op",
			}

			result := handler.Handle(req)
			assert.Equal(t, ActionContinue, result.Action)

			require.Len(t, emit.events, 1)
			ev := emit.events[0]
			assert.Equal(t, tt.wantType, ev.Type,
				"event Type must be file_<operation>")
			assert.Equal(t, "seccomp", ev.Source,
				"Source must always be seccomp")
			assert.Equal(t, gotOp, ev.Operation,
				"event Operation must match mapped operation")

			// Verify syscall name is in Fields
			require.NotNil(t, ev.Fields)
			assert.Equal(t, tt.wantSysc, ev.Fields["syscall"],
				"Fields[syscall] must be the syscall name")
		})
	}
}
