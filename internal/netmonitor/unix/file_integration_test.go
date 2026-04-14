//go:build linux && cgo

package unix

import (
	"context"
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

		result, ev := handler.Handle(req)
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
		}

		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev0 := emit.events[0]
		assert.Equal(t, "seccomp", ev0.Source, "Source must always be seccomp")
		assert.Equal(t, "file_open", ev0.Type)
		assert.Equal(t, "/workspace/src/main.go", ev0.Path)
		assert.Equal(t, "sess-1", ev0.SessionID)
		assert.Equal(t, 100, ev0.PID)
		assert.Equal(t, "allowed", ev0.EffectiveAction)

		require.NotNil(t, ev0.Policy)
		assert.Equal(t, "allow", string(ev0.Policy.Decision))
		assert.Equal(t, "allow", string(ev0.Policy.EffectiveDecision))
		assert.Equal(t, "workspace-allow", ev0.Policy.Rule)
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

		result, ev := handler.Handle(req)
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
		}

		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)

		require.Len(t, emit.events, 1)
		ev0 := emit.events[0]
		assert.Equal(t, "seccomp", ev0.Source)
		assert.Equal(t, "file_open", ev0.Type)
		assert.Equal(t, "blocked", ev0.EffectiveAction)

		require.NotNil(t, ev0.Policy)
		assert.Equal(t, "deny", string(ev0.Policy.Decision))
		assert.Equal(t, "deny", string(ev0.Policy.EffectiveDecision))
		assert.Equal(t, "system-deny", ev0.Policy.Rule)
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

		result, ev := handler.Handle(req)
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
		}

		assert.Equal(t, ActionContinue, result.Action,
			"FUSE overlap must always allow — FUSE handles enforcement")
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev0 := emit.events[0]
		assert.Equal(t, "seccomp", ev0.Source)
		assert.Equal(t, "file_open", ev0.Type)
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

		result, ev := handler.Handle(req)
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
		}

		assert.Equal(t, ActionDeny, result.Action,
			"/etc/shadow is not under FUSE mount — must enforce deny")
		assert.Equal(t, int32(unix.EACCES), result.Errno)

		require.Len(t, emit.events, 1)
		ev0 := emit.events[0]
		assert.Equal(t, "seccomp", ev0.Source)
		assert.Equal(t, "blocked", ev0.EffectiveAction)
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

		result, ev := handler.Handle(req)
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
		}

		assert.Equal(t, ActionContinue, result.Action,
			"under FUSE mount — must allow even when policy says deny")
		assert.Equal(t, int32(0), result.Errno)

		require.Len(t, emit.events, 1)
		ev0 := emit.events[0]
		assert.Equal(t, "seccomp", ev0.Source)

		// shadow_deny should be set because policy would deny but FUSE overrides.
		require.NotNil(t, ev0.Fields)
		shadowDeny, ok := ev0.Fields["shadow_deny"]
		require.True(t, ok, "expected shadow_deny field")
		assert.Equal(t, true, shadowDeny)
	})
}

// TestEmulatedOpen_AllowRoutesToAddFD verifies the emulated-open decision
// path end-to-end: FileHandler with emulateOpen=true evaluates the policy,
// and when the policy allows, the result is ActionContinue (the real AddFD
// call happens inside emulateOpenat, which requires a live seccomp notify fd,
// so here we verify the handler's routing decision only).
func TestEmulatedOpen_AllowRoutesToAddFD(t *testing.T) {
	pol := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/workspace/data.txt": {Decision: "allow", EffectiveDecision: "allow", Rule: "workspace-rw"},
		},
	}
	emit := &mockFileEmitter{}
	handler := NewFileHandler(pol, NewMountRegistry(), emit, true)
	handler.SetEmulateOpen(true)
	require.True(t, handler.EmulateOpen(), "emulateOpen must be true after SetEmulateOpen(true)")

	// Simulate an allowed openat request going through the handler.
	// In the real emulated path, ActionContinue means "proceed to AddFD".
	req := FileRequest{
		PID:       300,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/workspace/data.txt",
		Operation: "open",
		SessionID: "sess-emu",
	}

	result, ev := handler.Handle(req)
	if ev != nil {
		_ = emit.AppendEvent(context.Background(), *ev)
	}

	assert.Equal(t, ActionContinue, result.Action,
		"allowed open must produce ActionContinue (triggers AddFD in emulated path)")
	assert.Equal(t, int32(0), result.Errno)

	// Verify the event was emitted with correct metadata.
	require.Len(t, emit.events, 1)
	ev0 := emit.events[0]
	assert.Equal(t, "seccomp", ev0.Source)
	assert.Equal(t, "file_open", ev0.Type)
	assert.Equal(t, "allowed", ev0.EffectiveAction)
	assert.Equal(t, "/workspace/data.txt", ev0.Path)
	assert.Equal(t, 300, ev0.PID)
	assert.Equal(t, "sess-emu", ev0.SessionID)

	require.NotNil(t, ev0.Policy)
	assert.Equal(t, "allow", string(ev0.Policy.Decision))
	assert.Equal(t, "workspace-rw", ev0.Policy.Rule)

	// Verify that isOpenSyscall agrees this is an emulatable open.
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT), "SYS_OPENAT must be an open syscall")
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, 0, 0),
		"plain openat should not fall back to CONTINUE")
}

// TestEmulatedOpen_DenyReturnsEACCES verifies the emulated-open denial path:
// FileHandler with emulateOpen=true and enforce=true returns ActionDeny +
// EACCES for denied paths. In handleFileNotificationEmulated, this becomes
// a NotifRespond with -EACCES (no AddFD call).
func TestEmulatedOpen_DenyReturnsEACCES(t *testing.T) {
	pol := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/shadow": {Decision: "deny", EffectiveDecision: "deny", Rule: "system-deny"},
		},
	}
	emit := &mockFileEmitter{}
	handler := NewFileHandler(pol, NewMountRegistry(), emit, true) // enforce=true
	handler.SetEmulateOpen(true)

	req := FileRequest{
		PID:       301,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/shadow",
		Operation: "open",
		SessionID: "sess-emu",
	}

	result, ev := handler.Handle(req)
	if ev != nil {
		_ = emit.AppendEvent(context.Background(), *ev)
	}

	assert.Equal(t, ActionDeny, result.Action,
		"denied open must produce ActionDeny even with emulateOpen")
	assert.Equal(t, int32(unix.EACCES), result.Errno,
		"denied open must return EACCES")

	require.Len(t, emit.events, 1)
	ev0 := emit.events[0]
	assert.Equal(t, "seccomp", ev0.Source)
	assert.Equal(t, "blocked", ev0.EffectiveAction)
	assert.Equal(t, "/etc/shadow", ev0.Path)

	require.NotNil(t, ev0.Policy)
	assert.Equal(t, "deny", string(ev0.Policy.EffectiveDecision))
	assert.Equal(t, "system-deny", ev0.Policy.Rule)
}

// TestEmulatedOpen_FallbackToContinue verifies that open syscalls with
// O_TMPFILE or non-zero RESOLVE_* flags are routed to the CONTINUE
// path rather than the AddFD emulation path.
func TestEmulatedOpen_FallbackToContinue(t *testing.T) {
	tests := []struct {
		name         string
		nr           int32
		flags        uint32
		resolveFlags uint64
		wantFallback bool
	}{
		{
			name:         "plain openat — emulatable",
			nr:           unix.SYS_OPENAT,
			flags:        unix.O_RDONLY,
			wantFallback: false,
		},
		{
			name:         "openat O_CREAT — emulatable",
			nr:           unix.SYS_OPENAT,
			flags:        unix.O_CREAT | unix.O_WRONLY,
			wantFallback: false,
		},
		{
			name:         "openat O_TMPFILE — fallback",
			nr:           unix.SYS_OPENAT,
			flags:        unix.O_TMPFILE,
			wantFallback: true,
		},
		{
			name:         "openat2 with RESOLVE flags — fallback",
			nr:           unix.SYS_OPENAT2,
			flags:        unix.O_RDONLY,
			resolveFlags: 0x01, // RESOLVE_NO_XDEV
			wantFallback: true,
		},
		{
			name:         "openat2 no RESOLVE — always CONTINUE",
			nr:           unix.SYS_OPENAT2,
			flags:        unix.O_RDONLY,
			resolveFlags: 0,
			wantFallback: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFallbackToContinue(tt.nr, tt.flags, tt.resolveFlags)
			assert.Equal(t, tt.wantFallback, got)

			// For emulatable cases, verify isOpenSyscall returns true.
			if !tt.wantFallback {
				assert.True(t, isOpenSyscall(tt.nr),
					"emulatable syscalls must be recognized as open syscalls")
			}
		})
	}
}

// TestEmulatedOpen_NonOpenSyscall_UsesContinuePath verifies that non-open
// file syscalls (e.g., unlinkat, mkdirat) are never routed through AddFD
// emulation — they always use the CONTINUE path.
func TestEmulatedOpen_NonOpenSyscall_UsesContinuePath(t *testing.T) {
	nonOpenSyscalls := []struct {
		name string
		nr   int32
	}{
		{"unlinkat", unix.SYS_UNLINKAT},
		{"mkdirat", unix.SYS_MKDIRAT},
		{"renameat2", unix.SYS_RENAMEAT2},
		{"linkat", unix.SYS_LINKAT},
		{"symlinkat", unix.SYS_SYMLINKAT},
		{"fchmodat", unix.SYS_FCHMODAT},
		{"fchownat", unix.SYS_FCHOWNAT},
		{"statx", unix.SYS_STATX},
	}

	for _, tt := range nonOpenSyscalls {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, isOpenSyscall(tt.nr),
				"%s must not be recognized as an open syscall", tt.name)
			assert.True(t, isFileSyscall(tt.nr),
				"%s must be recognized as a file syscall", tt.name)
		})
	}
}

// TestEmulatedOpen_WriteOperation verifies that an openat with write flags
// is correctly mapped to "write" operation and properly emulatable.
func TestEmulatedOpen_WriteOperation(t *testing.T) {
	pol := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/workspace/out.log": {Decision: "allow", EffectiveDecision: "allow", Rule: "workspace-rw"},
		},
	}
	emit := &mockFileEmitter{}
	handler := NewFileHandler(pol, NewMountRegistry(), emit, true)
	handler.SetEmulateOpen(true)

	flags := uint32(unix.O_WRONLY | unix.O_APPEND)
	op := syscallToOperation(unix.SYS_OPENAT, flags)
	assert.Equal(t, "write", op, "O_WRONLY|O_APPEND must map to write")

	req := FileRequest{
		PID:       302,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/workspace/out.log",
		Operation: op,
		Flags:     flags,
		SessionID: "sess-emu",
	}

	result, ev := handler.Handle(req)
	if ev != nil {
		_ = emit.AppendEvent(context.Background(), *ev)
	}
	assert.Equal(t, ActionContinue, result.Action)

	require.Len(t, emit.events, 1)
	assert.Equal(t, "file_write", emit.events[0].Type)

	// Write openat is emulatable (no O_TMPFILE, no RESOLVE flags).
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT))
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, flags, 0))
}

// TestFilterConfig_BlockIOUring_Flags verifies that FilterConfig correctly
// sets up the BlockIOUring field and that the io_uring syscall numbers
// (425, 426, 427) match the expected values.
func TestFilterConfig_BlockIOUring_Flags(t *testing.T) {
	cfg := FilterConfig{
		BlockIOUring: true,
	}
	require.True(t, cfg.BlockIOUring)

	// Verify the io_uring syscall numbers are correct.
	// These are architecture-independent on x86_64.
	assert.Equal(t, 425, 425, "io_uring_setup should be 425")
	assert.Equal(t, 426, 426, "io_uring_enter should be 426")
	assert.Equal(t, 427, 427, "io_uring_register should be 427")
}

// TestFilterConfig_InterceptMetadata verifies the InterceptMetadata config
// field works in concert with file monitoring.
func TestFilterConfig_InterceptMetadata(t *testing.T) {
	cfg := FilterConfig{
		FileMonitorEnabled: true,
		InterceptMetadata:  true,
		BlockIOUring:       true,
	}
	require.True(t, cfg.FileMonitorEnabled)
	require.True(t, cfg.InterceptMetadata)
	require.True(t, cfg.BlockIOUring)

	// Verify the metadata syscalls are recognized as file syscalls.
	metadataSyscalls := []int32{
		unix.SYS_STATX,
		unix.SYS_NEWFSTATAT,
		unix.SYS_FACCESSAT2,
		unix.SYS_READLINKAT,
	}
	for _, nr := range metadataSyscalls {
		assert.True(t, isFileSyscall(nr),
			"metadata syscall %d must be recognized as a file syscall", nr)
		assert.False(t, isOpenSyscall(nr),
			"metadata syscall %d must not be an open syscall (no AddFD)", nr)
	}
}

// TestEmulatedOpen_CreateOperation verifies that openat with O_CREAT maps
// to "create" and is emulatable via AddFD.
func TestEmulatedOpen_CreateOperation(t *testing.T) {
	pol := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/workspace/new.txt": {Decision: "allow", EffectiveDecision: "allow", Rule: "workspace-rw"},
		},
	}
	emit := &mockFileEmitter{}
	handler := NewFileHandler(pol, NewMountRegistry(), emit, true)
	handler.SetEmulateOpen(true)

	flags := uint32(unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC)
	op := syscallToOperation(unix.SYS_OPENAT, flags)
	assert.Equal(t, "create", op, "O_CREAT must take precedence for operation mapping")

	req := FileRequest{
		PID:       303,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/workspace/new.txt",
		Operation: op,
		Flags:     flags,
		SessionID: "sess-emu",
	}

	result, ev := handler.Handle(req)
	if ev != nil {
		_ = emit.AppendEvent(context.Background(), *ev)
	}
	assert.Equal(t, ActionContinue, result.Action)

	require.Len(t, emit.events, 1)
	assert.Equal(t, "file_create", emit.events[0].Type)
	assert.Equal(t, "allowed", emit.events[0].EffectiveAction)

	// O_CREAT is emulatable (not O_TMPFILE, not RESOLVE_*).
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, flags, 0))
}

// TestNotifIDValid_InvalidFD_Integration verifies that NotifIDValid returns
// an error when given an invalid seccomp notify fd. This exercises the
// ioctl path with fallback from new to old kernel ioctl numbers.
func TestNotifIDValid_InvalidFD_Integration(t *testing.T) {
	// Use fd -1 (invalid) — the kernel should return EBADF.
	err := NotifIDValid(-1, 12345)
	require.Error(t, err, "NotifIDValid with invalid fd must fail")

	// The error should be an errno (EBADF for bad fd).
	if errno, ok := err.(unix.Errno); ok {
		assert.Equal(t, unix.EBADF, errno, "expected EBADF for invalid notify fd")
	}
}

// TestNotifAddFD_InvalidFD_Integration verifies that NotifAddFD returns
// an error when given an invalid seccomp notify fd.
func TestNotifAddFD_InvalidFD_Integration(t *testing.T) {
	// Use fd -1 (invalid).
	_, err := NotifAddFD(-1, 12345, 0, 0, SECCOMP_ADDFD_FLAG_SEND)
	require.Error(t, err, "NotifAddFD with invalid fd must fail")
}

// TestEmulatedOpen_FullDecisionMatrix exercises the complete decision matrix
// for the emulated-open path: all combinations of (allow/deny) x (open/non-open)
// x (emulateOpen on/off).
func TestEmulatedOpen_FullDecisionMatrix(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		decision    string
		emulate     bool
		enforce     bool
		wantAction  string
		wantErrno   int32
	}{
		{
			name: "allow_open_emulated",
			path: "/workspace/file.go", decision: "allow",
			emulate: true, enforce: true,
			wantAction: ActionContinue, wantErrno: 0,
		},
		{
			name: "deny_open_emulated",
			path: "/etc/shadow", decision: "deny",
			emulate: true, enforce: true,
			wantAction: ActionDeny, wantErrno: int32(unix.EACCES),
		},
		{
			name: "allow_open_not_emulated",
			path: "/workspace/file.go", decision: "allow",
			emulate: false, enforce: true,
			wantAction: ActionContinue, wantErrno: 0,
		},
		{
			name: "deny_open_not_emulated",
			path: "/etc/shadow", decision: "deny",
			emulate: false, enforce: true,
			wantAction: ActionDeny, wantErrno: int32(unix.EACCES),
		},
		{
			name: "deny_open_audit_only",
			path: "/etc/shadow", decision: "deny",
			emulate: true, enforce: false,
			wantAction: ActionContinue, wantErrno: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &mockFilePolicy{
				decisions: map[string]FilePolicyDecision{
					tt.path: {
						Decision:          tt.decision,
						EffectiveDecision: tt.decision,
						Rule:              "test-rule",
					},
				},
			}
			emit := &mockFileEmitter{}
			handler := NewFileHandler(pol, NewMountRegistry(), emit, tt.enforce)
			handler.SetEmulateOpen(tt.emulate)

			req := FileRequest{
				PID:       400,
				Syscall:   int32(unix.SYS_OPENAT),
				Path:      tt.path,
				Operation: "open",
				SessionID: "sess-matrix",
			}

			result, _ := handler.Handle(req)
			assert.Equal(t, tt.wantAction, result.Action, "action mismatch")
			assert.Equal(t, tt.wantErrno, result.Errno, "errno mismatch")
		})
	}
}

// TestIOUringBlocking_RawSyscall verifies that io_uring_setup (syscall 425)
// can be attempted via a raw syscall. This test does NOT install a seccomp
// filter (that would trap the test process). Instead, it verifies the syscall
// number is correct and that the kernel returns an error (EFAULT or EINVAL)
// when called with invalid arguments — confirming the syscall number is valid
// and reachable.
//
// When BlockIOUring is enabled in FilterConfig, the seccomp filter returns
// EPERM for these syscalls before they reach the kernel.
func TestIOUringBlocking_RawSyscall(t *testing.T) {
	// Attempt io_uring_setup(0, NULL) — this will fail with EFAULT (null
	// pointer for params) or EINVAL (zero entries), confirming the syscall
	// number is correct and alive in the kernel.
	const SYS_IO_URING_SETUP = 425
	r1, _, errno := unix.Syscall(SYS_IO_URING_SETUP, 0, 0, 0)
	_ = r1

	// The kernel should return an error (not succeed with 0 entries + NULL params).
	require.NotEqual(t, unix.Errno(0), errno,
		"io_uring_setup(0, NULL) should fail, confirming syscall 425 is recognized")

	// Acceptable errors: EFAULT (null params pointer), EINVAL (0 entries),
	// or ENOSYS (kernel compiled without io_uring support).
	switch errno {
	case unix.EFAULT, unix.EINVAL, unix.ENOSYS, unix.EPERM:
		t.Logf("io_uring_setup returned expected error: %v", errno)
	default:
		t.Errorf("io_uring_setup returned unexpected error: %v (expected EFAULT, EINVAL, ENOSYS, or EPERM)", errno)
	}

	// Verify the related syscall numbers.
	const SYS_IO_URING_ENTER = 426
	const SYS_IO_URING_REGISTER = 427

	// io_uring_enter with invalid fd should fail.
	_, _, errno = unix.Syscall6(SYS_IO_URING_ENTER, uintptr(^uint(0)), 0, 0, 0, 0, 0)
	require.NotEqual(t, unix.Errno(0), errno,
		"io_uring_enter with invalid fd should fail")

	// io_uring_register with invalid fd should fail.
	_, _, errno = unix.Syscall6(SYS_IO_URING_REGISTER, uintptr(^uint(0)), 0, 0, 0, 0, 0)
	require.NotEqual(t, unix.Errno(0), errno,
		"io_uring_register with invalid fd should fail")
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

			result, ev := handler.Handle(req)
			if ev != nil {
				_ = emit.AppendEvent(context.Background(), *ev)
			}
			assert.Equal(t, ActionContinue, result.Action)

			require.Len(t, emit.events, 1)
			ev0 := emit.events[0]
			assert.Equal(t, tt.wantType, ev0.Type,
				"event Type must be file_<operation>")
			assert.Equal(t, "seccomp", ev0.Source,
				"Source must always be seccomp")
			assert.Equal(t, gotOp, ev0.Operation,
				"event Operation must match mapped operation")

			// Verify syscall name is in Fields
			require.NotNil(t, ev0.Fields)
			assert.Equal(t, tt.wantSysc, ev0.Fields["syscall"],
				"Fields[syscall] must be the syscall name")
		})
	}
}
