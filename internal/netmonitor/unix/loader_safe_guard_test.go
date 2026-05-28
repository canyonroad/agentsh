//go:build linux && cgo

package unix

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestFileHandler_LoaderSafeReadOverride verifies the #369 loader-safe guard:
// a policy that DENIES the dynamic loader's essential system reads must not
// prevent programs from starting under file_monitor. Read-only opens of
// loader-essential system paths are overridden to allow; writes to the same
// paths and reads of non-system paths are still denied.
func TestFileHandler_LoaderSafeReadOverride(t *testing.T) {
	denyAll := func(paths ...string) *mockFilePolicy {
		m := &mockFilePolicy{decisions: map[string]FilePolicyDecision{}}
		for _, p := range paths {
			m.decisions[p] = FilePolicyDecision{
				Decision: "deny", EffectiveDecision: "deny", Rule: "default-deny-files",
			}
		}
		return m
	}

	cases := []struct {
		name    string
		path    string
		op      string
		syscall int32
		flags   uint32
		want    string // ActionContinue or ActionDeny
	}{
		{"ld.so.cache read", "/etc/ld.so.cache", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY, ActionContinue},
		{"ld.so.preload read", "/etc/ld.so.preload", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY, ActionContinue},
		{"bare /lib dir open", "/lib", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY | unix.O_DIRECTORY, ActionContinue},
		{"bare /usr dir open", "/usr", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY | unix.O_DIRECTORY, ActionContinue},
		{"libc.so read", "/usr/lib/x86_64-linux-gnu/libc.so.6", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY, ActionContinue},
		{"system stat", "/lib64", "stat", int32(unix.SYS_NEWFSTATAT), 0, ActionContinue},
		// Mutating op on a system path is NOT overridden — still denied.
		{"write to /lib", "/lib/evil.so", "write", int32(unix.SYS_OPENAT), unix.O_WRONLY | unix.O_CREAT, ActionDeny},
		// Read of a non-system path is NOT overridden — still denied.
		{"non-system read", "/home/user/secret", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY, ActionDeny},
		{"etc non-loader read", "/etc/shadow", "open", int32(unix.SYS_OPENAT), unix.O_RDONLY, ActionDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := denyAll(tc.path)
			handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true) // enforce=true
			res, _ := handler.Handle(FileRequest{
				PID: 1234, Syscall: tc.syscall, Path: tc.path, Operation: tc.op, Flags: tc.flags, SessionID: "sess-1",
			})
			if res.Action != tc.want {
				t.Errorf("Handle(%s %s) action = %s, want %s", tc.op, tc.path, res.Action, tc.want)
			}
		})
	}

	// An operator's EXPLICIT deny rule on a system subpath must still be honored
	// — only the catch-all default deny is overridden (matches ptrace).
	t.Run("explicit deny on system subpath is honored", func(t *testing.T) {
		policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/usr/lib/app/secret.key": {Decision: "deny", EffectiveDecision: "deny", Rule: "deny-app-secrets"},
		}}
		handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
		res, _ := handler.Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/usr/lib/app/secret.key",
			Operation: "open", Flags: unix.O_RDONLY, SessionID: "sess-1",
		})
		if res.Action != ActionDeny {
			t.Errorf("explicit (non-catch-all) deny on a system subpath must be honored, got %s", res.Action)
		}
	})

	// Bare system directory nodes are overridden regardless of which deny rule
	// fired — these are universally read-safe and the wrapped shell can't start
	// without them. Matches the ptrace enforcer; matches erans's working policy.
	t.Run("dir-node override applies to non-catch-all deny", func(t *testing.T) {
		// e.g. an explicit deny-proc-sys rule denying /proc/self — still overridden
		// for the bare directory node (contents like /proc/self/maps are not).
		policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/proc/self": {Decision: "deny", EffectiveDecision: "deny", Rule: "deny-proc-sys"},
		}}
		res, _ := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true).Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/proc/self", Operation: "open",
			Flags: unix.O_RDONLY | unix.O_DIRECTORY, SessionID: "sess-1",
		})
		if res.Action != ActionContinue {
			t.Errorf("/proc/self bare dir-node must be overridden even on an explicit deny rule, got %s", res.Action)
		}
	})

	// Dir-node CONTENTS are NOT covered by the exact-match override — a deny of
	// /proc/self/maps still stands (exact match doesn't catch subpaths).
	t.Run("dir-node override does NOT cover subpath contents", func(t *testing.T) {
		policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/proc/self/maps": {Decision: "deny", EffectiveDecision: "deny", Rule: "deny-proc-sys"},
		}}
		res, _ := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true).Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/proc/self/maps", Operation: "open",
			Flags: unix.O_RDONLY, SessionID: "sess-1",
		})
		if res.Action != ActionDeny {
			t.Errorf("contents of a system dir-node must remain policy-controlled, got %s", res.Action)
		}
	})

	// Writes to a system dir node are still enforced.
	t.Run("write to dir node is still denied", func(t *testing.T) {
		policy := denyAll("/etc/new.conf")
		res, _ := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true).Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/etc/new.conf", Operation: "write",
			Flags: unix.O_WRONLY | unix.O_CREAT, SessionID: "sess-1",
		})
		if res.Action != ActionDeny {
			t.Errorf("write to /etc/new.conf must stay denied, got %s", res.Action)
		}
	})

	// An overridden read must be recorded as a shadow-deny — the only forensic
	// trace that policy denied but file_monitor allowed it.
	t.Run("override emits shadow-deny event", func(t *testing.T) {
		policy := denyAll("/lib")
		res, ev := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true).Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/lib", Operation: "open",
			Flags: unix.O_RDONLY | unix.O_DIRECTORY, SessionID: "sess-1",
		})
		if res.Action != ActionContinue {
			t.Fatalf("expected override to allow, got %s", res.Action)
		}
		if ev == nil {
			t.Fatal("expected an audit event for the override")
		}
		if v, ok := ev.Fields["shadow_deny"]; !ok || v != true {
			t.Errorf("override event must carry shadow_deny=true; got %v (ok=%v)", v, ok)
		}
	})

	// In audit-only mode (enforce=false) the deny short-circuits to allow BEFORE
	// the override runs, so it must NOT be marked as a loader-safe shadow-deny.
	t.Run("enforce=false does not take the override path", func(t *testing.T) {
		policy := denyAll("/lib")
		res, ev := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, false).Handle(FileRequest{
			PID: 1234, Syscall: int32(unix.SYS_OPENAT), Path: "/lib", Operation: "open",
			Flags: unix.O_RDONLY | unix.O_DIRECTORY, SessionID: "sess-1",
		})
		if res.Action != ActionContinue {
			t.Fatalf("audit-only should allow, got %s", res.Action)
		}
		if ev != nil {
			if v, ok := ev.Fields["shadow_deny"]; ok && v == true {
				t.Error("audit-only allow must not be marked as a loader-safe shadow-deny override")
			}
		}
	})
}

func TestIsSystemDirNode(t *testing.T) {
	// Kernel / process essentials — universally read-safe; override applies.
	safe := []string{"/", "/dev", "/dev/pts", "/dev/fd", "/proc", "/proc/self", "/proc/thread-self", "/sys", "/etc"}
	for _, p := range safe {
		if !isSystemDirNode(p) {
			t.Errorf("isSystemDirNode(%q) = false, want true", p)
		}
	}
	// Exact-match only — subpaths must NOT match. Plus paths intentionally left
	// OUT of the override (operator-policy territory: /tmp, /var, /etc/ssl, ...).
	unsafe := []string{
		"/proc/self/maps", "/etc/secret", "/etc/ssl/private", "/home/user",
		"/devnull", "/tmpfoo", "/var/log/secret", "/proc/1", "",
		"/tmp", "/var", "/var/tmp", "/run", "/etc/ssl", "/etc/ssl/certs", "/etc/ca-certificates",
	}
	for _, p := range unsafe {
		if isSystemDirNode(p) {
			t.Errorf("isSystemDirNode(%q) = true, want false (exact-match-only / outside narrowed set)", p)
		}
	}
}

func TestIsLoaderSafeSystemPath(t *testing.T) {
	safe := []string{"/lib", "/lib/x", "/usr", "/usr/lib/libc.so.6", "/etc/ld.so.cache", "/etc/ld.so.conf.d/x.conf", "/bin", "/sbin"}
	for _, p := range safe {
		if !isLoaderSafeSystemPath(p) {
			t.Errorf("isLoaderSafeSystemPath(%q) = false, want true", p)
		}
	}
	unsafe := []string{"/home/user", "/etc/shadow", "/etc/ld.so.cache.evil", "/libfoo", "/", "/var/lib", "/tmp", "/opt", "/opt/foo"}
	for _, p := range unsafe {
		if isLoaderSafeSystemPath(p) {
			t.Errorf("isLoaderSafeSystemPath(%q) = true, want false", p)
		}
	}
}
