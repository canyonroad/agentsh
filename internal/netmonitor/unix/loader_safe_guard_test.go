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
}

func TestIsLoaderSafeSystemPath(t *testing.T) {
	safe := []string{"/lib", "/lib/x", "/usr", "/usr/lib/libc.so.6", "/etc/ld.so.cache", "/etc/ld.so.conf.d/x.conf", "/bin", "/sbin", "/opt/foo"}
	for _, p := range safe {
		if !isLoaderSafeSystemPath(p) {
			t.Errorf("isLoaderSafeSystemPath(%q) = false, want true", p)
		}
	}
	unsafe := []string{"/home/user", "/etc/shadow", "/etc/ld.so.cache.evil", "/libfoo", "/", "/var/lib", "/tmp"}
	for _, p := range unsafe {
		if isLoaderSafeSystemPath(p) {
			t.Errorf("isLoaderSafeSystemPath(%q) = true, want false", p)
		}
	}
}
