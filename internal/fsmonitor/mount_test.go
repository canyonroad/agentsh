//go:build !windows

package fsmonitor

import (
	"slices"
	"testing"
	"time"
)

// TestBuildMountOptions_DefaultPermissionsAndCaching locks in the #369 #2
// FUSE<->clone deadlock fix. The workspace mount MUST carry the
// default_permissions option (so the kernel serves a child's chdir/path-walk
// permission check locally instead of round-tripping FUSE_ACCESS to this
// in-process daemon mid-forkExec) AND MUST set non-zero Entry/Attr timeouts
// (so that local check is served from cache with no GETATTR/LOOKUP round-trip
// in the same forkExec window). Dropping either reopens the deadlock on kernel
// 6.12.x under sustained FUSE-on load.
func TestBuildMountOptions_DefaultPermissionsAndCaching(t *testing.T) {
	opts := buildMountOptions(nil)

	if !slices.Contains(opts.MountOptions.Options, "default_permissions") {
		t.Errorf("mount Options must contain default_permissions (#369 #2); got %v", opts.MountOptions.Options)
	}
	if opts.EntryTimeout == nil || *opts.EntryTimeout != time.Second {
		t.Errorf("EntryTimeout must be 1s (#369 #2); got %v", opts.EntryTimeout)
	}
	if opts.AttrTimeout == nil || *opts.AttrTimeout != time.Second {
		t.Errorf("AttrTimeout must be 1s (#369 #2); got %v", opts.AttrTimeout)
	}

	// Existing identity options must be preserved by the refactor.
	if opts.MountOptions.FsName != "agentsh-workspace" {
		t.Errorf("FsName = %q, want agentsh-workspace", opts.MountOptions.FsName)
	}
	if opts.MountOptions.Name != "agentsh" {
		t.Errorf("Name = %q, want agentsh", opts.MountOptions.Name)
	}
	if !opts.MountOptions.AllowOther {
		t.Error("AllowOther must stay true")
	}
}

// TestBuildMountOptions_MaxBackground confirms the optional kernel async-queue
// knob is still wired from hooks, and left at the go-fuse default when unset.
func TestBuildMountOptions_MaxBackground(t *testing.T) {
	if mb := buildMountOptions(nil).MountOptions.MaxBackground; mb != 0 {
		t.Errorf("MaxBackground with nil hooks = %d, want 0 (go-fuse default)", mb)
	}
	if mb := buildMountOptions(&Hooks{MaxBackground: 64}).MountOptions.MaxBackground; mb != 64 {
		t.Errorf("MaxBackground = %d, want 64", mb)
	}
}
