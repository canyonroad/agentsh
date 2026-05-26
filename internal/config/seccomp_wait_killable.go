package config

// UnixSocketNotifyEnabled reports whether the seccomp wrapper will install
// unix-socket (socket-family) USER_NOTIF rules based on config alone. It is
// the OR of sandbox.seccomp.unix_socket.enabled and an explicitly-true
// sandbox.unix_sockets.enabled, mirroring the wrapper's resolution in
// internal/api/wrap.go (a nil top-level flag contributes nothing here, matching
// that path; applyDefaults populates it in production).
//
// Centralised so the wait_killable filter-composition check, the wrap-init
// path, and the direct exec path all agree on the wrapper's filter shape
// instead of each re-deriving it from a single field. Issue #369: a
// top-level-only `sandbox.unix_sockets.enabled` made the composition check miss
// the socket family, short-circuit to "filter_composition_safe", and skip the
// behavioral WAIT_KILLABLE_RECV probe entirely.
func (c SandboxConfig) UnixSocketNotifyEnabled() bool {
	if c.Seccomp.UnixSocket.Enabled {
		return true
	}
	return c.UnixSockets.Enabled != nil && *c.UnixSockets.Enabled
}

// WaitKillableFilterCompositionTriggersBug returns true when the effective
// seccomp filter for the given config would install notify rules from both
// the socket family (unix_socket / top-level unix_sockets) AND the
// file/metadata family (file_monitor or intercept_metadata). This is the
// known-bad combination from issue #369: on kernels that lie about
// WAIT_KILLABLE_RECV support (e.g. 6.12.67 with ProcessVMReadv=ENOSYS), the
// wrapped process is killed by signal during the post-execve syscall storm
// when this combination is present together with WAIT_KILLABLE_RECV.
//
// It takes the whole SandboxConfig so socket-family detection uses the same
// OR the wrapper does (UnixSocketNotifyEnabled), and resolves FileMonitor.*
// defaults exactly as buildSeccompWrapperConfig does — so the gotcha in the
// issue's bisection table (file_monitor.enabled=false with
// enforce_without_fuse=true still installs metadata notify rules) is caught.
func WaitKillableFilterCompositionTriggersBug(cfg SandboxConfig) bool {
	socketFamily := cfg.UnixSocketNotifyEnabled()

	fm := cfg.Seccomp.FileMonitor
	fmDefault := FileMonitorBoolWithDefault(fm.EnforceWithoutFUSE, false)
	fileFamily := FileMonitorBoolWithDefault(fm.Enabled, false) ||
		FileMonitorBoolWithDefault(fm.InterceptMetadata, fmDefault)

	return socketFamily && fileFamily
}
