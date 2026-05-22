package config

// WaitKillableFilterCompositionTriggersBug returns true when the effective
// seccomp filter for the given config would install notify rules from both
// the socket family (unix_socket) AND the file/metadata family
// (file_monitor or intercept_metadata). This is the known-bad combination
// from issue #369: on kernels that lie about WAIT_KILLABLE_RECV support
// (e.g. 6.12.67 with ProcessVMReadv=ENOSYS), the wrapped process is killed
// by signal during the post-execve syscall storm when this combination is
// present together with WAIT_KILLABLE_RECV.
//
// The function operates on effective config (resolving FileMonitor.*
// defaults exactly as buildSeccompWrapperConfig does) so that the gotcha
// in the issue's bisection table — file_monitor.enabled=false with
// enforce_without_fuse=true still installs metadata notify rules — is
// caught correctly.
func WaitKillableFilterCompositionTriggersBug(cfg SandboxSeccompConfig) bool {
	socketFamily := cfg.UnixSocket.Enabled

	fmDefault := FileMonitorBoolWithDefault(cfg.FileMonitor.EnforceWithoutFUSE, false)
	fileFamily := FileMonitorBoolWithDefault(cfg.FileMonitor.Enabled, false) ||
		FileMonitorBoolWithDefault(cfg.FileMonitor.InterceptMetadata, fmDefault)

	return socketFamily && fileFamily
}
