//go:build !linux

package kernelinstall

// Install on non-Linux platforms either fails closed (ModeOn) or skips
// gracefully.  The signal-filter relay that Install performs requires Linux
// AF_UNIX SCM_RIGHTS semantics and seccomp; there is no portable equivalent.
func Install(p InstallParams) (Result, error) {
	if p.Mode == ModeOn {
		return Result{
			Action: ResultFailClosed,
			Reason: "kernelinstall is not supported on this platform; mode=on requires Linux",
		}, nil
	}
	return Result{
		Action: ResultSkip,
		Reason: "kernelinstall is not supported on this platform",
	}, nil
}
