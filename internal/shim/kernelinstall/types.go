package kernelinstall

import "fmt"

// InstallParams holds everything Install needs to contact the server and
// launch the kernel-filter wrapper.
type InstallParams struct {
	ServerBaseURL string
	SessionID     string
	APIKey        string
	Mode          Mode
	RealShell     string
	ShellArgs     []string
	Env           []string
	CallerUID     int
}

// Result is returned by Install to tell the caller what to do next.
type Result struct {
	// Action says whether the caller should exec, skip, or abort.
	Action ResultAction

	// ExecPath / ExecArgs / ExecEnv are set when Action == ResultExec.
	// The caller should replace its process image with this command.
	ExecPath string
	ExecArgs []string
	ExecEnv  []string

	// WrapperExitCode is the exit code of the wrapper process when
	// Action == ResultExec (i.e. after cmd.Wait returns).
	WrapperExitCode int

	// Reason is a human-readable explanation for ResultSkip /
	// ResultFailClosed to aid debugging.
	Reason string
}

// ResultAction describes what Install's caller should do.
type ResultAction int

const (
	// ResultSkip means no kernel filters were installed; the caller should
	// fall through to its normal (unfiltered) execution path.
	ResultSkip ResultAction = iota

	// ResultExec means the wrapper binary ran and the caller should exec
	// ExecPath with ExecArgs / ExecEnv (the wrapper already set up the
	// seccomp filter in the child).
	ResultExec

	// ResultFailClosed means installation was required (Mode == ModeOn)
	// but failed; the caller must abort rather than run the command
	// without filters.
	ResultFailClosed
)

// ErrNotSupported is returned on non-Linux platforms.
var ErrNotSupported = fmt.Errorf("kernelinstall: not supported on this platform")
