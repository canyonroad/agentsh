//go:build linux && cgo

package signal

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// SignalFilterConfig configures which signal syscalls to intercept.
type SignalFilterConfig struct {
	Enabled  bool
	Syscalls []int
}

// DefaultSignalFilterConfig returns a config for intercepting all signal syscalls.
func DefaultSignalFilterConfig() SignalFilterConfig {
	return SignalFilterConfig{
		Enabled: true,
		Syscalls: []int{
			unix.SYS_KILL,
			unix.SYS_TGKILL,
			unix.SYS_TKILL,
			unix.SYS_RT_SIGQUEUEINFO,
			unix.SYS_RT_TGSIGQUEUEINFO,
		},
	}
}

// SignalFilter wraps a seccomp filter for signal syscall interception.
type SignalFilter struct {
	fd seccomp.ScmpFd
}

// SignalContext holds information extracted from a signal syscall.
type SignalContext struct {
	PID       int                  // PID of the process making the syscall
	Syscall   int                  // The syscall number (SYS_KILL, SYS_TGKILL, etc.)
	TargetPID int                  // Target PID of the signal
	TargetTID int                  // Target TID (for tgkill/tkill)
	Signal    int                  // The signal number being sent
}

// IsSignalSupportAvailable checks if seccomp user-notify is available (API >= 6).
func IsSignalSupportAvailable() bool {
	api, err := seccomp.GetAPI()
	if err != nil {
		return false
	}
	return api >= 6
}

// DetectSignalSupport returns an error if seccomp user-notify is not available.
func DetectSignalSupport() error {
	api, err := seccomp.GetAPI()
	if err != nil {
		return fmt.Errorf("get seccomp api: %w", err)
	}
	if api < 6 {
		return fmt.Errorf("seccomp API version %d lacks user notify (need >= 6)", api)
	}
	return nil
}

// InstallSignalFilter installs a user-notify seccomp filter for signal syscalls.
func InstallSignalFilter(cfg SignalFilterConfig) (*SignalFilter, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("signal filter not enabled in config")
	}

	if err := DetectSignalSupport(); err != nil {
		return nil, err
	}

	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("create seccomp filter: %w", err)
	}

	trap := seccomp.ActNotify
	for _, syscallNum := range cfg.Syscalls {
		sc := seccomp.ScmpSyscall(syscallNum)
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add rule for syscall %d: %w", syscallNum, err)
		}
	}

	if err := filt.Load(); err != nil {
		return nil, fmt.Errorf("load seccomp filter: %w", err)
	}

	fd, err := filt.GetNotifFd()
	if err != nil {
		return nil, fmt.Errorf("get notify fd: %w", err)
	}

	return &SignalFilter{fd: fd}, nil
}

// NotifFD returns the raw notify file descriptor for polling.
func (f *SignalFilter) NotifFD() int {
	if f == nil {
		return -1
	}
	return int(f.fd)
}

// Close closes the filter's notify file descriptor.
func (f *SignalFilter) Close() error {
	if f == nil || f.fd < 0 {
		return nil
	}
	return unix.Close(int(f.fd))
}

// Receive receives one seccomp notification.
func (f *SignalFilter) Receive() (*seccomp.ScmpNotifReq, error) {
	return seccomp.NotifReceive(f.fd)
}

// Respond replies to a notification with allow or deny.
func (f *SignalFilter) Respond(reqID uint64, allow bool, errno int32) error {
	resp := seccomp.ScmpNotifResp{ID: reqID}
	if allow {
		resp.Error = 0
		resp.Val = 0
		resp.Flags = seccomp.NotifRespFlagContinue
	} else {
		resp.Error = -errno
	}
	return seccomp.NotifRespond(f.fd, &resp)
}

// RespondWithValue replies to a notification with a specific return value.
func (f *SignalFilter) RespondWithValue(reqID uint64, val uint64, errno int32) error {
	resp := seccomp.ScmpNotifResp{
		ID:    reqID,
		Val:   val,
		Error: -errno,
	}
	return seccomp.NotifRespond(f.fd, &resp)
}

// ExtractSignalContext extracts signal information from a seccomp notify request.
// The syscall arguments vary by syscall:
//   - kill(pid, sig):           args[0]=pid, args[1]=sig
//   - tgkill(tgid, tid, sig):   args[0]=tgid, args[1]=tid, args[2]=sig
//   - tkill(tid, sig):          args[0]=tid, args[1]=sig
//   - rt_sigqueueinfo(tgid, sig, uinfo):    args[0]=tgid, args[1]=sig
//   - rt_tgsigqueueinfo(tgid, tid, sig, uinfo): args[0]=tgid, args[1]=tid, args[2]=sig
func ExtractSignalContext(req *seccomp.ScmpNotifReq) SignalContext {
	ctx := SignalContext{
		PID:     int(req.Pid),
		Syscall: int(req.Data.Syscall),
	}

	switch int(req.Data.Syscall) {
	case unix.SYS_KILL:
		// kill(pid_t pid, int sig)
		ctx.TargetPID = int(int32(req.Data.Args[0])) // Signed conversion for kill()
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_TGKILL:
		// tgkill(pid_t tgid, pid_t tid, int sig)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.TargetTID = int(req.Data.Args[1])
		ctx.Signal = int(req.Data.Args[2])

	case unix.SYS_TKILL:
		// tkill(pid_t tid, int sig)
		// For classification purposes, use TID as the target PID
		ctx.TargetTID = int(req.Data.Args[0])
		ctx.TargetPID = ctx.TargetTID // Use TID for classification
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_RT_SIGQUEUEINFO:
		// rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_RT_TGSIGQUEUEINFO:
		// rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.TargetTID = int(req.Data.Args[1])
		ctx.Signal = int(req.Data.Args[2])
	}

	return ctx
}

// IsProcessGroupSignal returns true if the signal targets a process group.
func (c *SignalContext) IsProcessGroupSignal() bool {
	// kill(0, sig) or kill(-pgid, sig)
	return c.TargetPID <= 0
}

// ProcessGroupID returns the process group ID for process group signals.
// Returns 0 for non-process-group signals.
func (c *SignalContext) ProcessGroupID() int {
	if c.TargetPID == 0 {
		return c.PID // Caller's process group
	}
	if c.TargetPID < 0 {
		return -c.TargetPID // Explicit process group
	}
	return 0 // Not a process group signal
}

// ErrSignalUnsupported indicates signal interception is not available.
var ErrSignalUnsupported = fmt.Errorf("signal interception unsupported on this platform")
