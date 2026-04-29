//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"log/slog"
	"unsafe"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// DetectSupport reports whether seccomp user-notify is available on this host.
func DetectSupport() error {
	api, err := seccomp.GetAPI()
	if err != nil {
		return fmt.Errorf("get seccomp api: %w", err)
	}
	if api < 6 {
		return fmt.Errorf("seccomp API version %d lacks user notify", api)
	}
	return nil
}

// Filter encapsulates a loaded seccomp user-notify filter and its notify fd.
type Filter struct {
	fd               seccomp.ScmpFd
	blockList        map[uint32]seccompkg.OnBlockAction
	blockedFamilyMap map[uint64]seccompkg.BlockedFamily
}

func (f *Filter) Close() error {
	if f == nil || f.fd < 0 {
		return nil
	}
	return unix.Close(int(f.fd))
}

// BlockListMap returns a copy of the block-list dispatch map (syscall nr → action)
// for consumers that need to route notifications. Used by the notify handler
// to distinguish block-listed syscalls from file/unix/signal/metadata ones.
func (f *Filter) BlockListMap() map[uint32]seccompkg.OnBlockAction {
	if f == nil || len(f.blockList) == 0 {
		return nil
	}
	out := make(map[uint32]seccompkg.OnBlockAction, len(f.blockList))
	for k, v := range f.blockList {
		out[k] = v
	}
	return out
}

// BlockedFamilyMap returns a copy of the per-family dispatch map
// (key = (syscall<<32)|family → BlockedFamily) for consumers that need to
// route log/log_and_kill family notifications. Used by the notify handler.
func (f *Filter) BlockedFamilyMap() map[uint64]seccompkg.BlockedFamily {
	if f == nil || len(f.blockedFamilyMap) == 0 {
		return nil
	}
	out := make(map[uint64]seccompkg.BlockedFamily, len(f.blockedFamilyMap))
	for k, v := range f.blockedFamilyMap {
		out[k] = v
	}
	return out
}

// InstallFilter installs a user-notify seccomp filter on the current process
// that traps socket-related syscalls. Caller must run the notify loop on fd.
func InstallFilter() (*Filter, error) {
	if err := DetectSupport(); err != nil {
		return nil, err
	}

	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}

	trap := seccomp.ActNotify
	rules := []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(unix.SYS_SOCKET),
		seccomp.ScmpSyscall(unix.SYS_CONNECT),
		seccomp.ScmpSyscall(unix.SYS_BIND),
		seccomp.ScmpSyscall(unix.SYS_LISTEN),
		seccomp.ScmpSyscall(unix.SYS_SENDTO),
	}
	for _, sc := range rules {
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add rule %v: %w", sc, err)
		}
	}

	if err := filt.Load(); err != nil {
		return nil, err
	}
	fd, err := filt.GetNotifFd()
	if err != nil {
		return nil, err
	}
	return &Filter{fd: fd}, nil
}

// ReadSockaddr reads up to maxLen bytes from the tracee at addrPtr.
func ReadSockaddr(pid int, addrPtr uint64, addrLen uint64) ([]byte, error) {
	if addrPtr == 0 || addrLen == 0 {
		return nil, errors.New("empty sockaddr")
	}
	maxLen := int(addrLen)
	if maxLen > 128 {
		maxLen = 128
	}
	local := make([]byte, maxLen)
	liov := unix.Iovec{Base: &local[0], Len: uint64(maxLen)}
	riov := unix.RemoteIovec{Base: uintptr(addrPtr), Len: maxLen}
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return nil, err
	}
	return local[:n], nil
}

// ParseSockaddr extracts AF_UNIX path/abstract from raw sockaddr bytes.
func ParseSockaddr(raw []byte) (path string, abstract bool, err error) {
	if len(raw) < 2 {
		return "", false, errors.New("short sockaddr")
	}
	family := *(*uint16)(unsafe.Pointer(&raw[0]))
	if family != unix.AF_UNIX {
		return "", false, fmt.Errorf("unexpected family %d", family)
	}
	data := raw[2:]
	if len(data) == 0 {
		return "", false, errors.New("empty sa_data")
	}
	if data[0] == 0 {
		end := 1
		for end < len(data) && data[end] != 0 {
			end++
		}
		return "@" + string(data[1:end]), true, nil
	}
	end := 0
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[:end]), false, nil
}

// NotifFD returns the raw notify fd for polling.
func (f *Filter) NotifFD() int {
	return int(f.fd)
}

// Receive receives one seccomp notification.
func (f *Filter) Receive() (*seccomp.ScmpNotifReq, error) {
	return seccomp.NotifReceive(f.fd)
}

// Respond replies to a notification.
func (f *Filter) Respond(reqID uint64, allow bool, errno int32) error {
	if allow {
		return NotifRespondContinue(int(f.fd), reqID)
	}
	if errno <= 0 {
		errno = int32(unix.EPERM) // normalize invalid errno to avoid unanswered notification
	}
	return NotifRespondDeny(int(f.fd), reqID, errno)
}

// Context holds the data needed to evaluate a trapped syscall.
type Context struct {
	PID     int
	Syscall seccomp.ScmpSyscall
	AddrPtr uint64
	AddrLen uint64
}

// ExtractContext maps a notify request to our simplified context.
func ExtractContext(req *seccomp.ScmpNotifReq) Context {
	return Context{
		PID:     int(req.Pid),
		Syscall: req.Data.Syscall,
		AddrPtr: req.Data.Args[1], // for connect/bind/sendto: arg1 = sockaddr
		AddrLen: req.Data.Args[2],
	}
}

// ErrUnsupported indicates user-notify not available.
var ErrUnsupported = fmt.Errorf("seccomp user-notify unsupported")

// ErrNotifyBlocked indicates that seccomp filter installation succeeded but the
// notification receive ioctl is blocked by a container security policy (e.g.,
// AppArmor), making the notification handler unable to operate.
var ErrNotifyBlocked = fmt.Errorf("seccomp notification ioctl blocked")

// ProbeNotifReceive tests whether seccomp notification ioctls are usable on a
// seccomp notify fd. Some container runtimes (e.g., AppArmor's
// containers-default profile) allow installing seccomp filters but block the
// notification ioctls, causing all intercepted syscalls to fail.
//
// Uses SECCOMP_IOCTL_NOTIF_ID_VALID as a lightweight probe — this is a pure
// syscall (no CGo) that returns ENOENT when the ioctl works (ID 0 is never
// valid), or EPERM when blocked by a security policy.
// Returns nil if ioctls are usable, or ErrNotifyBlocked if not.
func ProbeNotifReceive(notifFD int) error {
	err := NotifIDValid(notifFD, 0)
	if err == nil {
		return nil // unexpected but means ioctl works
	}
	// ENOENT: ID 0 not valid — expected, ioctl works.
	// EINVAL: kernel doesn't recognize this ioctl variant — ioctl
	//         dispatch itself works (AppArmor would return EPERM before
	//         the kernel reaches argument validation).
	if err == unix.ENOENT || err == unix.EINVAL {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrNotifyBlocked, err)
}

// InstallOrWarn installs filter or returns ErrUnsupported.
func InstallOrWarn() (*Filter, error) {
	if err := DetectSupport(); err != nil {
		return nil, ErrUnsupported
	}
	return InstallFilter()
}

// FilterConfig configures the seccomp filter to install.
type FilterConfig struct {
	UnixSocketEnabled  bool
	ExecveEnabled      bool
	FileMonitorEnabled bool
	InterceptMetadata  bool  // statx, newfstatat, faccessat2, readlinkat
	BlockIOUring       bool  // io_uring_setup/enter/register → EPERM
	BlockedSyscalls    []int // syscall numbers to block; action controlled by OnBlockAction
	BlockedFamilies    []seccompkg.BlockedFamily
	OnBlockAction      seccompkg.OnBlockAction
}

// DefaultFilterConfig returns config for unix socket monitoring only.
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   nil,
	}
}

// InstallFilterWithConfig installs a seccomp filter based on config.
// Unix socket syscalls get user-notify, blocked syscalls get kill.
func InstallFilterWithConfig(cfg FilterConfig) (*Filter, error) {
	if err := DetectSupport(); err != nil {
		return nil, err
	}

	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}

	// Enable SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel 6.0+).
	// When active, non-fatal signals (including Go's ~10ms SIGURG preemption)
	// cannot interrupt seccomp_do_user_notification, preventing ERESTARTSYS loops.
	// The compile-time #error in seccomp_version_check.go guarantees the
	// libseccomp headers are >=2.6 and SetWaitKill is not a silent no-op.
	// If ProbeWaitKillable reports the kernel supports it but SetWaitKill
	// still fails, something is unexpected — warn loudly so operators can
	// investigate. Load() retry at the end of this function handles the
	// case where SetWaitKill succeeds but the kernel rejects the flag at
	// load time (custom/vendor kernels).
	waitKillSet := false
	if ProbeWaitKillable() {
		if err := filt.SetWaitKill(true); err != nil {
			slog.Warn("seccomp: WaitKillable unexpectedly unavailable despite kernel 6.0+; falling back to SIGURG signal mask only",
				"error", err)
		} else {
			waitKillSet = true
		}
	}

	// Unix socket monitoring via user-notify
	if cfg.UnixSocketEnabled {
		trap := seccomp.ActNotify
		rules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_SOCKET),
			seccomp.ScmpSyscall(unix.SYS_CONNECT),
			seccomp.ScmpSyscall(unix.SYS_BIND),
			seccomp.ScmpSyscall(unix.SYS_LISTEN),
			seccomp.ScmpSyscall(unix.SYS_SENDTO),
		}
		for _, sc := range rules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add notify rule %v: %w", sc, err)
			}
		}
	}

	// Execve interception via user-notify
	if cfg.ExecveEnabled {
		trap := seccomp.ActNotify
		execRules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_EXECVE),
			seccomp.ScmpSyscall(unix.SYS_EXECVEAT),
		}
		for _, sc := range execRules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add execve rule %v: %w", sc, err)
			}
		}
	}

	// File I/O monitoring via user-notify
	if cfg.FileMonitorEnabled {
		trap := seccomp.ActNotify
		fileRules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_OPENAT),
			seccomp.ScmpSyscall(unix.SYS_OPENAT2),
			seccomp.ScmpSyscall(unix.SYS_UNLINKAT),
			seccomp.ScmpSyscall(unix.SYS_MKDIRAT),
			seccomp.ScmpSyscall(unix.SYS_RENAMEAT2),
			seccomp.ScmpSyscall(unix.SYS_LINKAT),
			seccomp.ScmpSyscall(unix.SYS_SYMLINKAT),
			seccomp.ScmpSyscall(unix.SYS_FCHMODAT),
			seccomp.ScmpSyscall(unix.SYS_FCHOWNAT),
		}
		for _, sc := range fileRules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add file monitor rule %v: %w", sc, err)
			}
		}
		for _, sc := range legacyFileSyscallList() {
			if err := filt.AddRule(seccomp.ScmpSyscall(sc), trap); err != nil {
				return nil, fmt.Errorf("add legacy file rule %v: %w", sc, err)
			}
		}
	}

	// Metadata syscalls via user-notify (when intercept_metadata is enabled)
	if cfg.InterceptMetadata {
		trap := seccomp.ActNotify
		metadataRules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_STATX),
			seccomp.ScmpSyscall(unix.SYS_NEWFSTATAT),
			seccomp.ScmpSyscall(unix.SYS_FACCESSAT2),
			seccomp.ScmpSyscall(unix.SYS_READLINKAT),
		}
		for _, sc := range metadataRules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add metadata rule %v: %w", sc, err)
			}
		}
	}

	// mknodat is always included with file monitoring (create-category)
	if cfg.FileMonitorEnabled {
		trap := seccomp.ActNotify
		if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_MKNODAT), trap); err != nil {
			return nil, fmt.Errorf("add mknodat rule: %w", err)
		}
	}

	// Blocked syscalls — action controlled by OnBlockAction.
	// Silent modes (errno, kill) stay on the kernel fast path.
	// Auditable modes (log, log_and_kill) use ActNotify and the
	// notify handler routes via BlockListMap().
	action, ok := seccompkg.ParseOnBlock(string(cfg.OnBlockAction))
	if !ok {
		slog.Warn("seccomp: unknown on_block action; degrading to errno",
			"value", cfg.OnBlockAction)
	}
	blockListMap := map[uint32]seccompkg.OnBlockAction{}
	blockedFamilyMap := map[uint64]seccompkg.BlockedFamily{}
	switch action {
	case seccompkg.OnBlockErrno:
		errnoAction := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
		for _, nr := range cfg.BlockedSyscalls {
			if err := filt.AddRule(seccomp.ScmpSyscall(nr), errnoAction); err != nil {
				return nil, fmt.Errorf("add blocked errno rule %v: %w", nr, err)
			}
		}
	case seccompkg.OnBlockKill:
		for _, nr := range cfg.BlockedSyscalls {
			if err := filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActKillProcess); err != nil {
				return nil, fmt.Errorf("add blocked kill rule %v: %w", nr, err)
			}
		}
	case seccompkg.OnBlockLog, seccompkg.OnBlockLogAndKill:
		for _, nr := range cfg.BlockedSyscalls {
			if err := filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActNotify); err != nil {
				return nil, fmt.Errorf("add blocked notify rule %v: %w", nr, err)
			}
			blockListMap[uint32(nr)] = action
		}
	}

	// Per-socket-family blocking on socket(2) and socketpair(2).
	// libseccomp action-precedence (KILL > TRAP > ERRNO > … > NOTIFY) ensures
	// these conditional rules take priority over the unconditional ActNotify
	// rule on socket(2) added by UnixSocketEnabled.
	for _, bf := range cfg.BlockedFamilies {
		cond := seccomp.ScmpCondition{
			Argument: 0,
			Op:       seccomp.CompareEqual,
			Operand1: uint64(bf.Family),
		}
		famAction, err := familyToScmpAction(bf.Action)
		if err != nil {
			slog.Warn("seccomp: skipping family rule with unknown action",
				"family", bf.Name, "action", bf.Action, "error", err)
			continue
		}
		installed := true
		for _, sc := range []int{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
			if addErr := filt.AddRuleConditional(
				seccomp.ScmpSyscall(sc), famAction, []seccomp.ScmpCondition{cond},
			); addErr != nil {
				slog.Warn("seccomp: failed to add family rule; family skipped",
					"family", bf.Name, "syscall", sc, "error", addErr)
				installed = false
			}
		}
		if installed && (bf.Action == seccompkg.OnBlockLog || bf.Action == seccompkg.OnBlockLogAndKill) {
			blockedFamilyMap[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
			blockedFamilyMap[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
		}
	}

	// Block io_uring to prevent seccomp bypass.
	// Skip syscalls already in BlockedSyscalls to avoid duplicate rule errors.
	if cfg.BlockIOUring {
		blockedSet := make(map[int]bool, len(cfg.BlockedSyscalls))
		for _, nr := range cfg.BlockedSyscalls {
			blockedSet[nr] = true
		}
		ioUringBlock := seccomp.ActErrno.SetReturnCode(int16(1)) // EPERM = 1
		ioUringSyscalls := []int{
			unix.SYS_IO_URING_SETUP,
			unix.SYS_IO_URING_ENTER,
			unix.SYS_IO_URING_REGISTER,
		}
		for _, nr := range ioUringSyscalls {
			if blockedSet[nr] {
				continue // already blocked via BlockedSyscalls
			}
			if err := filt.AddRule(seccomp.ScmpSyscall(nr), ioUringBlock); err != nil {
				return nil, fmt.Errorf("add io_uring block rule %v: %w", nr, err)
			}
		}
	}

	if err := loadWithRetryOnWaitKillFailure(filt, waitKillSet, filt.Load); err != nil {
		return nil, err
	}
	fd, err := filt.GetNotifFd()
	if err != nil {
		// If no notify rules, fd will be -1, which is fine
		if !cfg.UnixSocketEnabled && !cfg.ExecveEnabled && !cfg.FileMonitorEnabled {
			return &Filter{fd: -1, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap}, nil
		}
		return nil, err
	}
	return &Filter{fd: fd, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap}, nil
}

// familyToScmpAction maps an OnBlockAction to the libseccomp action used
// for per-family conditional rules on socket(2)/socketpair(2).
func familyToScmpAction(a seccompkg.OnBlockAction) (seccomp.ScmpAction, error) {
	switch a {
	case seccompkg.OnBlockErrno:
		return seccomp.ActErrno.SetReturnCode(int16(unix.EAFNOSUPPORT)), nil
	case seccompkg.OnBlockKill:
		return seccomp.ActKillProcess, nil
	case seccompkg.OnBlockLog, seccompkg.OnBlockLogAndKill:
		return seccomp.ActNotify, nil
	default:
		return seccomp.ActAllow, fmt.Errorf("unknown family block action %q", a)
	}
}

// loadWithRetryOnWaitKillFailure loads a seccomp filter and, if the load
// fails with WaitKill set, clears WaitKill and retries once. This handles
// custom or vendor kernels that report 6.0+ but reject
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV at filter load time.
//
// loadFn is injected so tests can simulate Load() failures deterministically.
// Production call sites pass `filt.Load`.
func loadWithRetryOnWaitKillFailure(filt *seccomp.ScmpFilter, waitKillSet bool, loadFn func() error) error {
	err := loadFn()
	if err == nil {
		return nil
	}
	if !waitKillSet {
		return err
	}
	slog.Warn("seccomp: WaitKillable rejected at filter load time; falling back to SIGURG signal mask only",
		"error", err)
	if clearErr := filt.SetWaitKill(false); clearErr != nil {
		return err
	}
	return loadFn()
}
