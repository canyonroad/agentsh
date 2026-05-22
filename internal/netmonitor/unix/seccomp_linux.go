//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	socketRules      []seccompkg.SocketRule
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

// SocketRules returns a copy of notify-mode socket tuple rules retained for
// later notification dispatch. Kernel-only errno/kill rules are not included.
func (f *Filter) SocketRules() []seccompkg.SocketRule {
	if f == nil || len(f.socketRules) == 0 {
		return nil
	}
	return cloneSocketRules(f.socketRules)
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
	WriteOnlyOpens     bool  // trap only write/create-style open/openat calls
	BlockIOUring       bool  // io_uring_setup/enter/register → EPERM
	BlockedSyscalls    []int // syscall numbers to block; action controlled by OnBlockAction
	BlockedFamilies    []seccompkg.BlockedFamily
	SocketRules        []seccompkg.SocketRule
	OnBlockAction      seccompkg.OnBlockAction

	// WaitKillable, when non-nil, overrides the legacy kernel-version
	// probe for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV. Nil keeps the
	// legacy ProbeWaitKillable() fallback for direct/test invocations
	// where the server hasn't computed a decision. Issue #369.
	WaitKillable *bool

	// WaitKillableSource is a stable string identifying why WaitKillable
	// was chosen ("config", "kernel_unsupported", "filter_composition_safe",
	// "behavioral_probe", "behavioral_probe_error"). Forwarded from the
	// server so the per-exec "seccomp: filter loaded" log line can record
	// it. Issue #369.
	WaitKillableSource string
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

	// Surface raw kernel errnos from filt.Load() instead of letting
	// libseccomp mask every failure as ECANCELED. Without this, a kernel
	// rejection (EINVAL for unknown flags, EBUSY for listener conflicts,
	// EPERM/EACCES for missing privileges, ...) is indistinguishable from
	// any other "system failure beyond the control of the library" — which
	// is exactly the diagnostic dead-end hit on Runloop devboxes in #282.
	// Best-effort: if libseccomp is too old (<2.5) we continue without
	// raw errnos and rely on the masked ECANCELED.
	if rcErr := filt.SetRawRC(true); rcErr != nil {
		slog.Debug("seccomp: SetRawRC unsupported; kernel errnos will be masked as ECANCELED",
			"error", rcErr)
	}

	// Per-category rule counts surfaced in the pre-load diagnostic
	// snapshot below. Useful when narrowing down which feature triggers a
	// kernel rejection on hostile devbox kernels (issue #282 EFAULT) — a
	// single "install seccomp filter: bad address" line is far less
	// actionable than "filter had N rules across these categories with
	// these flags."
	ruleCounts := map[string]int{}

	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel >=5.19) is applied
	// at filter load time via the raw seccomp(2) syscall in
	// loadFilterWithRetry below — NOT through libseccomp's SetWaitKill,
	// whose silent-no-op behavior on pre-2.6 headers motivated this
	// design. The flag value is a kernel ABI constant in x/sys/unix.
	// See docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md.
	var wantWaitKill bool
	if cfg.WaitKillable != nil {
		wantWaitKill = *cfg.WaitKillable
	} else {
		// Legacy fallback for direct/test invocations: when no explicit
		// decision is provided, fall back to the kernel-version probe.
		// Server-side decisions (issue #369) always set WaitKillable, so
		// this path only runs when the wrapper is invoked outside the
		// normal server flow.
		wantWaitKill = ProbeWaitKillable()
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
		ruleCounts["unix_socket"] = len(rules)
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
		ruleCounts["execve"] = len(execRules)
	}

	// File I/O monitoring via user-notify
	if cfg.FileMonitorEnabled {
		added, err := installFileMonitorRules(filt, seccomp.ActNotify, cfg.WriteOnlyOpens)
		if err != nil {
			return nil, err
		}
		ruleCounts["file_monitor"] = added
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
		ruleCounts["metadata"] = len(metadataRules)
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
	socketRules := []seccompkg.SocketRule{}
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
	ruleCounts["blocked_syscalls"] = len(cfg.BlockedSyscalls)

	// Per-socket tuple blocking on socket(2) and socketpair(2).
	// These narrow family/type/protocol rules are installed before broad
	// family-only rules so later dispatch can evaluate the most specific
	// configured tuples first. Kernel action precedence still determines the
	// result when actions differ, preserving existing blocked-family behavior.
	socketRules, socketRulesAdded, err := installSocketRulesConditional(filt, cfg.SocketRules)
	if err != nil {
		return nil, err
	}
	ruleCounts["socket_rules"] = socketRulesAdded

	// Per-socket-family blocking on socket(2) and socketpair(2).
	// libseccomp action-precedence (KILL > TRAP > ERRNO > … > NOTIFY) ensures
	// these conditional rules take priority over the unconditional ActNotify
	// rule on socket(2) added by UnixSocketEnabled.
	familyRulesAdded := 0
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
			} else {
				familyRulesAdded++
			}
		}
		if installed && (bf.Action == seccompkg.OnBlockLog || bf.Action == seccompkg.OnBlockLogAndKill) {
			blockedFamilyMap[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
			blockedFamilyMap[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
		}
	}
	ruleCounts["blocked_families"] = familyRulesAdded

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
		ioUringRulesAdded := 0
		for _, nr := range ioUringSyscalls {
			if blockedSet[nr] {
				continue // already blocked via BlockedSyscalls
			}
			if err := filt.AddRule(seccomp.ScmpSyscall(nr), ioUringBlock); err != nil {
				return nil, fmt.Errorf("add io_uring block rule %v: %w", nr, err)
			}
			ioUringRulesAdded++
		}
		ruleCounts["io_uring_block"] = ioUringRulesAdded
	}

	// Pre-load diagnostic snapshot. Logged at DEBUG so it stays out of
	// stderr captured by integration tests on the success path.
	snapshot := filterDiagnosticFields(filt, cfg, wantWaitKill, ruleCounts)
	slog.Debug("seccomp: filter snapshot before Load", snapshot...)

	// Export the filter to BPF bytes, then load it ourselves via
	// seccomp(2). This bypasses libseccomp's seccomp_load() so the
	// WAIT_KILLABLE_RECV flag can be set as a kernel ABI bit
	// regardless of the linked libseccomp version (see design doc).
	// We must export BEFORE Release; afterwards filt's C context is
	// gone but we still own the BPF bytes.
	prog, err := exportFilterBPF(filt)
	if err != nil {
		return nil, fmt.Errorf("export seccomp filter: %w", err)
	}
	filt.Release()

	rawFd, gotWaitKill, err := loadFilterWithRetry(prog, wantWaitKill, snapshot)
	if err != nil {
		return nil, err
	}
	// rawFd is the listener fd from SECCOMP_FILTER_FLAG_NEW_LISTENER.
	// loadFilterWithRetry returns >=0 on success; the legacy
	// "no notify rules, fd=-1" path is unreachable because we always
	// pass NEW_LISTENER (kernel returns the fd even for filters
	// without ActNotify rules — it's just never readable).
	libVer := libseccompRuntimeVersion()
	// kernel_probe_supports reflects the raw kernel probe, independent of
	// the resolved decision in wait_killable. Logging both lets an
	// operator see why an exec saw a given flag (wait_killable_source)
	// alongside what the kernel itself reports. ProbeWaitKillable is
	// cheap (a Uname()+parse) so calling it twice per filter install is
	// fine. Issue #369.
	slog.Info("seccomp: filter loaded",
		"fd", rawFd,
		"wait_killable", gotWaitKill,
		"wait_killable_source", cfg.WaitKillableSource,
		"kernel_probe_supports", ProbeWaitKillable(),
		"libseccomp_runtime", libVer)

	if !filterConfigNeedsNotifyFD(cfg, blockListMap, blockedFamilyMap, socketRules) {
		// Close the now-unused listener fd. The filter is still
		// installed; only the userspace dispatch handle is dropped.
		_ = unix.Close(rawFd)
		return &Filter{fd: -1, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
	}
	return &Filter{fd: seccomp.ScmpFd(rawFd), blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
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

type fileMonitorRuleAdder interface {
	AddRule(seccomp.ScmpSyscall, seccomp.ScmpAction) error
	AddRuleConditional(seccomp.ScmpSyscall, seccomp.ScmpAction, []seccomp.ScmpCondition) error
}

func installFileMonitorRules(adder fileMonitorRuleAdder, action seccomp.ScmpAction, writeOnlyOpens bool) (int, error) {
	added := 0
	addRule := func(sc seccomp.ScmpSyscall, label string) error {
		if err := adder.AddRule(sc, action); err != nil {
			return fmt.Errorf("add %s rule %v: %w", label, sc, err)
		}
		added++
		return nil
	}

	if writeOnlyOpens {
		n, err := installFlaggedOpenNotifyRules(adder, seccomp.ScmpSyscall(unix.SYS_OPENAT), 2, action)
		added += n
		if err != nil {
			return added, fmt.Errorf("add openat write-only rules: %w", err)
		}
		// openat2 stores flags in the user-space open_how struct, which seccomp
		// BPF cannot dereference. Keep trapping it rather than allowing writes to
		// bypass policy.
		if err := addRule(seccomp.ScmpSyscall(unix.SYS_OPENAT2), "file monitor"); err != nil {
			return added, err
		}
	} else {
		for _, sc := range []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_OPENAT),
			seccomp.ScmpSyscall(unix.SYS_OPENAT2),
		} {
			if err := addRule(sc, "file monitor"); err != nil {
				return added, err
			}
		}
	}

	for _, sc := range []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(unix.SYS_UNLINKAT),
		seccomp.ScmpSyscall(unix.SYS_MKDIRAT),
		seccomp.ScmpSyscall(unix.SYS_RENAMEAT2),
		seccomp.ScmpSyscall(unix.SYS_LINKAT),
		seccomp.ScmpSyscall(unix.SYS_SYMLINKAT),
		seccomp.ScmpSyscall(unix.SYS_FCHMODAT),
		seccomp.ScmpSyscall(unix.SYS_FCHOWNAT),
		seccomp.ScmpSyscall(unix.SYS_MKNODAT),
	} {
		if err := addRule(sc, "file monitor"); err != nil {
			return added, err
		}
	}

	flaggedLegacyOpen := map[int32]bool{}
	for _, sc := range legacyFlaggedOpenSyscallList() {
		flaggedLegacyOpen[sc] = true
		if writeOnlyOpens {
			n, err := installFlaggedOpenNotifyRules(adder, seccomp.ScmpSyscall(sc), 1, action)
			added += n
			if err != nil {
				return added, fmt.Errorf("add legacy open write-only rules %v: %w", sc, err)
			}
		} else if err := addRule(seccomp.ScmpSyscall(sc), "legacy file"); err != nil {
			return added, err
		}
	}
	for _, sc := range legacyFileSyscallList() {
		if flaggedLegacyOpen[sc] {
			continue
		}
		if err := addRule(seccomp.ScmpSyscall(sc), "legacy file"); err != nil {
			return added, err
		}
	}

	return added, nil
}

func installFlaggedOpenNotifyRules(adder fileMonitorRuleAdder, sc seccomp.ScmpSyscall, flagsArg uint, action seccomp.ScmpAction) (int, error) {
	added := 0
	for _, condition := range openWriteFlagConditions(flagsArg) {
		if err := adder.AddRuleConditional(sc, action, []seccomp.ScmpCondition{condition}); err != nil {
			return added, fmt.Errorf("add conditional rule for syscall %d: %w", sc, err)
		}
		added++
	}
	return added, nil
}

func openWriteFlagConditions(flagsArg uint) []seccomp.ScmpCondition {
	return []seccomp.ScmpCondition{
		maskedOpenFlagCondition(flagsArg, unix.O_ACCMODE, unix.O_WRONLY),
		maskedOpenFlagCondition(flagsArg, unix.O_ACCMODE, unix.O_RDWR),
		maskedOpenFlagCondition(flagsArg, unix.O_CREAT, unix.O_CREAT),
		maskedOpenFlagCondition(flagsArg, unix.O_TRUNC, unix.O_TRUNC),
		maskedOpenFlagCondition(flagsArg, unix.O_APPEND, unix.O_APPEND),
		maskedOpenFlagCondition(flagsArg, unix.O_TMPFILE, unix.O_TMPFILE),
	}
}

func maskedOpenFlagCondition(argument uint, mask, value int) seccomp.ScmpCondition {
	return seccomp.ScmpCondition{
		Argument: argument,
		Op:       seccomp.CompareMaskedEqual,
		Operand1: uint64(mask),
		Operand2: uint64(value),
	}
}

type conditionalRuleAdder interface {
	AddRuleConditional(seccomp.ScmpSyscall, seccomp.ScmpAction, []seccomp.ScmpCondition) error
}

func installSocketRulesConditional(adder conditionalRuleAdder, rules []seccompkg.SocketRule) ([]seccompkg.SocketRule, int, error) {
	retained := []seccompkg.SocketRule{}
	rulesAdded := 0
	for _, rule := range rules {
		action, err := familyToScmpAction(rule.Action)
		if err != nil {
			slog.Warn("seccomp: skipping socket rule with unknown action",
				"rule", rule.Name, "family", rule.FamilyName, "action", rule.Action, "error", err)
			continue
		}
		added, addErr := installSocketRuleConditional(adder, rule, action)
		rulesAdded += added
		if addErr != nil {
			if added > 0 {
				return nil, rulesAdded, fmt.Errorf("partial socket rule install for %q: %w", rule.Name, addErr)
			}
			return nil, rulesAdded, fmt.Errorf("add socket rule %q: %w", rule.Name, addErr)
		}
		if socketRuleUsesNotify(rule) {
			retained = append(retained, cloneSocketRule(rule))
		}
	}
	if len(retained) == 0 {
		return nil, rulesAdded, nil
	}
	return retained, rulesAdded, nil
}

func installSocketRuleConditional(adder conditionalRuleAdder, rule seccompkg.SocketRule, action seccomp.ScmpAction) (int, error) {
	conditions := socketRuleConditions(rule)
	added := 0
	for _, sc := range []int{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		if err := adder.AddRuleConditional(seccomp.ScmpSyscall(sc), action, conditions); err != nil {
			return added, fmt.Errorf("add conditional rule for syscall %d: %w", sc, err)
		}
		added++
	}
	return added, nil
}

func socketRuleConditions(rule seccompkg.SocketRule) []seccomp.ScmpCondition {
	conditions := []seccomp.ScmpCondition{
		{
			Argument: 0,
			Op:       seccomp.CompareEqual,
			Operand1: uint64(rule.Family),
		},
	}
	if rule.Type != nil {
		conditions = append(conditions, seccomp.ScmpCondition{
			Argument: 1,
			Op:       seccomp.CompareMaskedEqual,
			Operand1: uint64(seccompkg.SocketTypeMask),
			Operand2: uint64(*rule.Type),
		})
	}
	if rule.Protocol != nil {
		conditions = append(conditions, seccomp.ScmpCondition{
			Argument: 2,
			Op:       seccomp.CompareEqual,
			Operand1: uint64(*rule.Protocol),
		})
	}
	return conditions
}

func notifySocketRules(rules []seccompkg.SocketRule) []seccompkg.SocketRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]seccompkg.SocketRule, 0, len(rules))
	for _, rule := range rules {
		if socketRuleUsesNotify(rule) {
			out = append(out, cloneSocketRule(rule))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func socketRuleUsesNotify(rule seccompkg.SocketRule) bool {
	return rule.Action == seccompkg.OnBlockLog || rule.Action == seccompkg.OnBlockLogAndKill
}

func cloneSocketRules(rules []seccompkg.SocketRule) []seccompkg.SocketRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]seccompkg.SocketRule, len(rules))
	for i, rule := range rules {
		out[i] = cloneSocketRule(rule)
	}
	return out
}

func cloneSocketRule(rule seccompkg.SocketRule) seccompkg.SocketRule {
	if rule.Type != nil {
		typ := *rule.Type
		rule.Type = &typ
	}
	if rule.Protocol != nil {
		protocol := *rule.Protocol
		rule.Protocol = &protocol
	}
	return rule
}

func filterConfigNeedsNotifyFD(cfg FilterConfig, blockListMap map[uint32]seccompkg.OnBlockAction, blockedFamilyMap map[uint64]seccompkg.BlockedFamily, socketRules []seccompkg.SocketRule) bool {
	return cfg.UnixSocketEnabled ||
		cfg.ExecveEnabled ||
		cfg.FileMonitorEnabled ||
		cfg.InterceptMetadata ||
		len(blockListMap) > 0 ||
		len(blockedFamilyMap) > 0 ||
		len(socketRules) > 0
}

// appendSnapshot returns a new slice that prepends snapshot's fields to
// extra, used to embed the pre-Load diagnostic fields inline in a
// failure-path WARN entry without copying the snapshot at every call
// site. Returning a fresh slice avoids aliasing the caller's snapshot
// when several WARN entries fire in the same process (retry path).
func appendSnapshot(snapshot []any, extra ...any) []any {
	out := make([]any, 0, len(snapshot)+len(extra))
	out = append(out, snapshot...)
	out = append(out, extra...)
	return out
}

// errnoString returns a short stable string identifying the errno class
// of err (e.g., "EFAULT", "EINVAL"), or "non-errno" if err is not a
// syscall.Errno. Used in structured log fields so log scrapers and
// engineers can search on the symbolic name rather than the localized
// "bad address" message.
func errnoString(err error) string {
	var en unix.Errno
	if !errors.As(err, &en) {
		return "non-errno"
	}
	switch en {
	case unix.EINVAL:
		return "EINVAL"
	case unix.EFAULT:
		return "EFAULT"
	case unix.EBUSY:
		return "EBUSY"
	case unix.EPERM:
		return "EPERM"
	case unix.EACCES:
		return "EACCES"
	case unix.ENOMEM:
		return "ENOMEM"
	case unix.ENOSYS:
		return "ENOSYS"
	case unix.ECANCELED:
		return "ECANCELED"
	case unix.ESRCH:
		return "ESRCH"
	}
	return fmt.Sprintf("errno=%d", int(en))
}

// filterDiagnosticFields builds the structured slog field list capturing
// the filter context state just before Load() is invoked: libseccomp
// version + API level, kernel release, the rule-count breakdown by
// category, the set of flags about to be applied to the seccomp(2)
// syscall, and the calling process's prior seccomp state from
// /proc/self/status (the unforgeable signal that distinguishes a clean
// first install from a nested-install on top of an inherited filter,
// per issue #282).
//
// The caller logs the slice at DEBUG just before Load (so the snapshot
// is available when the user enables debug logging), and embeds it
// inline in the WARN entry on Load failure (so a single visible line is
// enough to triage). Returning fields rather than calling slog directly
// avoids logging at INFO on the success path — which polluted stderr
// captured by integration tests in v0.19.2-rc1 and broke their `tail
// -n 1` assertions on the wrapped command's output.
func filterDiagnosticFields(filt *seccomp.ScmpFilter, cfg FilterConfig, waitKillSet bool, ruleCounts map[string]int) []any {
	libMaj, libMin, libMicro := seccomp.GetLibraryVersion()
	libVer := fmt.Sprintf("%d.%d.%d", libMaj, libMin, libMicro)

	apiLevel, apiErr := seccomp.GetAPI()
	apiStr := fmt.Sprintf("%d", apiLevel)
	if apiErr != nil {
		apiStr = "unavailable"
	}

	var kernel string
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err == nil {
		kernel = unix.ByteSliceToString(utsname.Release[:])
	}

	// libseccomp-golang sets SCMP_FLTATR_CTL_TSYNC = 1 in NewFilter() with
	// no exported getter; it is enabled when the kernel supports it. We
	// surface "default(NewFilter)" to make it explicit in the snapshot
	// rather than implying it was independently chosen.
	tsync := "default(NewFilter)"
	nnp := "unknown"
	if v, err := filt.GetNoNewPrivsBit(); err == nil {
		nnp = fmt.Sprintf("%t", v)
	}
	rawRC := "unknown"
	if v, err := filt.GetRawRC(); err == nil {
		rawRC = fmt.Sprintf("%t", v)
	}

	total := 0
	for _, n := range ruleCounts {
		total += n
	}

	procState := readSelfSeccompState()
	procStateStr := "unreadable"
	if procState.Present {
		procStateStr = fmt.Sprintf("mode=%d filter_count=%d", procState.Mode, procState.FilterCount)
	}
	pid := os.Getpid()
	ppid := os.Getppid()
	parentComm := readProcComm(ppid)
	selfComm := readProcComm(pid)

	return []any{
		"libseccomp_version", libVer,
		"libseccomp_api", apiStr,
		"kernel_release", kernel,
		"self_pid", pid,
		"self_comm", selfComm,
		"parent_pid", ppid,
		"parent_comm", parentComm,
		"caller_seccomp_state", procStateStr,
		"attr_tsync", tsync,
		"attr_no_new_privs", nnp,
		"attr_raw_rc", rawRC,
		"attr_wait_killable_recv", waitKillSet,
		"rules_total", total,
		"rules_unix_socket", ruleCounts["unix_socket"],
		"rules_execve", ruleCounts["execve"],
		"rules_file_monitor", ruleCounts["file_monitor"],
		"rules_metadata", ruleCounts["metadata"],
		"rules_blocked_syscalls", ruleCounts["blocked_syscalls"],
		"rules_blocked_families", ruleCounts["blocked_families"],
		"rules_socket_rules", ruleCounts["socket_rules"],
		"rules_io_uring_block", ruleCounts["io_uring_block"],
		"cfg_unix_socket_enabled", cfg.UnixSocketEnabled,
		"cfg_execve_enabled", cfg.ExecveEnabled,
		"cfg_file_monitor_enabled", cfg.FileMonitorEnabled,
		"cfg_intercept_metadata", cfg.InterceptMetadata,
		"cfg_write_only_opens", cfg.WriteOnlyOpens,
		"cfg_block_io_uring", cfg.BlockIOUring,
	}
}

// libseccompRuntimeVersion returns the version of libseccomp that is
// actually linked at runtime (not the build-time headers). Used in the
// post-load startup log so docker matrix tests can confirm what
// userspace they are exercising.
func libseccompRuntimeVersion() string {
	major, minor, micro := seccomp.GetLibraryVersion()
	return fmt.Sprintf("%d.%d.%d", major, minor, micro)
}
