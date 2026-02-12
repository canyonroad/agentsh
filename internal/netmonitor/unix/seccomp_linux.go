//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"unsafe"

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
	fd seccomp.ScmpFd
}

func (f *Filter) Close() error {
	if f == nil || f.fd < 0 {
		return nil
	}
	return unix.Close(int(f.fd))
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

// InstallOrWarn installs filter or returns ErrUnsupported.
func InstallOrWarn() (*Filter, error) {
	if err := DetectSupport(); err != nil {
		return nil, ErrUnsupported
	}
	return InstallFilter()
}

// FilterConfig configures the seccomp filter to install.
type FilterConfig struct {
	UnixSocketEnabled bool
	ExecveEnabled     bool
	FileMonitorEnabled bool
	BlockedSyscalls   []int // syscall numbers to block with KILL
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
	}

	// Blocked syscalls via kill
	for _, nr := range cfg.BlockedSyscalls {
		sc := seccomp.ScmpSyscall(nr)
		if err := filt.AddRule(sc, seccomp.ActKillProcess); err != nil {
			return nil, fmt.Errorf("add kill rule %v: %w", sc, err)
		}
	}

	if err := filt.Load(); err != nil {
		return nil, err
	}
	fd, err := filt.GetNotifFd()
	if err != nil {
		// If no notify rules, fd will be -1, which is fine
		if !cfg.UnixSocketEnabled && !cfg.ExecveEnabled && !cfg.FileMonitorEnabled {
			return &Filter{fd: -1}, nil
		}
		return nil, err
	}
	return &Filter{fd: fd}, nil
}
