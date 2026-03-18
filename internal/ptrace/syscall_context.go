//go:build linux

package ptrace

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptraceGetSyscallInfo is the ptrace request for PTRACE_GET_SYSCALL_INFO (Linux 5.3+).
const ptraceGetSyscallInfo = 0x420e

// SyscallEntryInfo holds syscall number and arguments extracted at entry time.
type SyscallEntryInfo struct {
	Nr   int
	Args [6]uint64
}

// SyscallContext wraps entry info with lazy full-register access.
// Handlers use Info.Args for the fast allow path and call Regs() only
// when they need to modify registers (deny/redirect).
type SyscallContext struct {
	Info   SyscallEntryInfo
	tid    int
	tracer *Tracer
	regs   Regs
	loaded bool
}

// Regs lazily loads the full register set. Cached after first call.
func (sc *SyscallContext) Regs() (Regs, error) {
	if !sc.loaded {
		var err error
		sc.regs, err = sc.tracer.getRegs(sc.tid)
		if err != nil {
			return nil, err
		}
		sc.loaded = true
	}
	return sc.regs, nil
}

// ptraceSyscallInfo mirrors the entry variant of struct ptrace_syscall_info (Linux 5.3+).
// The kernel struct is a union; we only use the entry fields (op==1).
// We request ptraceSyscallInfoSize bytes; the kernel writes min(requested, actual).
type ptraceSyscallInfo struct {
	Op                 uint8
	_                  [3]byte // pad
	Arch               uint32
	InstructionPointer uint64
	StackPointer       uint64
	// Union: entry variant fields follow
	EntryNr   uint64
	EntryArgs [6]uint64
}

const ptraceSyscallInfoSize = int(unsafe.Sizeof(ptraceSyscallInfo{}))

// getSyscallEntryInfo retrieves syscall entry info via PTRACE_GET_SYSCALL_INFO.
func (t *Tracer) getSyscallEntryInfo(tid int) (*SyscallEntryInfo, error) {
	var info ptraceSyscallInfo
	_, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		uintptr(tid),
		uintptr(ptraceSyscallInfoSize),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: %w", errno)
	}
	if info.Op != 1 {
		return nil, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: unexpected op %d (want entry=1)", info.Op)
	}
	return &SyscallEntryInfo{
		Nr:   int(info.EntryNr),
		Args: info.EntryArgs,
	}, nil
}

// buildSyscallContext constructs a SyscallContext for a stopped tracee.
// Uses PTRACE_GET_SYSCALL_INFO when available, falls back to full getRegs.
func (t *Tracer) buildSyscallContext(tid int) (*SyscallContext, error) {
	sc := &SyscallContext{tid: tid, tracer: t}

	if t.hasSyscallInfo {
		info, err := t.getSyscallEntryInfo(tid)
		if err == nil {
			sc.Info = *info
			return sc, nil
		}
		// Fallback to full register read
	}

	regs, err := t.getRegs(tid)
	if err != nil {
		return nil, err
	}
	sc.Info = SyscallEntryInfo{Nr: regs.SyscallNr()}
	for i := 0; i < 6; i++ {
		sc.Info.Args[i] = regs.Arg(i)
	}
	sc.regs = regs
	sc.loaded = true
	return sc, nil
}

// probePtraceSyscallInfo returns true if PTRACE_GET_SYSCALL_INFO is supported.
// Probes with pid=0 (invalid): supported kernels return ESRCH, unsupported return EIO/EINVAL.
func probePtraceSyscallInfo() bool {
	var info ptraceSyscallInfo
	_, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		0,
		uintptr(ptraceSyscallInfoSize),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	)
	return errno == unix.ESRCH
}
