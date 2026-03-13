//go:build linux

package ptrace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ExecHandler evaluates execve policy.
type ExecHandler interface {
	HandleExecve(ctx context.Context, ec ExecContext) ExecResult
}

// ExecContext carries execve information for policy evaluation.
type ExecContext struct {
	PID       int
	ParentPID int
	Filename  string
	Argv      []string
	Truncated bool
	SessionID string
	Depth     int
}

// ExecResult carries the policy decision.
type ExecResult struct {
	Allow    bool
	Action   string // "continue", "deny", "redirect"
	Errno    int32
	Rule     string
	Reason   string
	StubPath string // for redirect: path to stub binary
}

// FileHandler evaluates file syscall policy.
type FileHandler interface {
	HandleFile(ctx context.Context, fc FileContext) FileResult
}

// FileContext carries file syscall information for policy evaluation.
type FileContext struct {
	PID       int
	SessionID string
	Syscall   int
	Path      string
	Path2     string
	Operation string
	Flags     int
}

// FileResult carries the file policy decision.
type FileResult struct {
	Allow        bool
	Action       string // "" (legacy), "allow", "deny", "redirect", "soft-delete"
	Errno        int32
	RedirectPath string // for redirect
	TrashDir     string // for soft-delete
}

// NetworkHandler evaluates network syscall policy.
type NetworkHandler interface {
	HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult
}

// NetworkContext carries network syscall information for policy evaluation.
type NetworkContext struct {
	PID       int
	SessionID string
	Syscall   int
	Family    int
	Address   string
	Port      int
	Operation string
}

// NetworkResult carries the network policy decision.
type NetworkResult struct {
	Allow        bool
	Action       string // "" (legacy), "allow", "deny", "redirect"
	Errno        int32
	RedirectAddr string // for redirect
	RedirectPort int    // for redirect
}

// SignalHandler evaluates signal delivery policy.
type SignalHandler interface {
	HandleSignal(ctx context.Context, sc SignalContext) SignalResult
}

// SignalContext carries signal delivery information for policy evaluation.
type SignalContext struct {
	PID       int
	SessionID string
	TargetPID int
	Signal    int
}

// SignalResult carries the signal policy decision.
type SignalResult struct {
	Allow          bool
	Errno          int32
	RedirectSignal int
}

// TracerConfig holds configuration for the ptrace tracer.
type TracerConfig struct {
	AttachMode       string
	TargetPID        int
	TargetPIDFile    string
	TraceExecve      bool
	TraceFile        bool
	TraceNetwork     bool
	TraceSignal      bool
	SeccompPrefilter bool
	MaxTracees       int
	MaxHoldMs        int
	OnAttachFailure  string
	ExecHandler      ExecHandler
	FileHandler      FileHandler
	NetworkHandler   NetworkHandler
	SignalHandler    SignalHandler
	Metrics          Metrics
}

// TraceeState tracks the state of a single traced thread.
type TraceeState struct {
	TID              int
	TGID             int
	ParentPID        int
	SessionID        string
	InSyscall        bool
	LastNr           int
	Attached         time.Time
	ParkedAt         time.Time
	PendingDenyErrno      int
	PendingFakeZero       bool  // force return value to 0 on syscall exit
	PendingReturnOverride int64 // force return value to this on syscall exit
	HasPendingReturn      bool  // whether PendingReturnOverride is active
	PendingInterrupt      bool
	IsVforkChild     bool
	SuppressInitialStop bool // suppress initial SIGSTOP from auto-trace
	PendingExecStubFD  int // fd injected for exec redirect; cleaned up on exec failure (-1 = none)
	PendingExecSavedFD int // fd that was displaced by stub fd; restored on exec failure (-1 = none)
	MemFD              int
}

type resumeRequest struct {
	TID   int
	Allow bool
	Errno int
}

// Tracer implements a ptrace-based syscall tracer.
type Tracer struct {
	cfg             TracerConfig
	metrics         Metrics
	processTree     *ProcessTree
	prefilterActive bool

	attachQueue chan int
	resumeQueue chan resumeRequest

	mu            sync.Mutex
	tracees       map[int]*TraceeState
	parkedTracees map[int]struct{}
	tgidScratch   map[int]*scratchPage

	stopped chan struct{}
}

// NewTracer creates a new ptrace tracer.
func NewTracer(cfg TracerConfig) *Tracer {
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = nopMetrics{}
	}
	return &Tracer{
		cfg:           cfg,
		metrics:       metrics,
		processTree:   NewProcessTree(),
		attachQueue:   make(chan int, 64),
		resumeQueue:   make(chan resumeRequest, 64),
		tracees:       make(map[int]*TraceeState),
		parkedTracees: make(map[int]struct{}),
		tgidScratch:   make(map[int]*scratchPage),
		stopped:       make(chan struct{}),
	}
}

// TraceeCount returns the number of currently traced threads.
func (t *Tracer) TraceeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tracees)
}

// AttachPID enqueues attachment to a process.
func (t *Tracer) AttachPID(pid int) error {
	t.attachQueue <- pid
	return nil
}

// ParkTracee marks a tracee as parked (awaiting async approval).
func (t *Tracer) ParkTracee(tid int) {
	t.mu.Lock()
	t.parkedTracees[tid] = struct{}{}
	if state, ok := t.tracees[tid]; ok {
		state.ParkedAt = time.Now()
	}
	t.mu.Unlock()
}

// Available returns whether ptrace tracing is available.
func (t *Tracer) Available() bool {
	return true
}

// Implementation returns "ptrace".
func (t *Tracer) Implementation() string {
	return "ptrace"
}

func (t *Tracer) ptraceOptions() int {
	opts := unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_TRACEEXIT |
		unix.PTRACE_O_EXITKILL

	if t.prefilterActive {
		opts |= unix.PTRACE_O_TRACESECCOMP
	} else {
		opts |= unix.PTRACE_O_TRACESYSGOOD
	}

	return opts
}

func (t *Tracer) getRegs(tid int) (Regs, error) {
	return getRegsArch(tid)
}

func (t *Tracer) setRegs(tid int, regs Regs) error {
	return setRegsArch(tid, regs)
}

// allowSyscall resumes the tracee, allowing the syscall to proceed.
func (t *Tracer) allowSyscall(tid int) {
	var err error
	if t.prefilterActive {
		err = unix.PtraceCont(tid, 0)
	} else {
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil && errors.Is(err, unix.ESRCH) {
		t.handleExit(tid)
	}
}

// denySyscall invalidates the current syscall and arranges for return value fixup.
func (t *Tracer) denySyscall(tid int, errno int) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid)
			return nil
		}
		return err
	}
	regs.SetSyscallNr(-1)
	if err := t.setRegs(tid, regs); err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid)
			return nil
		}
		t.mu.Lock()
		state := t.tracees[tid]
		tgid := tid
		if state != nil {
			tgid = state.TGID
		}
		t.mu.Unlock()
		unix.Tgkill(tgid, tid, unix.SIGKILL)
		return fmt.Errorf("deny failed, killed tid %d: %w", tid, err)
	}

	t.mu.Lock()
	if state, ok := t.tracees[tid]; ok {
		state.PendingDenyErrno = errno
		state.InSyscall = true
	}
	t.mu.Unlock()

	if err := unix.PtraceSyscall(tid, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid)
			return nil
		}
		return err
	}
	return nil
}

// resumeTracee resumes a tracee with an optional signal to deliver.
func (t *Tracer) resumeTracee(tid int, sig int) {
	if t.prefilterActive {
		unix.PtraceCont(tid, sig)
	} else {
		unix.PtraceSyscall(tid, sig)
	}
}

// ptraceListen calls PTRACE_LISTEN on the specified tid. In PTRACE_SEIZE
// mode, this keeps the tracee group-stopped while still allowing the tracer
// to receive ptrace events.
func ptraceListen(tid int) {
	unix.RawSyscall6(unix.SYS_PTRACE,
		uintptr(unix.PTRACE_LISTEN), uintptr(tid), 0, 0, 0, 0)
}

// resumeWithErrno resumes a tracee from EXIT/between-syscalls state,
// making the current or previous syscall appear to return the specified errno.
// Used in error paths after advancePastEntry or injection has consumed the
// original entry.
func (t *Tracer) resumeWithErrno(tid int, savedRegs Regs, errno int) {
	errRegs := savedRegs.Clone()
	errRegs.SetReturnValue(int64(-errno))
	t.setRegs(tid, errRegs)
	t.allowSyscall(tid)
}

// applyDenyFixup overwrites the syscall return value with -errno.
func (t *Tracer) applyDenyFixup(tid int, errno int) {
	regs, err := t.getRegs(tid)
	if err != nil {
		return
	}
	regs.SetReturnValue(-int64(errno))
	t.setRegs(tid, regs)
}

// applyReturnOverride overwrites the syscall return value with an arbitrary value.
// Used by file redirect to pass through the fd from an injected openat syscall.
func (t *Tracer) applyReturnOverride(tid int, retval int64) {
	regs, err := t.getRegs(tid)
	if err != nil {
		return
	}
	regs.SetReturnValue(retval)
	t.setRegs(tid, regs)
}

// hasPendingSyscallExit returns true if the tracee has a pending deny errno,
// fake-zero fixup, return override, or exec stub fd cleanup that needs to be
// applied at syscall exit.
func (t *Tracer) hasPendingSyscallExit(tid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.tracees[tid]
	if state == nil {
		return false
	}
	return state.InSyscall && (state.PendingDenyErrno != 0 || state.PendingFakeZero || state.HasPendingReturn || state.PendingExecStubFD >= 0)
}

// handleStop dispatches a tracee stop event.
func (t *Tracer) handleStop(ctx context.Context, tid int, status unix.WaitStatus) {
	switch {
	case status.Exited() || status.Signaled():
		t.handleExit(tid)

	case status.Stopped():
		sig := status.StopSignal()

		switch {
		case sig == unix.SIGTRAP|0x80:
			t.handleSyscallStop(ctx, tid)

		case sig == unix.SIGTRAP:
			event := status.TrapCause()
			switch event {
			case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_CLONE:
				t.handleNewChild(tid, event)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_VFORK:
				t.handleNewChild(tid, event)
				t.markVforkChild(tid)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_EXEC:
				t.handleExecEvent(tid)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_SECCOMP:
				t.handleSeccompStop(ctx, tid)
			case unix.PTRACE_EVENT_EXIT:
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_STOP:
				t.handleEventStop(tid)
			default:
				// In prefilter mode (PTRACE_O_TRACESECCOMP without
				// TRACESYSGOOD), a plain SIGTRAP with no event can be
				// a syscall-exit stop if we explicitly used PtraceSyscall
				// (e.g., after soft-delete). Check for pending fixups.
				if t.hasPendingSyscallExit(tid) {
					t.handleSyscallStop(ctx, tid)
				} else {
					t.resumeTracee(tid, 0)
				}
			}

		default:
			// In PTRACE_SEIZE mode, group-stops (SIGSTOP, SIGTSTP, SIGTTIN,
			// SIGTTOU) are reported with TrapCause == PTRACE_EVENT_STOP and
			// the stopping signal in StopSignal. Use PTRACE_LISTEN to keep
			// the tracee group-stopped.
			if status.TrapCause() == unix.PTRACE_EVENT_STOP {
				t.mu.Lock()
				state := t.tracees[tid]
				hasState := state != nil
				suppress := state != nil && sig == unix.SIGSTOP && state.SuppressInitialStop
				if suppress {
					state.SuppressInitialStop = false
				}
				t.mu.Unlock()

				// Auto-attached children may receive this stop before
				// handleNewChild creates their state. Create minimal
				// state and resume to avoid leaving them stuck.
				if !hasState {
					childTGID, _ := readTGID(tid)
					if childTGID == 0 {
						childTGID = tid
					}
					t.mu.Lock()
					if _, exists := t.tracees[tid]; !exists {
						t.tracees[tid] = &TraceeState{
							TID:                tid,
							TGID:               childTGID,
							MemFD:              -1,
							PendingExecStubFD:  -1,
							PendingExecSavedFD: -1,
						}
						t.metrics.SetTraceeCount(len(t.tracees))
					}
					t.mu.Unlock()
					t.resumeTracee(tid, 0)
					break
				}

				if suppress {
					t.resumeTracee(tid, 0)
					break
				}

				ptraceListen(tid)
				break
			}

			// Suppress initial SIGSTOP for auto-traced children (non-group-stop).
			if sig == unix.SIGSTOP {
				t.mu.Lock()
				state := t.tracees[tid]
				suppress := state != nil && state.SuppressInitialStop
				if suppress {
					state.SuppressInitialStop = false
				}
				t.mu.Unlock()
				if suppress {
					t.resumeTracee(tid, 0)
					break
				}
			}
			t.resumeTracee(tid, int(sig))
		}
	}
}

// handleSyscallStop handles SIGTRAP|0x80 stops (TRACESYSGOOD mode).
func (t *Tracer) handleSyscallStop(ctx context.Context, tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		t.allowSyscall(tid)
		return
	}
	entering := !state.InSyscall
	state.InSyscall = entering
	pendingErrno := 0
	pendingFakeZero := false
	hasPendingReturn := false
	var pendingReturnOverride int64
	pendingExecStubFD := -1
	pendingExecSavedFD := -1
	if !entering {
		pendingErrno = state.PendingDenyErrno
		state.PendingDenyErrno = 0
		pendingFakeZero = state.PendingFakeZero
		state.PendingFakeZero = false
		hasPendingReturn = state.HasPendingReturn
		pendingReturnOverride = state.PendingReturnOverride
		state.HasPendingReturn = false
		state.PendingReturnOverride = 0
		pendingExecStubFD = state.PendingExecStubFD
		pendingExecSavedFD = state.PendingExecSavedFD
		state.PendingExecStubFD = -1
		state.PendingExecSavedFD = -1
	}
	t.mu.Unlock()

	if entering {
		regs, err := t.getRegs(tid)
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		nr := regs.SyscallNr()
		t.mu.Lock()
		state.LastNr = nr
		tgid := state.TGID
		t.mu.Unlock()

		// Reset scratch page allocator at each syscall-enter so that
		// redirect/soft-delete operations always start with a fresh page.
		t.resetScratchIfPresent(tgid)

		t.dispatchSyscall(ctx, tid, nr, regs)
	} else {
		if pendingErrno != 0 {
			t.applyDenyFixup(tid, pendingErrno)
		} else if pendingFakeZero {
			t.applyDenyFixup(tid, 0)
		} else if hasPendingReturn {
			t.applyReturnOverride(tid, pendingReturnOverride)
		}

		// If an exec redirect injected a stub fd and the exec failed,
		// clean up the leaked fd in the tracee.
		if pendingExecStubFD >= 0 {
			regs, err := t.getRegs(tid)
			if err == nil && regs.ReturnValue() < 0 {
				savedRegs := regs.Clone()
				t.cleanupInjectedFD(tid, savedRegs, pendingExecStubFD, pendingExecSavedFD)
			}
		}

		t.allowSyscall(tid)
	}
}

// handleSeccompStop handles PTRACE_EVENT_SECCOMP stops (prefilter mode).
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
	regs, err := t.getRegs(tid)
	if err != nil {
		t.allowSyscall(tid)
		return
	}
	nr := regs.SyscallNr()

	// Mark as syscall-entry so that injection helpers (injectSyscall)
	// use the single-phase entry protocol (modify ORIG_RAX, one cycle
	// to exit) instead of the two-phase gadget protocol.
	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
		state.InSyscall = true
	}
	t.mu.Unlock()
	if tgid != 0 {
		t.resetScratchIfPresent(tgid)
	}

	t.dispatchSyscall(ctx, tid, nr, regs)
}

// dispatchSyscall routes a syscall to the appropriate handler.
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isExecveSyscall(nr):
		t.handleExecve(ctx, tid, regs)
	case isFileSyscall(nr):
		t.handleFile(ctx, tid, regs)
	case isNetworkSyscall(nr):
		t.handleNetwork(ctx, tid, regs)
	case isSignalSyscall(nr):
		t.handleSignal(ctx, tid, regs)
	default:
		t.allowSyscall(tid)
	}
}

// handleNewChild processes a fork/clone/vfork event.
func (t *Tracer) handleNewChild(parentTID int, event int) {
	childTID, err := unix.PtraceGetEventMsg(parentTID)
	if err != nil {
		return
	}
	tid := int(childTID)

	childTGID, err := readTGID(tid)
	if err != nil {
		slog.Warn("handleNewChild: cannot read TGID", "tid", tid, "error", err)
		return
	}

	t.mu.Lock()
	parent := t.tracees[parentTID]
	if parent == nil {
		t.mu.Unlock()
		return
	}

	isNewProcess := childTGID != parent.TGID

	// If a child-stop arrived before this parent event, a minimal state
	// already exists and the initial SIGSTOP was already handled. Update
	// metadata in place to preserve runtime fields (InSyscall, MemFD, etc.).
	existing := t.tracees[tid]
	if existing != nil {
		existing.TGID = childTGID
		existing.ParentPID = parent.TGID
		existing.SessionID = parent.SessionID
		existing.Attached = time.Now()
	} else {
		t.tracees[tid] = &TraceeState{
			TID:                 tid,
			TGID:                childTGID,
			ParentPID:           parent.TGID,
			SessionID:           parent.SessionID,
			Attached:            time.Now(),
			MemFD:               -1,
			PendingExecStubFD:   -1,
			PendingExecSavedFD:  -1,
			SuppressInitialStop: true,
		}
	}
	t.metrics.SetTraceeCount(len(t.tracees))
	t.mu.Unlock()

	if isNewProcess {
		t.processTree.AddChild(parent.TGID, childTGID)
	}
}

func (t *Tracer) markVforkChild(parentTID int) {
	childTID, err := unix.PtraceGetEventMsg(parentTID)
	if err != nil {
		return
	}
	t.mu.Lock()
	if state, ok := t.tracees[int(childTID)]; ok {
		state.IsVforkChild = true
	}
	t.mu.Unlock()
}

func (t *Tracer) handleExecEvent(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		return
	}
	state.IsVforkChild = false
	// Exec succeeded: the stub fd is now inherited by the new process.
	// Clear PendingExecStubFD so the exit handler doesn't try to clean it up.
	// The saved fd (if any) was also replaced by exec; discard it.
	state.PendingExecStubFD = -1
	state.PendingExecSavedFD = -1
	// Keep InSyscall = true: the PTRACE_EVENT_EXEC fires between the
	// execve's syscall-enter and syscall-exit. The next SIGTRAP|0x80
	// stop will be the execve exit; by leaving InSyscall true, the
	// tracer correctly treats it as an exit (entering = !true = false)
	// and subsequent syscalls are dispatched on entry as expected.
	// Without this, the enter/exit tracking drifts off-by-one and
	// handlers see syscalls only at exit — too late to intercept.

	formerTID, err := unix.PtraceGetEventMsg(tid)
	if err == nil && int(formerTID) != tid {
		delete(t.tracees, int(formerTID))
	}

	tgid := state.TGID
	for otherTID, otherState := range t.tracees {
		if otherState.TGID == tgid && otherTID != tid {
			if otherState.MemFD >= 0 {
				unix.Close(otherState.MemFD)
			}
			delete(t.tracees, otherTID)
		}
	}

	// Exec replaces the process address space, so reopen /proc/<tid>/mem
	// to get a fresh fd pointing to the new address space.
	if state.MemFD >= 0 {
		unix.Close(state.MemFD)
		state.MemFD = -1
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDWR, 0)
	if err != nil {
		slog.Warn("handleExecEvent: O_RDWR open failed, trying O_RDONLY", "tid", tid, "error", err)
		fd, _ = unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDONLY, 0)
	}
	state.MemFD = fd

	t.metrics.SetTraceeCount(len(t.tracees))
	t.mu.Unlock()

	// Exec replaces the process address space, invalidating any scratch page.
	t.invalidateScratchPage(tgid)
}

func (t *Tracer) handleExit(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	lastThread := true
	if state != nil {
		tgid = state.TGID
		if state.MemFD >= 0 {
			unix.Close(state.MemFD)
		}
		delete(t.tracees, tid)
		if _, parked := t.parkedTracees[tid]; parked {
			delete(t.parkedTracees, tid)
			slog.Warn("ptrace: parked tracee exited before approval", "tid", tid)
		}
		// Check if any remaining threads belong to the same TGID.
		for _, other := range t.tracees {
			if other.TGID == tgid {
				lastThread = false
				break
			}
		}
		t.metrics.SetTraceeCount(len(t.tracees))
	}
	t.mu.Unlock()

	if state != nil && lastThread {
		t.invalidateScratchPage(tgid)
	}
}

func (t *Tracer) handleEventStop(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil && state.PendingInterrupt {
		state.PendingInterrupt = false
		t.mu.Unlock()
		t.resumeTracee(tid, 0)
		return
	}
	hasState := state != nil
	t.mu.Unlock()

	// This handler is only reached when sig == SIGTRAP (see handleStop
	// dispatcher). Group-stops under PTRACE_SEIZE have the actual stopping
	// signal (SIGSTOP/SIGTSTP/etc.) as StopSignal, so they fall into the
	// default signal handler and never reach here. That means we only see
	// two kinds of PTRACE_EVENT_STOP with SIGTRAP:
	//   1. Initial auto-attach stops for children traced via
	//      PTRACE_O_TRACEFORK/VFORK/CLONE.
	//   2. PTRACE_INTERRUPT-induced stops (handled above via PendingInterrupt).
	// Both are correctly resumed with PtraceSyscall/PtraceCont; PTRACE_LISTEN
	// is not needed here.
	if !hasState {
		// Create minimal state so the child doesn't get lost.
		childTGID, _ := readTGID(tid)
		if childTGID == 0 {
			childTGID = tid
		}
		t.mu.Lock()
		if _, exists := t.tracees[tid]; !exists {
			t.tracees[tid] = &TraceeState{
				TID:                tid,
				TGID:               childTGID,
				MemFD:              -1,
				PendingExecStubFD:  -1,
				PendingExecSavedFD: -1,
			}
			t.metrics.SetTraceeCount(len(t.tracees))
		}
		t.mu.Unlock()
	}

	t.resumeTracee(tid, 0)
}

// handleExecve intercepts execve/execveat syscalls for policy evaluation.
func (t *Tracer) handleExecve(ctx context.Context, tid int, regs Regs) {
	if t.cfg.ExecHandler == nil || !t.cfg.TraceExecve {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()
	var filenamePtr uint64
	if nr == unix.SYS_EXECVEAT {
		filenamePtr = regs.Arg(1)
	} else {
		filenamePtr = regs.Arg(0)
	}

	filename, err := t.readString(tid, filenamePtr, 4096)
	if err != nil {
		slog.Warn("handleExecve: cannot read filename", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	var argvPtr uint64
	if nr == unix.SYS_EXECVEAT {
		argvPtr = regs.Arg(2)
	} else {
		argvPtr = regs.Arg(1)
	}

	argv, truncated, err := t.readArgv(tid, argvPtr, 1000, 65536)
	if err != nil {
		slog.Warn("handleExecve: cannot read argv", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid, parentPID int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		parentPID = state.ParentPID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	depth := t.processTree.Depth(tgid)

	result := t.cfg.ExecHandler.HandleExecve(ctx, ExecContext{
		PID:       tgid,
		ParentPID: parentPID,
		Filename:  filename,
		Argv:      argv,
		Truncated: truncated,
		SessionID: sessionID,
		Depth:     depth,
	})

	// Dispatch based on Action field (preferred) or Allow field (legacy fallback).
	action := result.Action
	if action == "" {
		if result.Allow {
			action = "allow"
		} else {
			action = "deny"
		}
	}

	switch action {
	case "allow", "continue":
		t.allowSyscall(tid)
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	case "redirect":
		t.redirectExec(ctx, tid, regs, result)
	default:
		slog.Warn("handleExecve: unknown action, denying", "tid", tid, "action", action)
		t.denySyscall(tid, int(unix.EACCES))
	}
}

// Run starts the ptrace event loop.
func (t *Tracer) Run(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		if err := t.drainQueues(ctx); err != nil {
			return err
		}

		// Sweep parked timeouts on every iteration so enforcement is not
		// load-dependent (previously only ran on the idle path).
		t.sweepParkedTimeouts()

		var status unix.WaitStatus
		tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, nil)

		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.ECHILD {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-t.stopped:
					return nil
				case pid := <-t.attachQueue:
					if err := t.attachProcess(pid); err != nil {
						slog.Error("attach from queue failed", "pid", pid, "error", err)
					}
					continue
				case req := <-t.resumeQueue:
					t.handleResumeRequest(req)
					continue
				}
			}
			return fmt.Errorf("wait4: %w", err)
		}

		if tid == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.stopped:
				return nil
			case pid := <-t.attachQueue:
				if err := t.attachProcess(pid); err != nil {
					slog.Error("attach from queue failed", "pid", pid, "error", err)
				}
			case req := <-t.resumeQueue:
				t.handleResumeRequest(req)
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}

		t.handleStop(ctx, tid, status)
	}
}

// Start implements the SyscallTracer interface.
func (t *Tracer) Start(ctx context.Context) error {
	return t.Run(ctx)
}

// Stop signals the event loop to exit.
func (t *Tracer) Stop() {
	select {
	case <-t.stopped:
	default:
		close(t.stopped)
	}
}

func (t *Tracer) drainQueues(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.stopped:
			return fmt.Errorf("tracer stopped")
		case pid := <-t.attachQueue:
			if err := t.attachProcess(pid); err != nil {
				slog.Error("attach from queue failed", "pid", pid, "error", err)
			}
		case req := <-t.resumeQueue:
			t.handleResumeRequest(req)
		default:
			return nil
		}
	}
}

// sweepParkedTimeouts denies parked tracees that have exceeded max_hold_ms.
func (t *Tracer) sweepParkedTimeouts() {
	if t.cfg.MaxHoldMs <= 0 {
		return
	}
	maxDuration := time.Duration(t.cfg.MaxHoldMs) * time.Millisecond

	t.mu.Lock()
	var expired []int
	for tid := range t.parkedTracees {
		state := t.tracees[tid]
		if state == nil {
			// Tracee already exited — clean up stale parking entry.
			delete(t.parkedTracees, tid)
			continue
		}
		if !state.ParkedAt.IsZero() && time.Since(state.ParkedAt) > maxDuration {
			expired = append(expired, tid)
		}
	}
	t.mu.Unlock()

	for _, tid := range expired {
		slog.Warn("ptrace: max_hold_ms timeout, denying syscall",
			"tid", tid,
			"max_hold_ms", t.cfg.MaxHoldMs,
		)

		resolved := false
		if err := t.denySyscall(tid, int(unix.EACCES)); err != nil {
			slog.Error("ptrace: deny after timeout failed, killing tracee",
				"tid", tid, "error", err)
			t.mu.Lock()
			state := t.tracees[tid]
			tgid := tid
			if state != nil {
				tgid = state.TGID
			}
			t.mu.Unlock()
			if err := unix.Tgkill(tgid, tid, unix.SIGKILL); err != nil {
				if errors.Is(err, unix.ESRCH) {
					// Tracee already gone.
					t.handleExit(tid)
					resolved = true
				} else {
					slog.Error("ptrace: kill after timeout also failed, will retry",
						"tid", tid, "error", err)
				}
			} else {
				resolved = true
			}
		} else {
			resolved = true
		}

		if resolved {
			t.metrics.IncTimeout()
			t.mu.Lock()
			delete(t.parkedTracees, tid)
			if state, ok := t.tracees[tid]; ok {
				state.ParkedAt = time.Time{}
			}
			t.mu.Unlock()
		}
	}
}

func (t *Tracer) handleResumeRequest(req resumeRequest) {
	t.mu.Lock()
	_, parked := t.parkedTracees[req.TID]
	if parked {
		delete(t.parkedTracees, req.TID)
	}
	state := t.tracees[req.TID]
	if state != nil {
		state.ParkedAt = time.Time{}
	}
	t.mu.Unlock()

	if !parked {
		slog.Warn("resume request for non-parked tracee", "tid", req.TID)
		return
	}

	if state == nil {
		slog.Warn("resume request for exited tracee, skipping", "tid", req.TID)
		return
	}

	if req.Allow {
		t.allowSyscall(req.TID)
	} else {
		t.denySyscall(req.TID, req.Errno)
	}
}
