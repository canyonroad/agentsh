//go:build linux

package ptrace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"syscall"
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
	Allow  bool
	Action string // "continue", "deny", "redirect"
	Errno  int32
	Rule   string
	Reason string
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
	Allow bool
	Errno int32
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
	Allow bool
	Errno int32
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
	PendingDenyErrno int
	PendingInterrupt bool
	IsVforkChild     bool
	MemFD            int
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

// applyDenyFixup overwrites the syscall return value with -errno.
func (t *Tracer) applyDenyFixup(tid int, errno int) {
	regs, err := t.getRegs(tid)
	if err != nil {
		return
	}
	regs.SetReturnValue(-int64(errno))
	t.setRegs(tid, regs)
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
				t.resumeTracee(tid, 0)
			}

		default:
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
	if !entering {
		pendingErrno = state.PendingDenyErrno
		state.PendingDenyErrno = 0
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
		t.mu.Unlock()

		t.dispatchSyscall(ctx, tid, nr, regs)
	} else {
		if pendingErrno != 0 {
			t.applyDenyFixup(tid, pendingErrno)
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

	t.tracees[tid] = &TraceeState{
		TID:       tid,
		TGID:      childTGID,
		ParentPID: parent.TGID,
		SessionID: parent.SessionID,
		Attached:  time.Now(),
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
	state.InSyscall = false

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
	t.metrics.SetTraceeCount(len(t.tracees))
	t.mu.Unlock()
}

func (t *Tracer) handleExit(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil {
		if state.MemFD >= 0 {
			unix.Close(state.MemFD)
		}
		delete(t.tracees, tid)
		if _, parked := t.parkedTracees[tid]; parked {
			delete(t.parkedTracees, tid)
			slog.Warn("ptrace: parked tracee exited before approval", "tid", tid)
		}
		t.metrics.SetTraceeCount(len(t.tracees))
	}
	t.mu.Unlock()
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
	t.mu.Unlock()
	// PTRACE_LISTEN is not wrapped by x/sys/unix, so use RawSyscall directly.
	_, _, e := syscall.RawSyscall6(syscall.SYS_PTRACE, unix.PTRACE_LISTEN, uintptr(tid), 0, 0, 0, 0)
	_ = e
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

	switch result.Action {
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	default:
		t.allowSyscall(tid)
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
			expired = append(expired, tid)
			continue
		}
		if !state.ParkedAt.IsZero() && time.Since(state.ParkedAt) > maxDuration {
			expired = append(expired, tid)
		}
	}
	for _, tid := range expired {
		delete(t.parkedTracees, tid)
	}
	t.mu.Unlock()

	for _, tid := range expired {
		t.mu.Lock()
		state := t.tracees[tid]
		t.mu.Unlock()
		if state == nil {
			continue
		}
		slog.Warn("ptrace: max_hold_ms timeout, denying syscall",
			"tid", tid,
			"max_hold_ms", t.cfg.MaxHoldMs,
		)
		t.metrics.IncTimeout()
		t.denySyscall(tid, int(unix.EACCES))
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
