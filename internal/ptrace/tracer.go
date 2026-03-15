//go:build linux

package ptrace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	Domain    string // DNS query name (set when Operation == "dns")
	QueryType uint16 // DNS query type: A=1, AAAA=28, CNAME=5, etc.
}

// NetworkResult carries the network policy decision.
type NetworkResult struct {
	Allow            bool
	Action           string // "" (legacy), "allow", "deny", "redirect"
	Errno            int32
	RedirectAddr     string // for redirect
	RedirectPort     int    // for redirect
	RedirectUpstream string // Forward DNS query to this resolver (ip:port)
	Records          []DNSRecord // Synthetic DNS response records
}

// DNSRecord represents a single DNS response record.
type DNSRecord struct {
	Type  uint16 // A=1, AAAA=28, CNAME=5
	Value string // IP address or domain name
	TTL   uint32
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
	MaskTracerPid    bool
	SeccompPrefilter bool
	MaxTracees       int
	MaxHoldMs        int
	OnAttachFailure  string
	ReadyFile        string // Path to write after successful attach (sentinel for workload readiness)
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
	CommandID        string
	InSyscall        bool
	LastNr           int
	Attached         time.Time
	ParkedAt         time.Time
	PendingDenyErrno      int
	PendingFakeZero       bool  // force return value to 0 on syscall exit
	PendingReturnOverride int64 // force return value to this on syscall exit
	HasPendingReturn      bool  // whether PendingReturnOverride is active
	PendingInterrupt      bool
	HasPrefilter     bool // true if seccomp prefilter is installed for this tracee
	PendingPrefilter bool // inject seccomp filter on next syscall stop
	NeedExitStop     bool // resume with PtraceSyscall to catch exit
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

// ExitReason describes why a process exited.
type ExitReason int

const (
	ExitNormal    ExitReason = iota // process exited or was signaled (Code/Signal valid)
	ExitVanished                    // ESRCH — process disappeared (ptrace call failed)
	ExitTracerDown                  // tracer shut down while process was running
)

// ExitStatus carries process exit information for tracer-managed wait.
type ExitStatus struct {
	PID    int
	Code   int
	Signal int
	Reason ExitReason
	Rusage *unix.Rusage
}

// attachRequest carries a PID and options for the attach queue.
type attachRequest struct {
	pid  int
	opts attachOpts
}

type attachOpts struct {
	sessionID   string
	commandID   string
	keepStopped bool
}

// AttachOption configures how a process is attached.
type AttachOption func(*attachOpts)

// WithSessionID associates a session ID with the attached process.
func WithSessionID(id string) AttachOption {
	return func(o *attachOpts) { o.sessionID = id }
}

// WithCommandID associates a command ID with the attached process.
func WithCommandID(id string) AttachOption {
	return func(o *attachOpts) { o.commandID = id }
}

// WithKeepStopped keeps the tracee stopped after attach (for cgroup hook).
func WithKeepStopped() AttachOption {
	return func(o *attachOpts) { o.keepStopped = true }
}

// Tracer implements a ptrace-based syscall tracer.
type Tracer struct {
	cfg             TracerConfig
	metrics         Metrics
	processTree     *ProcessTree

	attachQueue chan attachRequest
	resumeQueue chan resumeRequest

	fds      *fdTracker
	dnsProxy *dnsProxy

	mu            sync.Mutex
	tracees       map[int]*TraceeState
	parkedTracees map[int]struct{}
	tgidScratch   map[int]*scratchPage

	attachDone sync.Map // pid → chan error
	exitNotify sync.Map // pid → chan ExitStatus

	readyFileWritten  bool
	readyFileAttempts int

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
		attachQueue:   make(chan attachRequest, 64),
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

// writeReadyFile writes the sentinel file if configured and not yet written.
// Retries up to 3 times on failure before giving up.
func (t *Tracer) writeReadyFile() {
	if t.cfg.ReadyFile == "" || t.readyFileWritten {
		return
	}
	t.readyFileAttempts++
	if err := os.WriteFile(t.cfg.ReadyFile, []byte("ready\n"), 0644); err != nil {
		slog.Error("failed to write ready file", "path", t.cfg.ReadyFile, "error", err, "attempt", t.readyFileAttempts)
		if t.readyFileAttempts >= 3 {
			slog.Error("giving up on ready file after max attempts", "path", t.cfg.ReadyFile)
			t.readyFileWritten = true // stop retrying
		}
		return
	}
	t.readyFileWritten = true
	slog.Info("tracer ready file written", "path", t.cfg.ReadyFile)
}

// AttachPID enqueues attachment to a process.
func (t *Tracer) AttachPID(pid int, opts ...AttachOption) error {
	var o attachOpts
	for _, fn := range opts {
		fn(&o)
	}
	done := make(chan error, 1)
	t.attachDone.Store(pid, done)
	t.attachQueue <- attachRequest{pid: pid, opts: o}
	return nil
}

// WaitAttached blocks until the process has been attached (or attach failed).
// Times out after 10 seconds to avoid indefinite blocking when the tracer is down.
func (t *Tracer) WaitAttached(pid int) error {
	v, ok := t.attachDone.Load(pid)
	if !ok {
		return fmt.Errorf("no pending attach for pid %d", pid)
	}
	done := v.(chan error)
	select {
	case err := <-done:
		t.attachDone.Delete(pid)
		return err
	case <-time.After(10 * time.Second):
		t.attachDone.Delete(pid)
		return fmt.Errorf("attach timed out for pid %d", pid)
	}
}

// ResumePID resumes all keepStopped threads of a process via the resume queue.
// For freshly-started processes (exec path), only one thread exists.
// For multi-threaded processes, all threads sharing the TGID are resumed.
func (t *Tracer) ResumePID(pid int) error {
	t.mu.Lock()
	var tids []int
	for tid := range t.parkedTracees {
		state := t.tracees[tid]
		if state != nil && (state.TGID == pid || tid == pid) {
			tids = append(tids, tid)
		}
	}
	t.mu.Unlock()

	if len(tids) == 0 {
		// Fallback: send resume for the pid directly
		t.resumeQueue <- resumeRequest{TID: pid, Allow: true}
		return nil
	}
	for _, tid := range tids {
		t.resumeQueue <- resumeRequest{TID: tid, Allow: true}
	}
	return nil
}

// signalAttachDone signals the WaitAttached channel for a PID, if one exists.
func (t *Tracer) signalAttachDone(pid int, err error) {
	if v, ok := t.attachDone.Load(pid); ok {
		v.(chan error) <- err
	}
}

// cancelPendingAttachWaiters signals all pending WaitAttached callers with an
// error so they don't block indefinitely when the tracer shuts down.
func (t *Tracer) cancelPendingAttachWaiters() {
	t.attachDone.Range(func(key, value any) bool {
		ch := value.(chan error)
		select {
		case ch <- fmt.Errorf("tracer shutting down"):
		default:
		}
		t.attachDone.Delete(key)
		return true
	})
}

// RegisterExitNotify registers an exit notification channel for a PID (TGID).
// Must be called before AttachPID to ensure no race with fast-exit processes.
// Returns an error if a channel is already registered for this PID.
func (t *Tracer) RegisterExitNotify(pid int) (<-chan ExitStatus, error) {
	ch := make(chan ExitStatus, 1)
	_, loaded := t.exitNotify.LoadOrStore(pid, ch)
	if loaded {
		return nil, fmt.Errorf("exit notify already registered for pid %d", pid)
	}
	return ch, nil
}

// UnregisterExitNotify removes a pending exit notification only if it matches
// the given channel (ownership check). Safe for concurrent flows on different PIDs.
func (t *Tracer) UnregisterExitNotify(pid int, ch <-chan ExitStatus) {
	if v, ok := t.exitNotify.Load(pid); ok {
		if v.(chan ExitStatus) == ch {
			t.exitNotify.Delete(pid)
		}
	}
}

// cancelPendingExitWaiters signals all pending exit notification channels
// so they don't block indefinitely when the tracer shuts down.
func (t *Tracer) cancelPendingExitWaiters() {
	t.exitNotify.Range(func(key, value any) bool {
		ch := value.(chan ExitStatus)
		select {
		case ch <- ExitStatus{Reason: ExitTracerDown}:
		default:
		}
		t.exitNotify.Delete(key)
		return true
	})
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
		unix.PTRACE_O_EXITKILL |
		unix.PTRACE_O_TRACESYSGOOD
	if t.cfg.SeccompPrefilter {
		opts |= unix.PTRACE_O_TRACESECCOMP
	}
	return opts
}

func (t *Tracer) getRegs(tid int) (Regs, error) {
	return getRegsArch(tid)
}

func (t *Tracer) setRegs(tid int, regs Regs) error {
	return setRegsArch(tid, regs)
}

// needsExitStop returns true for syscalls that need exit-time processing.
// These syscalls must be resumed with PtraceSyscall (not PtraceCont) so the
// tracer catches the exit stop. All other traced syscalls are entry-only and
// can use PtraceCont to skip directly to the next seccomp event.
func needsExitStop(nr int) bool {
	switch nr {
	case unix.SYS_READ, unix.SYS_PREAD64: // handleReadExit (TracerPid masking)
		return true
	case unix.SYS_OPENAT: // handleOpenatExit (fd tracking)
		return true
	case unix.SYS_OPENAT2: // handleOpenatExit (fd tracking)
		return true
	case unix.SYS_CONNECT: // handleConnectExit (TLS fd watch)
		return true
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT: // failed exec needs exit to reset InSyscall
		return true
	}
	return false
}

// allowSyscall resumes the tracee, allowing the syscall to proceed.
func (t *Tracer) allowSyscall(tid int) {
	t.mu.Lock()
	hasPrefilter := false
	needExit := false
	if s := t.tracees[tid]; s != nil {
		hasPrefilter = s.HasPrefilter
		needExit = s.NeedExitStop
	}
	t.mu.Unlock()

	var err error
	if hasPrefilter && !needExit {
		err = unix.PtraceCont(tid, 0)
	} else {
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil && errors.Is(err, unix.ESRCH) {
		t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
	}
}

// denySyscall invalidates the current syscall and arranges for return value fixup.
func (t *Tracer) denySyscall(tid int, errno int) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
			return nil
		}
		return err
	}
	regs.SetSyscallNr(-1)
	if err := t.setRegs(tid, regs); err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
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
			t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
			return nil
		}
		return err
	}
	return nil
}

// resumeTracee resumes a tracee with an optional signal to deliver.
// Always uses PtraceSyscall to catch exit-time stops (see allowSyscall).
func (t *Tracer) resumeTracee(tid int, sig int) {
	t.mu.Lock()
	hasPrefilter := false
	needExit := false
	if s := t.tracees[tid]; s != nil {
		hasPrefilter = s.HasPrefilter
		needExit = s.NeedExitStop
	}
	t.mu.Unlock()

	if hasPrefilter && !needExit {
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
func (t *Tracer) handleStop(ctx context.Context, tid int, status unix.WaitStatus, rusage *unix.Rusage) {
	switch {
	case status.Exited() || status.Signaled():
		t.handleExit(tid, status, rusage, ExitNormal)

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
							LastNr:             -1,
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
	// Deferred seccomp prefilter injection: inject on the first syscall EXIT
	// (not entry — injectFromEntry replaces the current syscall, which would
	// drop the tracee's first real syscall). At exit, the syscall already
	// completed, so injection is safe.
	//
	// State.InSyscall tracks what the PREVIOUS stop set:
	//   InSyscall=false → this is an entry stop (first time)
	//   InSyscall=true  → this is an exit stop (entry was processed)
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil && state.PendingPrefilter && !state.InSyscall {
		// This is a syscall entry. Let normal handling process it.
		// The next stop will be the exit, where we'll inject.
		t.mu.Unlock()
	} else if state != nil && state.PendingPrefilter && state.InSyscall {
		// This is a syscall exit — safe to inject now.
		state.PendingPrefilter = false
		// Set InSyscall=false before injection so injectSyscall uses the
		// correct exit-stop protocol (injectFromExit).
		state.InSyscall = false
		t.mu.Unlock()
		if err := t.injectSeccompFilter(tid); err != nil {
			slog.Warn("seccomp prefilter injection failed, falling back to TRACESYSGOOD",
				"tid", tid, "error", err)
		} else {
			t.mu.Lock()
			if s := t.tracees[tid]; s != nil {
				s.HasPrefilter = true
			}
			t.mu.Unlock()
		}
		// Fall through to normal exit handling for this syscall.
		// Do NOT return — the first syscall's exit handlers still need to run.
		// Restore InSyscall=true so the normal toggle correctly identifies
		// this as a syscall exit (entering := !state.InSyscall → false).
		t.mu.Lock()
		if s := t.tracees[tid]; s != nil {
			s.InSyscall = true
		}
		t.mu.Unlock()
	} else {
		t.mu.Unlock()
	}

	t.mu.Lock()
	state = t.tracees[tid]
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
		state.NeedExitStop = needsExitStop(nr)
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

		// Phase 4b: exit-time handlers
		nr := -1
		t.mu.Lock()
		if state != nil {
			nr = state.LastNr
			state.NeedExitStop = false
		}
		t.mu.Unlock()

		if nr >= 0 {
			exitRegs, err := t.getRegs(tid)
			if err == nil {
				t.handleSyscallExit(tid, nr, exitRegs)
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
		state.LastNr = nr
		state.NeedExitStop = needsExitStop(nr)
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
	case isWriteSyscall(nr):
		t.handleWrite(ctx, tid, regs)
	case isCloseSyscall(nr):
		t.handleClose(ctx, tid, regs)
	case isReadSyscall(nr):
		t.allowSyscall(tid) // read is handled on exit, not entry
	default:
		t.allowSyscall(tid)
	}
}

// handleSyscallExit runs exit-time handlers for syscalls that need post-processing.
func (t *Tracer) handleSyscallExit(tid int, nr int, regs Regs) {
	switch {
	case isReadSyscall(nr):
		t.handleReadExit(tid, regs)
	case nr == unix.SYS_OPENAT || nr == unix.SYS_OPENAT2:
		t.handleOpenatExit(tid, regs)
	case nr == unix.SYS_CONNECT:
		t.handleConnectExit(tid, regs)
	}
}

// handleOpenatExit tracks fds opened on /proc/*/status for TracerPid masking.
func (t *Tracer) handleOpenatExit(tid int, regs Regs) {
	if t.fds == nil || !t.cfg.MaskTracerPid {
		return
	}

	retVal := regs.ReturnValue()
	if retVal < 0 {
		return // open failed
	}
	fd := int(retVal)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Read the path from /proc/<tid>/fd/<fd> to check if it's a status file.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil {
		return
	}

	if isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
	}
}

// handleConnectExit marks fds as TLS-watched after successful connect to TLS ports.
func (t *Tracer) handleConnectExit(tid int, regs Regs) {
	if t.fds == nil {
		return
	}

	retVal := regs.ReturnValue()
	// connect returns 0 on success, or -EINPROGRESS for non-blocking
	if retVal != 0 && retVal != -int64(unix.EINPROGRESS) {
		return
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Read the destination address from the connect args.
	addrPtr := regs.Arg(1)
	addrLen := int(regs.Arg(2))
	if addrLen <= 0 || addrLen > 128 {
		return
	}

	buf := make([]byte, addrLen)
	if err := t.readBytes(tid, addrPtr, buf); err != nil {
		return
	}

	_, address, port, err := parseSockaddr(buf)
	if err != nil {
		return
	}

	// Only watch TLS-relevant ports
	if port != 443 && port != 853 {
		return
	}

	fd := int(int32(regs.Arg(0)))

	// Look up domain from DNS resolution cache
	domain, ok := t.fds.domainForIP(address)
	if !ok || domain == "" {
		return // No domain known — skip TLS watch to avoid empty SNI rewrite
	}
	t.fds.watchTLS(tgid, fd, domain)
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
		existing.HasPrefilter = parent.HasPrefilter
		existing.PendingPrefilter = parent.PendingPrefilter
		existing.Attached = time.Now()
	} else {
		t.tracees[tid] = &TraceeState{
			TID:                 tid,
			TGID:                childTGID,
			ParentPID:           parent.TGID,
			SessionID:           parent.SessionID,
			HasPrefilter:        parent.HasPrefilter,
			PendingPrefilter:    parent.PendingPrefilter,
			Attached:            time.Now(),
			LastNr:              -1,
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

	// Phase 4b: exec resets fd table, clear all fd tracking for this TGID.
	if t.fds != nil {
		t.fds.clearTGID(tgid)
	}

	// Exec replaces the process address space, invalidating any scratch page.
	t.invalidateScratchPage(tgid)
}

func (t *Tracer) handleExit(tid int, status unix.WaitStatus, rusage *unix.Rusage, reason ExitReason) {
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
		if v, ok := t.exitNotify.LoadAndDelete(tgid); ok {
			ch := v.(chan ExitStatus)
			// Deep-copy rusage to avoid aliasing the loop-local variable
			// in Run() which gets reused on subsequent Wait4 iterations.
			var ruCopy *unix.Rusage
			if rusage != nil {
				ru := *rusage
				ruCopy = &ru
			}
			es := ExitStatus{
				PID:    tgid,
				Reason: reason,
				Rusage: ruCopy,
			}
			if status.Exited() {
				es.Code = status.ExitStatus()
			} else if status.Signaled() {
				es.Signal = int(status.Signal())
			}
			ch <- es
		}
		if t.fds != nil {
			t.fds.clearTGID(tgid)
		}
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
				LastNr:             -1,
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
	defer t.cancelPendingAttachWaiters()
	defer t.cancelPendingExitWaiters()

	t.fds = newFdTracker()
	if t.cfg.TraceNetwork && t.cfg.NetworkHandler != nil {
		proxy, err := newDNSProxy(t.cfg.NetworkHandler, t.fds)
		if err != nil {
			slog.Warn("ptrace: failed to start DNS proxy", "error", err)
		} else {
			t.dnsProxy = proxy
			go t.dnsProxy.run(ctx)
			slog.Info("ptrace: DNS proxy started", "addr4", t.dnsProxy.addr4(), "addr6", t.dnsProxy.addr6())
		}
	}

	for {
		if err := t.drainQueues(ctx); err != nil {
			return err
		}

		// Sweep parked timeouts on every iteration so enforcement is not
		// load-dependent (previously only ran on the idle path).
		t.sweepParkedTimeouts()

		if !t.readyFileWritten && t.TraceeCount() > 0 {
			t.writeReadyFile()
		}

		var status unix.WaitStatus
		var rusage unix.Rusage
		tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, &rusage)

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
				case req := <-t.attachQueue:
					if err := t.attachProcess(req.pid, req.opts); err != nil {
						slog.Error("attach from queue failed", "pid", req.pid, "error", err)
						t.signalAttachDone(req.pid, err)
					} else {
						t.signalAttachDone(req.pid, nil)
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
			case req := <-t.attachQueue:
				if err := t.attachProcess(req.pid, req.opts); err != nil {
					slog.Error("attach from queue failed", "pid", req.pid, "error", err)
					t.signalAttachDone(req.pid, err)
				} else {
					t.signalAttachDone(req.pid, nil)
				}
			case req := <-t.resumeQueue:
				t.handleResumeRequest(req)
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}

		t.handleStop(ctx, tid, status, &rusage)
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
		case req := <-t.attachQueue:
			if err := t.attachProcess(req.pid, req.opts); err != nil {
				slog.Error("attach from queue failed", "pid", req.pid, "error", err)
				t.signalAttachDone(req.pid, err)
			} else {
				t.signalAttachDone(req.pid, nil)
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
					t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
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
