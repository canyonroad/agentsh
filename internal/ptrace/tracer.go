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
	ArgLevelFilter   bool
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
	// TGID-level: any thread in this TGID triggered escalation
	NeedsReadEscalation  bool
	NeedsWriteEscalation bool
	// Per-thread: escalation filter installed on this specific thread
	ThreadHasReadEscalation  bool
	ThreadHasWriteEscalation bool
	// Deferred: inject escalation at next exit stop
	PendingReadEscalation  bool
	PendingWriteEscalation bool
	IsVforkChild     bool
	SuppressInitialStop bool // suppress initial SIGSTOP from auto-trace
	LastOpenFlags    int    // flags from last openat/openat2 entry (event-loop-only)
	LastOpenOp       string // operation from last openat/openat2 entry (event-loop-only)
	LastFileAction   string // action from last file entry-time policy check (event-loop-only)
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

	hasSyscallInfo bool // true if PTRACE_GET_SYSCALL_INFO is supported (Linux 5.3+)

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
func (t *Tracer) needsExitStop(nr int) bool {
	switch nr {
	case unix.SYS_READ, unix.SYS_PREAD64:
		return true // only traced when escalated — always needs exit
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		// Exit-time path verification (symlink defense-in-depth) or
		// TracerPid fd tracking. Skip when neither is active.
		return (t.cfg.TraceFile && t.cfg.FileHandler != nil) || t.cfg.MaskTracerPid
	case unix.SYS_CONNECT:
		return t.cfg.TraceNetwork // inline skip in handleNetwork handles port granularity
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT:
		return true // exec failure cleanup
	}
	return false
}

// mustCatchExit returns true if the tracee must be resumed with PtraceSyscall
// to catch the syscall exit stop. True when NeedExitStop is set or when
// pending fixups (deny errno, fake zero, return override, exec stub) require
// exit-time processing.
func mustCatchExit(s *TraceeState) bool {
	if s == nil {
		return false
	}
	return s.NeedExitStop || s.PendingDenyErrno != 0 || s.PendingFakeZero || s.HasPendingReturn || s.PendingExecStubFD >= 0
}

// allowSyscall resumes the tracee, allowing the syscall to proceed.
func (t *Tracer) allowSyscall(tid int) {
	// Fast path: without seccomp prefilter, hasPrefilter is always false,
	// so the result is always PtraceSyscall. Skip the mutex entirely.
	if !t.cfg.SeccompPrefilter {
		if err := unix.PtraceSyscall(tid, 0); err != nil && errors.Is(err, unix.ESRCH) {
			t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
		}
		return
	}

	t.mu.Lock()
	hasPrefilter := false
	needExit := false
	if s := t.tracees[tid]; s != nil {
		hasPrefilter = s.HasPrefilter
		needExit = mustCatchExit(s)
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
// Uses PtraceCont when prefilter is active and no exit stop is needed,
// PtraceSyscall otherwise.
func (t *Tracer) resumeTracee(tid int, sig int) {
	// Fast path: without seccomp prefilter, always use PtraceSyscall.
	if !t.cfg.SeccompPrefilter {
		unix.PtraceSyscall(tid, sig)
		return
	}

	t.mu.Lock()
	hasPrefilter := false
	needExit := false
	if s := t.tracees[tid]; s != nil {
		hasPrefilter = s.HasPrefilter
		needExit = mustCatchExit(s)
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
				if t.shouldDetachAfterExec(tid) {
					if err := unix.PtraceDetach(tid); err != nil && err != unix.ESRCH {
						slog.Warn("ptrace: detach after exec failed, resuming instead", "tid", tid, "err", err)
						t.resumeTracee(tid, 0)
					} else {
						t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
					}
				} else {
					t.resumeTracee(tid, 0)
				}
			case unix.PTRACE_EVENT_SECCOMP:
				t.handleSeccompStop(ctx, tid)
			case unix.PTRACE_EVENT_EXIT:
				t.handleExitEvent(tid)
			case unix.PTRACE_EVENT_STOP:
				t.handleEventStop(tid)
			default:
				// With TRACESYSGOOD always set, syscall stops are SIGTRAP|0x80.
				// Seccomp entries are PTRACE_EVENT_SECCOMP. A plain SIGTRAP
				// with no event is always a real signal — reinject it.
				t.resumeTracee(tid, int(sig))
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
	// Deferred seccomp prefilter and escalation injection are only relevant
	// when SeccompPrefilter is configured. Skip entirely in nofilter mode
	// to avoid dead-code mutex acquisitions.
	if t.cfg.SeccompPrefilter {
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
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.InSyscall = true
				}
				t.mu.Unlock()
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.HasPrefilter = true
					s.InSyscall = true
				}
				t.mu.Unlock()
			}
			// Fall through to normal exit handling for this syscall.
			// Do NOT return — the first syscall's exit handlers still need to run.
			// InSyscall=true restored above so the normal toggle correctly
			// identifies this as a syscall exit (entering := !state.InSyscall → false).
		} else {
			t.mu.Unlock()
		}

		// Deferred BPF escalation: inject escalation filters at exit stops.
		// Follows the same pattern as PendingPrefilter above.
		// Only attempt injection when a seccomp prefilter is installed;
		// without one, all syscalls are already traced via TRACESYSGOOD.
		t.mu.Lock()
		state = t.tracees[tid]
		if state != nil && state.HasPrefilter && state.InSyscall && state.PendingReadEscalation {
			state.PendingReadEscalation = false
			state.InSyscall = false
			t.mu.Unlock()
			if err := t.injectEscalationFilter(tid, readEscalationSyscalls); err != nil {
				slog.Warn("deferred read escalation failed", "tid", tid, "error", err)
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.InSyscall = true
				}
				t.mu.Unlock()
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.ThreadHasReadEscalation = true
					s.InSyscall = true
				}
				t.mu.Unlock()
			}
		} else if state != nil && state.HasPrefilter && state.InSyscall && state.PendingWriteEscalation {
			state.PendingWriteEscalation = false
			state.InSyscall = false
			t.mu.Unlock()
			if err := t.injectEscalationFilter(tid, writeEscalationSyscalls); err != nil {
				slog.Warn("deferred write escalation failed", "tid", tid, "error", err)
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.InSyscall = true
				}
				t.mu.Unlock()
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.ThreadHasWriteEscalation = true
					s.InSyscall = true
				}
				t.mu.Unlock()
			}
		} else if state != nil && state.HasPrefilter && !state.InSyscall {
			// Entry stop — set pending flags for next exit.
			if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
				state.PendingReadEscalation = true
			}
			if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
				state.PendingWriteEscalation = true
			}
			t.mu.Unlock()
		} else {
			t.mu.Unlock()
		}
	}

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
		sc, err := t.buildSyscallContext(tid)
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		nr := sc.Info.Nr
		// LastNr, NeedExitStop are only accessed from the event-loop
		// goroutine (runtime.LockOSThread), no mutex needed. TGID is
		// immutable after creation.
		state.LastNr = nr
		state.NeedExitStop = t.needsExitStop(nr)

		// Fast-path vfork children for known safe setup syscalls.
		if state.IsVforkChild && !isExecveSyscall(nr) && isVforkSafeSyscall(nr) {
			t.allowSyscall(tid)
			return
		}

		t.dispatchSyscall(ctx, tid, nr, sc)
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
		// LastNr, NeedExitStop are event-loop-only — no mutex needed.
		nr := state.LastNr
		needExitHandler := state.NeedExitStop
		state.NeedExitStop = false

		if needExitHandler && nr >= 0 {
			exitRegs, err := t.getRegs(tid)
			if err == nil {
				t.handleSyscallExit(ctx, tid, nr, exitRegs)
			}
		}

		t.allowSyscall(tid)
	}
}

// handleSeccompStop handles PTRACE_EVENT_SECCOMP stops (prefilter mode).
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
	sc, err := t.buildSyscallContext(tid)
	if err != nil {
		t.allowSyscall(tid)
		return
	}
	nr := sc.Info.Nr

	// Mark as syscall-entry so that injection helpers (injectSyscall)
	// use the single-phase entry protocol (modify ORIG_RAX, one cycle
	// to exit) instead of the two-phase gadget protocol.
	t.mu.Lock()
	state := t.tracees[tid]
	isVfork := state != nil && state.IsVforkChild
	if state != nil {
		state.InSyscall = true
		state.LastNr = nr
		state.NeedExitStop = t.needsExitStop(nr)
		// Seccomp stops are entry-only. Defer escalation to next exit stop.
		if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
			state.PendingReadEscalation = true
		}
		if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
			state.PendingWriteEscalation = true
		}
	}
	t.mu.Unlock()

	// Fast-path: vfork children skip policy for known safe setup syscalls.
	// Between vfork and exec, only async-signal-safe operations should occur.
	// Safe syscalls (close, dup2, sigaction, etc.) are allowed immediately.
	// Execve gets full policy evaluation. Anything else (file, network,
	// signal) goes through normal dispatch for policy enforcement.
	if isVfork && !isExecveSyscall(nr) && isVforkSafeSyscall(nr) {
		t.allowSyscall(tid)
		return
	}

	t.dispatchSyscall(ctx, tid, nr, sc)
}

// dispatchSyscall routes a syscall to the appropriate handler.
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, sc *SyscallContext) {
	switch {
	case isExecveSyscall(nr):
		t.handleExecve(ctx, tid, sc)
	case isFileSyscall(nr):
		t.handleFile(ctx, tid, sc)
	case isNetworkSyscall(nr):
		t.handleNetwork(ctx, tid, sc)
	case isSignalSyscall(nr):
		t.handleSignal(ctx, tid, sc)
	case isWriteSyscall(nr):
		t.handleWrite(ctx, tid, sc)
	case isCloseSyscall(nr):
		t.handleClose(ctx, tid, sc)
	case isReadSyscall(nr):
		t.handleReadEntry(tid, sc)
	default:
		t.allowSyscall(tid)
	}
}

// handleSyscallExit runs exit-time handlers for syscalls that need post-processing.
func (t *Tracer) handleSyscallExit(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isReadSyscall(nr):
		t.handleReadExit(tid, regs)
	case nr == unix.SYS_OPENAT || nr == unix.SYS_OPENAT2:
		t.handleOpenatExit(ctx, tid, regs)
	case nr == unix.SYS_CONNECT:
		t.handleConnectExit(tid, regs)
	}
}

// handleOpenatExit verifies the opened path against policy and tracks
// /proc/*/status fds for TracerPid masking.
func (t *Tracer) handleOpenatExit(ctx context.Context, tid int, regs Regs) {
	retVal := regs.ReturnValue()
	if retVal < 0 {
		return // open failed
	}
	fd := int(retVal)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	// Event-loop-only fields — no mutex needed.
	nr := unix.SYS_OPENAT
	openFlags := 0
	openOp := "open"
	entryAction := ""
	if state != nil {
		nr = state.LastNr
		openFlags = state.LastOpenFlags
		openOp = state.LastOpenOp
		entryAction = state.LastFileAction
	}

	// Read the real path the kernel opened.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil {
		// Cannot verify — fail closed only when file policy is active.
		if t.cfg.FileHandler != nil && t.cfg.TraceFile {
			slog.Warn("handleOpenatExit: cannot read fd path, denying",
				"tid", tid, "fd", fd, "error", err)
			savedRegs := regs.Clone()
			t.cleanupInjectedFD(tid, savedRegs, fd, -1)
			t.applyReturnOverride(tid, -int64(unix.EACCES))
		}
		return
	}

	// TracerPid masking: track fds opened on /proc/*/status.
	if t.fds != nil && t.cfg.MaskTracerPid && isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
		t.escalateReadForTGID(tgid, tid)
	}

	// Exit-time path verification: only re-check when entry-time allowed.
	// If entry denied, the syscall was already blocked. If entry redirected
	// or soft-deleted, the kernel operated on the modified path — exit-time
	// readlink reflects that modified path, not a symlink bypass.
	// No sessionID gate — consistent with entry-time handleFile which also
	// calls HandleFile regardless of session state.
	if t.cfg.FileHandler != nil && t.cfg.TraceFile &&
		(entryAction == "allow" || entryAction == "continue" || entryAction == "") {
		result := t.cfg.FileHandler.HandleFile(ctx, FileContext{
			PID:       tgid,
			SessionID: sessionID,
			Syscall:   nr,
			Path:      path,
			Operation: openOp,
			Flags:     openFlags,
		})
		action := result.Action
		if action == "" {
			if result.Allow {
				action = "allow"
			} else {
				action = "deny"
			}
		}
		// At exit time, only "allow" and "continue" are valid passes.
		// Redirect/soft-delete cannot be enforced post-open — treat as deny.
		if action != "allow" && action != "continue" {
			errno := result.Errno
			if errno == 0 {
				errno = int32(unix.EACCES)
			}
			slog.Warn("handleOpenatExit: exit-time verification denied",
				"tid", tid, "fd", fd, "path", path, "action", action)
			savedRegs := regs.Clone()
			t.cleanupInjectedFD(tid, savedRegs, fd, -1)
			t.applyReturnOverride(tid, -int64(errno))
		}
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
	// Escalate BPF to trace write for this TGID.
	t.escalateWriteForTGID(tgid, tid)
}

// escalateReadForTGID marks all threads in the TGID for read/pread64
// escalation and injects the escalation filter into the triggering thread.
func (t *Tracer) escalateReadForTGID(tgid int, triggerTID int) {
	t.mu.Lock()
	for _, s := range t.tracees {
		if s.TGID == tgid {
			s.NeedsReadEscalation = true
		}
	}
	triggerState := t.tracees[triggerTID]
	alreadyEscalated := triggerState != nil && triggerState.ThreadHasReadEscalation
	hasPrefilter := triggerState != nil && triggerState.HasPrefilter
	t.mu.Unlock()

	if alreadyEscalated || !hasPrefilter {
		return
	}

	if err := t.injectEscalationFilter(triggerTID, readEscalationSyscalls); err != nil {
		slog.Warn("read escalation injection failed", "tid", triggerTID, "error", err)
		return
	}

	t.mu.Lock()
	if s := t.tracees[triggerTID]; s != nil {
		s.ThreadHasReadEscalation = true
	}
	t.mu.Unlock()
}

// escalateWriteForTGID marks all threads in the TGID for write
// escalation and injects the escalation filter into the triggering thread.
func (t *Tracer) escalateWriteForTGID(tgid int, triggerTID int) {
	t.mu.Lock()
	for _, s := range t.tracees {
		if s.TGID == tgid {
			s.NeedsWriteEscalation = true
		}
	}
	triggerState := t.tracees[triggerTID]
	alreadyEscalated := triggerState != nil && triggerState.ThreadHasWriteEscalation
	hasPrefilter := triggerState != nil && triggerState.HasPrefilter
	t.mu.Unlock()

	if alreadyEscalated || !hasPrefilter {
		return
	}

	if err := t.injectEscalationFilter(triggerTID, writeEscalationSyscalls); err != nil {
		slog.Warn("write escalation injection failed", "tid", triggerTID, "error", err)
		return
	}

	t.mu.Lock()
	if s := t.tracees[triggerTID]; s != nil {
		s.ThreadHasWriteEscalation = true
	}
	t.mu.Unlock()
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
		// Children inherit parent's kernel filter stack via fork().
		// Skip PendingPrefilter if parent already has a filter installed.
		if parent.HasPrefilter {
			existing.PendingPrefilter = false
		} else {
			existing.PendingPrefilter = parent.PendingPrefilter
		}
		existing.NeedsReadEscalation = parent.NeedsReadEscalation
		existing.NeedsWriteEscalation = parent.NeedsWriteEscalation
		existing.ThreadHasReadEscalation = parent.ThreadHasReadEscalation
		existing.ThreadHasWriteEscalation = parent.ThreadHasWriteEscalation
		existing.Attached = time.Now()
	} else {
		pendingPrefilter := false
		if !parent.HasPrefilter {
			pendingPrefilter = parent.PendingPrefilter
		}
		t.tracees[tid] = &TraceeState{
			TID:                      tid,
			TGID:                     childTGID,
			ParentPID:                parent.TGID,
			SessionID:                parent.SessionID,
			HasPrefilter:             parent.HasPrefilter,
			PendingPrefilter:         pendingPrefilter,
			NeedsReadEscalation:      parent.NeedsReadEscalation,
			NeedsWriteEscalation:     parent.NeedsWriteEscalation,
			ThreadHasReadEscalation:  parent.ThreadHasReadEscalation,
			ThreadHasWriteEscalation: parent.ThreadHasWriteEscalation,
			Attached:                 time.Now(),
			LastNr:                   -1,
			MemFD:                    -1,
			PendingExecStubFD:        -1,
			PendingExecSavedFD:       -1,
			SuppressInitialStop:      true,
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

// shouldDetachAfterExec checks whether a tracee should be detached after exec.
// Returns true if: parent is traced, no exitNotify registered, no seccomp
// prefilter.  Without a prefilter the child doesn't inherit a SECCOMP_RET_TRACE
// filter, so detaching is safe and prevents pipe deadlocks between two ptraced
// processes on gVisor.
func (t *Tracer) shouldDetachAfterExec(tid int) bool {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		return false
	}
	// Don't detach if seccomp prefilter is active — child inherits the
	// SECCOMP_RET_TRACE filter and would get ENOSYS without a tracer.
	if state.HasPrefilter {
		t.mu.Unlock()
		return false
	}
	tgid := state.TGID
	parentTraced := false
	if state.ParentPID != 0 {
		for otherTID, other := range t.tracees {
			if otherTID != tid && other.TGID == state.ParentPID {
				parentTraced = true
				break
			}
		}
	}
	t.mu.Unlock()

	_, hasExitNotify := t.exitNotify.Load(tgid)
	return parentTraced && !hasExitNotify
}

// handleExitEvent decides whether to detach or resume a tracee that hit
// PTRACE_EVENT_EXIT.  On gVisor, the sentry's two-phase exit notification
// re-delivery is unreliable: if a traced child exits, the traced parent's
// wait4 may block forever.  Detaching auto-traced children whose parent is
// also traced lets the parent reap them directly.
func (t *Tracer) handleExitEvent(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		t.resumeTracee(tid, 0)
		return
	}
	tgid := state.TGID
	parentTraced := false
	if state.ParentPID != 0 {
		for otherTID, other := range t.tracees {
			if otherTID != tid && other.TGID == state.ParentPID {
				parentTraced = true
				break
			}
		}
	}
	t.mu.Unlock()

	// Never detach processes with a registered exit notification —
	// the exec API is blocking on that channel.
	_, hasExitNotify := t.exitNotify.Load(tgid)

	if parentTraced && !hasExitNotify {
		// Detach so the traced parent can reap the child directly,
		// bypassing gVisor's two-phase exit notification re-delivery.
		// Detach first: if it fails with anything other than ESRCH
		// (process already gone), fall back to the normal resume path
		// so the tracee stays tracked.
		if err := unix.PtraceDetach(tid); err != nil && err != unix.ESRCH {
			slog.Warn("ptrace: detach on exit failed, resuming instead", "tid", tid, "err", err)
			t.resumeTracee(tid, 0)
			return
		}
		t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
		return
	}

	t.resumeTracee(tid, 0)
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
func (t *Tracer) handleExecve(ctx context.Context, tid int, sc *SyscallContext) {
	if t.cfg.ExecHandler == nil || !t.cfg.TraceExecve {
		t.allowSyscall(tid)
		return
	}

	nr := sc.Info.Nr
	var filenamePtr uint64
	if nr == unix.SYS_EXECVEAT {
		filenamePtr = sc.Info.Args[1]
	} else {
		filenamePtr = sc.Info.Args[0]
	}

	filename, err := t.readString(tid, filenamePtr, 4096)
	if err != nil {
		slog.Warn("handleExecve: cannot read filename", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	var argvPtr uint64
	if nr == unix.SYS_EXECVEAT {
		argvPtr = sc.Info.Args[2]
	} else {
		argvPtr = sc.Info.Args[1]
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

	// Reset scratch page so exec redirect operations start fresh.
	t.resetScratchIfPresent(tgid)

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
		regs, err := sc.Regs()
		if err != nil {
			slog.Warn("handleExecve: cannot load regs for redirect, denying", "tid", tid, "error", err)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}
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

	t.hasSyscallInfo = probePtraceSyscallInfo()
	if t.hasSyscallInfo {
		slog.Info("ptrace: PTRACE_GET_SYSCALL_INFO supported")
	}

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

	// Reusable idle timer to avoid per-iteration allocation from time.After.
	idleTimer := time.NewTimer(5 * time.Millisecond)
	defer idleTimer.Stop()

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
			case <-idleTimer.C:
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(5 * time.Millisecond)
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
