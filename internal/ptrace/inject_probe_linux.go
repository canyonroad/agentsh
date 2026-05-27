//go:build linux

package ptrace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Issue #369: ptrace syscall *injection* can be silently broken on a kernel
// even when attach/seize works. On exe.dev 6.12.90 an injected
// mmap(NULL, 4096, ...) returns a plausible page-aligned address but creates NO
// VMA in the tracee — the prefilter's scratch-page write then EIOs and the
// command dies. A read-only "can we ptrace?" capability check cannot catch
// this; only exercising the *production gadget inject* against a controlled
// child and verifying a real mapping appears can.
//
// ProbePtraceInject re-execs a throwaway child that simply blocks, attaches to
// it, drives it to a between-syscalls EXIT stop, and runs the SAME
// ensureScratchPage → injectSyscallRet(SYS_MMAP) → injectFromExit gadget path
// the runtime uses. If the injected mmap's returned address is not present in
// the child's /proc/<pid>/maps, injection is declared non-functional.
//
// This file intentionally mirrors the structure of
// internal/netmonitor/unix/seccomp_install_probe_linux.go (re-exec child +
// argv sentinel + >=16-char env token two-factor detection + init() dispatch).

const (
	injectProbeArgvSentinel = "--agentsh-internal-ptrace-inject-probe-child-v1"
	injectProbeEnv          = "AGENTSH_PTRACE_INJECT_PROBE_CHILD"
	// injectProbeIterations is how many independent inject attempts must all
	// map before we trust injection. A genuinely broken kernel fails the
	// FIRST iteration cleanly and repeatably (#369), so 8 is ample margin
	// without meaningfully slowing a healthy boot.
	injectProbeIterations = 8
	// injectProbeIterDeadline bounds a single iteration so a hung child or
	// lost stop cannot stall startup. On timeout the iteration is treated as
	// a probe error (fail-open), not a clean mapped==false.
	injectProbeIterDeadline = 1 * time.Second
)

// InjectProbeResult reports whether ptrace syscall injection actually produces
// real mappings on this kernel. Detail carries human-readable context for logs.
type InjectProbeResult struct {
	Injectable bool
	Detail     string
}

var (
	probeInjectOnce   sync.Once
	probeInjectResult InjectProbeResult
)

// injectProbeChildTokenOnce/Token is the per-process random token the parent
// uses to authenticate inject-probe-child invocations (defence-in-depth: a
// stray sentinel argv alone must never trip the child path).
var (
	injectProbeChildTokenOnce sync.Once
	injectProbeChildToken     string
)

func ensureInjectProbeChildToken() string {
	injectProbeChildTokenOnce.Do(func() {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			injectProbeChildToken = fmt.Sprintf("pid-%d-time-%d", os.Getpid(), time.Now().UnixNano())
			return
		}
		injectProbeChildToken = hex.EncodeToString(b[:])
	})
	return injectProbeChildToken
}

// isInjectProbeChildInvocation gates inject-probe-child mode (two-factor: argv
// sentinel + env token length >= 16), mirroring isInstallProbeChildInvocation.
func isInjectProbeChildInvocation() bool {
	if len(os.Args) < 2 || os.Args[1] != injectProbeArgvSentinel {
		return false
	}
	return len(os.Getenv(injectProbeEnv)) >= 16
}

func init() {
	if isInjectProbeChildInvocation() {
		runInjectProbeChild()
		os.Exit(0) // unreachable: runInjectProbeChild blocks/exits
	}
}

// runInjectProbeChild is the child sentinel: it blocks forever so the parent
// probe can attach, inject a test mmap, verify the mapping, and kill it. It is
// only reached when both the sentinel argv and a valid env token are present,
// so a normal `agentsh` invocation never enters here. PTRACE_O_EXITKILL set by
// the parent guarantees the child dies if the parent does, so a lost parent
// cannot orphan a blocked child.
func runInjectProbeChild() {
	for {
		// Pause returns on signal delivery; loop so a stray signal cannot let
		// the child fall through and exit before the parent finishes.
		_ = unix.Pause()
	}
}

// ProbePtraceInject reports whether ptrace syscall injection creates real
// mappings on this kernel. Cached per process via sync.Once.
//
// Fail-OPEN: if the probe cannot run to a clean conclusion (exec/fork fails,
// attach denied, unexpected wait state, timeout), it returns Injectable=true
// with an "inconclusive" Detail. A genuinely broken kernel (#369) produces a
// clean, repeatable mapped==false on the first iteration — that, and only
// that, returns Injectable=false. Assuming healthy on a probe *error* avoids
// spuriously disabling ptrace on hosts where the probe merely had trouble.
func ProbePtraceInject() InjectProbeResult {
	probeInjectOnce.Do(func() {
		probeInjectResult = runInjectProbe()
	})
	return probeInjectResult
}

// runInjectProbe runs injectProbeIterations independent inject attempts. The
// caller (ProbePtraceInject) caches the result.
func runInjectProbe() InjectProbeResult {
	// ptrace requires every call for a tracee to originate from the same OS
	// thread. Pin for the whole probe.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	self, err := os.Executable()
	if err != nil {
		return InjectProbeResult{Injectable: true, Detail: fmt.Sprintf("ptrace inject probe inconclusive: os.Executable: %v", err)}
	}
	token := ensureInjectProbeChildToken()

	for i := 0; i < injectProbeIterations; i++ {
		mapped, detail, probeErr := runInjectProbeIteration(self, token)
		if probeErr != nil {
			// Fail-open on any inability to run the probe cleanly.
			return InjectProbeResult{Injectable: true, Detail: fmt.Sprintf("ptrace inject probe inconclusive: %v", probeErr)}
		}
		if !mapped {
			// Clean, repeatable broken-kernel signal: disable injection.
			return InjectProbeResult{Injectable: false, Detail: detail}
		}
	}
	return InjectProbeResult{Injectable: true, Detail: fmt.Sprintf("ptrace inject probe: %d/%d mmap mapped", injectProbeIterations, injectProbeIterations)}
}

// runInjectProbeIteration runs one inject attempt against a fresh child.
//
// Return contract:
//   - (true, "", nil)        injected mmap created a real mapping (success)
//   - (false, detail, nil)   injected mmap returned but did NOT map (broken kernel)
//   - (_, _, err)            probe could not run cleanly (fail-open at caller)
func runInjectProbeIteration(self, token string) (mapped bool, detail string, probeErr error) {
	cmd := exec.Command(self, injectProbeArgvSentinel)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}
	cmd.Env = append(os.Environ(), injectProbeEnv+"="+token)
	if err := cmd.Start(); err != nil {
		return false, "", fmt.Errorf("start probe child: %w", err)
	}
	pid := cmd.Process.Pid

	// Watchdog: ptrace requires every call for this tracee to come from the
	// caller's (locked) OS thread, so the inject body MUST run inline — we
	// cannot move it to another goroutine for a select-on-timeout. Instead a
	// watchdog goroutine SIGKILLs the whole child pgroup (Setpgid ⇒ pid==pgid)
	// if the body overruns the deadline. A killed tracee makes the inline
	// ptrace/Wait4 calls fail (ESRCH / exit status), so the body unwinds with a
	// probe error → fail-open. timedOut records the cause for that error.
	var timedOut bool
	watchdogDone := make(chan struct{})
	watchdogStop := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		select {
		case <-time.After(injectProbeIterDeadline):
			timedOut = true
			_ = unix.Kill(-pid, unix.SIGKILL)
		case <-watchdogStop:
		}
	}()

	mapped, detail, probeErr = injectProbeBody(pid)

	// Stop the watchdog and ensure it has observed timedOut before we read it.
	close(watchdogStop)
	<-watchdogDone

	// Final teardown: kill the whole pgroup (idempotent if the watchdog
	// already did) and reap.
	_ = unix.Kill(-pid, unix.SIGKILL)
	_, _ = cmd.Process.Wait()

	if timedOut {
		return false, "", fmt.Errorf("probe iteration timed out after %v (pid %d)", injectProbeIterDeadline, pid)
	}
	return mapped, detail, probeErr
}

// injectProbeBody attaches to an already-started, ptrace-stopped child, drives
// it to a between-syscalls EXIT stop, and runs the production gadget mmap
// inject via ensureScratchPage. It MUST run on the locked OS thread that
// started the child (the caller pins it).
func injectProbeBody(pid int) (mapped bool, detail string, probeErr error) {
	// 1. Reap the initial exec/trace stop (SysProcAttr.Ptrace ⇒ TRACEME).
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return false, "", fmt.Errorf("initial wait4: %w", err)
	}
	if !ws.Stopped() {
		return false, "", fmt.Errorf("child did not reach initial trace stop: status=%v", ws)
	}

	// TRACESYSGOOD so syscall stops carry SIGTRAP|0x80 (matches the runtime and
	// what the inject wait loop expects); EXITKILL so the child cannot outlive
	// the probe.
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_EXITKILL); err != nil {
		return false, "", fmt.Errorf("PTRACE_SETOPTIONS: %w", err)
	}

	// 2. Build a minimal tracer to reuse the production inject path. We do NOT
	// run its event loop; we only borrow its inject helpers + tracee state map.
	tr := NewTracer(TracerConfig{SeccompPrefilter: true})
	tr.hasSyscallInfo = probePtraceSyscallInfo()
	tr.mu.Lock()
	tr.tracees[pid] = &TraceeState{TID: pid, TGID: pid, InSyscall: false, MemFD: -1}
	tr.mu.Unlock()

	// 3. Drive the child to a between-syscalls EXIT stop so injectFromExit's
	// gadget protocol applies (the path that fails on exe.dev 6.12.90).
	//    a. PtraceSyscall → wait → syscall-ENTER stop.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return false, "", fmt.Errorf("ptracesyscall to entry: %w", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return false, "", fmt.Errorf("wait4 entry: %w", err)
	}
	if !ws.Stopped() {
		return false, "", fmt.Errorf("child exited before syscall-enter: status=%v", ws)
	}
	//    b. Capture entry regs, advance past the entry to leave it at an EXIT
	//       stop (InSyscall=false), then re-read savedRegs.
	savedRegs, err := tr.getRegs(pid)
	if err != nil {
		return false, "", fmt.Errorf("getRegs at entry: %w", err)
	}
	if err := tr.advancePastEntry(pid, savedRegs); err != nil {
		return false, "", fmt.Errorf("advancePastEntry: %w", err)
	}
	savedRegs, err = tr.getRegs(pid)
	if err != nil {
		return false, "", fmt.Errorf("getRegs after advancePastEntry: %w", err)
	}

	// 4. THE PRODUCTION GADGET MMAP INJECT. ensureScratchPage injects the mmap
	// and itself verifies a real VMA appeared at the returned address (#369).
	// classifyScratchInjectErr turns its result into the probe's contract.
	if _, err := tr.ensureScratchPage(pid, pid, savedRegs); err != nil {
		return classifyScratchInjectErr(err)
	}
	return true, "", nil
}

// classifyScratchInjectErr maps an ensureScratchPage error to the inject
// probe's (mapped, detail, probeErr) contract (#369):
//   - errScratchUnmapped → the injected mmap returned but mapped no VMA: the
//     clean broken-kernel signal (mapped==false, no probe error), which makes
//     runInjectProbe report Injectable=false and DEGRADE (fail-closed).
//   - any other error → the probe could not run cleanly: a probe error, which
//     makes runInjectProbe report Injectable=true (fail-open).
//
// This is the load-bearing fail-closed/fail-open decision: a regression here
// (or dropping the %w wrap in scratchUnmappedError) silently reverts the probe
// to fail-open on the exact broken-kernel class it exists to catch, so it is
// unit-tested directly.
func classifyScratchInjectErr(err error) (mapped bool, detail string, probeErr error) {
	if errors.Is(err, errScratchUnmapped) {
		return false, fmt.Sprintf("ptrace inject probe: %v", err), nil
	}
	return false, "", fmt.Errorf("ensureScratchPage: %w", err)
}
