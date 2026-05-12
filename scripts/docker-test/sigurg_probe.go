// sigurg_probe is a best-effort sanity check that the WAIT_KILLABLE_RECV
// flag is functionally engaged end-to-end. It is invoked inside every
// docker-test matrix cell to catch gross regressions where the kernel
// accepts the flag but it has been silently broken. See
// docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md
// section "Functional smoke test in each cell".
//
// Limitations: the deterministic ERESTARTSYS repro from PR #225 requires
// arm64-VM-under-load conditions; on amd64 docker the race window is
// small enough that absence-of-hang is not a hard regression catcher.
// This program only catches the "kernel accepts flag but it does
// nothing" failure class.
//
// Build:    go build -o sigurg_probe scripts/docker-test/sigurg_probe.go
// Run:      ./sigurg_probe
// Success:  exit 0 within 5 seconds
// Failure:  exit non-zero, message on stderr
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	deadline := time.Now().Add(5 * time.Second)
	var iterations atomic.Int64

	// Goroutine 1: spam SIGURG at the current process. Go's runtime
	// uses SIGURG internally for async preemption (~10 ms cadence), so
	// even without our own signal traffic SIGURG lands inside any
	// blocking syscall. We add an explicit spam to widen the window.
	stop := make(chan struct{})
	go func() {
		pid := os.Getpid()
		for {
			select {
			case <-stop:
				return
			default:
				_ = syscall.Kill(pid, syscall.SIGURG)
				runtime.Gosched()
			}
		}
	}()

	// Goroutine 2 (this goroutine): busy-loop a syscall that, when run
	// under unixwrap's seccomp notify filter, traps to userspace and
	// hits the kernel's wait-for-notification path. Without
	// WAIT_KILLABLE_RECV a SIGURG mid-trap returns ERESTARTSYS and Go's
	// libc retries forever; with the flag the trap completes normally.
	//
	// Outside unixwrap (no filter), this is just a benign getpid loop
	// — the probe still asserts liveness but does not exercise the
	// notify path. The wrapping is provided by the docker invocation.
	for time.Now().Before(deadline) {
		_ = syscall.Getpid()
		iterations.Add(1)
	}
	close(stop)

	if iterations.Load() < 1000 {
		fmt.Fprintf(os.Stderr, "sigurg_probe: only %d iterations in 5s — likely hung\n", iterations.Load())
		os.Exit(2)
	}
	fmt.Fprintf(os.Stdout, "sigurg_probe: ok (%d iterations)\n", iterations.Load())
}
