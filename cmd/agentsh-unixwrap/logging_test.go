//go:build linux && cgo

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/wrapperlog"
	"golang.org/x/sys/unix"
)

// resetLogging restores the process-global logging state mutated by
// setupLogging so tests don't leak into each other.
func resetLogging(origSlog *slog.Logger) {
	log.SetOutput(os.Stderr)
	slog.SetDefault(origSlog)
	logDest = nil
}

func TestSetupLogging_RoutesBothSinksAndSetsCloexec(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// Hand setupLogging a dup of the write end so logDest owns its fd
	// exclusively; w keeps owning the original. Without the dup, two
	// *os.File values share one fd and w's finalizer would re-close a
	// possibly-reused fd number after logDest.Close().
	dupFD, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	t.Setenv(wrapperlog.EnvKey, strconv.Itoa(dupFD))

	setupLogging()

	if os.Getenv(wrapperlog.EnvKey) != "" {
		t.Error("env var not stripped after setupLogging")
	}
	if logDest == nil {
		t.Fatal("logDest not set for a valid fd")
	}
	flags, err := unix.FcntlInt(uintptr(dupFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("fcntl(F_GETFD): %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("FD_CLOEXEC not set on log fd")
	}

	log.Printf("stdlib-marker")
	slog.Info("slog-marker")

	logDest.Close() // closes the dup — its sole owner
	w.Close()       // close the original write end too so the reader sees EOF
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "stdlib-marker") {
		t.Errorf("stdlib log not routed, got: %s", s)
	}
	if !strings.Contains(s, "slog-marker") {
		t.Errorf("slog not routed, got: %s", s)
	}
}

func TestSetupLogging_InvalidFDFallsBackToStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	// Use an fd number far above any plausible rlimit so Fstat is
	// guaranteed to fail with EBADF — no fd-reuse race window, unlike
	// probing with a just-closed real fd.
	const closedFD = 1 << 20

	t.Setenv(wrapperlog.EnvKey, strconv.Itoa(closedFD))
	setupLogging()
	if logDest != nil {
		t.Fatal("expected stderr fallback for closed fd")
	}
	if os.Getenv(wrapperlog.EnvKey) != "" {
		t.Error("env var must be stripped even on fallback")
	}
}

func TestSetupLogging_NonNumericFallsBackToStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	t.Setenv(wrapperlog.EnvKey, "not-a-number")
	setupLogging()
	if logDest != nil {
		t.Fatal("expected stderr fallback for non-numeric value")
	}
	if os.Getenv(wrapperlog.EnvKey) != "" {
		t.Error("env var must be stripped even on parse failure")
	}
}

func TestSetupLogging_UnsetKeepsStderr(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	t.Setenv(wrapperlog.EnvKey, "")
	setupLogging()
	if logDest != nil {
		t.Fatal("expected no routing when env var unset")
	}
}

func TestWriteFatal_DualWritesWhenRouted(t *testing.T) {
	orig := slog.Default()
	defer resetLogging(orig)

	destR, destW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	logDest = destW

	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = errW
	defer func() { os.Stderr = origStderr }()

	writeFatal("boom: 42")

	destW.Close()
	errW.Close()
	destOut, _ := io.ReadAll(destR)
	errOut, _ := io.ReadAll(errR)
	if !strings.Contains(string(destOut), "boom: 42") {
		t.Errorf("routed destination missing message: %q", destOut)
	}
	if !strings.Contains(string(errOut), "boom: 42") {
		t.Errorf("stderr missing message: %q", errOut)
	}
}

// wrapperFMHelperEnv gates the re-exec child body for
// TestSetupLogging_NoSelfDeadlockUnderFileMonitor. Never set it outside
// the parent->child dispatch: the child installs a real seccomp filter.
const wrapperFMHelperEnv = "AGENTSH_TEST_WRAPPER_FM_HELPER"

// TestSetupLogging_NoSelfDeadlockUnderFileMonitor re-execs the test
// binary to reproduce the #415/PR#419 CI hang: with diagnostics routed
// (AGENTSH_WRAPPER_LOG_FD set) and a file-monitor seccomp filter
// installed, the first routed slog record must not perform a trapped
// syscall (lazy tzdata openat) while nobody drains the notify fd —
// that self-deadlocks the wrapper. The child routes its logs, installs
// a FileMonitorEnabled filter, emits one slog record, and exits 0; the
// parent fails if the child does not finish within a generous timeout.
func TestSetupLogging_NoSelfDeadlockUnderFileMonitor(t *testing.T) {
	if os.Getenv(wrapperFMHelperEnv) == "1" {
		// Child: route diagnostics to the inherited fd (set by parent),
		// install a file-monitor filter, then log — exactly the
		// production sequence that deadlocked when tzdata loaded lazily.
		setupLogging()
		cfg := unixmon.FilterConfig{FileMonitorEnabled: true, InterceptMetadata: true}
		if _, err := unixmon.InstallFilterWithConfig(cfg); err != nil {
			// Mirror the skip conditions the parent checks for.
			fmt.Fprintf(os.Stderr, "install filter: %v\n", err)
			os.Exit(3)
		}
		slog.Info("post-filter routed record")
		os.Exit(0)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	logR, logW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer logR.Close()
	defer logW.Close()
	// Drain the routed sink so it can never backpressure the child:
	// if wrapper diagnostics ever outgrow the pipe buffer, an undrained
	// pipe would block the child post-filter and masquerade as the tz
	// deadlock this test guards against.
	go func() { _, _ = io.Copy(io.Discard, logR) }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSetupLogging_NoSelfDeadlockUnderFileMonitor$")
	cmd.ExtraFiles = []*os.File{logW} // fd 3 in the child
	cmd.Env = append(os.Environ(),
		wrapperFMHelperEnv+"=1",
		wrapperlog.EnvKey+"=3",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	runErr := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("child deadlocked under file-monitor filter (#415 tz lazy-load regression)\noutput:\n%s", out.String())
	}
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok && ee.ExitCode() == 3 {
			lower := strings.ToLower(out.String())
			if strings.Contains(lower, "permission denied") ||
				strings.Contains(lower, "operation not permitted") ||
				strings.Contains(lower, "unsupported") {
				t.Skipf("host cannot install seccomp filter; skipping.\n%s", out.String())
			}
		}
		t.Fatalf("child failed: %v\noutput:\n%s", runErr, out.String())
	}
}
