//go:build linux && cgo

package main

import (
	"io"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

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
