//go:build linux && cgo

package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/agentsh/agentsh/internal/wrapperlog"
	"golang.org/x/sys/unix"
)

// logDest is the routed diagnostics destination; nil means stderr (no
// routing active). Set by setupLogging, consulted by writeFatal.
var logDest *os.File

// setupLogging routes the wrapper's diagnostics (default slog handler +
// stdlib log) to the inherited fd named by wrapperlog.EnvKey, so the
// per-exec "seccomp: filter loaded" line and friends land in the
// parent's log sink instead of the wrapped command's stderr (issue
// #415). Must run first thing in main(), before anything can log.
//
// Every failure path falls back to stderr (legacy behavior) — logging
// must never abort an exec.
func setupLogging() {
	val := os.Getenv(wrapperlog.EnvKey)
	// Strip unconditionally: syscall.Exec passes os.Environ() to the
	// wrapped command, and a stale fd number inherited by a NESTED
	// wrapper invocation (wrapped command → shell → shim → wrapper)
	// could point at an unrelated fd reused by the intermediate
	// process — the nested wrapper would write log lines onto it.
	_ = os.Unsetenv(wrapperlog.EnvKey)
	if val == "" {
		return
	}
	fd, err := strconv.Atoi(val)
	if err != nil || fd < 0 {
		log.Printf("warning: invalid %s=%q; wrapper diagnostics stay on stderr", wrapperlog.EnvKey, val)
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		log.Printf("warning: %s=%d is not a usable fd (%v); wrapper diagnostics stay on stderr", wrapperlog.EnvKey, fd, err)
		return
	}
	// Close-on-exec: the wrapped command must never inherit the log
	// destination. All wrapper logging happens before syscall.Exec, and
	// pipe-backed parents rely on this close for drain-goroutine EOF.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		log.Printf("warning: set FD_CLOEXEC on %s=%d: %v; wrapper diagnostics stay on stderr", wrapperlog.EnvKey, fd, err)
		return
	}
	f := os.NewFile(uintptr(fd), "wrapper-log")
	if f == nil {
		log.Printf("warning: cannot adopt %s=%d; wrapper diagnostics stay on stderr", wrapperlog.EnvKey, fd)
		return
	}
	log.SetOutput(f)
	slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
	logDest = f
}

// fatalf replaces log.Fatalf: a user whose command dies must still see
// why on stderr even when diagnostics are routed elsewhere, and the
// routed sink (server log / state file) must record it too.
func fatalf(format string, args ...any) {
	writeFatal(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// writeFatal writes msg to the routed destination (when active) and
// always to stderr. Split from fatalf so the dual-write is testable
// without os.Exit.
func writeFatal(msg string) {
	if logDest != nil {
		fmt.Fprintln(logDest, msg)
	}
	fmt.Fprintln(os.Stderr, msg)
}
