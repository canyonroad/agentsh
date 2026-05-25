//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Issue #388: detect must report seccomp enforcement from a REAL NEW_LISTENER
// install, not a read-only capability probe. This probe re-execs a throwaway
// child that runs the exact loadRawFilter install the runtime uses and reports
// success or the failing errno.

const (
	installProbeArgvSentinel = "--agentsh-internal-seccomp-install-probe-child-v1"
	installProbeEnv          = "AGENTSH_SECCOMP_INSTALL_PROBE_CHILD"
	installProbeStderrCap    = 4096
	// installErrnoPrefix is printed by the child on failure so the parent can
	// recover the precise errno without encoding it in the exit status.
	installErrnoPrefix = "INSTALL_ERRNO="
)

// InstallProbeResult reports whether agentsh can install its NEW_LISTENER
// seccomp filter in this environment. Errno is 0 when Installable.
type InstallProbeResult struct {
	Installable bool
	Errno       syscall.Errno
	Detail      string
}

// runInstallProbe spawns the probe child and returns its exit code, captured
// (bounded) stderr, and any spawn error. Injectable seam for tests.
var runInstallProbe = realRunInstallProbe

var (
	installProbeOnce   sync.Once
	installProbeResult InstallProbeResult
)

// ProbeSeccompInstall returns whether a NEW_LISTENER filter install succeeds
// here. Cached per process. Fail-safe: any inability to run the probe yields
// Installable=false with a descriptive Detail — never a false positive.
func ProbeSeccompInstall() InstallProbeResult {
	installProbeOnce.Do(func() {
		code, stderr, err := runInstallProbe()
		installProbeResult = classifyInstallProbe(code, stderr, err)
	})
	return installProbeResult
}

func classifyInstallProbe(exitCode int, stderr string, spawnErr error) InstallProbeResult {
	if spawnErr != nil {
		return InstallProbeResult{Installable: false, Detail: fmt.Sprintf("install probe could not run: %v", spawnErr)}
	}
	if exitCode == 0 {
		return InstallProbeResult{Installable: true}
	}
	if errno := parseInstallErrno(stderr); errno != 0 {
		return InstallProbeResult{Installable: false, Errno: errno, Detail: fmt.Sprintf("%s (errno %d)", errno, int(errno))}
	}
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = fmt.Sprintf("install probe exited %d", exitCode)
	}
	return InstallProbeResult{Installable: false, Detail: detail}
}

func parseInstallErrno(stderr string) syscall.Errno {
	for _, line := range strings.Split(stderr, "\n") {
		i := strings.Index(line, installErrnoPrefix)
		if i < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[i+len(installErrnoPrefix):]))
		if err == nil && n > 0 {
			return syscall.Errno(n)
		}
	}
	return 0
}

func realRunInstallProbe() (int, string, error) {
	bin, err := os.Executable()
	if err != nil {
		return -1, "", fmt.Errorf("os.Executable: %w", err)
	}
	cmd := exec.Command(bin, installProbeArgvSentinel)
	cmd.Env = append(os.Environ(), installProbeEnv+"="+ensureProbeChildToken())
	stderr := &boundedBuffer{cap: installProbeStderrCap}
	cmd.Stdout = nil
	cmd.Stderr = stderr
	cmd.Stdin = nil
	runErr := cmd.Run()
	if runErr == nil {
		return 0, stderr.String(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode(), stderr.String(), nil // non-zero exit, not a spawn failure
	}
	return -1, stderr.String(), runErr // could not start / other
}

// isInstallProbeChildInvocation gates probe-child mode (two-factor: argv
// sentinel + env token length >= 16), mirroring isProbeChildInvocation.
func isInstallProbeChildInvocation() bool {
	if len(os.Args) < 2 || os.Args[1] != installProbeArgvSentinel {
		return false
	}
	return len(os.Getenv(installProbeEnv)) >= 16
}

func init() {
	if isInstallProbeChildInvocation() {
		runInstallProbeChild()
		os.Exit(0) // unreachable: runInstallProbeChild always exits
	}
}

// runInstallProbeChild installs the probe filter via the SAME loadRawFilter the
// runtime uses, then exits. The filter's ActAllow default means the child's own
// close/write/exit syscalls are never trapped, so no servicing is needed and
// the child cannot hang. Exits 0 on install success; on failure prints
// INSTALL_ERRNO=<n> (when the error is an errno) and exits 1.
func runInstallProbeChild() {
	prog, err := buildProbeFilterBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seccomp install probe: build filter: %v\n", err)
		os.Exit(1)
	}
	fd, err := loadRawFilter(prog, false)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			fmt.Fprintf(os.Stderr, "seccomp install probe: install filter: %v %s%d\n", err, installErrnoPrefix, int(errno))
		} else {
			fmt.Fprintf(os.Stderr, "seccomp install probe: install filter: %v\n", err)
		}
		os.Exit(1)
	}
	_ = unix.Close(fd)
	os.Exit(0)
}

// probeSeccompUserNotifyKernel is a read-only "does the kernel know user-notify"
// check (SECCOMP_GET_NOTIF_SIZES), used only as a test skip guard. Returns nil
// when supported.
func probeSeccompUserNotifyKernel() error {
	var sizes [3]uint16 // struct seccomp_notif_sizes { __u16 seccomp_notif, seccomp_notif_resp, seccomp_data; }
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return errno
	}
	return nil
}
