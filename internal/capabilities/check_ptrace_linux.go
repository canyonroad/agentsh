//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const capSysPtrace = 19

// readCapEff reads the effective capability set from /proc/self/status.
func readCapEff() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	return parseCapEff(string(data))
}

// parseCapEff extracts the CapEff value from /proc/self/status content.
func parseCapEff(content string) (uint64, error) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "CapEff:\t") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:\t"))
			return strconv.ParseUint(hex, 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff not found in /proc/self/status")
}

// checkPtraceCapability checks if ptrace is available and functional.
func checkPtraceCapability() bool {
	capEff, err := readCapEff()
	if err != nil {
		return false
	}
	if capEff&(1<<capSysPtrace) == 0 {
		return false
	}
	return probePtraceAttach()
}

// probePtraceAttach forks a short-lived child and attempts PTRACE_SEIZE.
func probePtraceAttach() bool {
	cmd := exec.Command("/bin/sleep", "0.1")
	if err := cmd.Start(); err != nil {
		return false
	}

	pid := cmd.Process.Pid

	err := unix.PtraceSeize(pid)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return false
	}

	// Seize succeeded. Clean up: interrupt, wait, detach.
	if err := unix.PtraceInterrupt(pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return true
	}

	var status unix.WaitStatus
	_, err = unix.Wait4(pid, &status, 0, nil)
	if err == nil && status.Stopped() {
		unix.PtraceDetach(pid)
	}

	cmd.Process.Kill()
	cmd.Wait()
	return true
}
