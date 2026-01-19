//go:build linux

package capabilities

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// alwaysDropCaps are capabilities that are NEVER allowed - container escape vectors.
var alwaysDropCaps = map[string]struct{}{
	"CAP_SYS_ADMIN":       {}, // Mount, namespace escape, catch-all
	"CAP_SYS_PTRACE":      {}, // Attach to processes, read memory
	"CAP_SYS_MODULE":      {}, // Load kernel modules
	"CAP_DAC_OVERRIDE":    {}, // Bypass file permissions
	"CAP_DAC_READ_SEARCH": {}, // Bypass read/search permissions
	"CAP_SETUID":          {}, // Change UID
	"CAP_SETGID":          {}, // Change GID
	"CAP_SETPCAP":         {}, // Modify capability bounding set (could re-add dropped caps)
	"CAP_CHOWN":           {}, // Change file ownership
	"CAP_FOWNER":          {}, // Bypass owner permission checks
	"CAP_MKNOD":           {}, // Create device files
	"CAP_SYS_RAWIO":       {}, // Raw I/O port access
	"CAP_SYS_BOOT":        {}, // Reboot system
	"CAP_NET_ADMIN":       {}, // Network configuration
	"CAP_SYS_CHROOT":      {}, // chroot escape vector
	"CAP_LINUX_IMMUTABLE": {}, // Modify immutable files
}

// defaultDropCaps are dropped by default but can be explicitly allowed.
var defaultDropCaps = map[string]struct{}{
	"CAP_NET_BIND_SERVICE": {}, // Bind to ports < 1024
	"CAP_NET_RAW":          {}, // Raw sockets (ping)
	"CAP_KILL":             {}, // Signal any same-UID process
	"CAP_SETFCAP":          {}, // Set file capabilities
}

// isAlwaysDrop returns true if the capability must always be dropped.
func isAlwaysDrop(cap string) bool {
	cap = strings.ToUpper(cap)
	if !strings.HasPrefix(cap, "CAP_") {
		cap = "CAP_" + cap
	}
	_, ok := alwaysDropCaps[cap]
	return ok
}

// ValidateCapabilityAllowList checks that no always-drop caps are in the allow list.
func ValidateCapabilityAllowList(allow []string) error {
	for _, cap := range allow {
		if isAlwaysDrop(cap) {
			return fmt.Errorf("capability %s cannot be allowed: hardcoded deny", cap)
		}
	}
	return nil
}

// DropCapabilities drops all capabilities except those in the allow list.
func DropCapabilities(allow []string) error {
	if err := ValidateCapabilityAllowList(allow); err != nil {
		return err
	}

	// Build set of allowed caps
	allowSet := make(map[string]struct{})
	for _, cap := range allow {
		cap = strings.ToUpper(cap)
		if !strings.HasPrefix(cap, "CAP_") {
			cap = "CAP_" + cap
		}
		allowSet[cap] = struct{}{}
	}

	// Get the last valid capability number for this kernel
	lastCap := getLastCap()

	// Drop from bounding set
	for cap := 0; cap <= lastCap; cap++ {
		capName := capToName(cap)
		if _, allowed := allowSet[capName]; allowed {
			continue
		}

		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			// Ignore EINVAL for caps that don't exist on this kernel
			if err != unix.EINVAL {
				return fmt.Errorf("failed to drop %s: %w", capName, err)
			}
		}
	}

	return nil
}

// getLastCap returns the highest valid capability number for this kernel.
func getLastCap() int {
	// Try to read /proc/sys/kernel/cap_last_cap
	// If that fails, use a reasonable default
	const defaultLastCap = 40 // CAP_CHECKPOINT_RESTORE as of kernel 5.9

	data := make([]byte, 16)
	fd, err := unix.Open("/proc/sys/kernel/cap_last_cap", unix.O_RDONLY, 0)
	if err != nil {
		return defaultLastCap
	}
	defer unix.Close(fd)

	n, err := unix.Read(fd, data)
	if err != nil || n == 0 {
		return defaultLastCap
	}

	// Parse the number
	var lastCap int
	for i := 0; i < n; i++ {
		if data[i] >= '0' && data[i] <= '9' {
			lastCap = lastCap*10 + int(data[i]-'0')
		} else {
			break
		}
	}

	if lastCap == 0 {
		return defaultLastCap
	}
	return lastCap
}

// capToName converts capability number to name.
func capToName(cap int) string {
	names := map[int]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
		38: "CAP_PERFMON",
		39: "CAP_BPF",
		40: "CAP_CHECKPOINT_RESTORE",
	}
	if name, ok := names[cap]; ok {
		return name
	}
	return fmt.Sprintf("CAP_%d", cap)
}
