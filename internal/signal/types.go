//go:build !windows

// internal/signal/types.go
package signal

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Signal name to number mapping (Unix signals)
var signalNames = map[string]int{
	"SIGHUP":    int(unix.SIGHUP),
	"SIGINT":    int(unix.SIGINT),
	"SIGQUIT":   int(unix.SIGQUIT),
	"SIGILL":    int(unix.SIGILL),
	"SIGTRAP":   int(unix.SIGTRAP),
	"SIGABRT":   int(unix.SIGABRT),
	"SIGBUS":    int(unix.SIGBUS),
	"SIGFPE":    int(unix.SIGFPE),
	"SIGKILL":   int(unix.SIGKILL),
	"SIGUSR1":   int(unix.SIGUSR1),
	"SIGSEGV":   int(unix.SIGSEGV),
	"SIGUSR2":   int(unix.SIGUSR2),
	"SIGPIPE":   int(unix.SIGPIPE),
	"SIGALRM":   int(unix.SIGALRM),
	"SIGTERM":   int(unix.SIGTERM),
	"SIGCHLD":   int(unix.SIGCHLD),
	"SIGCONT":   int(unix.SIGCONT),
	"SIGSTOP":   int(unix.SIGSTOP),
	"SIGTSTP":   int(unix.SIGTSTP),
	"SIGTTIN":   int(unix.SIGTTIN),
	"SIGTTOU":   int(unix.SIGTTOU),
	"SIGURG":    int(unix.SIGURG),
	"SIGXCPU":   int(unix.SIGXCPU),
	"SIGXFSZ":   int(unix.SIGXFSZ),
	"SIGVTALRM": int(unix.SIGVTALRM),
	"SIGPROF":   int(unix.SIGPROF),
	"SIGWINCH":  int(unix.SIGWINCH),
	"SIGIO":     int(unix.SIGIO),
	"SIGSYS":    int(unix.SIGSYS),
}

// Signal groups for policy convenience
var signalGroups = map[string][]int{
	"@fatal":  {int(unix.SIGKILL), int(unix.SIGTERM), int(unix.SIGQUIT), int(unix.SIGABRT)},
	"@job":    {int(unix.SIGSTOP), int(unix.SIGCONT), int(unix.SIGTSTP), int(unix.SIGTTIN), int(unix.SIGTTOU)},
	"@reload": {int(unix.SIGHUP), int(unix.SIGUSR1), int(unix.SIGUSR2)},
	"@ignore": {int(unix.SIGCHLD), int(unix.SIGURG), int(unix.SIGWINCH)},
	"@all":    nil, // Initialized in init() to avoid circular dependency
}

func init() {
	signalGroups["@all"] = AllSignals()
}

// SignalFromString converts a signal name or number to its numeric value.
func SignalFromString(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	// Try as number first
	if num, err := strconv.Atoi(s); err == nil {
		if num > 0 && num < 64 {
			return num, nil
		}
		return 0, fmt.Errorf("signal number out of range: %d", num)
	}

	// Try as name
	if sig, ok := signalNames[s]; ok {
		return sig, nil
	}

	// Try with SIG prefix
	if !strings.HasPrefix(s, "SIG") {
		if sig, ok := signalNames["SIG"+s]; ok {
			return sig, nil
		}
	}

	return 0, fmt.Errorf("unknown signal: %s", s)
}

// SignalName returns the name of a signal number.
func SignalName(sig int) string {
	for name, num := range signalNames {
		if num == sig {
			return name
		}
	}
	return fmt.Sprintf("SIG%d", sig)
}

// ExpandSignalGroup expands a signal group (e.g., "@fatal") to its signal numbers.
func ExpandSignalGroup(group string) ([]int, error) {
	group = strings.ToLower(strings.TrimSpace(group))
	if signals, ok := signalGroups[group]; ok {
		return append([]int{}, signals...), nil
	}
	return nil, fmt.Errorf("unknown signal group: %s", group)
}

// IsSignalGroup returns true if the string is a signal group (starts with @).
func IsSignalGroup(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "@")
}

// AllSignals returns all signal numbers (1-31 for standard signals).
func AllSignals() []int {
	signals := make([]int, 31)
	for i := range signals {
		signals[i] = i + 1
	}
	return signals
}
