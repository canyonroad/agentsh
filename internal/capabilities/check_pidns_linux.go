//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"strings"
)

func probePIDNamespace() ProbeResult {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ProbeResult{Available: false, Detail: "cannot read /proc/self/status"}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			levels := len(fields) - 1
			if levels > 1 {
				return ProbeResult{Available: true, Detail: fmt.Sprintf("NSpid: %d levels", levels)}
			}
			return ProbeResult{Available: false, Detail: "host namespace"}
		}
	}
	return ProbeResult{Available: false, Detail: "NSpid not supported"}
}
