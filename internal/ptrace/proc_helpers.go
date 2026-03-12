//go:build linux

package ptrace

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readTGID(tid int) (int, error) {
	return readProcStatusField(tid, "Tgid:")
}

func readPPID(tid int) (int, error) {
	return readProcStatusField(tid, "PPid:")
}

func readProcStatusField(tid int, field string) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, field) {
			val := strings.TrimSpace(strings.TrimPrefix(line, field))
			return strconv.Atoi(val)
		}
	}
	return 0, fmt.Errorf("%s not found in /proc/%d/status", field, tid)
}
