//go:build !linux

package api

import "fmt"

func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool) (resume func() error, err error) {
	return nil, fmt.Errorf("ptrace not supported on this platform")
}
