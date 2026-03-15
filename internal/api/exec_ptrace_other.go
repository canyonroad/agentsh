//go:build !linux

package api

import (
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

type ptraceExecResult struct {
	exitCode  int
	resources types.ExecResources
}

func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool) (waitExit func() ptraceExecResult, resume func() error, err error) {
	return nil, nil, fmt.Errorf("ptrace not supported on this platform")
}
