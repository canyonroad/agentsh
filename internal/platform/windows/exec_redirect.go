package windows

import (
	"fmt"
	"sync/atomic"
)

// RedirectConfig holds configuration for redirecting a suspended process through the stub.
type RedirectConfig struct {
	StubBinary string // Path to agentsh-stub.exe
	SessionID  string // Current session ID
}

var pipeSeq atomic.Uint64

// generateStubPipeNameForRedirect returns a unique pipe name for a redirect operation.
func generateStubPipeNameForRedirect(sessionID string, pid uint32) string {
	return fmt.Sprintf(`\\.\pipe\agentsh-stub-%s-%d-%d`, sessionID, pid, pipeSeq.Add(1))
}

// splitCommandLine splits a Windows command line into arguments, respecting double-quoted strings.
func splitCommandLine(cmdLine string) []string {
	if cmdLine == "" {
		return nil
	}

	var args []string
	var current []byte
	inQuote := false

	for i := 0; i < len(cmdLine); i++ {
		ch := cmdLine[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case (ch == ' ' || ch == '\t') && !inQuote:
			if len(current) > 0 {
				args = append(args, string(current))
				current = current[:0]
			}
		default:
			current = append(current, ch)
		}
	}
	if len(current) > 0 {
		args = append(args, string(current))
	}
	return args
}
