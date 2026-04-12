//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/store/jsonl"
)

func openAndLockAuditFile(path string) (*os.File, error) {
	file, err := jsonl.AcquireLock(path)
	if err != nil {
		if errors.Is(err, jsonl.ErrLocked) {
			return nil, fmt.Errorf("agentsh server is running; stop it before resetting the chain")
		}
		return nil, fmt.Errorf("agentsh server is running; stop it before resetting the chain")
	}
	return file, nil
}

func closeAndUnlockAuditFile(file *os.File) error {
	return jsonl.ReleaseLock(file)
}
