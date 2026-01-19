//go:build linux && cgo

package unix

import (
	"path/filepath"
	"time"
)

// ExecveHandlerConfig configures the execve handler.
type ExecveHandlerConfig struct {
	MaxArgc               int
	MaxArgvBytes          int
	OnTruncated           string // deny | allow | approval
	ApprovalTimeout       time.Duration
	ApprovalTimeoutAction string // deny | allow
	InternalBypass        []string
}

// ExecveHandler handles execve/execveat notifications.
type ExecveHandler struct {
	cfg          ExecveHandlerConfig
	depthTracker *DepthTracker
}

// NewExecveHandler creates a new execve handler.
// Note: policy and emitter params are placeholders for future tasks
func NewExecveHandler(cfg ExecveHandlerConfig, policy interface{}, dt *DepthTracker, emitter interface{}) *ExecveHandler {
	return &ExecveHandler{
		cfg:          cfg,
		depthTracker: dt,
	}
}

// isInternalBypass checks if filename matches internal bypass patterns.
func (h *ExecveHandler) isInternalBypass(filename string) bool {
	base := filepath.Base(filename)

	for _, pattern := range h.cfg.InternalBypass {
		// Try full path match
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
		// Try basename match
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}
