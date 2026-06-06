// Package wrapperlog defines the env contract and fallback file
// destination for routing agentsh-unixwrap diagnostics off the wrapped
// command's stderr (issue #415). The wrapper execs the real command in
// place, so anything it logs to stderr lands on the user-visible stream
// of the wrapped command; parents pass an inherited fd via EnvKey
// instead.
package wrapperlog

import (
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
)

// EnvKey names the env var carrying the inherited fd number that
// agentsh-unixwrap routes its diagnostics (slog + stdlib log) to.
// Unset means stderr (legacy behavior).
const EnvKey = "AGENTSH_WRAPPER_LOG_FD"

// OpenStateLogFile opens <user-state-dir>/logs/unixwrap.log for append,
// creating the directory as needed. Used by parents that have no live
// log sink of their own (shell-shim relay, agentsh wrap CLI); O_APPEND
// keeps concurrent wrapper invocations line-atomic.
func OpenStateLogFile() (*os.File, error) {
	dir := filepath.Join(config.GetUserStateDir(), "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "unixwrap.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
