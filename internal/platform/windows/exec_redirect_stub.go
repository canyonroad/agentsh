//go:build !windows

package windows

import "fmt"

// handleRedirect is only available on Windows.
func handleRedirect(req *SuspendedProcessRequest, cfg RedirectConfig) error {
	return fmt.Errorf("handleRedirect: not available on this platform")
}

// HandleRedirect terminates the suspended process, spawns agentsh-stub.exe
// as a child of the original parent, and serves the original command through
// the stub protocol. Only available on Windows.
func HandleRedirect(req *SuspendedProcessRequest, cfg RedirectConfig) error {
	return handleRedirect(req, cfg)
}
