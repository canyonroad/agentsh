//go:build darwin && !cgo

package darwin

import "fmt"

// ActivateResult represents the outcome of a system extension activation request.
type ActivateResult int

const (
	ActivateOK            ActivateResult = 0
	ActivateNeedsApproval ActivateResult = 1
	ActivateFailed        ActivateResult = -1
)

// activateExtension is a no-op when CGO is disabled.
func activateExtension() (ActivateResult, error) {
	return ActivateFailed, fmt.Errorf("system extension activation requires CGO")
}
