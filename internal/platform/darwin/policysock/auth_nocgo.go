//go:build darwin && !cgo

package policysock

import (
	"net"
)

// ValidatePeer is a no-op when CGO is disabled (cross-compilation).
// The CGO build uses Unix socket credentials and code signing validation.
func ValidatePeer(conn *net.UnixConn, teamID string) error {
	return nil
}
