//go:build !windows

package windows

import (
	"fmt"
	"net"
	"time"
)

// ListenNamedPipe is only available on Windows.
func ListenNamedPipe(pipeName string) (net.Listener, error) {
	return nil, fmt.Errorf("named pipes only available on Windows")
}

// DialNamedPipe is only available on Windows.
func DialNamedPipe(pipeName string, timeout time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("named pipes only available on Windows")
}
