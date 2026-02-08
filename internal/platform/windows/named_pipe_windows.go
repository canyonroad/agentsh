//go:build windows

package windows

import (
	"net"
	"time"

	winio "github.com/Microsoft/go-winio"
)

// ListenNamedPipe creates a named pipe listener on the given pipe name.
func ListenNamedPipe(pipeName string) (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: PipeSecuritySDDL(),
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}
	return winio.ListenPipe(pipeName, cfg)
}

// DialNamedPipe connects to an existing named pipe.
func DialNamedPipe(pipeName string, timeout time.Duration) (net.Conn, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return winio.DialPipe(pipeName, &timeout)
}
