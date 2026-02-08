package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/agentsh/agentsh/internal/stub"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Check for named pipe first (Windows)
	pipeName := os.Getenv("AGENTSH_STUB_PIPE")
	if pipeName != "" {
		code := runWithPipe(pipeName)
		if code >= 0 {
			return code
		}
		// Negative return means pipe not supported on this platform; fall through to fd
	}

	// Fall back to fd (Unix)
	fdStr := os.Getenv("AGENTSH_STUB_FD")
	if fdStr == "" {
		fmt.Fprintf(os.Stderr, "agentsh-stub: neither AGENTSH_STUB_PIPE nor AGENTSH_STUB_FD set\n")
		return 126
	}

	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd < 0 {
		fmt.Fprintf(os.Stderr, "agentsh-stub: invalid AGENTSH_STUB_FD: %s\n", fdStr)
		return 126
	}

	f := os.NewFile(uintptr(fd), "agentsh-stub-socket")
	if f == nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: failed to open fd %d\n", fd)
		return 126
	}

	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: failed to create connection from fd %d: %v\n", fd, err)
		return 126
	}
	defer conn.Close()

	exitCode, err := stub.RunProxy(conn, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-stub: proxy error: %v\n", err)
		return 126
	}

	return exitCode
}
