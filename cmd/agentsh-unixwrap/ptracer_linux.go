//go:build linux && cgo

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

const ptracerLibName = "libagentsh-ptracer.so"

// setupPtracerPreload finds the ptracer LD_PRELOAD library and sets the
// environment variables so that child processes call PR_SET_PTRACER(server_pid).
// This allows the server to use ProcessVMReadv on child processes under Yama
// ptrace_scope=1, restoring seccomp path resolution for file monitoring.
//
// The library is searched for in:
//  1. Same directory as the wrapper binary
//  2. /usr/lib/agentsh/ (deb/rpm install path)
func setupPtracerPreload(serverPID int) {
	if serverPID <= 0 {
		return
	}

	soPath := findPtracerLib()
	if soPath == "" {
		log.Printf("ptracer: %s not found, child ProcessVMReadv may fail under Yama", ptracerLibName)
		return
	}

	// Set the server PID for the library's constructor to read.
	os.Setenv("AGENTSH_SERVER_PID", strconv.Itoa(serverPID))

	// Prepend to LD_PRELOAD (preserve existing entries).
	if existing := os.Getenv("LD_PRELOAD"); existing != "" {
		os.Setenv("LD_PRELOAD", fmt.Sprintf("%s:%s", soPath, existing))
	} else {
		os.Setenv("LD_PRELOAD", soPath)
	}
}

// findPtracerLib searches standard locations for the ptracer .so.
func findPtracerLib() string {
	// 1. Next to the wrapper binary.
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), ptracerLibName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 2. System install path.
	candidate := filepath.Join("/usr/lib/agentsh", ptracerLibName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	return ""
}
