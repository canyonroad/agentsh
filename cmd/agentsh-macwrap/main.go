//go:build darwin && cgo

// agentsh-macwrap: applies macOS sandbox profile with XPC restrictions,
// then execs the target command.
// Usage: agentsh-macwrap -- <command> [args...]
// Requires env AGENTSH_SANDBOX_CONFIG set to JSON config.

package main

/*
#cgo LDFLAGS: -framework Foundation
#include <sandbox.h>
#include <stdlib.h>
#include <stdint.h>

// sandbox_init_with_parameters is a private API not declared in public headers.
// It applies a custom SBPL profile string to the current process.
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);

int apply_sandbox(const char *profile, char **errorbuf) {
    return sandbox_init_with_parameters(profile, 0, NULL, errorbuf);
}

void free_error(char *errorbuf) {
    sandbox_free_error(errorbuf);
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	log.SetFlags(0)

	cmd, args, err := validateArgs(os.Args)
	if err != nil {
		log.Fatalf("usage: %s -- <command> [args...]\nerror: %v", os.Args[0], err)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	profile := generateProfile(cfg)

	if err := applySandbox(profile); err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}

	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}

// applySandbox applies the SBPL profile using sandbox_init.
func applySandbox(profile string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var errorbuf *C.char
	rc := C.apply_sandbox(cProfile, &errorbuf)
	if rc != 0 {
		var errMsg string
		if errorbuf != nil {
			errMsg = C.GoString(errorbuf)
			C.free_error(errorbuf)
		}
		return fmt.Errorf("sandbox_init failed (rc=%d): %s", rc, errMsg)
	}
	return nil
}
