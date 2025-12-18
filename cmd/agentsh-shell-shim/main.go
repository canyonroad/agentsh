package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/agentsh/agentsh/internal/shim"
	"golang.org/x/term"
)

func main() {
	argv0 := os.Args[0]
	invoked := filepath.Base(argv0)

	shellName := strings.TrimLeft(invoked, "-")
	if shellName != "sh" && shellName != "bash" {
		// Default to sh semantics for unknown names.
		shellName = "sh"
	}

	realShell, err := resolveRealShell(shellName)
	if err != nil {
		fatalf(127, "agentsh-shell-shim: resolve real shell: %v", err)
	}

	// Recursion guard: when agentsh executes a process, it sets AGENTSH_IN_SESSION=1.
	// In that case, run the real shell directly.
	if strings.TrimSpace(os.Getenv("AGENTSH_IN_SESSION")) == "1" {
		execOrExit(realShell, append([]string{argv0}, os.Args[1:]...), os.Environ())
		return
	}

	agentshBin, err := resolveAgentshBin()
	if err != nil {
		fatalf(127, "agentsh-shell-shim: resolve agentsh: %v", err)
	}

	wd, _ := os.Getwd()
	sessID, _, err := shim.ResolveSessionID(shim.ResolveSessionIDOptions{
		WorkDir: wd,
	})
	if err != nil {
		fatalf(127, "agentsh-shell-shim: resolve session id: %v", err)
	}

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	args := []string{agentshBin, "exec"}
	if tty {
		args = append(args, "--pty")
	}
	args = append(args, "--argv0", argv0, sessID, "--", realShell)
	args = append(args, os.Args[1:]...)

	execOrExit(agentshBin, args, os.Environ())
}

func resolveAgentshBin() (string, error) {
	if v := strings.TrimSpace(os.Getenv("AGENTSH_BIN")); v != "" {
		return exec.LookPath(v)
	}
	return exec.LookPath("agentsh")
}

func resolveRealShell(shellName string) (string, error) {
	var candidates []string

	// Prefer resolving relative to argv[0] when it includes a path, since callers often exec "/bin/sh"
	// with argv0 "sh" or "/bin/sh" depending on the harness.
	if strings.Contains(os.Args[0], "/") {
		p := os.Args[0]
		if !filepath.IsAbs(p) {
			if wd, err := os.Getwd(); err == nil {
				p = filepath.Join(wd, p)
			}
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Clean(p)), shellName+".real"))
	}

	// Common install locations.
	candidates = append(candidates,
		filepath.Join("/bin", shellName+".real"),
		filepath.Join("/usr/bin", shellName+".real"),
	)

	// Fallback to the actual executable's directory (works when shim is installed as a copy into /bin).
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), shellName+".real"))
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("could not find %s.real (tried %v)", shellName, candidates)
}

func execOrExit(path string, argv []string, env []string) {
	if err := syscall.Exec(path, argv, env); err != nil {
		fatalf(127, "agentsh-shell-shim: exec %s: %v", path, err)
	}
}

func fatalf(code int, format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
