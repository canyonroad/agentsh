package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/agentsh/agentsh/internal/shim"
	"golang.org/x/term"
)

func main() {
	argv0 := os.Args[0]
	invoked := filepath.Base(argv0)

	// Version stamp — always log when debug is on so we can verify which binary is deployed.
	debugLog("shim v0.16.8+170 (pipe-through mode) invoked=%s argv=%v", invoked, os.Args)

	shellName := strings.TrimLeft(invoked, "-")
	if shellName != "sh" && shellName != "bash" {
		// Default to sh semantics for unknown names.
		shellName = "sh"
	}

	// Recursion guard: when agentsh executes a process, it sets AGENTSH_IN_SESSION=1.
	// In that case, run the real shell directly. We try .real first (for proper shim
	// installations) but fall back to system shell via PATH for containers/environments
	// where the shim is installed but .real doesn't exist.
	inSession := strings.TrimSpace(os.Getenv("AGENTSH_IN_SESSION"))
	debugLog("recursion check: AGENTSH_IN_SESSION=%q", inSession)
	if inSession == "1" {
		realShell, err := resolveRealShell(shellName)
		if err != nil {
			// Fall back to looking up the shell in PATH (skipping ourselves)
			realShell, err = lookupShellInPath(shellName)
			if err != nil {
				fatalWithHint(127,
					fmt.Sprintf("agentsh-shell-shim: in-session: could not find %s", shellName),
					fmt.Sprintf("Tried %s.real and PATH lookup. Ensure the real shell is available.", shellName),
				)
			}
		}
		debugLog("recursion guard: executing real shell %s", realShell)
		runAndExit(realShell, argv0, os.Args[1:], os.Environ())
		return
	}

	realShell, err := resolveRealShell(shellName)
	if err != nil {
		fatalWithHint(127,
			fmt.Sprintf("agentsh-shell-shim: resolve real shell: %v", err),
			fmt.Sprintf("Expected %s.real to exist next to the shim (or in /bin or /usr/bin).", shellName),
		)
	}

	// Agentsh CLI bypass: if the command being run IS the agentsh binary,
	// exec the real shell directly. The agentsh CLI connects back to the
	// server, which would deadlock if the server is handling this shim's
	// exec request. This applies to: agentsh detect, agentsh --version,
	// agentsh debug policy-test, agentsh trash list, etc.
	if isAgentshCommand(os.Args[1:]) {
		debugLog("agentsh CLI bypass: command is agentsh itself, executing real shell %s", realShell)
		runAndExit(realShell, argv0, os.Args[1:], os.Environ())
		return
	}

	// Non-interactive bypass: when stdin is not a terminal (piped data, e.g.
	// docker exec -i container sh -c "cat > /file" < binary), exec the real
	// shell directly. This preserves binary stdin/stdout integrity — the shim
	// never touches the data streams. Policy enforcement for commands inside
	// agentsh sessions is handled by AGENTSH_IN_SESSION (checked above).
	//
	// AGENTSH_SHIM_FORCE=1 overrides this bypass for environments like sandbox
	// platforms where commands are always non-interactive but still require
	// policy enforcement (e.g. Blaxel, E2B sandbox APIs).
	//
	// /etc/agentsh/shim.conf with force=true also overrides the bypass, for
	// platforms where env vars cannot be injected (e.g. exe.dev).
	// Precedence: AGENTSH_SHIM_FORCE=1 (env) > config file > default (false).
	// Note: env can only ADD enforcement, never remove it.
	conf, confErr := shim.ReadShimConf(shimConfRoot())
	if confErr != nil {
		// Fail-closed: if the config file exists but can't be read (permission
		// denied, I/O error), assume force=true. An operator wrote the file for
		// a reason — silently bypassing policy is worse than over-enforcing.
		// Only a missing file (ENOENT) is non-fatal (handled inside ReadShimConf).
		debugLog("read shim.conf: %v (fail-closed: assuming force=true)", confErr)
		conf.Force = true
	}
	forceShim := strings.TrimSpace(os.Getenv("AGENTSH_SHIM_FORCE"))
	switch {
	case forceShim == "1":
		debugLog("AGENTSH_SHIM_FORCE=1: enforcing policy despite non-interactive stdin")
	case conf.Force:
		forceShim = "1"
		debugLog("shim.conf force=true: enforcing policy despite non-interactive stdin")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) && forceShim != "1" {
		debugLog("non-interactive bypass: stdin is not a tty, executing real shell %s", realShell)
		runAndExit(realShell, argv0, os.Args[1:], os.Environ())
		return
	}

	agentshBin, err := resolveAgentshBin()
	if err != nil {
		hint := "Set AGENTSH_BIN=/path/to/agentsh or ensure `agentsh` is available on PATH."
		if v := strings.TrimSpace(os.Getenv("AGENTSH_BIN")); v != "" {
			hint = fmt.Sprintf("AGENTSH_BIN is set to %q but wasn't executable; fix it or unset it to use PATH.", v)
		}
		fatalWithHint(127, fmt.Sprintf("agentsh-shell-shim: resolve agentsh: %v", err), hint)
	}

	wd, _ := os.Getwd()
	sessID, sessFile, err := shim.ResolveSessionID(shim.ResolveSessionIDOptions{
		WorkDir: wd,
	})
	if err != nil {
		fatalWithHint(127,
			fmt.Sprintf("agentsh-shell-shim: resolve session id: %v", err),
			"Set AGENTSH_SESSION_ID (best), or set AGENTSH_SESSION_FILE to a writable file path for a stable ID.",
		)
	}
	debugLog("resolved session: id=%s file=%s wd=%s", sessID, sessFile, wd)

	// Stdin-mode detection: when the shim is invoked with no command args
	// (bare /bin/bash, no -c) and stdin is a pipe, the caller is sending
	// the command via stdin (e.g. Daytona toolbox). Read stdin and convert
	// to -c so the command goes through agentsh policy enforcement.
	shellArgs := os.Args[1:]
	if len(shellArgs) == 0 && !term.IsTerminal(int(os.Stdin.Fd())) {
		debugLog("stdin-mode: no shell args, stdin is pipe — reading command from stdin")
		stdinData, err := io.ReadAll(os.Stdin)
		if err == nil {
			cmd := strings.TrimSpace(string(stdinData))
			if cmd != "" {
				debugLog("stdin-mode: read %d bytes, converting to -c", len(stdinData))
				shellArgs = []string{"-c", cmd}
			}
		}
	}

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	args := []string{agentshBin, "exec"}
	if tty {
		args = append(args, "--pty")
	}
	if sessFile != "" {
		args = append(args, "--session-file", sessFile)
	}
	args = append(args, "--argv0", argv0, sessID, "--", realShell)
	args = append(args, shellArgs...)

	// Run agentsh exec as a child process rather than replacing the shim via
	// syscall.Exec. In sandbox toolboxes (Daytona, E2B), the toolbox captures
	// output by reading pipes attached to the process it started (the shim).
	// With syscall.Exec, the toolbox may not see output written by the exec'd
	// process. Running as a child keeps the shim's pipes alive and the parent
	// process visible to the toolbox until all output is written.
	runAndExit(agentshBin, "", args[1:], os.Environ())
}

// isMCPCommand checks if the command being executed is an MCP server.
func isMCPCommand(argv0 string, args []string) bool {
	// Extract command from shell -c "command"
	if len(args) >= 2 && args[0] == "-c" {
		// Parse the command string
		cmdParts := strings.Fields(args[1])
		if len(cmdParts) > 0 {
			return shim.IsMCPServer(cmdParts[0], cmdParts[1:], nil)
		}
	}

	// Direct command execution
	return shim.IsMCPServer(argv0, args, nil)
}

// isAgentshCommand checks if the command being executed is the agentsh binary.
// This prevents a deadlock where the shim routes agentsh CLI commands through
// the server, and the CLI connects back to the same blocked server.
// Fail-safe: returns false on any error (worst case is existing deadlock, not a bypass).
func isAgentshCommand(args []string) bool {
	// Only match when -c is the first argument. Scanning further into args
	// could misinterpret script arguments as shell flags (e.g., "sh script.sh -c ...").
	// Also reject login shell flags in the first position.
	if len(args) < 2 {
		return false
	}
	if args[0] == "-l" || args[0] == "--login" {
		return false
	}
	if args[0] != "-c" {
		return false
	}
	cmdStr := args[1]
	if cmdStr == "" {
		return false
	}

	// Reject compound commands (shell operators that chain multiple commands).
	// Only bypass for simple single-command invocations to prevent enforcement
	// bypass for chained commands like "agentsh detect; rm -rf /".
	// We check for compound OPERATORS, not individual characters, because
	// characters like & and > appear in legitimate redirections (2>&1).
	if containsCompoundOperator(cmdStr) {
		return false
	}

	cmdParts := strings.Fields(cmdStr)
	if len(cmdParts) == 0 {
		return false
	}
	// Skip common shell prefixes to find the actual command:
	// - "exec agentsh detect" → "agentsh"
	// - "env FOO=1 agentsh detect" → "agentsh"
	// - "env -i agentsh detect" → "agentsh"
	cmd := extractCommand(cmdParts)
	if cmd == "" {
		return false
	}
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		return false
	}
	agentshPath, err := resolveAgentshBin()
	if err != nil {
		return false
	}
	// Resolve symlinks to handle installations where agentsh is symlinked
	// (e.g., /usr/local/bin/agentsh -> /opt/agentsh/bin/agentsh).
	cmdResolved, err := filepath.EvalSymlinks(cmdPath)
	if err != nil {
		cmdResolved = cmdPath
	}
	agentshResolved, err := filepath.EvalSymlinks(agentshPath)
	if err != nil {
		agentshResolved = agentshPath
	}
	return cmdResolved == agentshResolved
}

// containsCompoundOperator checks if a shell command string contains operators
// that chain multiple commands. Returns false for simple redirections like 2>&1.
func containsCompoundOperator(s string) bool {
	// These always indicate compound commands or subshells.
	if strings.ContainsAny(s, ";`\n\r") {
		return true
	}
	if strings.Contains(s, "&&") || strings.Contains(s, "||") || strings.Contains(s, "$(") {
		return true
	}
	// Check for pipe: | that is NOT preceded by > (which would be >| clobber
	// or part of a >&| redirect). A bare | chains commands.
	for i, c := range s {
		if c == '|' {
			if i > 0 && s[i-1] == '>' {
				continue // part of >| or >&| redirect
			}
			if i+1 < len(s) && s[i+1] == '|' {
				continue // || already handled above
			}
			return true // bare pipe
		}
	}
	return false
}

// extractCommand skips shell builtins that don't affect command resolution
// (exec, nice, nohup, command) to find the actual executable name.
// Does NOT skip env or VAR=VAL prefixes because those can modify PATH and
// change which binary is resolved — skipping them would be a security bypass.
func extractCommand(parts []string) string {
	i := 0
	for i < len(parts) {
		word := parts[i]
		switch word {
		case "exec", "nice", "nohup", "command":
			// Shell builtins/wrappers that don't affect command resolution.
			i++
		default:
			return word
		}
	}
	return ""
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
			// Resolve symlinks to avoid loops where sh.real -> bash (the shim).
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil {
				return p, nil
			}
			// If the resolved path is the shim itself, skip this candidate.
			if self, err := os.Executable(); err == nil {
				if selfResolved, err := filepath.EvalSymlinks(self); err == nil {
					if resolved == selfResolved {
						continue
					}
				}
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("could not find %s.real (tried %v)", shellName, candidates)
}

// lookupShellInPath finds the shell binary in PATH, skipping the current executable
// (to avoid infinite recursion when the shim is installed as /bin/bash).
func lookupShellInPath(shellName string) (string, error) {
	// Get our own executable path to skip it
	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	selfReal, _ := filepath.EvalSymlinks(self)

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/bin:/bin"
	}

	for _, dir := range filepath.SplitList(pathEnv) {
		candidate := filepath.Join(dir, shellName)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		// Check if this is a symlink and resolve it
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		// Skip if this resolves to ourselves
		if resolved == self || resolved == selfReal {
			continue
		}
		// Check if it's executable
		if info.Mode()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not find %s in PATH", shellName)
}

func execOrExit(path string, argv []string, env []string) {
	if err := syscall.Exec(path, argv, env); err != nil {
		fatalWithHint(127,
			fmt.Sprintf("agentsh-shell-shim: exec %s: %v", path, err),
			"If you see 'permission denied' in a container, check that the shim and agentsh binaries are executable.",
		)
	}
}

// runAndExit runs a command as a child process, copies its stdout/stderr
// through the shim process, and exits with the child's exit code.
//
// Critical: the shim must read the child's output via pipes and re-write it
// to its own stdout/stderr. Direct fd pass-through (cmd.Stdout = os.Stdout)
// doesn't work in sandbox toolboxes like Daytona because the toolbox captures
// output per-process — writes from a child PID aren't attributed to the shim
// PID that the toolbox started. By piping through, all output flows through
// the shim process that the toolbox is monitoring.
//
// argv0 overrides the child's argv[0] if non-empty. This is needed because
// busybox (Alpine) uses argv[0] to determine which applet to run — if the
// binary is "/bin/sh.real" but argv[0] must be "sh" for busybox to work.
func runAndExit(path string, argv0 string, args []string, env []string) {
	cmd := exec.Command(path, args...)
	if argv0 != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = argv0
	}
	cmd.Stdin = os.Stdin
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fatalWithHint(127, fmt.Sprintf("agentsh-shell-shim: stdout pipe: %v", err), "")
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fatalWithHint(127, fmt.Sprintf("agentsh-shell-shim: stderr pipe: %v", err), "")
	}

	debugLog("runAndExit: path=%s argv0=%s args=%v", path, argv0, args)
	if err := cmd.Start(); err != nil {
		fatalWithHint(127,
			fmt.Sprintf("agentsh-shell-shim: run %s: %v", path, err),
			"If you see 'permission denied' in a container, check that the shim and agentsh binaries are executable.",
		)
	}

	// Copy child stdout/stderr through the shim process concurrently.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(os.Stdout, stdoutPipe) }()
	go func() { defer wg.Done(); _, _ = io.Copy(os.Stderr, stderrPipe) }()

	// Wait for pipes to drain, then wait for process exit.
	wg.Wait()
	waitErr := cmd.Wait()

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fatalWithHint(127,
			fmt.Sprintf("agentsh-shell-shim: run %s: %v", path, waitErr),
			"If you see 'permission denied' in a container, check that the shim and agentsh binaries are executable.",
		)
	}
	os.Exit(0)
}

func fatalWithHint(code int, msg string, hint string) {
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(msg))
	if strings.TrimSpace(hint) != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Hint: %s\n", strings.TrimSpace(hint))
	}
	if strings.TrimSpace(os.Getenv("AGENTSH_SHIM_DEBUG")) == "1" {
		_, _ = fmt.Fprintf(os.Stderr, "Debug: argv0=%q args=%q\n", os.Args[0], os.Args[1:])
		if p := strings.TrimSpace(os.Getenv("PATH")); p != "" {
			_, _ = fmt.Fprintf(os.Stderr, "Debug: PATH=%s\n", p)
		}
	}
	os.Exit(code)
}

func debugLog(format string, args ...any) {
	if strings.TrimSpace(os.Getenv("AGENTSH_SHIM_DEBUG")) == "1" {
		_, _ = fmt.Fprintf(os.Stderr, "agentsh-shell-shim: "+format+"\n", args...)
	}
}
