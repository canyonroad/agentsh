//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/agentsh/agentsh/internal/platform/darwin/xpc"
	"github.com/agentsh/agentsh/internal/stub"
	"golang.org/x/sys/unix"
)

// ESExecPolicyChecker evaluates exec commands against policy.
// This is a richer interface than xpc.PolicyHandler.CheckCommand because it
// returns the full policy decision (including shadow-mode effective decisions),
// not just allow/deny.
type ESExecPolicyChecker interface {
	CheckCommand(cmd string, args []string) ESExecPolicyResult
}

// ESExecPolicyResult represents a policy check result with both the raw
// policy decision and the effective decision (which may differ in shadow mode).
type ESExecPolicyResult struct {
	Decision          string // allow, deny, approve, audit, redirect
	EffectiveDecision string // What actually happens (respects shadow mode)
	Rule              string
	Message           string
}

// ESExecHandler handles exec pipeline checks from the ESF client.
// It evaluates policy and, for redirect/approve decisions, spawns an
// agentsh-stub server-side to run the command through the stub protocol.
//
// On macOS, the ES framework cannot rewrite exec targets (unlike Linux seccomp
// ADDFD). Instead, the original exec is denied (EPERM) and the command is run
// server-side with I/O proxied through the stub binary.
type ESExecHandler struct {
	policyChecker ESExecPolicyChecker
	stubBinary    string // Path to agentsh-stub binary
}

// NewESExecHandler creates a new ES exec handler.
func NewESExecHandler(checker ESExecPolicyChecker, stubBinary string) *ESExecHandler {
	return &ESExecHandler{
		policyChecker: checker,
		stubBinary:    stubBinary,
	}
}

// CheckExec evaluates an exec request and returns the pipeline decision.
// Implements the xpc.ExecHandler interface.
func (h *ESExecHandler) CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string, execCtx xpc.ExecContext) xpc.ExecCheckResult {
	if h.policyChecker == nil {
		return xpc.ExecCheckResult{
			Decision: "allow",
			Action:   "continue",
			Rule:     "no_policy",
		}
	}

	result := h.policyChecker.CheckCommand(executable, args)

	// Use EffectiveDecision for action mapping (what actually happens, respects shadow mode).
	// Use Decision for logging to preserve full policy semantics.
	effectiveDecision := result.EffectiveDecision
	if effectiveDecision == "" {
		effectiveDecision = result.Decision
	}

	switch effectiveDecision {
	case "allow", "audit":
		return xpc.ExecCheckResult{
			Decision: result.Decision,
			Action:   "continue",
			Rule:     result.Rule,
			Message:  result.Message,
		}

	case "deny":
		return xpc.ExecCheckResult{
			Decision: result.Decision,
			Action:   "deny",
			Rule:     result.Rule,
			Message:  result.Message,
		}

	case "approve", "redirect":
		// For redirect/approve: deny the original exec, spawn stub server-side.
		// The ESF client will deny the exec (process gets EPERM), and we run
		// the command independently through the stub protocol.
		go h.spawnStubServer(executable, args, pid, parentPID, sessionID, execCtx)
		return xpc.ExecCheckResult{
			Decision: result.Decision,
			Action:   "redirect",
			Rule:     result.Rule,
			Message:  result.Message,
		}

	default:
		// Unknown decision -- fail-secure by denying.
		slog.Warn("es_exec: unknown effective decision, denying",
			"decision", result.Decision,
			"effective", effectiveDecision,
			"cmd", executable,
		)
		return xpc.ExecCheckResult{
			Decision: result.Decision,
			Action:   "deny",
			Rule:     "unknown",
			Message:  "unknown effective decision",
		}
	}
}

// createSocketPair creates a Unix socketpair for stub <-> server communication.
// Returns (stubFile, srvConn, error):
//   - stubFile: *os.File for passing to the subprocess via ExtraFiles (becomes fd 3)
//   - srvConn: net.Conn for ServeStubConnection on the server side
func createSocketPair() (stubFile *os.File, srvConn net.Conn, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	// Set close-on-exec to prevent fd leaks to unrelated child processes.
	// (ExtraFiles in exec.Command will dup the fd without CLOEXEC for the stub.)
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])

	// fds[0] → stubFile (will be passed to the stub subprocess via ExtraFiles)
	stubFile = os.NewFile(uintptr(fds[0]), "stub-sock")

	// fds[1] → srvConn (for ServeStubConnection)
	srvFile := os.NewFile(uintptr(fds[1]), "srv-sock")
	srvConn, err = net.FileConn(srvFile)
	srvFile.Close() // FileConn dups the fd, so close the original
	if err != nil {
		stubFile.Close()
		return nil, nil, fmt.Errorf("srv FileConn: %w", err)
	}

	return stubFile, srvConn, nil
}

// spawnStubServer spawns the original command via the stub protocol.
// On macOS, we can't rewrite the exec target in ES, so we deny the original
// exec and run the command server-side, with I/O proxied through the stub.
//
// This creates a Unix socketpair: one end is passed to the agentsh-stub
// subprocess as fd 3 (via AGENTSH_STUB_FD=3), and the other end is used by
// ServeStubConnection to execute the command and proxy its I/O.
func (h *ESExecHandler) spawnStubServer(executable string, args []string, pid int32, parentPID int32, sessionID string, execCtx xpc.ExecContext) {
	if h.stubBinary == "" {
		slog.Error("es_exec: stub binary path not configured, cannot redirect exec",
			"cmd", executable,
			"pid", pid,
		)
		return
	}

	stubFile, srvConn, err := createSocketPair()
	if err != nil {
		slog.Error("es_exec: failed to create socketpair for stub",
			"cmd", executable,
			"pid", pid,
			"error", err,
		)
		return
	}

	// Use a timeout context to prevent indefinite hangs if the stub never
	// sends MsgReady or the connection stalls.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Start serving the stub connection with the original command.
	go func() {
		defer cancel()
		defer srvConn.Close()
		sErr := stub.ServeStubConnection(ctx, srvConn, stub.ServeConfig{
			Command:    executable,
			Args:       args,
			WorkingDir: execCtx.CWDPath,
		})
		if sErr != nil {
			slog.Error("es_exec: stub serve error",
				"pid", pid,
				"cmd", executable,
				"error", sErr,
			)
		}
	}()

	// Launch agentsh-stub with the socketpair fd.
	h.launchStub(stubFile, executable, pid, execCtx)
}

// launchStub spawns the agentsh-stub binary connected to the stub server.
//
// The stubFile is passed as fd 3 to the subprocess via ExtraFiles, and the
// AGENTSH_STUB_FD=3 env var tells the stub which fd to use. Stdout/stderr
// are connected to the denied process's TTY so output appears in the
// original terminal.
//
// On macOS this is fundamentally different from Linux:
//   - Linux: stub is injected INTO the trapped process via SECCOMP_ADDFD
//   - macOS: original exec is denied (EPERM), stub is spawned as a new process
func (h *ESExecHandler) launchStub(stubFile *os.File, originalCmd string, originalPID int32, execCtx xpc.ExecContext) {
	defer stubFile.Close()

	if h.stubBinary == "" {
		slog.Error("es_exec: stub binary path not configured")
		return
	}

	cmd := exec.Command(h.stubBinary)
	cmd.ExtraFiles = []*os.File{stubFile} // fd 3
	cmd.Env = []string{
		"AGENTSH_STUB_FD=3",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	}

	if execCtx.CWDPath != "" {
		cmd.Dir = execCtx.CWDPath
	}

	// Connect stdin/stdout/stderr to the denied process's TTY so output
	// appears in the original terminal where the command was typed.
	if execCtx.TTYPath != "" {
		ttyOut, err := os.OpenFile(execCtx.TTYPath, os.O_WRONLY, 0)
		if err == nil {
			defer ttyOut.Close()
			cmd.Stdout = ttyOut
			cmd.Stderr = ttyOut
		} else {
			slog.Warn("es_exec: cannot open TTY for output",
				"tty", execCtx.TTYPath,
				"error", err,
			)
		}

		ttyIn, err := os.OpenFile(execCtx.TTYPath, os.O_RDONLY, 0)
		if err == nil {
			defer ttyIn.Close()
			cmd.Stdin = ttyIn
		} else {
			slog.Warn("es_exec: cannot open TTY for input",
				"tty", execCtx.TTYPath,
				"error", err,
			)
		}
	}

	slog.Info("es_exec: launching stub for redirected exec",
		"cmd", originalCmd,
		"pid", originalPID,
		"stub", h.stubBinary,
		"tty", execCtx.TTYPath,
		"cwd", execCtx.CWDPath,
	)

	if err := cmd.Start(); err != nil {
		slog.Error("es_exec: failed to start stub",
			"cmd", originalCmd,
			"pid", originalPID,
			"error", err,
		)
		return
	}

	if err := cmd.Wait(); err != nil {
		slog.Debug("es_exec: stub exited with error",
			"cmd", originalCmd,
			"pid", originalPID,
			"error", err,
		)
	}
}

// Compile-time interface check: ESExecHandler must implement xpc.ExecHandler.
var _ xpc.ExecHandler = (*ESExecHandler)(nil)
