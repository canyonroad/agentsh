//go:build darwin

package darwin

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/agentsh/agentsh/internal/platform/darwin/xpc"
	"github.com/agentsh/agentsh/internal/stub"
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

// spawnStubServer spawns the original command via the stub protocol.
// On macOS, we can't rewrite the exec target in ES, so we deny the original
// exec and run the command server-side, with I/O proxied through the stub.
//
// This creates an in-process net.Pipe between the stub server (which runs the
// command) and the stub client side. The stub server uses ServeStubConnection
// to execute the command and proxy its I/O.
//
// TODO(phase2): The full implementation needs to connect the stub output back
// to the original process's terminal/PTY. For now, the server-side command
// execution works but the output goes to the server's log rather than to the
// caller. The launchStub method is a placeholder for the process-spawning part.
func (h *ESExecHandler) spawnStubServer(executable string, args []string, pid int32, parentPID int32, sessionID string, execCtx xpc.ExecContext) {
	if h.stubBinary == "" {
		slog.Error("es_exec: stub binary path not configured, cannot redirect exec",
			"cmd", executable,
			"pid", pid,
		)
		return
	}

	srvConn, stubConn := net.Pipe()

	// Use a timeout context to prevent indefinite hangs if the stub never
	// sends MsgReady or the connection stalls.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Start serving the stub connection with the original command.
	go func() {
		defer cancel()
		defer srvConn.Close()
		sErr := stub.ServeStubConnection(ctx, srvConn, stub.ServeConfig{
			Command: executable,
			Args:    args,
		})
		if sErr != nil {
			slog.Error("es_exec: stub serve error",
				"pid", pid,
				"cmd", executable,
				"error", sErr,
			)
		}
	}()

	// Launch agentsh-stub with the connection.
	h.launchStub(stubConn, executable, pid)
}

// launchStub spawns the agentsh-stub binary connected to the stub server.
//
// TODO(phase2): This is a placeholder. The full implementation needs to:
//  1. Create a Unix socketpair (net.Pipe is in-process only, not passable to a subprocess)
//  2. Pass the FD to the stub binary via AGENTSH_STUB_FD env var
//  3. Connect the stub's stdout/stderr to the original process's terminal
//
// On macOS this is fundamentally different from Linux:
//   - Linux: stub is injected INTO the trapped process via SECCOMP_ADDFD
//   - macOS: original exec is denied (EPERM), stub is spawned as a new process
//
// For now, we log the intent and close the connection.
func (h *ESExecHandler) launchStub(conn net.Conn, originalCmd string, originalPID int32) {
	defer conn.Close()

	if h.stubBinary == "" {
		slog.Error("es_exec: stub binary path not configured")
		return
	}

	slog.Info("es_exec: would launch stub for redirected exec",
		"cmd", originalCmd,
		"pid", originalPID,
		"stub", h.stubBinary,
	)
}

// Compile-time interface check: ESExecHandler must implement xpc.ExecHandler.
var _ xpc.ExecHandler = (*ESExecHandler)(nil)
