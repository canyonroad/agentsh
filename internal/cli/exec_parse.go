package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

func parseExecInput(args []string, jsonStr string, timeoutFlag string, stream bool) (sessionID string, req types.ExecRequest, err error) {
	return parseExecInputWithEnv(args, jsonStr, timeoutFlag, stream, "")
}

// parseExecInputWithEnv parses exec command input, using envSessionID as fallback if no session ID in args.
// Formats supported:
//   - SESSION_ID -- COMMAND [ARGS...]
//   - SESSION_ID COMMAND [ARGS...]       (no -- separator)
//   - -- COMMAND [ARGS...]               (with AGENTSH_SESSION_ID env var)
//   - COMMAND [ARGS...]                  (with AGENTSH_SESSION_ID env var, no --)
func parseExecInputWithEnv(args []string, jsonStr string, timeoutFlag string, stream bool, envSessionID string) (sessionID string, req types.ExecRequest, err error) {
	timeoutFlag = strings.TrimSpace(timeoutFlag)

	// Handle --json mode
	if strings.TrimSpace(jsonStr) != "" {
		// In JSON mode, first arg (if any) is session ID, or use env
		if len(args) > 0 && envSessionID == "" {
			sessionID = args[0]
		} else {
			sessionID = envSessionID
		}
		if sessionID == "" {
			return "", types.ExecRequest{}, fmt.Errorf("session id is required (provide as argument or set AGENTSH_SESSION_ID)")
		}
		if err := json.Unmarshal([]byte(jsonStr), &req); err != nil {
			return "", types.ExecRequest{}, fmt.Errorf("invalid --json: %w", err)
		}
		if timeoutFlag != "" {
			req.Timeout = timeoutFlag
		}
		if stream {
			req.StreamOutput = true
		}
		if req.Command == "" {
			return "", types.ExecRequest{}, fmt.Errorf("command is required")
		}
		return sessionID, req, nil
	}

	// Find "--" separator if present
	dashDashIdx := -1
	for i, arg := range args {
		if arg == "--" {
			dashDashIdx = i
			break
		}
	}

	cmdStart := 0
	if dashDashIdx >= 0 {
		// "--" found: format is [SESSION_ID] -- COMMAND [ARGS...]
		// Everything before "--" is potential session ID, after is command
		if dashDashIdx == 0 {
			// "-- COMMAND" - no session ID in args, use env
			sessionID = envSessionID
		} else {
			// "SESSION_ID -- COMMAND" - session ID is in args
			// Prefer env if set, otherwise use arg
			if envSessionID != "" {
				sessionID = envSessionID
			} else {
				sessionID = args[0]
			}
		}
		cmdStart = dashDashIdx + 1
	} else {
		// No "--" separator (note: Cobra strips "--" before passing args)
		if envSessionID != "" {
			sessionID = envSessionID
			// Check if first arg looks like a duplicate session ID
			// This happens when shim passes session ID in both env and args,
			// and Cobra strips the "--" separator
			if len(args) > 0 && args[0] == envSessionID {
				// First arg is the session ID (duplicate), skip it
				cmdStart = 1
			} else {
				// All args are the command
				cmdStart = 0
			}
		} else if len(args) > 0 {
			// First arg is session ID, rest is command
			sessionID = args[0]
			cmdStart = 1
		}
	}

	if sessionID == "" {
		return "", types.ExecRequest{}, fmt.Errorf("session id is required (provide as argument or set AGENTSH_SESSION_ID)")
	}

	if cmdStart >= len(args) {
		return "", types.ExecRequest{}, fmt.Errorf("command is required")
	}

	req.Command = args[cmdStart]
	req.Args = args[cmdStart+1:]
	req.Timeout = timeoutFlag
	if stream {
		req.StreamOutput = true
	}
	return sessionID, req, nil
}
