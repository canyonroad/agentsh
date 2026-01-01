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
// Format: [SESSION_ID] -- COMMAND [ARGS...]
// If envSessionID is set and no explicit session ID before "--", all args are treated as the command.
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

	// If env session ID is set, all args are the command
	// If not set, first arg is session ID, rest is command
	cmdStart := 0
	if envSessionID != "" {
		// Use env session ID, all args are the command
		sessionID = envSessionID
		cmdStart = 0
	} else if len(args) > 0 {
		// First arg is session ID
		sessionID = args[0]
		cmdStart = 1
		// Skip "--" if present after session ID
		if len(args) > 1 && args[1] == "--" {
			cmdStart = 2
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
