package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

func parseExecInput(args []string, jsonStr string, timeoutFlag string, stream bool) (sessionID string, req types.ExecRequest, err error) {
	if len(args) < 1 {
		return "", types.ExecRequest{}, fmt.Errorf("session id is required")
	}
	sessionID = args[0]
	timeoutFlag = strings.TrimSpace(timeoutFlag)

	if strings.TrimSpace(jsonStr) != "" {
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

	if len(args) < 2 {
		return "", types.ExecRequest{}, fmt.Errorf("command is required")
	}
	start := 1
	if args[1] == "--" {
		start = 2
	}
	if start >= len(args) {
		return "", types.ExecRequest{}, fmt.Errorf("command is required")
	}
	req.Command = args[start]
	req.Args = args[start+1:]
	req.Timeout = timeoutFlag
	if stream {
		req.StreamOutput = true
	}
	return sessionID, req, nil
}
