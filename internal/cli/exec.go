package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	var timeout string
	var jsonStr string
	var stream bool
	c := &cobra.Command{
		Use:   "exec SESSION_ID -- COMMAND [ARGS...]",
		Short: "Execute a command in a session",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, req, err := parseExecInput(args, jsonStr, timeout, stream)
			if err != nil {
				return err
			}

			cfg := getClientConfig(cmd)
			cl := client.New(cfg.serverAddr, cfg.apiKey)

			if req.StreamOutput {
				return execStream(cmd, cl, cfg.serverAddr, sessionID, req)
			}

			resp, err := cl.Exec(cmd.Context(), sessionID, req)
			if err != nil && !autoDisabled() && isConnectionError(err) {
				if startErr := ensureServerRunning(cmd.Context(), cfg.serverAddr, cmd.ErrOrStderr()); startErr == nil {
					resp, err = cl.Exec(cmd.Context(), sessionID, req)
				} else {
					return fmt.Errorf("server unreachable (%v); auto-start failed: %w", err, startErr)
				}
			}
			if err != nil && !autoDisabled() {
				var he *client.HTTPError
				if errors.As(err, &he) && he.StatusCode == http.StatusNotFound && strings.Contains(strings.ToLower(he.Body), "session not found") {
					wd, wdErr := os.Getwd()
					if wdErr == nil {
						if _, createErr := cl.CreateSessionWithID(cmd.Context(), sessionID, wd, ""); createErr == nil {
							resp, err = cl.Exec(cmd.Context(), sessionID, req)
						}
					}
				}
			}
			if err != nil {
				return err
			}
			return printJSON(cmd, resp)
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVar(&timeout, "timeout", "", "Command timeout (e.g. 30s, 5m)")
	c.Flags().StringVar(&jsonStr, "json", "", "Exec request as JSON (e.g. '{\"command\":\"ls\",\"args\":[\"-la\"]}')")
	c.Flags().BoolVar(&stream, "stream", false, "Stream output (requires server support)")
	return c
}

func execStream(cmd *cobra.Command, cl *client.Client, serverAddr, sessionID string, req types.ExecRequest) error {
	body, err := cl.ExecStream(cmd.Context(), sessionID, req)
	if err != nil && !autoDisabled() && isConnectionError(err) {
		if startErr := ensureServerRunning(cmd.Context(), serverAddr, cmd.ErrOrStderr()); startErr == nil {
			body, err = cl.ExecStream(cmd.Context(), sessionID, req)
		} else {
			return fmt.Errorf("server unreachable (%v); auto-start failed: %w", err, startErr)
		}
	}
	if err != nil && !autoDisabled() {
		var he *client.HTTPError
		if errors.As(err, &he) && he.StatusCode == http.StatusNotFound && strings.Contains(strings.ToLower(he.Body), "session not found") {
			wd, wdErr := os.Getwd()
			if wdErr == nil {
				if _, createErr := cl.CreateSessionWithID(cmd.Context(), sessionID, wd, ""); createErr == nil {
					body, err = cl.ExecStream(cmd.Context(), sessionID, req)
				}
			}
		}
	}
	if err != nil {
		return err
	}
	defer body.Close()

	type payload struct {
		CommandID  string `json:"command_id"`
		Stream     string `json:"stream"`
		Data       string `json:"data"`
		ExitCode   int    `json:"exit_code"`
		DurationMs int64  `json:"duration_ms"`
	}

	sc := bufio.NewScanner(body)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event: "))
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if data == "" {
			continue
		}
		var p payload
		_ = json.Unmarshal([]byte(data), &p)
		switch event {
		case "stdout":
			fmt.Fprint(cmd.OutOrStdout(), "[stdout] "+p.Data)
			if !strings.HasSuffix(p.Data, "\n") {
				fmt.Fprintln(cmd.OutOrStdout())
			}
		case "stderr":
			fmt.Fprint(cmd.ErrOrStderr(), "[stderr] "+p.Data)
			if !strings.HasSuffix(p.Data, "\n") {
				fmt.Fprintln(cmd.ErrOrStderr())
			}
		case "done":
			if p.ExitCode != 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "exit_code=%d duration_ms=%d\n", p.ExitCode, p.DurationMs)
				return fmt.Errorf("command exited with %d", p.ExitCode)
			}
			return nil
		default:
			// Unknown event type; ignore.
		}
	}
	return sc.Err()
}
