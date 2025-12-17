package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newExecCmd() *cobra.Command {
	var timeout string
	var jsonStr string
	var stream bool
	var argv0 string
	var output string
	var events string
	c := &cobra.Command{
		Use:   "exec SESSION_ID -- COMMAND [ARGS...]",
		Short: "Execute a command in a session",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, req, err := parseExecInput(args, jsonStr, timeout, stream)
			if err != nil {
				return err
			}
			if strings.TrimSpace(argv0) != "" {
				req.Argv0 = argv0
			}

			outMode := strings.ToLower(strings.TrimSpace(output))
			if outMode == "" {
				outMode = "shell"
			}
			switch outMode {
			case "shell", "json":
			default:
				return fmt.Errorf("invalid --output %q (expected shell|json)", output)
			}

			evMode := strings.ToLower(strings.TrimSpace(events))
			if evMode == "" {
				if outMode == "shell" {
					evMode = "none"
				} else {
					evMode = "summary"
				}
			}
			switch evMode {
			case "all", "summary", "blocked", "none":
			default:
				return fmt.Errorf("invalid --events %q (expected all|summary|blocked|none)", events)
			}
			req.IncludeEvents = evMode

			cfg := getClientConfig(cmd)
			cl, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			if req.StreamOutput {
				return execStream(cmd, cl, cfg.serverAddr, sessionID, req, outMode)
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
				grpcNotFound := func(e error) bool {
					st, ok := status.FromError(e)
					return ok && st.Code() == codes.NotFound
				}
				if (errors.As(err, &he) && he.StatusCode == http.StatusNotFound && strings.Contains(strings.ToLower(he.Body), "session not found")) || grpcNotFound(err) {
					wd, wdErr := os.Getwd()
					if wdErr == nil {
						if _, createErr := cl.CreateSessionWithID(cmd.Context(), sessionID, wd, ""); createErr == nil {
							resp, err = cl.Exec(cmd.Context(), sessionID, req)
						}
					}
				}
			}
			// Server returns a structured ExecResponse body for certain non-2xx statuses (e.g. policy denies).
			// Decode it so CLI can still render output and exit with the intended command exit code.
			if err != nil {
				if decoded, ok := decodeExecResponseFromHTTPError(err); ok {
					resp = decoded
					err = nil
				}
			}
			if err != nil {
				return err
			}

			switch outMode {
			case "json":
				if err := printJSON(cmd, resp); err != nil {
					return err
				}
				if resp.Result.ExitCode != 0 {
					return &ExitError{code: resp.Result.ExitCode}
				}
				return nil
			case "shell":
				return printShellExec(cmd, resp)
			default:
				return fmt.Errorf("invalid output mode %q", outMode)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVar(&timeout, "timeout", "", "Command timeout (e.g. 30s, 5m)")
	c.Flags().StringVar(&jsonStr, "json", "", "Exec request as JSON (e.g. '{\"command\":\"ls\",\"args\":[\"-la\"]}')")
	c.Flags().BoolVar(&stream, "stream", false, "Stream output (requires server support)")
	c.Flags().StringVar(&argv0, "argv0", "", "Override argv[0] for the executed process")
	c.Flags().StringVar(&output, "output", getenvDefault("AGENTSH_OUTPUT", "shell"), "Output format: shell|json")
	c.Flags().StringVar(&events, "events", getenvDefault("AGENTSH_EVENTS", ""), "Events to include in response: all|summary|blocked|none (default depends on --output)")
	return c
}

func execStream(cmd *cobra.Command, cl client.CLIClient, serverAddr, sessionID string, req types.ExecRequest, output string) error {
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
		grpcNotFound := func(e error) bool {
			st, ok := status.FromError(e)
			return ok && st.Code() == codes.NotFound
		}
		if (errors.As(err, &he) && he.StatusCode == http.StatusNotFound && strings.Contains(strings.ToLower(he.Body), "session not found")) || grpcNotFound(err) {
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
			if strings.EqualFold(output, "shell") {
				_, _ = io.WriteString(cmd.OutOrStdout(), p.Data)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), "[stdout] "+p.Data)
				if !strings.HasSuffix(p.Data, "\n") {
					fmt.Fprintln(cmd.OutOrStdout())
				}
			}
		case "stderr":
			if strings.EqualFold(output, "shell") {
				_, _ = io.WriteString(cmd.ErrOrStderr(), p.Data)
			} else {
				fmt.Fprint(cmd.ErrOrStderr(), "[stderr] "+p.Data)
				if !strings.HasSuffix(p.Data, "\n") {
					fmt.Fprintln(cmd.ErrOrStderr())
				}
			}
		case "done":
			if p.ExitCode != 0 {
				if !strings.EqualFold(output, "shell") {
					fmt.Fprintf(cmd.ErrOrStderr(), "exit_code=%d duration_ms=%d\n", p.ExitCode, p.DurationMs)
				}
				return &ExitError{code: p.ExitCode}
			}
			return nil
		default:
			// Unknown event type; ignore.
		}
	}
	return sc.Err()
}

func decodeExecResponseFromHTTPError(err error) (types.ExecResponse, bool) {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return types.ExecResponse{}, false
	}
	// Only attempt decode for small error bodies; doJSON caps at 64KB.
	if strings.TrimSpace(he.Body) == "" {
		return types.ExecResponse{}, false
	}
	var out types.ExecResponse
	if json.Unmarshal([]byte(he.Body), &out) != nil {
		return types.ExecResponse{}, false
	}
	if out.CommandID == "" || out.SessionID == "" {
		return types.ExecResponse{}, false
	}
	return out, true
}

func printShellExec(cmd *cobra.Command, resp types.ExecResponse) error {
	if resp.Result.Stdout != "" {
		_, _ = io.WriteString(cmd.OutOrStdout(), resp.Result.Stdout)
	}
	if resp.Result.Stderr != "" {
		_, _ = io.WriteString(cmd.ErrOrStderr(), resp.Result.Stderr)
	}

	if resp.Guidance != nil {
		if msg := strings.TrimSpace(resp.Guidance.Reason); msg != "" && (resp.Guidance.Blocked || resp.Result.ExitCode != 0) {
			if resp.Guidance.PolicyRule != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "agentsh: %s (rule=%s)\n", msg, resp.Guidance.PolicyRule)
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "agentsh: "+msg)
			}
			for _, s := range resp.Guidance.Substitutions {
				if strings.TrimSpace(s.Command) != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "agentsh: try: "+s.Command)
				}
			}
			for _, s := range resp.Guidance.Suggestions {
				if strings.TrimSpace(s.Command) != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "agentsh: try: "+s.Command)
					continue
				}
				if strings.TrimSpace(s.Reason) != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "agentsh: hint: "+s.Reason)
				}
			}
		}
	} else if msg := shellBlockSummary(resp); msg != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), msg)
		for _, s := range shellSubstitutions(resp) {
			fmt.Fprintln(cmd.ErrOrStderr(), "agentsh: try: "+s)
		}
	}

	if resp.Result.ExitCode != 0 {
		return &ExitError{code: resp.Result.ExitCode}
	}
	return nil
}

func shellBlockSummary(resp types.ExecResponse) string {
	// Prefer explicit policy error when present.
	if resp.Result.Error != nil && resp.Result.Error.PolicyRule != "" {
		return fmt.Sprintf("agentsh: blocked by policy (rule=%s): %s", resp.Result.Error.PolicyRule, resp.Result.Error.Message)
	}
	// Otherwise, summarize first blocked operation if present.
	if len(resp.Events.BlockedOperations) == 0 {
		return ""
	}
	ev := resp.Events.BlockedOperations[0]
	rule := ""
	if ev.Policy != nil {
		rule = ev.Policy.Rule
	}
	target := ev.Path
	if target == "" {
		if ev.Remote != "" {
			target = ev.Remote
		} else if ev.Domain != "" {
			target = ev.Domain
		} else if ev.Operation != "" {
			target = ev.Operation
		} else {
			target = ev.Type
		}
	}
	if rule != "" {
		return fmt.Sprintf("agentsh: blocked by policy (rule=%s): %s", rule, target)
	}
	return fmt.Sprintf("agentsh: blocked by policy: %s", target)
}

func shellSubstitutions(resp types.ExecResponse) []string {
	// Very small set of pragmatic substitutions for agents.
	cmd := filepath.Base(resp.Request.Command)
	if strings.EqualFold(cmd, "curl") {
		urlArg := ""
		for _, a := range resp.Request.Args {
			if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
				urlArg = a
			}
		}
		if urlArg != "" {
			return []string{fmt.Sprintf("wget -qO- %s", urlArg)}
		}
		return []string{"wget -qO- <URL>"}
	}
	return nil
}
