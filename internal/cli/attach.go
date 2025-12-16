package cli

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newSessionAttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach SESSION_ID",
		Short: "Attach to a session (interactive)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			cfg := getClientConfig(cmd)
			cl := client.New(cfg.serverAddr, cfg.apiKey)

			in := bufio.NewScanner(cmd.InOrStdin())
			for {
				snap, err := cl.GetSession(cmd.Context(), sessionID)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "agentsh:%s:%s$ ", sessionID, snap.Cwd)

				if !in.Scan() {
					return in.Err()
				}
				line := strings.TrimSpace(in.Text())
				if line == "" {
					continue
				}
				if line == "exit" || line == "quit" {
					return nil
				}

				argv, err := splitArgs(line)
				if err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), err.Error())
					continue
				}
				if len(argv) == 0 {
					continue
				}
				req := types.ExecRequest{Command: argv[0], Args: argv[1:]}
				resp, err := cl.Exec(cmd.Context(), sessionID, req)
				if err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), err.Error())
					continue
				}
				_ = printJSON(cmd, resp)
			}
		},
	}
	return cmd
}

func splitArgs(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := byte(0)
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if inQuote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return out, nil
}
