package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newWrapCmd() *cobra.Command {
	var sessionID string
	var policy string
	var root string
	var report bool

	cmd := &cobra.Command{
		Use:   "wrap [flags] -- COMMAND [ARGS...]",
		Short: "Wrap an AI agent with exec interception",
		Long: `Launch an AI agent with full exec interception.

Every command spawned by the agent and its descendants is routed through the
agentsh exec pipeline (policy check, approval workflow, audit logging).

Examples:
  agentsh wrap -- claude-code
  agentsh wrap --policy strict -- codex
  agentsh wrap --session my-dev -- cursor`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("command required after --\n\nUsage: agentsh wrap [flags] -- COMMAND [ARGS...]")
			}

			cfg := getClientConfig(cmd)
			return runWrap(cmd.Context(), cfg, wrapOptions{
				sessionID: sessionID,
				policy:    policy,
				root:      root,
				report:    report,
				agentCmd:  args[0],
				agentArgs: args[1:],
			})
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Reuse existing session ID (creates new if empty)")
	cmd.Flags().StringVar(&policy, "policy", "agent-default", "Policy name")
	cmd.Flags().StringVar(&root, "root", "", "Workspace root (default: current directory)")
	cmd.Flags().BoolVar(&report, "report", true, "Generate session report on exit")

	return cmd
}

type wrapOptions struct {
	sessionID string
	policy    string
	root      string
	report    bool
	agentCmd  string
	agentArgs []string
}

func runWrap(ctx context.Context, cfg *clientConfig, opts wrapOptions) error {
	// 1. Create or reuse session
	c, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL: cfg.serverAddr,
		GRPCAddr:    cfg.grpcAddr,
		APIKey:      cfg.apiKey,
		Transport:   cfg.transport,
	})
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}

	workspace := opts.root
	if workspace == "" {
		workspace, _ = os.Getwd()
	}

	var sessID string
	if opts.sessionID != "" {
		sess, err := c.GetSession(ctx, opts.sessionID)
		if err != nil {
			return fmt.Errorf("get session %s: %w", opts.sessionID, err)
		}
		sessID = sess.ID
	} else {
		sess, err := c.CreateSession(ctx, workspace, opts.policy)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}
		sessID = sess.ID
		fmt.Fprintf(os.Stderr, "agentsh: session %s created (policy: %s)\n", sessID, opts.policy)
	}

	// 2. Launch the agent process
	agentPath, err := exec.LookPath(opts.agentCmd)
	if err != nil {
		return fmt.Errorf("agent not found: %s: %w", opts.agentCmd, err)
	}

	agentProc := exec.CommandContext(ctx, agentPath, opts.agentArgs...)
	agentProc.Stdin = os.Stdin
	agentProc.Stdout = os.Stdout
	agentProc.Stderr = os.Stderr
	agentProc.Env = append(os.Environ(),
		fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
		fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
	)

	// Set up signal forwarding
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if agentProc.Process != nil {
				agentProc.Process.Signal(sig)
			}
		}
	}()

	if err := agentProc.Start(); err != nil {
		signal.Stop(sigCh)
		close(sigCh)
		return fmt.Errorf("start agent: %w", err)
	}

	fmt.Fprintf(os.Stderr, "agentsh: agent %s started (pid: %d)\n", opts.agentCmd, agentProc.Process.Pid)

	// 3. Wait for agent to exit
	waitErr := agentProc.Wait()

	signal.Stop(sigCh)
	close(sigCh)

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		}
	}

	// 4. Generate report
	if opts.report {
		fmt.Fprintf(os.Stderr, "\nagentsh: session %s complete (agent exit code: %d)\n", sessID, exitCode)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}
