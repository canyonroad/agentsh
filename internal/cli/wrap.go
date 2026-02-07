package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
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
		var wdErr error
		workspace, wdErr = os.Getwd()
		if wdErr != nil {
			return fmt.Errorf("getwd: %w", wdErr)
		}
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

	// 2. Resolve the agent binary
	agentPath, err := exec.LookPath(opts.agentCmd)
	if err != nil {
		return fmt.Errorf("agent not found: %s: %w", opts.agentCmd, err)
	}

	// 3. Try to set up exec interception (Linux seccomp / macOS ES)
	var wrapCfg *wrapLaunchConfig
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		wrapCfg, err = setupWrapInterception(ctx, c, sessID, agentPath, opts.agentArgs, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentsh: interception setup failed, running without interception: %v\n", err)
			// Fall through to direct launch
		}
	}

	// 4. Build the agent command
	var agentProc *exec.Cmd
	if wrapCfg != nil {
		// Launch through the seccomp wrapper
		agentProc = exec.CommandContext(ctx, wrapCfg.command, wrapCfg.args...)
		agentProc.Stdin = os.Stdin
		agentProc.Stdout = os.Stdout
		agentProc.Stderr = os.Stderr
		agentProc.Env = wrapCfg.env
		agentProc.ExtraFiles = wrapCfg.extraFiles
		agentProc.SysProcAttr = wrapCfg.sysProcAttr
	} else {
		// Direct launch (no interception)
		agentProc = exec.CommandContext(ctx, agentPath, opts.agentArgs...)
		agentProc.Stdin = os.Stdin
		agentProc.Stdout = os.Stdout
		agentProc.Stderr = os.Stderr
		agentProc.Env = append(os.Environ(),
			fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
			fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
		)
	}

	// Set up signal forwarding
	sigCh := make(chan os.Signal, 1)
	sigDone := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer close(sigDone)
		for sig := range sigCh {
			if agentProc.Process != nil {
				agentProc.Process.Signal(sig)
			}
		}
	}()

	if err := agentProc.Start(); err != nil {
		signal.Stop(sigCh)
		close(sigCh)
		// Clean up extra files
		if wrapCfg != nil {
			for _, f := range wrapCfg.extraFiles {
				if f != nil {
					f.Close()
				}
			}
		}
		return fmt.Errorf("start agent: %w", err)
	}

	// Close the child end of the socket pair (now owned by the child process)
	if wrapCfg != nil {
		for _, f := range wrapCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}

	if wrapCfg != nil {
		mechanism := "seccomp"
		if runtime.GOOS == "darwin" {
			mechanism = "ES"
		}
		fmt.Fprintf(os.Stderr, "agentsh: agent %s started with %s interception (pid: %d)\n", opts.agentCmd, mechanism, agentProc.Process.Pid)
		// Forward the notify fd to the server in the background
		if wrapCfg.postStart != nil {
			go wrapCfg.postStart()
		}
	} else {
		fmt.Fprintf(os.Stderr, "agentsh: agent %s started (pid: %d)\n", opts.agentCmd, agentProc.Process.Pid)
	}

	// 5. Wait for agent to exit
	waitErr := agentProc.Wait()

	signal.Stop(sigCh)
	close(sigCh)
	<-sigDone // Wait for the signal goroutine to exit before proceeding

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		}
	}

	// 6. Generate report
	if opts.report {
		fmt.Fprintf(os.Stderr, "\nagentsh: session %s complete (agent exit code: %d)\n", sessID, exitCode)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// wrapLaunchConfig holds the configuration for launching the agent through a wrapper.
type wrapLaunchConfig struct {
	command     string
	args        []string
	env         []string
	extraFiles  []*os.File
	sysProcAttr *syscall.SysProcAttr
	postStart   func() // Called after the process starts (e.g., to forward notify fd)
}

// setupWrapInterception initializes seccomp interception via the server and returns
// the launch configuration for the agent process. This is the platform-independent
// part that calls into platform-specific code.
func setupWrapInterception(ctx context.Context, c client.CLIClient, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	// Call the server to get wrapper configuration
	wrapResp, err := c.WrapInit(ctx, sessID, types.WrapInitRequest{
		AgentCommand: agentPath,
		AgentArgs:    agentArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("wrap-init: %w", err)
	}

	// On Linux, the server must provide a wrapper binary for seccomp interception.
	// On macOS, an empty WrapperBinary is valid — ES interception is system-wide
	// via the System Extension, so the agent can run directly.
	if wrapResp.WrapperBinary == "" && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("server returned empty wrapper binary")
	}

	// Delegate to platform-specific code for socket pair creation and fd management
	return platformSetupWrap(ctx, wrapResp, sessID, agentPath, agentArgs, cfg)
}
