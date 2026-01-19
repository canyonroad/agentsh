package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policy/ancestry"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newTaintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "taint",
		Short: "Process taint inspection and debugging",
		Long: `Commands for inspecting process ancestry taints.

Taints track which processes are descended from AI tools (like Cursor,
Claude Desktop, VS Code with Copilot). This enables parent-conditional
policies that restrict what AI-spawned processes can do.`,
	}

	cmd.AddCommand(newTaintListCmd())
	cmd.AddCommand(newTaintShowCmd())
	cmd.AddCommand(newTaintTraceCmd())
	cmd.AddCommand(newTaintWatchCmd())
	cmd.AddCommand(newTaintSimulateCmd())

	return cmd
}

func newTaintListCmd() *cobra.Command {
	var jsonOutput bool
	var sessionID string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tainted processes",
		Long:  `Lists all processes currently tracked as tainted (descended from AI tools).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			taints, err := c.ListTaints(cmd.Context(), sessionID)
			if err != nil {
				return fmt.Errorf("failed to list taints: %w", err)
			}

			if jsonOutput {
				return printJSON(cmd, taints)
			}

			return printTaintListHuman(cmd, taints)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID")
	return cmd
}

func printTaintListHuman(cmd *cobra.Command, taints []types.TaintInfo) error {
	w := cmd.OutOrStdout()

	if len(taints) == 0 {
		fmt.Fprintln(w, "No tainted processes")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PID\tSOURCE\tCONTEXT\tDEPTH\tAGENT\tVIA")

	for _, t := range taints {
		agent := ""
		if t.IsAgent {
			agent = "yes"
		}
		via := strings.Join(t.Via, " → ")
		if len(via) > 40 {
			via = via[:37] + "..."
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\n",
			t.PID, t.SourceName, t.ContextName, t.Depth, agent, via)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%d tainted process(es)\n", len(taints))
	return nil
}

func newTaintShowCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "show <pid>",
		Short: "Show taint details for a process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pid int
			if _, err := fmt.Sscanf(args[0], "%d", &pid); err != nil {
				return fmt.Errorf("invalid PID: %s", args[0])
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			taint, err := c.GetTaint(cmd.Context(), pid)
			if err != nil {
				return fmt.Errorf("failed to get taint: %w", err)
			}

			if taint == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Process %d is not tainted\n", pid)
				return nil
			}

			if jsonOutput {
				return printJSON(cmd, taint)
			}

			return printTaintShowHuman(cmd, taint)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}

func printTaintShowHuman(cmd *cobra.Command, t *types.TaintInfo) error {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "PID:          %d\n", t.PID)
	fmt.Fprintf(w, "Source PID:   %d\n", t.SourcePID)
	fmt.Fprintf(w, "Source Name:  %s\n", t.SourceName)
	fmt.Fprintf(w, "Context:      %s\n", t.ContextName)
	fmt.Fprintf(w, "Depth:        %d\n", t.Depth)
	fmt.Fprintf(w, "Is Agent:     %v\n", t.IsAgent)
	fmt.Fprintf(w, "Inherited At: %s\n", t.InheritedAt.Format(time.RFC3339))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Via Chain:")
	if len(t.Via) == 0 {
		fmt.Fprintln(w, "  (direct child of source)")
	} else {
		for i, v := range t.Via {
			class := ""
			if i < len(t.ViaClasses) {
				class = fmt.Sprintf(" [%s]", t.ViaClasses[i])
			}
			fmt.Fprintf(w, "  %d. %s%s\n", i+1, v, class)
		}
	}

	return nil
}

func newTaintTraceCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "trace <pid>",
		Short: "Show full ancestry trace for a process",
		Long: `Shows the complete process ancestry from the taint source to the
specified process, including classification of each intermediate process.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pid int
			if _, err := fmt.Sscanf(args[0], "%d", &pid); err != nil {
				return fmt.Errorf("invalid PID: %s", args[0])
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			trace, err := c.GetTaintTrace(cmd.Context(), pid)
			if err != nil {
				return fmt.Errorf("failed to get trace: %w", err)
			}

			if jsonOutput {
				return printJSON(cmd, trace)
			}

			return printTaintTraceHuman(cmd, trace)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}

func printTaintTraceHuman(cmd *cobra.Command, trace *types.TaintTrace) error {
	w := cmd.OutOrStdout()

	if trace == nil || trace.Taint == nil {
		fmt.Fprintln(w, "Process is not tainted")
		return nil
	}

	fmt.Fprintf(w, "Ancestry Trace for PID %d\n", trace.Taint.PID)
	fmt.Fprintln(w, strings.Repeat("─", 50))
	fmt.Fprintln(w)

	// Show source
	fmt.Fprintf(w, "┌─ SOURCE: %s (PID %d)\n", trace.Taint.SourceName, trace.Taint.SourcePID)
	fmt.Fprintf(w, "│  Context: %s\n", trace.Taint.ContextName)
	fmt.Fprintln(w, "│")

	// Show via chain
	for i, v := range trace.Taint.Via {
		class := "unknown"
		if i < len(trace.Taint.ViaClasses) {
			class = trace.Taint.ViaClasses[i]
		}
		if i == len(trace.Taint.Via)-1 {
			fmt.Fprintf(w, "└─ %s [%s] (depth %d)\n", v, class, i+1)
		} else {
			fmt.Fprintf(w, "├─ %s [%s] (depth %d)\n", v, class, i+1)
			fmt.Fprintln(w, "│")
		}
	}

	fmt.Fprintln(w)

	// Show analysis
	if len(trace.MatchedRules) > 0 {
		fmt.Fprintln(w, "Matched Chain Rules:")
		for _, rule := range trace.MatchedRules {
			fmt.Fprintf(w, "  • %s: %s\n", rule.Name, rule.Action)
			if rule.Message != "" {
				fmt.Fprintf(w, "    %s\n", rule.Message)
			}
		}
	}

	if trace.Taint.IsAgent {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "⚠ Process is marked as AI AGENT")
	}

	return nil
}

func newTaintWatchCmd() *cobra.Command {
	var agentOnly bool

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Stream taint events in real-time",
		Long:  `Watches for taint events (new taints, propagation, removal) in real-time.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "Watching for taint events... (press Ctrl+C to stop)")
			fmt.Fprintln(w)

			return c.WatchTaints(cmd.Context(), agentOnly, func(event types.TaintEvent) {
				printTaintEvent(cmd, event)
			})
		},
	}

	cmd.Flags().BoolVar(&agentOnly, "agent-only", false, "Only show agent-detected processes")
	return cmd
}

func printTaintEvent(cmd *cobra.Command, event types.TaintEvent) {
	w := cmd.OutOrStdout()
	ts := event.Timestamp.Format("15:04:05")

	switch event.Type {
	case "taint_created":
		fmt.Fprintf(w, "[%s] 🆕 TAINT SOURCE: %s (PID %d) → context: %s\n",
			ts, event.SourceName, event.PID, event.ContextName)
	case "taint_propagated":
		fmt.Fprintf(w, "[%s] 📥 PROPAGATED: PID %d ← %s (depth %d)\n",
			ts, event.PID, event.SourceName, event.Depth)
	case "taint_removed":
		fmt.Fprintf(w, "[%s] 🗑️  REMOVED: PID %d\n", ts, event.PID)
	case "agent_detected":
		fmt.Fprintf(w, "[%s] 🤖 AGENT DETECTED: PID %d (confidence: %.0f%%)\n",
			ts, event.PID, event.Confidence*100)
	default:
		fmt.Fprintf(w, "[%s] %s: PID %d\n", ts, event.Type, event.PID)
	}
}

// newTaintSimulateCmd creates a command for simulating taint scenarios locally.
func newTaintSimulateCmd() *cobra.Command {
	var ancestry string
	var command string
	var commandArgs string
	var contextName string
	var policyFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate taint evaluation for testing",
		Long: `Simulates taint evaluation locally without requiring a running daemon.
Useful for testing policy configurations with different ancestry scenarios.

Example:
  agentsh taint simulate --ancestry "cursor,bash,npm,node" --command "curl" --args "https://example.com"
  agentsh taint simulate --ancestry "cursor,bash" --command "git" --args "push" --policy ./my-policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ancestry == "" {
				return fmt.Errorf("--ancestry is required")
			}
			if command == "" {
				return fmt.Errorf("--command is required")
			}

			// Parse ancestry chain
			viaChain := strings.Split(ancestry, ",")
			for i := range viaChain {
				viaChain[i] = strings.TrimSpace(viaChain[i])
			}

			// Parse command args
			var cmdArgs []string
			if commandArgs != "" {
				cmdArgs = strings.Fields(commandArgs)
			}

			// Build simulation result
			result, err := simulateTaintEvaluation(cmd.Context(), viaChain, command, cmdArgs, contextName, policyFile)
			if err != nil {
				return err
			}

			if jsonOutput {
				return printJSON(cmd, result)
			}

			return printSimulationHuman(cmd, result)
		},
	}

	cmd.Flags().StringVar(&ancestry, "ancestry", "", "Comma-separated process chain (e.g., 'cursor,bash,npm')")
	cmd.Flags().StringVar(&command, "command", "", "Command to evaluate")
	cmd.Flags().StringVar(&commandArgs, "args", "", "Command arguments (space-separated)")
	cmd.Flags().StringVar(&contextName, "context", "", "Process context name (auto-detected from first ancestor if not specified)")
	cmd.Flags().StringVar(&policyFile, "policy", "", "Policy file to use (uses built-in test policy if not specified)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

// SimulationResult contains the result of a taint simulation.
type SimulationResult struct {
	Ancestry     []string                `json:"ancestry"`
	ViaClasses   []string                `json:"via_classes"`
	Command      string                  `json:"command"`
	Args         []string                `json:"args"`
	ContextName  string                  `json:"context_name"`
	Depth        int                     `json:"depth"`
	Decision     string                  `json:"decision"`
	Rule         string                  `json:"rule"`
	Message      string                  `json:"message,omitempty"`
	MatchedRules []SimulationMatchedRule `json:"matched_rules,omitempty"`
	IsAgent      bool                    `json:"is_agent"`
}

// SimulationMatchedRule represents a chain rule that matched.
type SimulationMatchedRule struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Message string `json:"message,omitempty"`
}

func simulateTaintEvaluation(ctx context.Context, viaChain []string, command string, args []string, contextName, policyFile string) (*SimulationResult, error) {
	// Classify via chain
	viaClasses := make([]string, len(viaChain))
	viaClassEnums := make([]ancestry.ProcessClass, len(viaChain))
	for i, v := range viaChain {
		class := ancestry.ClassifyProcess(v)
		viaClasses[i] = class.String()
		viaClassEnums[i] = class
	}

	// Determine context name from first ancestor if not specified
	if contextName == "" && len(viaChain) > 0 {
		// Use first element as source, determine context
		contextName = guessContextName(viaChain[0])
	}

	// Create simulated taint
	taint := &ancestry.ProcessTaint{
		SourcePID:   1000,
		SourceName:  viaChain[0],
		ContextName: contextName,
		IsAgent:     false,
		Via:         viaChain[1:], // First element is source, rest is via
		ViaClasses:  viaClassEnums[1:],
		Depth:       len(viaChain) - 1,
		InheritedAt: time.Now(),
	}

	result := &SimulationResult{
		Ancestry:    viaChain,
		ViaClasses:  viaClasses,
		Command:     command,
		Args:        args,
		ContextName: contextName,
		Depth:       taint.Depth,
	}

	// Load or create policy
	var p *policy.Policy
	var err error

	if policyFile != "" {
		p, err = policy.LoadFromFile(policyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy: %w", err)
		}
	} else {
		// Use a built-in test policy
		p = createTestPolicy(contextName)
	}

	// Create taint cache and context engine
	taintCache := ancestry.NewTaintCache(ancestry.TaintCacheConfig{
		TTL:      time.Hour,
		MaxDepth: 100,
	})
	taintCache.SetClassifyProcess(ancestry.ClassifyProcess)

	// Manually inject the taint for simulation
	// We simulate by adding the source and propagating
	sourcePID := 1000
	currentPID := sourcePID

	// Add source taint
	taintCache.SetMatchesTaintSource(func(info *ancestry.ProcessInfo) (string, bool) {
		if info.PID == sourcePID {
			return contextName, true
		}
		return "", false
	})

	// Spawn source
	taintCache.OnSpawn(sourcePID, 1, &ancestry.ProcessInfo{
		PID:  sourcePID,
		PPID: 1,
		Comm: viaChain[0],
	})

	// Spawn intermediates
	for i := 1; i < len(viaChain); i++ {
		newPID := sourcePID + i
		taintCache.OnSpawn(newPID, currentPID, &ancestry.ProcessInfo{
			PID:  newPID,
			PPID: currentPID,
			Comm: viaChain[i],
		})
		currentPID = newPID
	}

	// Create context engine
	ce, err := policy.NewContextEngine(p, true, policy.ContextEngineConfig{
		TaintCache: taintCache,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create context engine: %w", err)
	}

	// Evaluate
	dec := ce.CheckCommandWithContext(ctx, currentPID, command, args)

	result.Decision = string(dec.PolicyDecision)
	result.Rule = dec.Rule
	result.Message = dec.Message

	// Check if marked as agent
	finalTaint := taintCache.IsTainted(currentPID)
	if finalTaint != nil {
		result.IsAgent = finalTaint.IsAgent
	}

	return result, nil
}

func guessContextName(sourceName string) string {
	sourceLower := strings.ToLower(sourceName)
	switch {
	case strings.Contains(sourceLower, "cursor"):
		return "ai_tools"
	case strings.Contains(sourceLower, "claude"):
		return "ai_tools"
	case strings.Contains(sourceLower, "code"), strings.Contains(sourceLower, "vscode"):
		return "ai_tools"
	case strings.Contains(sourceLower, "aider"):
		return "ai_tools"
	default:
		return "ai_tools" // Default context
	}
}

func createTestPolicy(contextName string) *policy.Policy {
	return &policy.Policy{
		Version: 1,
		Name:    "test-policy",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		ProcessContexts: map[string]policy.ProcessContext{
			contextName: {
				Description: "AI tool context for simulation",
				Identities:  []string{"cursor", "claude-desktop", "code", "aider"},
				ChainRules: []policy.ChainRuleConfig{
					{
						Name:     "shell_laundering",
						Priority: 200,
						Condition: &policy.ChainConditionConfig{
							ConsecutiveClass: &policy.ConsecutiveMatchConfig{
								Value:   "shell",
								CountGE: 3,
							},
						},
						Action:  "deny",
						Message: "Shell laundering detected",
					},
					{
						Name:     "user_terminal",
						Priority: 100,
						Condition: &policy.ChainConditionConfig{
							And: []*policy.ChainConditionConfig{
								{DepthEQ: intPtr(1)},
								{ClassContains: []string{"shell"}},
							},
						},
						Action:  "allow_normal_policy",
						Message: "User-opened terminal",
					},
					{
						Name:     "depth_limit",
						Priority: 90,
						Condition: &policy.ChainConditionConfig{
							DepthGT: intPtr(10),
						},
						Action:  "deny",
						Message: "Process chain too deep",
					},
				},
				AllowedCommands: []string{"ls", "cat", "git", "npm", "node", "python", "go"},
				DeniedCommands:  []string{"rm -rf", "sudo"},
				RequireApproval: []string{"curl", "wget", "ssh"},
				DefaultDecision: "deny",
			},
		},
	}
}

func printSimulationHuman(cmd *cobra.Command, result *SimulationResult) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "Taint Simulation Result")
	fmt.Fprintln(w, strings.Repeat("─", 50))
	fmt.Fprintln(w)

	// Show ancestry
	fmt.Fprintln(w, "Ancestry Chain:")
	for i, proc := range result.Ancestry {
		class := "unknown"
		if i < len(result.ViaClasses) {
			class = result.ViaClasses[i]
		}
		role := ""
		if i == 0 {
			role = " (SOURCE)"
		}
		fmt.Fprintf(w, "  %d. %s [%s]%s\n", i+1, proc, class, role)
	}
	fmt.Fprintln(w)

	// Show command being evaluated
	cmdStr := result.Command
	if len(result.Args) > 0 {
		cmdStr += " " + strings.Join(result.Args, " ")
	}
	fmt.Fprintf(w, "Command:    %s\n", cmdStr)
	fmt.Fprintf(w, "Context:    %s\n", result.ContextName)
	fmt.Fprintf(w, "Depth:      %d\n", result.Depth)
	fmt.Fprintln(w)

	// Show decision
	decisionIcon := "❓"
	switch result.Decision {
	case "allow":
		decisionIcon = "✅"
	case "deny":
		decisionIcon = "❌"
	case "approve":
		decisionIcon = "⏳"
	}

	fmt.Fprintf(w, "Decision:   %s %s\n", decisionIcon, strings.ToUpper(result.Decision))
	fmt.Fprintf(w, "Rule:       %s\n", result.Rule)
	if result.Message != "" {
		fmt.Fprintf(w, "Message:    %s\n", result.Message)
	}
	if result.IsAgent {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "⚠ Process marked as AI AGENT")
	}

	return nil
}

func intPtr(i int) *int {
	return &i
}
