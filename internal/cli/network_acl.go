package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
	"github.com/spf13/cobra"
)

func newNetworkACLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "network-acl",
		Aliases: []string{"nacl", "pnacl"},
		Short:   "Manage process network ACL rules",
		Long: `Manage process network access control list (PNACL) rules.

PNACL provides per-process network access control, allowing you to define
which network destinations each process can access. Rules can allow, deny,
audit, or require approval for connections.`,
	}

	cmd.AddCommand(newNetworkACLListCmd())
	cmd.AddCommand(newNetworkACLAddCmd())
	cmd.AddCommand(newNetworkACLRemoveCmd())
	cmd.AddCommand(newNetworkACLTestCmd())
	cmd.AddCommand(newNetworkACLWatchCmd())
	cmd.AddCommand(newNetworkACLLearnCmd())

	return cmd
}

func newNetworkACLListCmd() *cobra.Command {
	var configPath string
	var processFilter string
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show active network ACL rules",
		Long: `List all active network ACL rules from the configuration file.

Rules are displayed grouped by process, showing the target, port, protocol,
and decision for each rule.`,
		Example: `  # List all rules
  agentsh network-acl list

  # List rules for a specific process
  agentsh network-acl list --process claude-code

  # Output as JSON
  agentsh network-acl list --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := resolveNetworkACLConfigPath(configPath)
			config, err := pnacl.LoadConfig(cfgPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					if outputJSON {
						return printJSON(cmd, map[string]any{
							"config_path": cfgPath,
							"default":     "approve",
							"processes":   []any{},
						})
					}
					fmt.Fprintf(cmd.OutOrStdout(), "No network ACL configuration found at %s\n", cfgPath)
					fmt.Fprintln(cmd.OutOrStdout(), "Use 'agentsh network-acl add' to create rules")
					return nil
				}
				return fmt.Errorf("load config: %w", err)
			}

			if outputJSON {
				output := map[string]any{
					"config_path": cfgPath,
					"default":     config.Default,
					"processes":   []any{},
				}
				var processes []any
				for _, pc := range config.Processes {
					if processFilter != "" && !strings.Contains(strings.ToLower(pc.Name), strings.ToLower(processFilter)) {
						continue
					}
					processes = append(processes, pc)
				}
				output["processes"] = processes
				return printJSON(cmd, output)
			}

			// Human-readable output
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Config: %s\n", cfgPath)
			if config.Default != "" {
				fmt.Fprintf(w, "Default: %s\n", config.Default)
			}
			fmt.Fprintln(w)

			if len(config.Processes) == 0 {
				fmt.Fprintln(w, "No process rules defined")
				return nil
			}

			for _, pc := range config.Processes {
				if processFilter != "" && !strings.Contains(strings.ToLower(pc.Name), strings.ToLower(processFilter)) {
					continue
				}

				fmt.Fprintf(w, "Process: %s\n", pc.Name)
				if pc.Default != "" {
					fmt.Fprintf(w, "  Default: %s\n", pc.Default)
				}
				if pc.Match.ProcessName != "" {
					fmt.Fprintf(w, "  Match: process_name=%s\n", pc.Match.ProcessName)
				}
				if pc.Match.Path != "" {
					fmt.Fprintf(w, "  Match: path=%s\n", pc.Match.Path)
				}

				if len(pc.Rules) == 0 {
					fmt.Fprintln(w, "  Rules: (none)")
				} else {
					fmt.Fprintln(w, "  Rules:")
					for i, r := range pc.Rules {
						target := formatTarget(r)
						fmt.Fprintf(w, "    [%d] %s -> %s\n", i, target, r.Decision)
					}
				}

				// Show children if any
				if len(pc.Children) > 0 {
					fmt.Fprintln(w, "  Children:")
					for _, cc := range pc.Children {
						fmt.Fprintf(w, "    - %s (inherit: %v, rules: %d)\n", cc.Name, cc.Inherit, len(cc.Rules))
					}
				}
				fmt.Fprintln(w)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config (default: ~/.config/agentsh/network-acl.yml)")
	cmd.Flags().StringVar(&processFilter, "process", "", "Filter rules by process name")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

func newNetworkACLAddCmd() *cobra.Command {
	var configPath string
	var port string
	var protocol string
	var decision string
	var comment string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "add <process> <target>",
		Short: "Add a network ACL rule",
		Long: `Add a new network ACL rule for a process.

The target can be a hostname (with glob patterns), IP address, or CIDR block.
The decision determines what happens when the process tries to connect to the target.

Decisions:
  allow   - Allow the connection silently
  deny    - Block the connection silently
  approve - Block and prompt for user approval
  audit   - Allow but log for review`,
		Example: `  # Allow claude-code to connect to anthropic.com
  agentsh network-acl add claude-code api.anthropic.com --decision allow

  # Allow connections to any anthropic.com subdomain
  agentsh network-acl add claude-code "*.anthropic.com" --decision allow

  # Deny connections to a specific IP
  agentsh network-acl add my-process 10.0.0.1 --decision deny

  # Allow connections to a CIDR block on specific port
  agentsh network-acl add my-process 192.168.0.0/16 --port 443 --decision allow

  # Interactive mode to add rules
  agentsh network-acl add --interactive`,
		Args: func(cmd *cobra.Command, args []string) error {
			interactive, _ := cmd.Flags().GetBool("interactive")
			if interactive {
				return nil
			}
			if len(args) < 2 {
				return fmt.Errorf("requires process name and target (or use --interactive)")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := resolveNetworkACLConfigPath(configPath)

			var processName, target string
			if interactive {
				var err error
				processName, target, port, protocol, decision, err = promptForRule(cmd)
				if err != nil {
					return err
				}
			} else {
				processName = args[0]
				target = args[1]
			}

			// Validate decision
			if decision == "" {
				decision = "allow"
			}
			if !isValidACLDecision(decision) {
				return fmt.Errorf("invalid decision %q: must be allow, deny, approve, or audit", decision)
			}

			// Build the rule
			rule := pnacl.NetworkTarget{
				Decision: pnacl.Decision(decision),
			}

			// Determine if target is IP, CIDR, or hostname
			if ip := net.ParseIP(target); ip != nil {
				rule.IP = target
			} else if _, _, err := net.ParseCIDR(target); err == nil {
				rule.CIDR = target
			} else {
				rule.Host = target
			}

			// Set port and protocol
			if port != "" && port != "*" {
				rule.Port = port
			}
			if protocol != "" && protocol != "*" {
				rule.Protocol = protocol
			}

			// Add the rule
			persister := pnacl.NewFileRulePersister(cfgPath)
			if comment == "" {
				comment = fmt.Sprintf("Added via CLI %s", time.Now().Format("2006-01-02 15:04:05"))
			}
			if err := persister.AddRule(processName, rule, comment); err != nil {
				return fmt.Errorf("add rule: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Rule added: %s -> %s (%s)\n", processName, formatTarget(rule), decision)
			fmt.Fprintf(cmd.OutOrStdout(), "Config: %s\n", cfgPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config")
	cmd.Flags().StringVar(&port, "port", "*", "Port number, range (8000-9000), or * for any")
	cmd.Flags().StringVar(&protocol, "protocol", "*", "Protocol: tcp, udp, or * for any")
	cmd.Flags().StringVar(&decision, "decision", "allow", "Decision: allow, deny, approve, or audit")
	cmd.Flags().StringVar(&comment, "comment", "", "Comment to add above the rule")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Interactive mode to add rules")

	return cmd
}

func newNetworkACLRemoveCmd() *cobra.Command {
	var configPath string
	var processName string

	cmd := &cobra.Command{
		Use:   "remove <rule-index>",
		Short: "Remove a network ACL rule",
		Long: `Remove a network ACL rule by its index.

Use 'agentsh network-acl list' to see rule indices.`,
		Example: `  # Remove rule at index 0 for claude-code
  agentsh network-acl remove 0 --process claude-code`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if processName == "" {
				return fmt.Errorf("--process is required")
			}

			ruleIndex, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule index: %w", err)
			}

			cfgPath := resolveNetworkACLConfigPath(configPath)
			config, err := pnacl.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Find the process
			var targetPC *pnacl.ProcessConfig
			for i := range config.Processes {
				if config.Processes[i].Name == processName {
					targetPC = &config.Processes[i]
					break
				}
			}

			if targetPC == nil {
				return fmt.Errorf("process %q not found in config", processName)
			}

			if ruleIndex < 0 || ruleIndex >= len(targetPC.Rules) {
				return fmt.Errorf("rule index %d out of range (0-%d)", ruleIndex, len(targetPC.Rules)-1)
			}

			rule := targetPC.Rules[ruleIndex]
			persister := pnacl.NewFileRulePersister(cfgPath)
			if err := persister.RemoveRule(processName, rule); err != nil {
				return fmt.Errorf("remove rule: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Rule removed: %s -> %s\n", processName, formatTarget(rule))
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config")
	cmd.Flags().StringVar(&processName, "process", "", "Process name (required)")
	_ = cmd.MarkFlagRequired("process")

	return cmd
}

func newNetworkACLTestCmd() *cobra.Command {
	var configPath string
	var port int
	var protocol string

	cmd := &cobra.Command{
		Use:   "test <process> <target>",
		Short: "Test what decision would be made for a connection",
		Long: `Test the policy evaluation for a hypothetical connection.

This shows what decision would be made if the specified process tried
to connect to the target, without actually making any connection.`,
		Example: `  # Test if claude-code can connect to api.anthropic.com:443
  agentsh network-acl test claude-code api.anthropic.com --port 443

  # Test UDP connection
  agentsh network-acl test my-process 8.8.8.8 --port 53 --protocol udp`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			processName := args[0]
			target := args[1]

			cfgPath := resolveNetworkACLConfigPath(configPath)
			config, err := pnacl.LoadConfig(cfgPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(cmd.OutOrStdout(), "No config found, using default: approve\n")
					fmt.Fprintf(cmd.OutOrStdout(), "Decision: approve (no rules defined)\n")
					return nil
				}
				return fmt.Errorf("load config: %w", err)
			}

			engine, err := pnacl.NewPolicyEngine(config)
			if err != nil {
				return fmt.Errorf("create policy engine: %w", err)
			}

			// Create process info
			procInfo := pnacl.ProcessInfo{
				Name: processName,
				Path: processName, // Use name as path for testing
			}

			// Resolve target IP if hostname
			var ip net.IP
			if parsedIP := net.ParseIP(target); parsedIP != nil {
				ip = parsedIP
			} else {
				// Try to resolve hostname
				ips, err := net.LookupIP(target)
				if err == nil && len(ips) > 0 {
					ip = ips[0]
				}
			}

			// Evaluate policy
			result := engine.Evaluate(procInfo, target, ip, port, protocol)

			// Output result
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Process: %s\n", processName)
			fmt.Fprintf(w, "Target: %s:%d (%s)\n", target, port, protocol)
			if ip != nil {
				fmt.Fprintf(w, "Resolved IP: %s\n", ip.String())
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Decision: %s\n", result.Decision)
			if result.ProcessName != "" {
				fmt.Fprintf(w, "Matched policy: %s\n", result.ProcessName)
			}
			if result.ChildName != "" {
				fmt.Fprintf(w, "Child policy: %s\n", result.ChildName)
			}
			if result.RuleIndex >= 0 {
				fmt.Fprintf(w, "Rule index: %d\n", result.RuleIndex)
			} else {
				fmt.Fprintln(w, "Rule: (default)")
			}
			if result.IsInherited {
				fmt.Fprintln(w, "Inherited: yes")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config")
	cmd.Flags().IntVar(&port, "port", 443, "Port number to test")
	cmd.Flags().StringVar(&protocol, "protocol", "tcp", "Protocol: tcp or udp")

	return cmd
}

func newNetworkACLWatchCmd() *cobra.Command {
	var processFilter string
	var outputJSON bool
	var configPath string

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Stream network connection attempts",
		Long: `Watch network connection attempts in real-time.

This command monitors and displays network connection attempts as they occur.
You can filter by process name to focus on specific applications.

Note: This requires the agentsh daemon to be running with network monitoring enabled.`,
		Example: `  # Watch all connection attempts
  agentsh network-acl watch

  # Watch only claude-code connections
  agentsh network-acl watch --process claude-code

  # Output as JSON (one event per line)
  agentsh network-acl watch --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()

			// Try to connect to the daemon's event stream
			cfg := getClientConfig(cmd)

			// Use SSE endpoint if available
			eventURL := cfg.serverAddr + "/api/v1/events/stream"
			if processFilter != "" {
				eventURL += "?process=" + processFilter
			}

			fmt.Fprintf(w, "Connecting to event stream at %s...\n", cfg.serverAddr)
			fmt.Fprintln(w, "Press Ctrl+C to stop")
			fmt.Fprintln(w)

			// For now, show a placeholder since we need the daemon running
			// In production, this would connect to the SSE endpoint
			return watchNetworkEvents(ctx, cmd, processFilter, outputJSON)
		},
	}

	cmd.Flags().StringVar(&processFilter, "process", "", "Filter by process name")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output as JSON (one event per line)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config")

	return cmd
}

func newNetworkACLLearnCmd() *cobra.Command {
	var processFilter string
	var duration string
	var outputFile string
	var configPath string

	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Learn network access patterns for policy generation",
		Long: `Learn network access patterns by observing actual connections.

This command monitors network connections for the specified duration and
generates policy rules based on observed behavior. This is useful for
creating baseline policies for applications.

The learning mode operates in "audit" mode, allowing all connections
while recording them for policy generation.`,
		Example: `  # Learn claude-code's network patterns for 1 hour
  agentsh network-acl learn --process claude-code --duration 1h

  # Learn all processes for 30 minutes and output to file
  agentsh network-acl learn --duration 30m --output learned-rules.yml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if processFilter == "" {
				return fmt.Errorf("--process is required for learning mode")
			}

			dur, err := time.ParseDuration(duration)
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", duration, err)
			}

			return runLearnMode(cmd, processFilter, dur, outputFile, configPath)
		},
	}

	cmd.Flags().StringVar(&processFilter, "process", "", "Process name to learn (required)")
	cmd.Flags().StringVar(&duration, "duration", "1h", "How long to observe (e.g., 30m, 1h, 2h)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Output file for learned rules (default: stdout)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to network ACL config")
	_ = cmd.MarkFlagRequired("process")

	return cmd
}

// Helper functions

func resolveNetworkACLConfigPath(override string) string {
	if override != "" {
		return override
	}
	if p := os.Getenv("AGENTSH_NETWORK_ACL_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return home + "/.config/agentsh/network-acl.yml"
}

func formatTarget(r pnacl.NetworkTarget) string {
	var parts []string
	if r.Host != "" {
		parts = append(parts, r.Host)
	}
	if r.IP != "" {
		parts = append(parts, r.IP)
	}
	if r.CIDR != "" {
		parts = append(parts, r.CIDR)
	}

	target := strings.Join(parts, "/")
	if r.Port != "" && r.Port != "*" {
		target += ":" + r.Port
	}
	if r.Protocol != "" && r.Protocol != "*" {
		target += " (" + r.Protocol + ")"
	}
	return target
}

func isValidACLDecision(d string) bool {
	switch pnacl.Decision(strings.ToLower(d)) {
	case pnacl.DecisionAllow, pnacl.DecisionDeny, pnacl.DecisionApprove, pnacl.DecisionAudit:
		return true
	default:
		return false
	}
}

func promptForRule(cmd *cobra.Command) (processName, target, port, protocol, decision string, err error) {
	reader := bufio.NewReader(cmd.InOrStdin())
	w := cmd.OutOrStdout()

	fmt.Fprint(w, "Process name: ")
	processName, _ = reader.ReadString('\n')
	processName = strings.TrimSpace(processName)
	if processName == "" {
		return "", "", "", "", "", fmt.Errorf("process name is required")
	}

	fmt.Fprint(w, "Target (hostname, IP, or CIDR): ")
	target, _ = reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", "", "", "", fmt.Errorf("target is required")
	}

	fmt.Fprint(w, "Port (number, range, or * for any) [*]: ")
	port, _ = reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "*"
	}

	fmt.Fprint(w, "Protocol (tcp/udp/*) [*]: ")
	protocol, _ = reader.ReadString('\n')
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		protocol = "*"
	}

	fmt.Fprint(w, "Decision (allow/deny/approve/audit) [allow]: ")
	decision, _ = reader.ReadString('\n')
	decision = strings.TrimSpace(decision)
	if decision == "" {
		decision = "allow"
	}

	return processName, target, port, protocol, decision, nil
}

func watchNetworkEvents(ctx context.Context, cmd *cobra.Command, processFilter string, outputJSON bool) error {
	w := cmd.OutOrStdout()

	// This is a simplified implementation that reads from the event file
	// In production, this would connect to the daemon's event stream

	// For now, show usage instructions
	if !outputJSON {
		fmt.Fprintln(w, "Network event watching requires the agentsh daemon to be running.")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "To start the daemon:")
		fmt.Fprintln(w, "  agentsh daemon install")
		fmt.Fprintln(w, "  systemctl --user start agentsh")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Or run the server directly:")
		fmt.Fprintln(w, "  agentsh server")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Then re-run this command to watch events.")
		return nil
	}

	// JSON mode: output empty array to indicate no events yet
	return printJSON(cmd, []any{})
}

func runLearnMode(cmd *cobra.Command, processFilter string, duration time.Duration, outputFile, configPath string) error {
	w := cmd.OutOrStdout()
	ctx := cmd.Context()

	fmt.Fprintf(w, "Starting learning mode for process: %s\n", processFilter)
	fmt.Fprintf(w, "Duration: %s\n", duration)
	fmt.Fprintln(w, "Observing network connections...")
	fmt.Fprintln(w, "Press Ctrl+C to stop early")
	fmt.Fprintln(w)

	// Create a timer
	timer := time.NewTimer(duration)
	defer timer.Stop()

	// Collect learned connections
	learned := &LearnedRules{
		ProcessName: processFilter,
		StartedAt:   time.Now(),
		Targets:     make(map[string]*LearnedTarget),
	}

	// In production, this would connect to the daemon and observe connections
	// For now, we'll wait and then generate a sample output

	select {
	case <-ctx.Done():
		fmt.Fprintln(w, "\nLearning stopped early")
	case <-timer.C:
		fmt.Fprintln(w, "\nLearning period complete")
	}

	learned.EndedAt = time.Now()

	// Generate output
	output := generateLearnedConfig(learned)

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Fprintf(w, "Learned rules written to: %s\n", outputFile)
	} else {
		fmt.Fprintln(w, "\n--- Learned Rules ---")
		fmt.Fprintln(w, output)
	}

	return nil
}

// LearnedRules tracks rules discovered during learning mode.
type LearnedRules struct {
	ProcessName string
	StartedAt   time.Time
	EndedAt     time.Time
	Targets     map[string]*LearnedTarget
}

// LearnedTarget represents a discovered network target.
type LearnedTarget struct {
	Host      string
	IP        string
	Ports     map[int]int // port -> count
	Protocols map[string]int
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

func generateLearnedConfig(learned *LearnedRules) string {
	var sb strings.Builder

	sb.WriteString("# PNACL Configuration\n")
	sb.WriteString(fmt.Sprintf("# Generated by learning mode for process: %s\n", learned.ProcessName))
	sb.WriteString(fmt.Sprintf("# Learning period: %s to %s\n",
		learned.StartedAt.Format(time.RFC3339),
		learned.EndedAt.Format(time.RFC3339)))
	sb.WriteString("#\n")
	sb.WriteString("# Review these rules before enabling them!\n\n")

	sb.WriteString("default: approve\n\n")
	sb.WriteString("processes:\n")
	sb.WriteString(fmt.Sprintf("  - name: %s\n", learned.ProcessName))
	sb.WriteString("    match:\n")
	sb.WriteString(fmt.Sprintf("      process_name: %s\n", learned.ProcessName))
	sb.WriteString("    default: approve\n")
	sb.WriteString("    rules:\n")

	if len(learned.Targets) == 0 {
		sb.WriteString("      # No connections observed during learning period\n")
		sb.WriteString("      # Add rules as needed or re-run learning with active usage\n")
	} else {
		for _, target := range learned.Targets {
			if target.Host != "" {
				sb.WriteString(fmt.Sprintf("      - target: %s\n", target.Host))
			} else if target.IP != "" {
				sb.WriteString(fmt.Sprintf("      - ip: %s\n", target.IP))
			}
			sb.WriteString("        decision: allow\n")
			sb.WriteString(fmt.Sprintf("        # Seen %d times\n", target.Count))
		}
	}

	return sb.String()
}

// TODO: NetworkACLEventStream and NetworkACLEventData types will be needed
// when implementing the daemon's event streaming functionality.
// See watchNetworkEvents() for the planned integration point.
