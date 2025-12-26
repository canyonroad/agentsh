package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Debugger provides an interactive debugging session.
type Debugger struct {
	client    Client
	sessionID string
	output    io.Writer
	input     io.Reader
	running   bool
	mu        sync.Mutex
	tracing   bool
}

// DebuggerConfig configures the debugger.
type DebuggerConfig struct {
	Client    Client
	SessionID string
	Output    io.Writer
	Input     io.Reader
}

// NewDebugger creates a new interactive debugger.
func NewDebugger(config DebuggerConfig) *Debugger {
	return &Debugger{
		client:    config.Client,
		sessionID: config.SessionID,
		output:    config.Output,
		input:     config.Input,
	}
}

// Run starts the interactive debugger.
func (d *Debugger) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("debugger already running")
	}
	d.running = true
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	// Get session info
	session, err := d.client.GetSession(ctx, d.sessionID)
	if err != nil {
		return fmt.Errorf("getting session: %w", err)
	}

	d.printHeader(session)
	d.printHelp()

	scanner := bufio.NewScanner(d.input)
	for {
		fmt.Fprint(d.output, "\n(agentsh) ")

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "help", "h", "?":
			d.printHelp()
		case "quit", "q", "exit":
			fmt.Fprintln(d.output, "Detaching from session...")
			return nil
		case "events", "e":
			d.cmdEvents(ctx, args)
		case "pending", "p":
			d.cmdPending(ctx)
		case "stats", "s":
			d.cmdStats(ctx)
		case "policy":
			d.cmdPolicy(ctx, args)
		case "trace":
			d.cmdTrace(ctx, args)
		case "info", "i":
			d.cmdInfo(ctx)
		default:
			fmt.Fprintf(d.output, "Unknown command: %s\n", cmd)
			fmt.Fprintln(d.output, "Type 'help' for available commands")
		}
	}

	return scanner.Err()
}

func (d *Debugger) printHeader(session *SessionDetail) {
	fmt.Fprintln(d.output, "")
	fmt.Fprintln(d.output, "agentsh debugger v1.0.0")
	fmt.Fprintf(d.output, "Session: %s\n", session.ID)
	if session.AgentID != "" {
		fmt.Fprintf(d.output, "Agent: %s\n", session.AgentID)
	}
	fmt.Fprintf(d.output, "State: %s\n", session.State)
	fmt.Fprintln(d.output, "")
}

func (d *Debugger) printHelp() {
	help := `Commands:
  events [--last N] [--type TYPE]  Show recent events
  pending                          Show pending approvals
  stats                            Show session statistics
  policy test <path>               Test policy against operation
  trace [on|off]                   Toggle detailed tracing
  info                             Show session info
  help                             Show this help
  quit                             Detach from session`
	fmt.Fprintln(d.output, help)
}

func (d *Debugger) cmdEvents(ctx context.Context, args []string) {
	opts := EventsOpts{Limit: 10}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--last", "-n":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &opts.Limit)
				i++
			}
		case "--type", "-t":
			if i+1 < len(args) {
				opts.Type = args[i+1]
				i++
			}
		}
	}

	events, err := d.client.GetSessionEvents(ctx, d.sessionID, opts)
	if err != nil {
		fmt.Fprintf(d.output, "Error: %v\n", err)
		return
	}

	if len(events) == 0 {
		fmt.Fprintln(d.output, "No events found")
		return
	}

	fmt.Fprintf(d.output, "%-12s %-30s %-8s %s\n", "TYPE", "PATH", "DECISION", "LATENCY")
	for _, e := range events {
		path := TruncatePath(e.Path, 30)
		fmt.Fprintf(d.output, "%-12s %-30s %-8s %s\n",
			e.Type, path, e.Decision, e.Latency)
	}
}

func (d *Debugger) cmdPending(ctx context.Context) {
	// Get events with pending decisions
	events, err := d.client.GetSessionEvents(ctx, d.sessionID, EventsOpts{Limit: 100})
	if err != nil {
		fmt.Fprintf(d.output, "Error: %v\n", err)
		return
	}

	var pending []Event
	for _, e := range events {
		if e.Decision == "pending" {
			pending = append(pending, e)
		}
	}

	if len(pending) == 0 {
		fmt.Fprintln(d.output, "No pending approvals")
		return
	}

	fmt.Fprintf(d.output, "Pending approvals: %d\n\n", len(pending))
	for i, e := range pending {
		fmt.Fprintf(d.output, "%d. %s: %s\n", i+1, e.Type, e.Path)
	}
}

func (d *Debugger) cmdStats(ctx context.Context) {
	session, err := d.client.GetSession(ctx, d.sessionID)
	if err != nil {
		fmt.Fprintf(d.output, "Error: %v\n", err)
		return
	}

	fmt.Fprintf(d.output, "Session: %s\n", session.ID)
	fmt.Fprintf(d.output, "State: %s\n", session.State)
	fmt.Fprintf(d.output, "Events: %d\n", session.EventCount)
	fmt.Fprintf(d.output, "Started: %s\n", session.StartTime.Format(time.RFC3339))

	if session.ResourceUsage != nil {
		ru := session.ResourceUsage
		fmt.Fprintln(d.output, "\nResource Usage:")
		fmt.Fprintf(d.output, "  CPU: %.1f%%\n", ru.CPUPercent)
		fmt.Fprintf(d.output, "  Memory: %d MB\n", ru.MemoryMB)
		fmt.Fprintf(d.output, "  Disk Read: %d MB\n", ru.DiskReadMB)
		fmt.Fprintf(d.output, "  Disk Write: %d MB\n", ru.DiskWriteMB)
		fmt.Fprintf(d.output, "  Network RX: %d MB\n", ru.NetworkRxMB)
		fmt.Fprintf(d.output, "  Network TX: %d MB\n", ru.NetworkTxMB)
		fmt.Fprintf(d.output, "  Processes: %d\n", ru.ProcessCount)
	}

	// Get event breakdown
	events, _ := d.client.GetSessionEvents(ctx, d.sessionID, EventsOpts{Limit: 1000})
	if len(events) > 0 {
		byType := make(map[string]int)
		byDecision := make(map[string]int)
		for _, e := range events {
			byType[e.Type]++
			byDecision[e.Decision]++
		}

		fmt.Fprintln(d.output, "\nEvents by Type:")
		for t, c := range byType {
			fmt.Fprintf(d.output, "  %s: %d\n", t, c)
		}

		fmt.Fprintln(d.output, "\nDecisions:")
		for decision, c := range byDecision {
			fmt.Fprintf(d.output, "  %s: %d\n", decision, c)
		}
	}
}

func (d *Debugger) cmdPolicy(ctx context.Context, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(d.output, "Usage: policy test <path>")
		return
	}

	if args[0] != "test" {
		fmt.Fprintf(d.output, "Unknown subcommand: %s\n", args[0])
		return
	}

	path := args[1]

	// Simulate a file_read operation
	result, err := d.client.SimulateRecording(ctx, path, "")
	if err != nil {
		fmt.Fprintf(d.output, "Error: %v\n", err)
		return
	}

	fmt.Fprintln(d.output, "\nResult:")
	if result.TotalEvents > 0 && len(result.Differences) == 0 {
		fmt.Fprintln(d.output, "  Decision: allow")
	} else {
		fmt.Fprintln(d.output, "  Decision: deny")
	}
}

func (d *Debugger) cmdTrace(ctx context.Context, args []string) {
	if len(args) == 0 {
		if d.tracing {
			fmt.Fprintln(d.output, "Tracing: enabled")
		} else {
			fmt.Fprintln(d.output, "Tracing: disabled")
		}
		return
	}

	switch args[0] {
	case "on":
		d.tracing = true
		fmt.Fprintln(d.output, "Tracing enabled. All operations will be logged in detail.")
	case "off":
		d.tracing = false
		fmt.Fprintln(d.output, "Tracing disabled.")
	default:
		fmt.Fprintln(d.output, "Usage: trace [on|off]")
	}
}

func (d *Debugger) cmdInfo(ctx context.Context) {
	session, err := d.client.GetSession(ctx, d.sessionID)
	if err != nil {
		fmt.Fprintf(d.output, "Error: %v\n", err)
		return
	}

	fmt.Fprintf(d.output, "Session ID: %s\n", session.ID)
	fmt.Fprintf(d.output, "State: %s\n", session.State)
	fmt.Fprintf(d.output, "Agent ID: %s\n", session.AgentID)
	if session.TenantID != "" {
		fmt.Fprintf(d.output, "Tenant ID: %s\n", session.TenantID)
	}
	if session.Workspace != "" {
		fmt.Fprintf(d.output, "Workspace: %s\n", session.Workspace)
	}
	if session.PolicyRef != "" {
		fmt.Fprintf(d.output, "Policy: %s\n", session.PolicyRef)
	}
	fmt.Fprintf(d.output, "Started: %s\n", session.StartTime.Format(time.RFC3339))
	fmt.Fprintf(d.output, "Events: %d\n", session.EventCount)

	if len(session.Metadata) > 0 {
		fmt.Fprintln(d.output, "\nMetadata:")
		keys := make([]string, 0, len(session.Metadata))
		for k := range session.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(d.output, "  %s: %s\n", k, session.Metadata[k])
		}
	}
}

// IsRunning returns whether the debugger is running.
func (d *Debugger) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}
