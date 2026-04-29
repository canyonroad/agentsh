package skillcheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
)

// CLI implements the `agentsh skillcheck` subcommand.
type CLI struct {
	Stdout     io.Writer
	Providers  map[string]ProviderEntry
	Thresholds Thresholds
	Limits     LoaderLimits
}

// Run dispatches one CLI invocation. argv[0] is the subcommand name
// (scan, doctor, list-quarantined, restore, cache).
func (c *CLI) Run(ctx context.Context, argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(c.stdout(), "usage: agentsh skillcheck <scan|doctor|list-quarantined|restore|cache>")
		return 2
	}
	switch argv[0] {
	case "scan":
		return c.runScan(ctx, argv[1:])
	case "doctor":
		return c.runDoctor()
	case "list-quarantined", "restore", "cache":
		fmt.Fprintln(c.stdout(), argv[0]+": not implemented yet (see Task 16+)")
		return 0
	default:
		fmt.Fprintln(c.stdout(), "unknown subcommand: "+argv[0])
		return 2
	}
}

func (c *CLI) stdout() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

func (c *CLI) runScan(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stdout(), "usage: agentsh skillcheck scan <path>")
		return 2
	}
	limits := c.Limits
	if limits.PerFileBytes == 0 {
		limits = DefaultLoaderLimits()
	}
	ref, files, err := LoadSkill(args[0], limits)
	if err != nil {
		fmt.Fprintln(c.stdout(), "load:", err)
		return 1
	}
	o := NewOrchestrator(OrchestratorConfig{Providers: c.Providers})
	findings, _ := o.ScanAll(ctx, ScanRequest{Skill: *ref, Files: files})
	v := NewEvaluator(c.Thresholds).Evaluate(findings, *ref)
	fmt.Fprintln(c.stdout(), v.String())
	if v.Action == VerdictBlock {
		return 3
	}
	return 0
}

func (c *CLI) runDoctor() int {
	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(c.stdout(), "%-12s ok\n", name)
	}
	return 0
}
