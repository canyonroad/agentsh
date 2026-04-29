package skillcheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/agentsh/agentsh/internal/trash"
)

// CLI implements the `agentsh skillcheck` subcommand.
type CLI struct {
	Stdout     io.Writer
	Providers  map[string]ProviderEntry
	Thresholds Thresholds
	Limits     LoaderLimits
	TrashDir   string
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
	case "list-quarantined":
		return c.runList()
	case "restore":
		return c.runRestore(argv[1:])
	case "cache":
		return c.runCache(argv[1:])
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
	limits := resolveLimits(c.Limits)
	ref, files, err := LoadSkill(args[0], limits)
	if err != nil {
		fmt.Fprintln(c.stdout(), "load:", err)
		return 1
	}
	o := NewOrchestrator(OrchestratorConfig{Providers: c.Providers})
	findings, provErrs := o.ScanAll(ctx, ScanRequest{Skill: *ref, Files: files})
	findings = append(findings, synthesizeProviderErrorFindings(provErrs, *ref)...)
	v := NewEvaluator(c.Thresholds).Evaluate(findings, *ref)
	floor := actionFloorFromProviderErrors(provErrs)
	if floor.weight() > v.Action.weight() {
		v.Action = floor
		if v.Summary == "" {
			v.Summary = fmt.Sprintf("escalated by provider failure floor=%s", floor)
		} else {
			v.Summary = v.Summary + fmt.Sprintf(" [floor=%s from provider failures]", floor)
		}
		if sv, ok := v.Skills[ref.String()]; ok {
			sv.Action = floor
			v.Skills[ref.String()] = sv
		}
	}
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

func (c *CLI) runList() int {
	if c.TrashDir == "" {
		fmt.Fprintln(c.stdout(), "trash dir not configured")
		return 1
	}
	entries, err := trash.List(c.TrashDir)
	if err != nil {
		fmt.Fprintln(c.stdout(), "list:", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(c.stdout(), "no quarantined skills")
		return 0
	}
	// Sort deterministically by token so output is stable regardless of
	// filesystem ordering or created timestamps.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Token < entries[j].Token
	})
	for _, e := range entries {
		fmt.Fprintf(c.stdout(), "%s\t%s\t%s\n", e.Token, e.OriginalPath, e.Command)
	}
	return 0
}

func (c *CLI) runRestore(args []string) int {
	if c.TrashDir == "" || len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(c.stdout(), "usage: agentsh skillcheck restore <token> [dest]")
		return 2
	}
	dest := ""
	if len(args) > 1 {
		dest = args[1]
	}
	out, err := trash.Restore(c.TrashDir, args[0], dest, false)
	if err != nil {
		fmt.Fprintln(c.stdout(), "restore:", err)
		return 1
	}
	fmt.Fprintln(c.stdout(), "restored to", out)
	return 0
}

func (c *CLI) runCache(args []string) int {
	if len(args) == 0 || args[0] != "prune" {
		fmt.Fprintln(c.stdout(), "usage: agentsh skillcheck cache prune")
		return 2
	}
	// Cache pruning requires daemon-level coordination; deferred.
	fmt.Fprintln(c.stdout(), "cache prune: not yet implemented at the daemon-level; deferred")
	return 0
}

// resolveLimits defaults each LoaderLimits field independently so callers
// that set only one field don't lose the other. Used by both CLI and Daemon.
func resolveLimits(cfg LoaderLimits) LoaderLimits {
	defaults := DefaultLoaderLimits()
	if cfg.PerFileBytes == 0 {
		cfg.PerFileBytes = defaults.PerFileBytes
	}
	if cfg.TotalBytes == 0 {
		cfg.TotalBytes = defaults.TotalBytes
	}
	return cfg
}
