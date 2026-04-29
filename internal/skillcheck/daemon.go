package skillcheck

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// ErrNilCache is returned by NewDaemon when DaemonConfig.Cache is nil.
var ErrNilCache = errors.New("skillcheck: DaemonConfig.Cache must not be nil")

// VerdictCache is a thread-safe keyed store for scan verdicts.
// The canonical implementation is skillcheck/cache.Cache; callers that wire
// the daemon from outside the package construct a *cache.Cache and pass it in.
// Tests may use any implementation that satisfies this interface.
type VerdictCache interface {
	Get(sha string) (*Verdict, bool)
	Put(sha string, v *Verdict)
	Flush() error
}

// DaemonConfig wires every skillcheck component together.
//
// Cache must be non-nil; callers are responsible for constructing it (typically
// via skillcheck/cache.New). Keeping cache construction outside the Daemon
// avoids an import cycle between skillcheck and its cache sub-package.
type DaemonConfig struct {
	Roots      []string
	TrashDir   string
	Cache      VerdictCache
	Providers  map[string]ProviderEntry
	Thresholds Thresholds
	Approval   Approver
	Audit      AuditSink
	Debounce   time.Duration
	Limits     LoaderLimits
}

// Daemon owns the watcher + orchestrator + cache and runs scans on demand.
//
// scanPath may be called concurrently from the watcher's debounce timers.
// The Orchestrator, Evaluator, and Cache are all independently thread-safe,
// so no additional locking is needed in scanPath itself.
type Daemon struct {
	cfg      DaemonConfig
	watcher  *Watcher
	orches   *Orchestrator
	eval     *Evaluator
	actioner *Actioner

	// runCtx is set by Run and carries the daemon's lifetime. scanPath uses it
	// so that in-progress scans are cancelled when the daemon shuts down.
	runCtx context.Context //nolint:containedctx
}

// NewDaemon constructs and wires all skillcheck components. Call Run to start.
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	if cfg.Cache == nil {
		return nil, ErrNilCache
	}
	// Default each limit field independently so callers that set only one
	// field don't lose the other.
	cfg.Limits = resolveLimits(cfg.Limits)
	d := &Daemon{
		cfg:    cfg,
		orches: NewOrchestrator(OrchestratorConfig{Providers: cfg.Providers}),
		eval:   NewEvaluator(cfg.Thresholds),
		actioner: NewActioner(
			NewTrashQuarantiner(cfg.TrashDir),
			cfg.Approval,
			cfg.Audit,
		),
		// runCtx starts as Background; replaced in Run before any scan fires.
		runCtx: context.Background(),
	}
	w, err := NewWatcher(WatcherConfig{
		Roots:    cfg.Roots,
		Debounce: cfg.Debounce,
		OnSkill:  d.scanPath,
	})
	if err != nil {
		return nil, err
	}
	d.watcher = w
	return d, nil
}

// Run blocks until ctx is cancelled. It performs a startup sweep of all roots
// (catching installs that happened while the daemon was down) and then hands
// off to the fsnotify watcher.
func (d *Daemon) Run(ctx context.Context) {
	d.runCtx = ctx
	d.startupSweep(ctx)
	d.watcher.Run(ctx)
}

// Close flushes the verdict cache to disk and releases the fsnotify watcher.
func (d *Daemon) Close() error {
	return errors.Join(d.cfg.Cache.Flush(), d.watcher.Close())
}

// startupSweep walks every root once on launch so installs that happened
// while the daemon was down still get scanned.
func (d *Daemon) startupSweep(ctx context.Context) {
	for _, r := range d.cfg.Roots {
		matches, _ := filepath.Glob(r)
		for _, m := range matches {
			entries, err := readDir(m)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ctx.Err() != nil {
					return
				}
				if e.IsDir() {
					d.scanPath(filepath.Join(m, e.Name()))
				}
			}
		}
	}
}

// scanPath loads, caches, evaluates, and acts on a single skill directory.
// It is safe for concurrent calls; the orchestrator, cache, and actioner are
// all thread-safe.
func (d *Daemon) scanPath(skillDir string) {
	ctx := d.runCtx

	ref, files, err := LoadSkill(skillDir, d.cfg.Limits)
	if err != nil {
		d.cfg.Audit.Emit(ctx, AuditEvent{
			Kind:  "skillcheck.scan_failed",
			Skill: SkillRef{Path: skillDir},
			Extra: map[string]string{"error": err.Error()},
		})
		return
	}
	if v, ok := d.cfg.Cache.Get(ref.SHA256); ok {
		d.applyAndAudit(ctx, *ref, v)
		return
	}
	findings, provErrs := d.orches.ScanAll(ctx, ScanRequest{Skill: *ref, Files: files})
	findings = append(findings, synthesizeProviderErrorFindings(provErrs, *ref)...)
	v := d.eval.Evaluate(findings, *ref)
	floor := actionFloorFromProviderErrors(provErrs)
	if floor.weight() > v.Action.weight() {
		v.Action = floor
		if v.Summary == "" {
			v.Summary = fmt.Sprintf("escalated by provider failure floor=%s", floor)
		} else {
			v.Summary = v.Summary + fmt.Sprintf(" [floor=%s from provider failures]", floor)
		}
		// Also update the per-skill verdict in v.Skills if present.
		if sv, ok := v.Skills[ref.String()]; ok {
			sv.Action = floor
			v.Skills[ref.String()] = sv
		}
	}
	d.cfg.Cache.Put(ref.SHA256, v)
	d.applyAndAudit(ctx, *ref, v)
}

// applyAndAudit calls actioner.Apply and emits a skillcheck.action_failed audit
// event if the action returns an error (e.g. quarantine fails due to disk full).
func (d *Daemon) applyAndAudit(ctx context.Context, skill SkillRef, v *Verdict) {
	if err := d.actioner.Apply(ctx, skill, v); err != nil {
		d.cfg.Audit.Emit(ctx, AuditEvent{
			Kind:    "skillcheck.action_failed",
			At:      time.Now(),
			Skill:   skill,
			Verdict: v,
			Extra:   map[string]string{"error": err.Error()},
		})
	}
}

// actionFloorFromProviderErrors computes the minimum VerdictAction that must
// be applied due to provider failures, regardless of finding severity or
// provenance adjustments. This is the configured OnFailure escalation floor.
func actionFloorFromProviderErrors(errs []ProviderError) VerdictAction {
	floor := VerdictAllow
	for _, e := range errs {
		var a VerdictAction
		switch e.OnFailure {
		case "deny", "block":
			a = VerdictBlock
		case "approve":
			a = VerdictApprove
		case "warn":
			a = VerdictWarn
		default:
			a = VerdictAllow
		}
		if a.weight() > floor.weight() {
			floor = a
		}
	}
	return floor
}

// synthesizeProviderErrorFindings converts ProviderErrors into synthetic Findings
// according to each provider's OnFailure policy so the evaluator can enforce them.
func synthesizeProviderErrorFindings(errs []ProviderError, skill SkillRef) []Finding {
	if len(errs) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(errs))
	for _, pe := range errs {
		switch pe.OnFailure {
		case "deny", "block":
			out = append(out, Finding{
				Type:     FindingPolicyViolation,
				Provider: pe.Provider,
				Skill:    skill,
				Severity: SeverityCritical,
				Title:    fmt.Sprintf("provider %s failed (on_failure: deny)", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		case "approve":
			out = append(out, Finding{
				Type:     FindingPolicyViolation,
				Provider: pe.Provider,
				Skill:    skill,
				Severity: SeverityHigh,
				Title:    fmt.Sprintf("provider %s failed (on_failure: approve)", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		case "warn":
			out = append(out, Finding{
				Type:     FindingPolicyViolation,
				Provider: pe.Provider,
				Skill:    skill,
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("provider %s failed (on_failure: warn)", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		default:
			// "allow" or empty: silent acceptance — no finding injected.
		}
	}
	return out
}
