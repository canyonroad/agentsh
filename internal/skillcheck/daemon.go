package skillcheck

import (
	"context"
	"errors"
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
	_ = d.cfg.Cache.Flush()
	return d.watcher.Close()
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

	limits := d.cfg.Limits
	if limits.PerFileBytes == 0 {
		limits = DefaultLoaderLimits()
	}
	ref, files, err := LoadSkill(skillDir, limits)
	if err != nil {
		d.cfg.Audit.Emit(ctx, AuditEvent{
			Kind:  "skillcheck.scan_failed",
			Skill: SkillRef{Path: skillDir},
			Extra: map[string]string{"error": err.Error()},
		})
		return
	}
	if v, ok := d.cfg.Cache.Get(ref.SHA256); ok {
		_ = d.actioner.Apply(ctx, *ref, v)
		return
	}
	findings, _ := d.orches.ScanAll(ctx, ScanRequest{Skill: *ref, Files: files})
	v := d.eval.Evaluate(findings, *ref)
	d.cfg.Cache.Put(ref.SHA256, v)
	_ = d.actioner.Apply(ctx, *ref, v)
}
