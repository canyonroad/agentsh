//go:build linux

package limits

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CgroupMode names an operating mode for cgroup v2 enforcement.
type CgroupMode string

const (
	ModeNested      CgroupMode = "nested"
	ModeTopLevel    CgroupMode = "top-level"
	ModeUnavailable CgroupMode = "unavailable"
)

// requiredControllers are the cgroup v2 controllers the probe insists on.
// io is tracked separately as a best-effort flag (see CgroupProbeResult.IOAvailable).
var requiredControllers = []string{"cpu", "memory", "pids"}

// CgroupProbeResult is the output of ProbeCgroupsV2. Callers store it on
// a CgroupManager or pass it to the detect command.
type CgroupProbeResult struct {
	Mode        CgroupMode
	Reason      string
	OwnCgroup   string // absolute path to the process's own cgroup dir
	SliceDir    string // absolute path to /sys/fs/cgroup/agentsh.slice (top-level mode only; empty otherwise)
	IOAvailable bool   // true if the io controller is usable in the chosen mode
	// OrphansReaped is populated in top-level mode when the probe removed
	// leftover unpopulated child cgroups from a prior agentsh run.
	OrphansReaped []string
}

// DefaultSliceDir is the stable top-level parent used when nested enforcement
// is not reachable. Exported so tests and the detect command can reference it.
const DefaultSliceDir = "/sys/fs/cgroup/agentsh.slice"

// ProbeCgroupsV2 runs the decision tree described in the design spec:
//
//  1. Resolve the "own" cgroup (ownHint overrides /proc/self/cgroup if non-empty).
//  2. If the own cgroup's cgroup.controllers lacks any required controller, try top-level.
//  3. If the own cgroup's cgroup.subtree_control already delegates the required set, return nested.
//  4. Try to enable the required set in subtree_control; on success, return nested.
//  5. On EBUSY / EACCES / other enable error, fall through to top-level.
//  6. Top-level: verify root controllers, ensure DefaultSliceDir exists with controller files,
//     reap orphans, return top-level.
//  7. Otherwise return unavailable with a structured reason.
//
// fs is the filesystem abstraction (osCgroupFS in production, fakeCgroupFS in tests).
// ownHint is an optional override for the "own" cgroup path used in step 1
// (intended to honor cfg.Sandbox.Cgroups.BasePath). Empty means "discover via /proc/self/cgroup".
func ProbeCgroupsV2(ctx context.Context, fs cgroupFS, ownHint string) (*CgroupProbeResult, error) {
	own := ownHint
	if own == "" {
		discovered, err := CurrentCgroupDir()
		if err != nil {
			return nil, fmt.Errorf("discover own cgroup: %w", err)
		}
		own = discovered
	} else if !filepath.IsAbs(own) {
		// Relative paths are joined with the process's current cgroup dir, matching
		// the prior behavior of internal/api/cgroups.go.
		cur, err := CurrentCgroupDir()
		if err != nil {
			return nil, fmt.Errorf("discover own cgroup for relative base path: %w", err)
		}
		own = filepath.Join(cur, own)
	}

	// Step 2: does the own cgroup even expose the required controllers?
	ownAvailable, err := readControllerSet(fs, filepath.Join(own, "cgroup.controllers"))
	if err != nil {
		// If we cannot read own controllers, fall through to top-level as a defensive measure.
		return tryTopLevel(ctx, fs, own, fmt.Sprintf("read own cgroup.controllers: %v", err))
	}
	if !containsAll(ownAvailable, requiredControllers) {
		missing := missingControllers(ownAvailable, requiredControllers)
		return tryTopLevel(ctx, fs, own,
			fmt.Sprintf("own cgroup missing controllers %v", missing))
	}

	// Step 3: already delegated?
	ownDelegated, err := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
	if err == nil && containsAll(ownDelegated, requiredControllers) {
		return &CgroupProbeResult{
			Mode:        ModeNested,
			Reason:      "already delegated",
			OwnCgroup:   own,
			IOAvailable: contains(ownDelegated, "io"),
		}, nil
	}

	// Step 4: try to enable the required set.
	enableErr := enableControllersFS(fs, own, requiredControllers)
	if enableErr == nil {
		// Re-read to confirm and to pick up the io flag.
		delegatedNow, _ := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
		return &CgroupProbeResult{
			Mode:        ModeNested,
			Reason:      "enabled by probe",
			OwnCgroup:   own,
			IOAvailable: contains(delegatedNow, "io"),
		}, nil
	}

	// Step 5: classify the enable failure and fall through to top-level.
	reason := classifyEnableError(enableErr)
	return tryTopLevel(ctx, fs, own, reason)
}

// ProbeCgroupsV2Default is a convenience wrapper that runs ProbeCgroupsV2 with
// the production cgroupFS and no ownHint. It is intended for callers outside
// the limits package (e.g. the capabilities probe).
func ProbeCgroupsV2Default(ctx context.Context) (*CgroupProbeResult, error) {
	return ProbeCgroupsV2(ctx, osCgroupFS{}, "")
}

// tryTopLevel runs steps 5b through 5f of the decision tree.
func tryTopLevel(ctx context.Context, fs cgroupFS, own, nestedFailureReason string) (*CgroupProbeResult, error) {
	rootAvailable, err := readControllerSet(fs, "/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; read root cgroup.controllers: %v", nestedFailureReason, err),
			OwnCgroup: own,
		}, nil
	}
	if !containsAll(rootAvailable, requiredControllers) {
		missing := missingControllers(rootAvailable, requiredControllers)
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; root cgroup missing controllers %v", nestedFailureReason, missing),
			OwnCgroup: own,
		}, nil
	}

	rootDelegated, _ := readControllerSet(fs, "/sys/fs/cgroup/cgroup.subtree_control")
	if !containsAll(rootDelegated, requiredControllers) {
		if err := enableControllersFS(fs, "/sys/fs/cgroup", requiredControllers); err != nil {
			return &CgroupProbeResult{
				Mode:      ModeUnavailable,
				Reason:    fmt.Sprintf("%s; root subtree_control not writable: %v", nestedFailureReason, err),
				OwnCgroup: own,
			}, nil
		}
		rootDelegated, _ = readControllerSet(fs, "/sys/fs/cgroup/cgroup.subtree_control")
	}

	// Ensure the slice exists with controller files populated.
	if err := fs.Mkdir(DefaultSliceDir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; mkdir %s: %v", nestedFailureReason, DefaultSliceDir, err),
			OwnCgroup: own,
		}, nil
	}
	if _, err := fs.Stat(filepath.Join(DefaultSliceDir, "memory.max")); err != nil {
		// memory.max is the canary: if it's missing, controller files weren't created
		// even though mkdir succeeded — enforcement is not possible here.
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; %s missing controller files after mkdir", nestedFailureReason, DefaultSliceDir),
			OwnCgroup: own,
			SliceDir:  DefaultSliceDir,
		}, nil
	}

	// Reap orphans left behind by a prior agentsh crash.
	reaped := reapOrphansFS(fs, DefaultSliceDir)

	return &CgroupProbeResult{
		Mode:          ModeTopLevel,
		Reason:        fmt.Sprintf("%s; using %s", nestedFailureReason, DefaultSliceDir),
		OwnCgroup:     own,
		SliceDir:      DefaultSliceDir,
		IOAvailable:   contains(rootDelegated, "io"),
		OrphansReaped: reaped,
	}, nil
}

// reapOrphansFS removes empty (unpopulated) children of the slice directory.
// It returns the names of the removed children. Errors on individual children
// are logged to stderr and skipped; this function never returns an error.
func reapOrphansFS(fs cgroupFS, sliceDir string) []string {
	entries, err := fs.ReadDir(sliceDir)
	if err != nil {
		return nil
	}
	var reaped []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		child := filepath.Join(sliceDir, e.Name())
		data, err := fs.ReadFile(filepath.Join(child, "cgroup.events"))
		if err != nil {
			// Skip children whose events file is unreadable — they may be actively used.
			continue
		}
		if !isUnpopulated(data) {
			continue
		}
		if err := fs.Remove(child); err != nil {
			fmt.Fprintf(os.Stderr, "agentsh: reap orphan %s: %v\n", child, err)
			continue
		}
		reaped = append(reaped, e.Name())
	}
	return reaped
}

// classifyEnableError turns an enableControllersFS error into a short human string.
func classifyEnableError(err error) string {
	var ece *EnableControllersError
	if !errors.As(err, &ece) {
		return fmt.Sprintf("enable controllers: %v", err)
	}
	switch {
	case errors.Is(err, syscall.EBUSY):
		return "parent cgroup has internal processes (EBUSY)"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "parent cgroup subtree_control not writable (EACCES)"
	default:
		return fmt.Sprintf("enable controller %q failed: %v", ece.Controller, ece.Err)
	}
}

// readControllerSet reads a cgroup.controllers or cgroup.subtree_control file and
// returns the whitespace-separated controller names it contains.
func readControllerSet(fs cgroupFS, path string) ([]string, error) {
	data, err := fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.TrimSpace(string(data))), nil
}

func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

func containsAll(set, want []string) bool {
	for _, w := range want {
		if !contains(set, w) {
			return false
		}
	}
	return true
}

func missingControllers(have, want []string) []string {
	var out []string
	for _, w := range want {
		if !contains(have, w) {
			out = append(out, w)
		}
	}
	return out
}

func isUnpopulated(eventsFileContent []byte) bool {
	for _, line := range strings.Split(string(eventsFileContent), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "populated ") {
			return strings.TrimPrefix(line, "populated ") == "0"
		}
	}
	return false
}
