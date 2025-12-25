package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gobwas/glob"
)

// PathRedirector redirects file paths based on configured rules.
// It is typically used by FUSE or other file system interceptors.
type PathRedirector struct {
	rules []compiledRedirectRule
}

// PathRedirectRule defines a path redirect rule.
type PathRedirectRule struct {
	Name          string   `yaml:"name"`
	SourcePattern string   `yaml:"source_pattern"` // Glob pattern for source path
	TargetBase    string   `yaml:"target_base"`    // Base directory for redirected files
	Operations    []string `yaml:"operations"`     // write, create, delete, etc.
	PreserveTree  bool     `yaml:"preserve_tree"`  // Preserve directory structure under target
}

type compiledRedirectRule struct {
	rule PathRedirectRule
	glob glob.Glob
	ops  map[string]struct{}
}

// NewPathRedirector creates a PathRedirector from a list of rules.
func NewPathRedirector(rules []PathRedirectRule) (*PathRedirector, error) {
	pr := &PathRedirector{}
	for _, r := range rules {
		g, err := glob.Compile(r.SourcePattern, '/')
		if err != nil {
			return nil, err
		}
		cr := compiledRedirectRule{
			rule: r,
			glob: g,
			ops:  make(map[string]struct{}),
		}
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}
		pr.rules = append(pr.rules, cr)
	}
	return pr, nil
}

// Redirect checks if a path should be redirected for the given operation.
// Returns the new path and true if redirected, or the original path and false if not.
func (pr *PathRedirector) Redirect(path string, operation string) (string, bool) {
	if pr == nil {
		return path, false
	}

	operation = strings.ToLower(operation)
	for _, r := range pr.rules {
		if !matchRedirectOp(r.ops, operation) {
			continue
		}
		if !r.glob.Match(path) {
			continue
		}

		// Calculate redirected path
		var newPath string
		if r.rule.PreserveTree {
			// /home/user/file.txt -> /workspace/.scratch/home/user/file.txt
			newPath = filepath.Join(r.rule.TargetBase, path)
		} else {
			// /home/user/file.txt -> /workspace/.scratch/file.txt
			newPath = filepath.Join(r.rule.TargetBase, filepath.Base(path))
		}

		return newPath, true
	}

	return path, false
}

// RedirectWithInfo is like Redirect but returns full redirect information.
func (pr *PathRedirector) RedirectWithInfo(path string, operation string) *types.FileRedirectInfo {
	if pr == nil {
		return nil
	}

	operation = strings.ToLower(operation)
	for _, r := range pr.rules {
		if !matchRedirectOp(r.ops, operation) {
			continue
		}
		if !r.glob.Match(path) {
			continue
		}

		var newPath string
		if r.rule.PreserveTree {
			newPath = filepath.Join(r.rule.TargetBase, path)
		} else {
			newPath = filepath.Join(r.rule.TargetBase, filepath.Base(path))
		}

		return &types.FileRedirectInfo{
			OriginalPath: path,
			RedirectPath: newPath,
			Operation:    operation,
			Reason:       r.rule.Name,
		}
	}

	return nil
}

// EnsureRedirectDir creates the parent directory for a redirected path if needed.
func EnsureRedirectDir(redirectPath string) error {
	return os.MkdirAll(filepath.Dir(redirectPath), 0o755)
}

func matchRedirectOp(ops map[string]struct{}, op string) bool {
	if len(ops) == 0 {
		return true // Empty means all operations
	}
	if _, ok := ops["*"]; ok {
		return true
	}
	_, ok := ops[op]
	return ok
}
