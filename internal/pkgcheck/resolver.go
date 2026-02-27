package pkgcheck

import "context"

// Resolver parses tool-specific lock files to extract an install plan.
type Resolver interface {
	// Name returns the resolver's identifier.
	Name() string

	// CanResolve reports whether this resolver handles the given tool command.
	CanResolve(tool string, args []string) bool

	// Resolve parses lock files and returns an install plan.
	Resolve(ctx context.Context, workDir string, command []string) (*InstallPlan, error)
}
