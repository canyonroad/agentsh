package resolver

import (
	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// Registry holds a set of resolvers and finds the appropriate one for a command.
type Registry struct {
	resolvers []pkgcheck.Resolver
}

// NewRegistry creates an empty resolver registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a resolver to the registry.
func (r *Registry) Register(res pkgcheck.Resolver) {
	r.resolvers = append(r.resolvers, res)
}

// Find returns the first resolver that can handle the given command and args.
// Returns nil if no resolver matches.
func (r *Registry) Find(command string, args []string) pkgcheck.Resolver {
	for _, res := range r.resolvers {
		if res.CanResolve(command, args) {
			return res
		}
	}
	return nil
}
