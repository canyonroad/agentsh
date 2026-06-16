// Package decisionctx resolves a process-level "decision context"
// (identity + environment signals) that AgentSH reports to Watchtower so
// the server can resolve the bound policy. It has no dependency on the
// WTP proto types; conversion to the wire shape happens in the caller.
package decisionctx

import (
	"context"
	"log/slog"
)

// UserSource identifies which signal produced a User value so the server
// can weigh trust (tailscale is stronger than os).
type UserSource string

// Source labels for User.Source.
const (
	SourceOS        UserSource = "os"
	SourceTailscale UserSource = "tailscale"
)

// User is the identity slot. Source records which signal produced Value
// so the server can weigh trust (tailscale is stronger than os).
type User struct {
	Value  string
	Source UserSource
}

// DecisionContext is the bundle reported to Watchtower. Fields are
// optional; the agent sends what it has.
type DecisionContext struct {
	Hostname string
	Tags     []string
	User     User
	Extra    map[string]string
}

// Source contributes one or more fields into a DecisionContext. A Source
// that cannot resolve its field returns nil and leaves the field unset —
// resolution must never fail because one signal is unavailable.
type Source interface {
	Name() string
	Resolve(ctx context.Context, into *DecisionContext) error
}

// Resolver runs its sources in order, later sources overriding earlier
// ones (e.g. tailscale overrides os-user in the User slot).
type Resolver struct {
	sources []Source
}

// Resolve runs every source. A source error is swallowed (the resulting
// context is simply partial); Resolve only returns an error for a truly
// fatal condition, of which there are currently none.
func (r *Resolver) Resolve(ctx context.Context) (DecisionContext, error) {
	dc := DecisionContext{}
	for _, s := range r.sources {
		if err := s.Resolve(ctx, &dc); err != nil {
			slog.Debug("decisionctx: source resolution failed (partial context)",
				"source", s.Name(), "error", err)
		}
	}
	return dc, nil
}

// Config drives NewResolver.
type Config struct {
	Tags             []string
	Extra            map[string]string
	TailscaleEnabled bool
	TailscaleSocket  string // "" => platform default
}
