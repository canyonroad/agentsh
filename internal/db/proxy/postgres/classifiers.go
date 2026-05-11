//go:build linux

package postgres

import (
	"fmt"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
)

// buildClassifierMap constructs one Parser per distinct dialect across the
// supplied services. Services sharing a dialect share a Parser instance.
// Returns an error when any service's Dialect is not a recognized name.
func buildClassifierMap(svcs []Service) (map[string]classify_pg.Parser, error) {
	out := make(map[string]classify_pg.Parser, 4)
	for _, svc := range svcs {
		if _, ok := out[svc.Dialect]; ok {
			continue
		}
		d, ok := classify_pg.ParseDialect(svc.Dialect)
		if !ok {
			return nil, fmt.Errorf("postgres.New: services[%q].Dialect = %q is not a recognized dialect",
				svc.Name, svc.Dialect)
		}
		out[svc.Dialect] = classify_pg.New(d)
	}
	return out, nil
}

// classifierFor returns the parser registered for the given dialect. Falls
// back to any parser from the map if a lookup fails — buildClassifierMap
// validated dialects at New() and guaranteed the map is non-empty, so all
// Parser instances are interchangeable for an unknown dialect.
// classifierForTest, when set on Config, overrides the map entirely.
func (s *Server) classifierFor(dialect string) classify_pg.Parser {
	if s.cfg.classifierForTest != nil {
		return s.cfg.classifierForTest(dialect)
	}
	if p, ok := s.classifiers[dialect]; ok {
		return p
	}
	// Fallback: pick any parser from the map. New() guaranteed the map is
	// non-empty in non-sentinel mode; in sentinel mode classifierFor is never
	// called. All Parser instances are interchangeable for an unknown dialect —
	// they all classify against the same libpg_query AST grammar.
	for _, p := range s.classifiers {
		return p
	}
	return nil
}
