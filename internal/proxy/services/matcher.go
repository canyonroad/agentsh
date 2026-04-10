package services

import "strings"

// ServicePattern describes a service's host matching rules.
type ServicePattern struct {
	Name  string
	Hosts []string // literal hostnames or "*.suffix" wildcards
}

// hostPattern is a pre-compiled host pattern.
type hostPattern struct {
	serviceName string
	isWildcard  bool
	literal     string // lowercase, used when isWildcard == false
	suffix      string // lowercase, ".example.com", used when isWildcard == true
}

// Matcher resolves HTTP Host headers to service names.
// Safe for concurrent use — all state is read-only after construction.
type Matcher struct {
	patterns []hostPattern
}

// NewMatcher pre-compiles service host patterns. Order matters:
// first match wins.
func NewMatcher(services []ServicePattern) *Matcher {
	var patterns []hostPattern
	for _, svc := range services {
		for _, h := range svc.Hosts {
			p := hostPattern{serviceName: svc.Name}
			if strings.HasPrefix(h, "*.") {
				p.isWildcard = true
				// Normalise suffix: lowercase and strip any trailing dot.
				p.suffix = strings.TrimSuffix(strings.ToLower(h[1:]), ".")
			} else {
				// Normalise literal: lowercase and strip any trailing dot.
				p.literal = strings.TrimSuffix(strings.ToLower(h), ".")
			}
			patterns = append(patterns, p)
		}
	}
	return &Matcher{patterns: patterns}
}

// Match returns the service name for the given host, or ("", false)
// if no pattern matches. Port is stripped before matching.
func (m *Matcher) Match(host string) (string, bool) {
	// Strip port if present, with bracket-aware IPv6 handling.
	if strings.HasPrefix(host, "[") {
		// Bracketed IPv6: look for "]:" to find port separator.
		if i := strings.Index(host, "]:"); i != -1 {
			host = host[:i+1] // keep the closing bracket, drop ":port"
		}
		// No "]:" found — no port to strip; leave host unchanged.
	} else {
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
	}
	// Lowercase then strip any trailing FQDN dot.
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	for _, p := range m.patterns {
		if p.isWildcard {
			// *.example.com matches api.example.com but not
			// example.com and not sub.api.example.com.
			if strings.HasSuffix(host, p.suffix) {
				prefix := host[:len(host)-len(p.suffix)]
				if len(prefix) > 0 && !strings.Contains(prefix, ".") {
					return p.serviceName, true
				}
			}
		} else {
			if host == p.literal {
				return p.serviceName, true
			}
		}
	}
	return "", false
}
