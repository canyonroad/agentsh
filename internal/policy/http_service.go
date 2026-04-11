package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// HTTPService declares an HTTP service that a cooperating child process
// can reach through the proxy gateway. Requests are matched to the service
// by a URL path prefix (/svc/<name>/), then evaluated against Rules in
// declaration order. First-match-wins; if no rule matches, Default applies
// (empty or "deny" means deny).
type HTTPService struct {
	Name        string            `yaml:"name"`
	Upstream    string            `yaml:"upstream"`               // https://api.github.com
	ExposeAs    string            `yaml:"expose_as,omitempty"`    // env var name; derived from Name if empty
	Aliases     []string          `yaml:"aliases,omitempty"`      // extra hostnames for the fail-closed check
	AllowDirect bool              `yaml:"allow_direct,omitempty"` // escape hatch; default false
	Default     string            `yaml:"default,omitempty"`      // allow | deny; default deny
	Rules       []HTTPServiceRule `yaml:"rules,omitempty"`
}

// HTTPServiceRule is a single method+path matching rule for an HTTP service.
type HTTPServiceRule struct {
	Name     string   `yaml:"name"`
	Methods  []string `yaml:"methods,omitempty"` // empty or "*" means any method
	Paths    []string `yaml:"paths"`             // gobwas/glob patterns, '/' separator
	Decision string   `yaml:"decision"`          // allow | deny | approve | audit
	Message  string   `yaml:"message,omitempty"`
	Timeout  duration `yaml:"timeout,omitempty"` // parsed but not wired in v1
}

var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// canonicalizeHost returns the canonical host form for duplicate-detection.
// It accepts bracketed IPv6 "[::1]" / "[::1]:443", hostnames, and
// "host:port" in any case with an optional trailing dot. It REJECTS
// bare (unbracketed) IPv6 literals because HTTP Host headers require
// IPv6 to be bracketed; treating bare forms as equivalent would create
// configs whose duplicate detection differs from runtime host matching
// (internal/proxy/services/matcher.go preserves brackets and matches
// "[::1]" literally — bare "::1" never matches).
//
// Returns (canonical, true) on success, ("", false) on reject.
//
// This helper lives in the policy package by design: the policy package
// must not import proxy-layer packages, so the normalization logic is
// duplicated here (with both sites anchored to the same documented rules).
func canonicalizeHost(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return "", false // unterminated bracket
		}
		inner := s[1:end]
		rest := s[end+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return "", false // junk after closing bracket
		}
		if inner == "" {
			return "", false // "[]"
		}
		return strings.TrimSuffix(strings.ToLower(inner), "."), true
	}
	// Not bracketed. If there are 2+ colons, it's a bare IPv6 literal — reject.
	if strings.Count(s, ":") >= 2 {
		return "", false
	}
	// hostname or host:port
	if i := strings.LastIndex(s, ":"); i != -1 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" {
		return "", false
	}
	return s, true
}

// ValidateHTTPServices checks an HTTPServices list for well-formedness.
// It is called from Policy.Validate. Errors include the offending service
// name (and rule name, when applicable) to aid debugging.
func ValidateHTTPServices(svcs []HTTPService) error {
	nameSeen := make(map[string]bool, len(svcs))
	hostSeen := make(map[string]string, len(svcs)) // host -> owning service name
	for i := range svcs {
		s := &svcs[i]
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("http_services[%d]: name is required", i)
		}
		lower := strings.ToLower(s.Name)
		if nameSeen[lower] {
			return fmt.Errorf("http_services: duplicate http_service name %q", s.Name)
		}
		nameSeen[lower] = true

		u, err := url.Parse(s.Upstream)
		if err != nil || u == nil || u.Host == "" {
			return fmt.Errorf("http_services[%q]: invalid upstream URL %q", s.Name, s.Upstream)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("http_services[%q]: upstream must be https (got %q)", s.Name, u.Scheme)
		}

		// u.Host (not u.Hostname()) preserves brackets for IPv6 literals so
		// the canonicalizer can distinguish bracketed from bare forms.
		host, ok := canonicalizeHost(u.Host)
		if !ok {
			return fmt.Errorf("http_services[%q]: invalid upstream host %q (IPv6 literals must be bracketed)", s.Name, u.Host)
		}
		if other, dup := hostSeen[host]; dup {
			return fmt.Errorf("http_services[%q]: duplicate upstream host %q (also claimed by %q)", s.Name, host, other)
		}
		hostSeen[host] = s.Name
		for _, alias := range s.Aliases {
			a, ok := canonicalizeHost(alias)
			if !ok {
				return fmt.Errorf("http_services[%q]: invalid alias %q (IPv6 literals must be bracketed, hostnames must be non-empty)", s.Name, alias)
			}
			if other, dup := hostSeen[a]; dup {
				return fmt.Errorf("http_services[%q]: duplicate upstream host %q via alias (also claimed by %q)", s.Name, a, other)
			}
			hostSeen[a] = s.Name
		}

		switch s.Default {
		case "", "allow", "deny":
			// OK
		default:
			return fmt.Errorf("http_services[%q]: invalid default %q (want allow|deny)", s.Name, s.Default)
		}

		exposeAs := s.ExposeAs
		if exposeAs == "" {
			exposeAs = strings.ToUpper(s.Name) + "_API_URL"
			if !envVarNameRe.MatchString(exposeAs) {
				return fmt.Errorf("http_services[%q]: derived env var name %q is invalid; set expose_as explicitly", s.Name, exposeAs)
			}
		} else if !envVarNameRe.MatchString(exposeAs) {
			return fmt.Errorf("http_services[%q]: invalid expose_as %q", s.Name, exposeAs)
		}

		for j := range s.Rules {
			r := &s.Rules[j]
			if err := validateHTTPServiceRule(s.Name, j, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHTTPServiceRule(svc string, idx int, r *HTTPServiceRule) error {
	label := fmt.Sprintf("http_services[%q].rules[%d] (%s)", svc, idx, r.Name)
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// OK
	default:
		return fmt.Errorf("%s: invalid rule decision %q", label, r.Decision)
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("%s: rule must have at least one path", label)
	}
	for _, pat := range r.Paths {
		if strings.TrimSpace(pat) == "" {
			return fmt.Errorf("%s: empty path in rule", label)
		}
		if _, err := glob.Compile(pat, '/'); err != nil {
			return fmt.Errorf("%s: invalid path glob %q: %w", label, pat, err)
		}
	}
	for _, m := range r.Methods {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("%s: empty method", label)
		}
	}
	return nil
}
