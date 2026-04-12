package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
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
	Default     string            `yaml:"default,omitempty"`      // allow | deny; default depends on Rules presence
	Rules       []HTTPServiceRule `yaml:"rules,omitempty"`

	// Credential substitution (unified from old services: section).
	Secret        *HTTPServiceSecret `yaml:"secret,omitempty"`
	Inject        *HTTPServiceInject `yaml:"inject,omitempty"`
	ScrubResponse *bool              `yaml:"scrub_response,omitempty"` // nil = default based on Secret presence
}

// HTTPServiceSecret defines how to fetch and fake a credential.
type HTTPServiceSecret struct {
	Ref    string `yaml:"ref"`    // e.g. "vault://kv/data/github#token"
	Format string `yaml:"format"` // e.g. "ghp_{rand:36}"
}

// HTTPServiceInject defines how the credential is injected into requests.
type HTTPServiceInject struct {
	Header *HTTPServiceInjectHeader `yaml:"header,omitempty"`
}

// HTTPServiceInjectHeader defines header injection config.
type HTTPServiceInjectHeader struct {
	Name     string `yaml:"name"`     // e.g. "Authorization"
	Template string `yaml:"template"` // e.g. "Bearer {{secret}}"
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

// knownProviderTypes lists the provider type names (URI schemes) that
// are supported. Ported from secrets.go for use by
// ValidateHTTPServicesWithProviders; will be the sole copy after
// secrets.go is deleted.
var knownProviderTypes = map[string]bool{
	"keyring":  true,
	"vault":    true,
	"aws-sm":   true,
	"gcp-sm":   true,
	"azure-kv": true,
	"op":       true,
}

// httpServiceNameRe restricts http_service.name to URL-safe path segment
// characters. Routing depends on the name appearing in /svc/<name>/ URLs,
// so any character the URL parser treats as a segment terminator (/, ?, #)
// or otherwise reserves must be rejected up front — otherwise the derived
// *_API_URL would be ambiguous and /svc/<name>/ dispatch would fall through
// to a 404 or match the wrong service.
var httpServiceNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// reservedEnvVarNames is the set of env var names that http_services must
// not claim via ExposeAs or via the derived <NAME>_API_URL form, because
// they are already emitted by Proxy.EnvVars() for the LLM proxy. Allowing
// collisions would silently overwrite one of the sides in the returned
// map. Keep additions here conservative — each entry shrinks the space of
// valid http_service configurations.
var reservedEnvVarNames = map[string]struct{}{
	"ANTHROPIC_BASE_URL": {},
	"OPENAI_BASE_URL":    {},
	"AGENTSH_SESSION_ID": {},
}

// httpServiceAllowInsecureUpstreamForTest, when true, lets ValidateHTTPServices
// accept http:// upstreams. Set from test init() functions only. Never set in
// production code.
var httpServiceAllowInsecureUpstreamForTest bool

// SetAllowInsecureHTTPServiceUpstreamForTest enables the test-only relaxation
// of the upstream scheme check so tests can point declared services at an
// httptest.Server listening on http://. This function exists so test files
// in other packages can flip the toggle without touching package-private
// state. Not thread-safe. Never call from production code.
func SetAllowInsecureHTTPServiceUpstreamForTest(v bool) {
	httpServiceAllowInsecureUpstreamForTest = v
}

// canonicalizeHost returns the canonical host form for duplicate-detection.
// It validates bracket contents as IPv6 literals via netip.ParseAddr but
// uses the lowercased textual form (not addr.String()) so that duplicate
// detection matches what the runtime host matcher would see.
//
// It accepts bracketed IPv6 "[::1]" / "[::1]:443", hostnames, and
// "host:port" in any case with an optional trailing dot. It REJECTS
// bare (unbracketed) IPv6 literals because HTTP Host headers require
// IPv6 to be bracketed; treating bare forms as equivalent would create
// configs whose duplicate detection differs from runtime host matching
// (internal/proxy/services/matcher.go preserves brackets and matches
// "[::1]" literally — bare "::1" never matches).
//
// Bracketed payloads MUST parse as valid IPv6 literals per RFC 3986
// §3.2.2; hostnames, malformed hex, embedded whitespace, "[..]",
// "[example.com]", and similar garbage are rejected. IPv4-in-IPv6
// forms like "[::ffff:192.168.1.1]" are syntactically valid IPv6 and
// accepted (the runtime matcher accepts them too).
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
		// Validate that the bracket payload is a real IPv6 literal per
		// RFC 3986 §3.2.2, but don't canonicalize its spelling — the
		// runtime host matcher compares bracketed literals textually
		// (only lowercase + port-strip), so we need validation to use
		// the same domain of equality. IPv4-in-IPv6 forms like
		// ::ffff:192.168.1.1 are syntactically valid IPv6 and accepted
		// by the runtime matcher — accept them too.
		addr, err := netip.ParseAddr(inner)
		if err != nil || !addr.Is6() {
			return "", false
		}
		_ = addr
		return strings.ToLower(inner), true
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
	hostSeen := make(map[string]string, len(svcs))   // host -> owning service name
	envVarSeen := make(map[string]string, len(svcs)) // env var name -> owning service name
	for i := range svcs {
		s := &svcs[i]
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("http_services[%d]: name is required", i)
		}
		if !httpServiceNameRe.MatchString(s.Name) {
			return fmt.Errorf("http_services[%d]: name %q must match %s (URL-safe segment)", i, s.Name, httpServiceNameRe)
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
		if u.Scheme != "https" && !(httpServiceAllowInsecureUpstreamForTest && u.Scheme == "http") {
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

		// Derive the effective env var name once and use it for both the
		// regex check and the reserved/duplicate collision checks. This
		// matches what Proxy.EnvVars() will emit at runtime, so validation
		// rejects misconfigurations that would cause silent overwrites of
		// LLM proxy envs or of another http_service's entry.
		//
		// Windows treats environment variables as case-insensitive, so the
		// reserved-name and duplicate-detection keys are upper-cased before
		// comparison. The raw form is preserved in error messages so users
		// see the exact value they wrote in their YAML. The regex check
		// still runs on the raw name since env var names may be lowercase
		// on Linux (the regex allows [A-Za-z_]).
		exposeAs := s.ExposeAs
		if exposeAs == "" {
			exposeAs = strings.ToUpper(s.Name) + "_API_URL"
			if !envVarNameRe.MatchString(exposeAs) {
				return fmt.Errorf("http_services[%q]: derived env var name %q is invalid; set expose_as explicitly", s.Name, exposeAs)
			}
		} else if !envVarNameRe.MatchString(exposeAs) {
			return fmt.Errorf("http_services[%q]: invalid expose_as %q", s.Name, exposeAs)
		}
		exposeAsKey := strings.ToUpper(exposeAs)
		if _, reserved := reservedEnvVarNames[exposeAsKey]; reserved {
			return fmt.Errorf("http_services[%q]: reserved env var name %q (used by LLM proxy)", s.Name, exposeAs)
		}
		if other, dup := envVarSeen[exposeAsKey]; dup {
			return fmt.Errorf("http_services[%q]: duplicate env var name %q (also claimed by %q)", s.Name, exposeAs, other)
		}
		envVarSeen[exposeAsKey] = s.Name

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

// ValidateHTTPServicesWithProviders runs structural validation via
// ValidateHTTPServices, then validates credential-related fields against
// the declared providers. It checks that secret refs parse, reference a
// declared provider scheme, use a valid fake format, and that inject
// templates contain the {{secret}} placeholder.
func ValidateHTTPServicesWithProviders(svcs []HTTPService, providers map[string]yaml.Node) error {
	// Run structural validation first.
	if err := ValidateHTTPServices(svcs); err != nil {
		return err
	}

	// Build provider scheme set with duplicate-type detection.
	// Mirrors the validation from ValidateSecrets so the rules carry
	// over when secrets.go is deleted.
	providerSchemes := make(map[string]string) // scheme -> provider name
	for name, node := range providers {
		var base struct {
			Type string `yaml:"type"`
		}
		if err := node.Decode(&base); err != nil {
			return fmt.Errorf("providers.%s: cannot decode type: %w", name, err)
		}
		if base.Type == "" {
			return fmt.Errorf("providers.%s: type is required", name)
		}
		if !knownProviderTypes[base.Type] {
			return fmt.Errorf("providers.%s: unknown type %q", name, base.Type)
		}
		if prev, dup := providerSchemes[base.Type]; dup {
			return fmt.Errorf("providers.%s: duplicate type %q (already declared by %q)", name, base.Type, prev)
		}
		providerSchemes[base.Type] = name
	}

	for _, s := range svcs {
		if s.Secret == nil && len(s.Rules) == 0 {
			return fmt.Errorf("http_services[%q]: service has no secret and no rules", s.Name)
		}
		if s.Inject != nil && s.Secret == nil {
			return fmt.Errorf("http_services[%q]: inject requires secret", s.Name)
		}
		if s.Secret != nil {
			ref, err := secrets.ParseRef(s.Secret.Ref)
			if err != nil {
				return fmt.Errorf("http_services[%q]: invalid secret ref: %w", s.Name, err)
			}
			if len(providerSchemes) > 0 {
				if _, ok := providerSchemes[ref.Scheme]; !ok {
					return fmt.Errorf("http_services[%q]: secret ref scheme %q has no matching provider", s.Name, ref.Scheme)
				}
			}
			if len(providerSchemes) == 0 && s.Secret != nil {
				return fmt.Errorf("http_services[%q]: secret ref scheme %q has no matching provider (no providers declared)", s.Name, ref.Scheme)
			}
			if _, _, err := secrets.ParseFormat(s.Secret.Format); err != nil {
				return fmt.Errorf("http_services[%q]: invalid fake format: %w", s.Name, err)
			}
		}
		if s.Inject != nil && s.Inject.Header != nil {
			if !strings.Contains(s.Inject.Header.Template, "{{secret}}") {
				return fmt.Errorf("http_services[%q]: inject.header.template must contain {{secret}}", s.Name)
			}
			if strings.TrimSpace(s.Inject.Header.Name) == "" {
				return fmt.Errorf("http_services[%q]: inject.header name is required", s.Name)
			}
		}
		if s.Inject != nil && s.Inject.Header == nil {
			return fmt.Errorf("http_services[%q]: inject.header is required when inject is set", s.Name)
		}
	}
	return nil
}
