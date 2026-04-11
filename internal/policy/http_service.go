package policy

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
