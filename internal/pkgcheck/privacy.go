package pkgcheck

import (
	"net/url"
	"path"
	"strings"
)

// PrivacyConfig configures the privacy filter.
//
// LIMITATION: the privacy filter compares against PackageRef.Registry,
// which is populated by package-manager resolvers. Resolvers do NOT
// currently parse `.npmrc`, `~/.config/pip/pip.conf`, or environment
// variables that override the default registry — they only honor
// CLI flags (--registry, --index-url, etc.). Operators whose
// installs use config-file or env-var registry overrides must
// explicitly include those registries in `external_scan_registries`,
// or omit the public-registry defaults to keep private packages
// behind the privacy gate. Scoped npm packages fail closed for this
// reason (see resolver/npm.go).
type PrivacyConfig struct {
	// ExternalScanRegistries lists registries whose packages may be sent to
	// external providers. An empty list means "do not filter by registry."
	ExternalScanRegistries []string

	// PrivateScopeDenylist lists package name prefixes / glob patterns that
	// should NOT be sent externally even when on an allowed registry.
	// Each entry is matched as either an exact prefix (`@acme`) or a
	// glob (`@internal-*`).
	PrivateScopeDenylist []string
}

// PrivacyFilter partitions a list of PackageRef into "to-scan" and "to-skip".
type PrivacyFilter struct {
	allowedRegistries map[string]struct{}
	denylistPatterns  []string
}

// NewPrivacyFilter builds a filter from configuration.
func NewPrivacyFilter(cfg PrivacyConfig) *PrivacyFilter {
	allowed := make(map[string]struct{}, len(cfg.ExternalScanRegistries))
	for _, r := range cfg.ExternalScanRegistries {
		allowed[normalizeRegistry(r)] = struct{}{}
	}
	return &PrivacyFilter{
		allowedRegistries: allowed,
		denylistPatterns:  append([]string(nil), cfg.PrivateScopeDenylist...),
	}
}

// Partition splits the input into packages eligible for external scanning
// and packages skipped due to privacy rules. Order within each slice
// preserves the order of the input.
//
// Decision order: registry rule first (if an allowlist is configured),
// then scope/prefix denylist. A package skipped for "private_registry"
// is never re-classified to "private_scope_denylist."
//
// Fail-closed semantics: when the allowlist is non-empty, packages with
// an empty Registry are treated as private (skipped), not waved through.
// Missing registry metadata can mean an unresolved or internal package
// whose origin is unknown to us — sending its name to a third-party API
// would leak information about internal architecture.
func (f *PrivacyFilter) Partition(pkgs []PackageRef) (scan []PackageRef, skip []SkippedPackage) {
	for _, p := range pkgs {
		if len(f.allowedRegistries) > 0 {
			if _, ok := f.allowedRegistries[normalizeRegistry(p.Registry)]; !ok {
				skip = append(skip, SkippedPackage{Package: p, Reason: SkipReasonPrivateRegistry})
				continue
			}
		}
		if f.matchesDenylist(p.Name) {
			skip = append(skip, SkippedPackage{Package: p, Reason: SkipReasonPrivateScopeDenylist})
			continue
		}
		scan = append(scan, p)
	}
	return scan, skip
}

func (f *PrivacyFilter) matchesDenylist(name string) bool {
	for _, pat := range f.denylistPatterns {
		if pat == "" {
			continue // empty pattern is a no-op; ignore rather than match-all
		}
		if strings.ContainsAny(pat, "*?[") {
			if ok, _ := path.Match(pat, name); ok {
				return true
			}
			// Also match against the leading scope segment for patterns like @internal-*
			if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
				scope := strings.SplitN(name, "/", 2)[0]
				if ok, _ := path.Match(pat, scope); ok {
					return true
				}
			}
		} else {
			// Plain prefix match. Examples:
			//   "@acme" matches "@acme" and "@acme/billing".
			//   "internal-" matches "internal-tool", "internal-foo".
			// Privacy semantics are fail-safe: an over-broad prefix produces
			// over-skip (private), not under-skip (leak), so we err on the
			// HasPrefix side. Users who need stricter semantics use globs.
			if strings.HasPrefix(name, pat) {
				return true
			}
		}
	}
	return false
}

// normalizeRegistry reduces a registry URL or host string to a canonical
// form for comparison.  Path segments are preserved so that
// "https://artifact.example/team-a/" and "https://artifact.example/team-b/"
// are treated as distinct registries.
//
// Examples:
//
//	"https://registry.npmjs.org/"          → "registry.npmjs.org"
//	"https://artifact.example/team-a/"     → "artifact.example/team-a"
//	"registry.npmjs.org"                   → "registry.npmjs.org"
func normalizeRegistry(s string) string {
	if s == "" {
		return ""
	}
	// If it parses as a URL with a host, return host + path (trailing slash stripped).
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			path := strings.TrimRight(u.Path, "/")
			if path == "" {
				return host
			}
			return host + path
		}
	}
	// No scheme — treat the whole string as host-or-host+path.
	// Trim trailing slash, lowercase the host portion only.
	s = strings.TrimRight(s, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return strings.ToLower(s[:i]) + s[i:]
	}
	return strings.ToLower(s)
}
