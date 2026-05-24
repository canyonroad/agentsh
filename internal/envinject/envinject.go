// Package envinject applies operator-configured environment variable
// injection (sandbox.env_inject) to a process environment.
package envinject

import "strings"

// Apply overlays operator-configured env_inject values onto base, returning a
// new "KEY=VALUE" slice. For every key in inject, all pre-existing occurrences
// are removed from base and a single injected entry is appended. This mirrors
// the server-spawned exec path (internal/api/exec.go) and guarantees the
// injected value wins: POSIX getenv returns the first matching entry, so a
// stale duplicate left earlier in the slice would otherwise shadow it.
//
// Keys not present in inject are preserved in their original order. When inject
// is empty, base is returned unchanged.
func Apply(base []string, inject map[string]string) []string {
	if len(inject) == 0 {
		return base
	}

	out := make([]string, 0, len(base)+len(inject))
	for _, e := range base {
		k, _, ok := strings.Cut(e, "=")
		if ok {
			if _, override := inject[k]; override {
				continue // drop stale occurrence; injected value appended below
			}
		}
		out = append(out, e)
	}
	for k, v := range inject {
		out = append(out, k+"="+v)
	}
	return out
}
