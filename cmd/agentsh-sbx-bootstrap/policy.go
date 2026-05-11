package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/policy"
	"gopkg.in/yaml.v3"
)

// mergeAndWritePolicy reads the baked template at `tmpl`, reads the optional
// user override at `overlay` (any read or parse failure is logged to stderr
// and treated as "no overlay"), merges them via policy.MergeOverlay, and
// writes the result atomically to `out` via a temp file + rename.
//
// Returns an error only when the template itself cannot be read or parsed.
// A missing/broken overlay is intentionally non-fatal: the template alone is
// always a safe fallback and the bootstrap is required to fail-open.
func mergeAndWritePolicy(tmpl, overlay, out string) error {
	tmplBytes, err := os.ReadFile(tmpl)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	base, err := policy.LoadFromBytes(tmplBytes)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var ov *policy.Policy
	if overlay != "" {
		ovBytes, ovErr := os.ReadFile(overlay)
		switch {
		case errors.Is(ovErr, os.ErrNotExist):
			// No override file: fine. Bare template wins.
		case ovErr != nil:
			fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: read overlay %q: %v (falling back to template only)\n", overlay, ovErr)
		default:
			parsed, pErr := policy.LoadFromBytes(ovBytes)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: parse overlay %q: %v (falling back to template only)\n", overlay, pErr)
			} else {
				ov = parsed
			}
		}
	}

	merged := policy.MergeOverlay(base, ov)

	mergedYAML, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged policy: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, mergedYAML, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
