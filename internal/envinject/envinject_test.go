package envinject

import (
	"strings"
	"testing"
)

// envToMap parses a "KEY=VALUE" slice into a map and the count of entries per
// key, so tests can assert both the resolved value and that no duplicate
// occurrences of an injected key remain.
func envToMap(env []string) (map[string]string, map[string]int) {
	vals := make(map[string]string, len(env))
	counts := make(map[string]int, len(env))
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		vals[k] = v
		counts[k]++
	}
	return vals, counts
}

func TestApply_OverridesExistingKey(t *testing.T) {
	base := []string{"BASH_ENV=/inherited", "PATH=/usr/bin", "HOME=/root"}
	inject := map[string]string{"BASH_ENV": "/usr/lib/agentsh/bash_startup.sh"}

	got := Apply(base, inject)

	vals, counts := envToMap(got)
	if vals["BASH_ENV"] != "/usr/lib/agentsh/bash_startup.sh" {
		t.Fatalf("BASH_ENV = %q, want injected value", vals["BASH_ENV"])
	}
	if counts["BASH_ENV"] != 1 {
		t.Fatalf("BASH_ENV appears %d times, want exactly 1 (stale entry not removed)", counts["BASH_ENV"])
	}
	if vals["PATH"] != "/usr/bin" || vals["HOME"] != "/root" {
		t.Fatalf("untouched keys altered: PATH=%q HOME=%q", vals["PATH"], vals["HOME"])
	}
}

func TestApply_AddsNewKey(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	inject := map[string]string{"OTEL_SERVICE_NAME": "agentsh-blaxel"}

	got := Apply(base, inject)

	vals, counts := envToMap(got)
	if vals["OTEL_SERVICE_NAME"] != "agentsh-blaxel" {
		t.Fatalf("OTEL_SERVICE_NAME = %q, want injected value", vals["OTEL_SERVICE_NAME"])
	}
	if counts["OTEL_SERVICE_NAME"] != 1 {
		t.Fatalf("OTEL_SERVICE_NAME appears %d times, want 1", counts["OTEL_SERVICE_NAME"])
	}
}

func TestApply_RemovesAllDuplicateOccurrences(t *testing.T) {
	// POSIX getenv returns the first match; a stale earlier duplicate would
	// shadow the injected value, so every prior occurrence must be removed.
	base := []string{"X=first", "Y=keep", "X=second"}
	inject := map[string]string{"X": "injected"}

	got := Apply(base, inject)

	vals, counts := envToMap(got)
	if counts["X"] != 1 {
		t.Fatalf("X appears %d times, want exactly 1", counts["X"])
	}
	if vals["X"] != "injected" {
		t.Fatalf("X = %q, want injected", vals["X"])
	}
	if vals["Y"] != "keep" {
		t.Fatalf("Y = %q, want keep", vals["Y"])
	}
}

func TestApply_EmptyInjectReturnsBaseUnchanged(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/root"}

	for _, inject := range []map[string]string{nil, {}} {
		got := Apply(base, inject)
		if len(got) != len(base) {
			t.Fatalf("len(got) = %d, want %d for inject=%v", len(got), len(base), inject)
		}
		vals, _ := envToMap(got)
		if vals["PATH"] != "/usr/bin" || vals["HOME"] != "/root" {
			t.Fatalf("base altered with empty inject: %v", got)
		}
	}
}
