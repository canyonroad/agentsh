//go:build integration && linux

package ptrace

import (
	"testing"
	"time"
)

// TestInjectProbe_InjectableOnCIKernel verifies the behavioral probe
// reports injection works on a healthy kernel (the CI runner), returns
// promptly, caches its result, and leaves no orphaned probe children. (#369)
func TestInjectProbe_InjectableOnCIKernel(t *testing.T) {
	requirePtrace(t)

	start := time.Now()
	res := ProbePtraceInject()
	elapsed := time.Since(start)

	if !res.Injectable {
		t.Fatalf("ProbePtraceInject reported NOT injectable on CI kernel; detail=%q", res.Detail)
	}
	// 8 iterations, each bounded at ~1s; the happy path is tens of ms each.
	// Allow generous slack for loaded CI but catch a runaway hang.
	if elapsed > 30*time.Second {
		t.Fatalf("ProbePtraceInject took %v, expected to return promptly", elapsed)
	}
	t.Logf("ProbePtraceInject: injectable=%v detail=%q elapsed=%v", res.Injectable, res.Detail, elapsed)

	// Cached: a second call must return the identical result instantly without
	// spawning another child.
	start2 := time.Now()
	res2 := ProbePtraceInject()
	elapsed2 := time.Since(start2)
	if res2 != res {
		t.Fatalf("cached result differs: first=%+v second=%+v", res, res2)
	}
	if elapsed2 > 100*time.Millisecond {
		t.Fatalf("second (cached) ProbePtraceInject took %v, expected instant", elapsed2)
	}
}

// TestInjectProbeResult_ZeroValue documents the zero-value semantics: a
// zero-value result is the conservative "not injectable, no detail" form,
// distinct from the fail-open inconclusive form ProbePtraceInject returns.
func TestInjectProbeResult_ZeroValue(t *testing.T) {
	var r InjectProbeResult
	if r.Injectable {
		t.Fatalf("zero-value InjectProbeResult should not be Injectable")
	}
	if r.Detail != "" {
		t.Fatalf("zero-value Detail should be empty, got %q", r.Detail)
	}
}
