//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestProbeWaitKillableBehavior_AllPass(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		return IterPass, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatal("want true")
	}
	if calls != 5 {
		t.Fatalf("want 5 iterations, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_FirstFailShortCircuits(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		return IterKilled, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("want false")
	}
	if calls != 1 {
		t.Fatalf("want short-circuit after 1 iteration, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_MidFail(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		if calls == 3 {
			return IterTimeout, nil
		}
		return IterPass, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("want false (timeout at iter 3 must fail the probe)")
	}
	if calls != 3 {
		t.Fatalf("want 3 iterations, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_ErrorPropagates(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	want := errors.New("fork failed")
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		return 0, want
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
	if ok {
		t.Fatal("want false on error")
	}
}

func TestProbeWaitKillableBehavior_CancelledContext(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		return IterPass, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := ProbeWaitKillableBehavior(ctx, 5)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if ok {
		t.Fatal("want false on cancel")
	}
}

func TestProbeWaitKillableBehavior_ZeroIterations(t *testing.T) {
	_, err := ProbeWaitKillableBehavior(context.Background(), 0)
	if err == nil {
		t.Fatal("want error for iterations=0")
	}
}

func TestProbeWaitKillableBehavior_NegativeIterations(t *testing.T) {
	_, err := ProbeWaitKillableBehavior(context.Background(), -1)
	if err == nil {
		t.Fatal("want error for iterations=-1")
	}
}

func TestProbeWaitKillableBehavior_RealKernel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-fork probe test in short mode")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true missing on this host")
	}
	if !ProbeWaitKillable() {
		t.Skip("kernel <6: WAIT_KILLABLE_RECV not supported on this host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	start := time.Now()
	ok, err := ProbeWaitKillableBehavior(ctx, 2)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	// Do NOT assert ok==true here: this test runs on real kernels, and
	// on a host that genuinely exhibits the issue #369 kernel bug the
	// probe will (correctly) return false. That outcome is the whole
	// point of the probe — failing the test in that case would mean
	// the test breaks precisely when the code works as designed. The
	// real assertion is "no error, ran in reasonable time".
	t.Logf("probe result: ok=%v duration=%v (note for triage if ok=false on this host)", ok, dur)
	if dur > 5*time.Second {
		t.Errorf("probe took too long: %v (expected <5s)", dur)
	}
}
