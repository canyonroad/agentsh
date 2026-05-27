//go:build linux

package ptrace

import (
	"errors"
	"testing"
)

// TestScratchUnmappedError_WrapsSentinel locks the load-bearing %w wrap in
// scratchUnmappedError: the no-VMA error MUST satisfy errors.Is(err,
// errScratchUnmapped). The #399 probe's fail-closed broken-kernel signal
// depends on it; a %w→%v regression here would silently revert the probe to
// fail-open on the exact kernel class it exists to catch (#369).
func TestScratchUnmappedError_WrapsSentinel(t *testing.T) {
	err := scratchUnmappedError(0x1000, []string{"0x1000-0x2000"})
	if !errors.Is(err, errScratchUnmapped) {
		t.Fatalf("scratchUnmappedError must wrap errScratchUnmapped; got %v", err)
	}
}

// TestClassifyScratchInjectErr locks the probe's fail-closed vs fail-open
// decision: an unmapped-VMA error must DEGRADE (mapped=false, detail set, no
// probe error → Injectable=false), while any other error must FAIL-OPEN
// (probe error set → Injectable=true). This is the decision that silently
// flipped in the original regression (#369).
func TestClassifyScratchInjectErr(t *testing.T) {
	// Unmapped VMA → fail-CLOSED.
	mapped, detail, probeErr := classifyScratchInjectErr(scratchUnmappedError(0x1000, nil))
	if mapped {
		t.Error("unmapped case must report mapped=false")
	}
	if probeErr != nil {
		t.Errorf("unmapped case must not be a probe error (would fail-open); got %v", probeErr)
	}
	if detail == "" {
		t.Error("unmapped case must carry a detail for logs")
	}

	// Any other error → fail-OPEN.
	if _, _, probeErr = classifyScratchInjectErr(errors.New("attach denied")); probeErr == nil {
		t.Fatal("a generic inject error must be a probe error (fail-open)")
	}
}
