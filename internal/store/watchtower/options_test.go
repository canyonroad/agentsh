package watchtower_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/pkg/types"
)

// testHMACKey is a fixed 32-byte HMAC key used across watchtower tests.
// audit.NewSinkChain rejects keys shorter than audit.MinKeyLength (32),
// so test fixtures must hit at least that length.
func testHMACKey() []byte { return bytes.Repeat([]byte("a"), 32) }

// validOpts returns a watchtower.Options that satisfies validate() —
// individual tests then mutate one field to exercise a specific
// rejection branch.
func validOpts(dir string) watchtower.Options {
	return watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		HMACKeyID:       "k1",
		HMACSecret:      testHMACKey(),
		BatchMaxRecords: 256,
		BatchMaxBytes:   256 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
	}
}

// TestNew_RejectsStubMapperInProduction verifies validate() rejects a
// StubMapper unless AllowStubMapper is true.
func TestNew_RejectsStubMapperInProduction(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.AllowStubMapper = false
	_, err := watchtower.New(context.Background(), opts)
	if err == nil {
		t.Fatal("expected New to reject StubMapper")
	}
	if !strings.Contains(err.Error(), "StubMapper") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RequiresHMACSecret(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.HMACSecret = nil
	_, err := watchtower.New(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "HMAC secret") {
		t.Fatalf("expected HMAC secret error, got: %v", err)
	}
}

// TestNew_RejectsShortHMACSecret verifies validate() mirrors
// audit.MinKeyLength.
func TestNew_RejectsShortHMACSecret(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.HMACSecret = bytes.Repeat([]byte("a"), 16)
	_, err := watchtower.New(context.Background(), opts)
	if err == nil {
		t.Fatal("expected validate() to reject a 16-byte HMAC secret")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error must mention key length: %v", err)
	}
}

// TestNew_RejectsUntypedNilMapper verifies validate() rejects an unset
// Mapper field with a clear "mapper is required" error.
func TestNew_RejectsUntypedNilMapper(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.Mapper = nil
	_, err := watchtower.New(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "mapper is required") {
		t.Fatalf("expected 'mapper is required' error, got: %v", err)
	}
}

// TestNew_RejectsTypedNilMapper verifies validate() rejects a typed-nil
// pointer wrapped in the compact.Mapper interface. The reflect check
// catches the case `o.Mapper == nil` misses (interface value's dynamic
// type is non-nil, value is nil).
func TestNew_RejectsTypedNilMapper(t *testing.T) {
	opts := validOpts(t.TempDir())
	var typedNil *compact.StubMapper
	opts.Mapper = typedNil
	opts.AllowStubMapper = true // even with this on, typed-nil should still fail
	_, err := watchtower.New(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "mapper is required") {
		t.Fatalf("expected 'mapper is required' (typed-nil) error, got: %v", err)
	}
}

// fakeMapper proves the typed-nil pointer rejection branch fires for
// arbitrary non-stub Mapper implementations.
type fakeMapper struct{}

func (*fakeMapper) Map(types.Event) (compact.MappedEvent, error) {
	panic("must not be called — validate() should reject the typed-nil before any Map invocation")
}

// TestNew_RejectsTypedNilNonStubMapper locks in that the typed-nil
// pointer rejection branch isn't stub-specific.
func TestNew_RejectsTypedNilNonStubMapper(t *testing.T) {
	opts := validOpts(t.TempDir())
	var m *fakeMapper
	opts.Mapper = m
	opts.AllowStubMapper = false
	_, err := watchtower.New(context.Background(), opts)
	if err == nil {
		t.Fatal("expected typed-nil pointer rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "mapper") {
		t.Errorf("error must mention mapper: %v", err)
	}
}

// TestNew_RejectsSinkChainOverrideInProduction verifies the
// SinkChainOverrideForTests gate: a non-nil override without
// AllowSinkChainOverrideForTests must be rejected.
func TestNew_RejectsSinkChainOverrideInProduction(t *testing.T) {
	innerChain, err := audit.NewSinkChain(testHMACKey(), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	override := chain.NewWatchtowerSink(innerChain)
	opts := validOpts(t.TempDir())
	opts.SinkChainOverrideForTests = override
	// AllowSinkChainOverrideForTests deliberately omitted.
	_, err = watchtower.New(context.Background(), opts)
	if err == nil {
		t.Fatal("expected New to reject SinkChainOverrideForTests without AllowSinkChainOverrideForTests")
	}
	if !strings.Contains(err.Error(), "SinkChainOverrideForTests") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNew_AcceptsSinkChainOverrideWhenAllowed verifies the gate's
// permissive path.
func TestNew_AcceptsSinkChainOverrideWhenAllowed(t *testing.T) {
	innerChain, err := audit.NewSinkChain(testHMACKey(), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	override := chain.NewWatchtowerSink(innerChain)
	opts := validOpts(t.TempDir())
	opts.SinkChainOverrideForTests = override
	opts.AllowSinkChainOverrideForTests = true
	_, err = watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected New to accept SinkChainOverrideForTests when AllowSinkChainOverrideForTests is true, got %v", err)
	}
}
