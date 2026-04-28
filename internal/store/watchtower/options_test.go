package watchtower_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/pkg/types"
)

// testHMACKey is a fixed 32-byte HMAC key used across watchtower tests.
// audit.NewSinkChain rejects keys shorter than audit.MinKeyLength (32),
// so test fixtures must hit at least that length.
func testHMACKey() []byte { return bytes.Repeat([]byte("a"), 32) }

// nopDialer satisfies validate()'s Dialer-required check without
// actually dialing — Dial returns an error so the bg run loop loops
// in dial-fail backoff. Tests that need real bg progress should
// substitute testserver.DialerFor (we keep that wiring out of this
// package to avoid importing testserver into a unit-test surface).
func nopDialer() transport.Dialer {
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		return nil, errors.New("nopDialer: no conn")
	})
}

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
		Dialer:          nopDialer(),
	}
}

// closeStore is a defer-friendly Close helper. Callers don't need a
// ctx because Store.Close uses opts.DrainDeadline internally per the
// EventStore interface.
func closeStore(t *testing.T, s *watchtower.Store) {
	t.Helper()
	if err := s.Close(); err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		// Close's internal bounded wait surfaces context.Canceled
		// when the bg loop exits via runCancel — that's the normal
		// shutdown path with the nopDialer. Tests with a real
		// dialer should see a clean nil here.
		_ = err
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
// permissive path. Cleans up the resulting Store via closeStore so
// the bg run loop exits before the test goroutine returns.
func TestNew_AcceptsSinkChainOverrideWhenAllowed(t *testing.T) {
	innerChain, err := audit.NewSinkChain(testHMACKey(), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	override := chain.NewWatchtowerSink(innerChain)
	opts := validOpts(t.TempDir())
	opts.SinkChainOverrideForTests = override
	opts.AllowSinkChainOverrideForTests = true
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected New to accept SinkChainOverrideForTests when AllowSinkChainOverrideForTests is true, got %v", err)
	}
	closeStore(t, s)
}

// TestNew_NilDialerUsesProductionDialer verifies that omitting opts.Dialer
// causes New to wire the production gRPC dialer (Task 27) rather than
// returning an error. The store opens successfully — the dialer only fires
// when Transport's background goroutine tries to connect.
//
// (This test replaces the pre-Task-27 TestNew_RejectsMissingDialer that
// verified the old placeholder-rejection guard.)
func TestNew_NilDialerUsesProductionDialer(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.Dialer = nil
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected New to succeed with nil Dialer (production dialer should be wired): %v", err)
	}
	closeStore(t, s)
}

// TestNew_RejectsCancelledSetupCtx verifies the ctx-already-cancelled
// guard. A caller passing an already-cancelled setup ctx has made a
// configuration mistake; surface it instead of allocating a bg
// goroutine that will exit immediately.
func TestNew_RejectsCancelledSetupCtx(t *testing.T) {
	opts := validOpts(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := watchtower.New(ctx, opts)
	if err == nil {
		t.Fatal("expected New to reject already-cancelled setup ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNew_RejectsNonPositiveBatchMaxAge verifies validate rejects a
// negative BatchMaxAge before the bg goroutine reaches time.NewTicker
// (which panics on non-positive durations).
//
// Zero is NOT tested here because Options' documented zero-value
// contract is "use the default" — applyDefaults rewrites zero to
// 100ms before validate runs. TestNew_ZeroBatchMaxAgeAppliesDefault
// covers the zero-as-default path.
func TestNew_RejectsNonPositiveBatchMaxAge(t *testing.T) {
	for _, d := range []time.Duration{-time.Second, -1} {
		t.Run(d.String(), func(t *testing.T) {
			opts := validOpts(t.TempDir())
			opts.BatchMaxAge = d
			_, err := watchtower.New(context.Background(), opts)
			if err == nil {
				t.Fatalf("expected validate to reject BatchMaxAge=%v", d)
			}
			if !strings.Contains(err.Error(), "BatchMaxAge") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestNew_ZeroBatchMaxAgeAppliesDefault verifies the documented
// zero-value contract on Options: a literal zero is rewritten by
// applyDefaults BEFORE validate runs, so New succeeds. Locks in the
// "zero = use default, negative = invalid" contract documented on
// the Options docstring.
func TestNew_ZeroBatchMaxAgeAppliesDefault(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.BatchMaxAge = 0 // explicit zero — should default to 100ms
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected New to accept BatchMaxAge=0 (defaults to 100ms), got %v", err)
	}
	defer closeStore(t, s)
}

// TestNew_RejectsIncoherentTLS verifies cert-without-key (and
// vice-versa) is rejected at validate time.
func TestNew_RejectsIncoherentTLS(t *testing.T) {
	t.Run("cert_without_key", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.TLSCertFile = "/tmp/cert.pem"
		_, err := watchtower.New(context.Background(), opts)
		if err == nil {
			t.Fatal("expected validate to reject cert without key")
		}
		if !strings.Contains(err.Error(), "TLSCertFile and TLSKeyFile must be set together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("key_without_cert", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.TLSKeyFile = "/tmp/key.pem"
		_, err := watchtower.New(context.Background(), opts)
		if err == nil {
			t.Fatal("expected validate to reject key without cert")
		}
		if !strings.Contains(err.Error(), "TLSCertFile and TLSKeyFile must be set together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestStore_CloseIsIdempotent verifies Close can be called multiple
// times and returns the same error.
func TestStore_CloseIsIdempotent(t *testing.T) {
	opts := validOpts(t.TempDir())
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err1 := s.Close()
	err2 := s.Close()
	if err1 == nil && err2 != nil {
		t.Fatalf("Close idempotency broken: first=%v, second=%v", err1, err2)
	}
	if err1 != nil && err2 != err1 {
		// Both should be the same captured error.
		t.Fatalf("Close returned different errors on idempotent calls: first=%v, second=%v", err1, err2)
	}
}

// TestOptions_EmitExtendedLossReasons_DefaultsFalse verifies that the
// zero value of Options.EmitExtendedLossReasons is false, matching the
// documented opt-in default.
func TestOptions_EmitExtendedLossReasons_DefaultsFalse(t *testing.T) {
	var opts watchtower.Options
	if opts.EmitExtendedLossReasons {
		t.Fatalf("zero-value Options.EmitExtendedLossReasons should be false")
	}
}

func TestStore_ErrIsNonBlocking(t *testing.T) {
	opts := validOpts(t.TempDir())
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeStore(t, s)

	done := make(chan struct{})
	go func() {
		_ = s.Err()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Err() did not return within 500ms; expected non-blocking peek")
	}
}

// TestOptions_CompressionValidation locks in the validate() contract
// for CompressionAlgo / ZstdLevel / GzipLevel. The upstream
// internal/config validator is the primary gate; this is defense-in-
// depth for tests and direct programmatic callers that bypass config.
func TestOptions_CompressionValidation(t *testing.T) {
	t.Run("empty_algo_ok", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = ""
		s, err := watchtower.New(context.Background(), opts)
		if err != nil {
			t.Fatalf("expected New to accept empty CompressionAlgo, got: %v", err)
		}
		defer closeStore(t, s)
	})
	t.Run("none_ok", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "none"
		s, err := watchtower.New(context.Background(), opts)
		if err != nil {
			t.Fatalf("expected New to accept CompressionAlgo=none, got: %v", err)
		}
		defer closeStore(t, s)
	})
	t.Run("zstd_valid_level_ok", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "zstd"
		opts.ZstdLevel = 3
		s, err := watchtower.New(context.Background(), opts)
		if err != nil {
			t.Fatalf("expected New to accept zstd with level=3, got: %v", err)
		}
		defer closeStore(t, s)
	})
	t.Run("gzip_valid_level_ok", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "gzip"
		opts.GzipLevel = 6
		s, err := watchtower.New(context.Background(), opts)
		if err != nil {
			t.Fatalf("expected New to accept gzip with level=6, got: %v", err)
		}
		defer closeStore(t, s)
	})
	t.Run("zstd_level_too_low_rejected", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "zstd"
		opts.ZstdLevel = 0
		_, err := watchtower.New(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "ZstdLevel") {
			t.Fatalf("expected ZstdLevel error, got: %v", err)
		}
	})
	t.Run("zstd_level_too_high_rejected", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "zstd"
		opts.ZstdLevel = 23
		_, err := watchtower.New(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "ZstdLevel") {
			t.Fatalf("expected ZstdLevel error, got: %v", err)
		}
	})
	t.Run("gzip_level_too_low_rejected", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "gzip"
		opts.GzipLevel = 0
		_, err := watchtower.New(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "GzipLevel") {
			t.Fatalf("expected GzipLevel error, got: %v", err)
		}
	})
	t.Run("gzip_level_too_high_rejected", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "gzip"
		opts.GzipLevel = 10
		_, err := watchtower.New(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "GzipLevel") {
			t.Fatalf("expected GzipLevel error, got: %v", err)
		}
	})
	t.Run("unknown_algo_rejected", func(t *testing.T) {
		opts := validOpts(t.TempDir())
		opts.CompressionAlgo = "snappy"
		_, err := watchtower.New(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "CompressionAlgo") {
			t.Fatalf("expected CompressionAlgo error, got: %v", err)
		}
	})
}
