package watchtower

import (
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/eventfilter"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// Options configures a watchtower Store.
type Options struct {
	// WAL configuration.
	WALDir          string
	WALSegmentSize  int64
	WALMaxTotalSize int64

	// Mapper translates types.Event → wtpv1.CompactEvent.
	Mapper compact.Mapper

	// Allocator hands out (sequence, generation) tuples; supplied by
	// the composite store in production.
	Allocator *audit.SequenceAllocator

	// Identity. SessionID is persisted into wal.Meta on every MarkAcked
	// call; KeyFingerprint is the hex digest of the active signing key
	// and is persisted alongside SessionID. The pair is what
	// distinguishes one installation's WAL from another's — wal.Open
	// refuses to mount a Dir whose meta.json carries a mismatching
	// (SessionID, KeyFingerprint) pair (Task 14a's first-writer-wins
	// rule).
	AgentID        string
	SessionID      string
	KeyFingerprint string

	// HMAC integrity chain config.
	HMACKeyID     string
	HMACSecret    []byte
	HMACAlgorithm string // "hmac-sha256" (default) or "hmac-sha512"

	// Batch flush thresholds.
	BatchMaxRecords int
	BatchMaxBytes   int
	BatchMaxAge     time.Duration

	// Transport endpoint (Task 27 wiring).
	Endpoint    string
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSInsecure bool
	AuthBearer  string

	// Filter is the optional eventfilter.Filter applied before
	// AppendEvent reaches the chain/WAL pipeline.
	Filter *eventfilter.Filter

	// DrainDeadline bounds Close's best-effort flush.
	DrainDeadline time.Duration

	// AllowStubMapper unlocks compact.StubMapper for tests. Production
	// callers MUST leave this false; validate() rejects StubMapper
	// without it.
	AllowStubMapper bool

	// Dialer is an optional override; tests use this to inject
	// testserver.DialerFor(). Nil = production gRPC dialer (Task 27).
	Dialer transport.Dialer

	// Logger is the slog handle the Store and Transport use for
	// operator-facing diagnostics. Nil defaults to slog.Default() in
	// applyDefaults.
	Logger *slog.Logger

	// Metrics is the metrics collector wtp_* series are emitted
	// through. Nil is safe — the WTP() accessor on a nil Collector
	// returns a *WTPMetrics whose mutators are no-ops.
	Metrics *metrics.Collector

	// SinkChainOverrideForTests, when non-nil, replaces the default
	// chain.WatchtowerSink (wrapping *audit.SinkChain) constructed by
	// New. Permanent test-only seam — production callers MUST leave
	// this nil. validate() rejects a non-nil value unless
	// AllowSinkChainOverrideForTests is also true (mirroring the
	// AllowStubMapper pattern). The companion flag forces tests to
	// opt in explicitly and makes accidental production wiring a
	// startup error rather than a silent behavior change.
	//
	// API stability: these two fields are exempt from normal API-
	// stability expectations. They are test-only seams that may be
	// renamed, refactored, or replaced without notice.
	SinkChainOverrideForTests      chain.SinkChainAPI
	AllowSinkChainOverrideForTests bool
}

// applyDefaults fills zero-valued fields with the spec's defaults.
// Idempotent — safe to call more than once.
func (o *Options) applyDefaults() {
	if o.WALSegmentSize == 0 {
		o.WALSegmentSize = 256 * 1024
	}
	if o.WALMaxTotalSize == 0 {
		o.WALMaxTotalSize = 16 * 1024 * 1024
	}
	if o.BatchMaxRecords == 0 {
		o.BatchMaxRecords = 256
	}
	if o.BatchMaxBytes == 0 {
		o.BatchMaxBytes = 256 * 1024
	}
	if o.BatchMaxAge == 0 {
		o.BatchMaxAge = 100 * time.Millisecond
	}
	if o.DrainDeadline == 0 {
		o.DrainDeadline = 2 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// validate returns an error if Options is missing required fields or
// contains contradictions. Called from New AFTER applyDefaults so the
// defaulted values are visible.
func (o *Options) validate() error {
	if o.WALDir == "" {
		return errors.New("watchtower: WALDir is required")
	}
	// Mapper rejection has three branches that MUST run in this order:
	//   (1) untyped nil — `o.Mapper == nil` catches the zero interface
	//       value.
	//   (2) typed-nil pointer — a caller writing
	//       `var m *compact.StubMapper; opts.Mapper = m` produces an
	//       interface value with non-nil type and nil dynamic value.
	//       `o.Mapper == nil` returns false, so we use reflect to detect
	//       it. Detection is scoped to pointer form (reflect.Ptr +
	//       IsNil) because production Mapper implementations are struct
	//       pointers; map/slice/chan/func types implementing Mapper are
	//       pathological and not part of the contract. This branch must
	//       run BEFORE IsStubMapper so the error message points the
	//       caller at the real bug (a nil mapper) rather than the
	//       secondary issue (the stub type). Without this branch the
	//       stub-rejection in (3) would fire for *StubMapper(nil), but
	//       a non-stub typed-nil pointer would slip through and panic
	//       on the first AppendEvent.
	//   (3) test-only StubMapper — compact.IsStubMapper matches both
	//       value and pointer forms. Gated by AllowStubMapper so unit
	//       tests can opt in.
	if o.Mapper == nil {
		return errors.New("watchtower: mapper is required")
	}
	if rv := reflect.ValueOf(o.Mapper); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return errors.New("watchtower: mapper is required (got typed-nil pointer)")
	}
	if !o.AllowStubMapper && compact.IsStubMapper(o.Mapper) {
		return errors.New("watchtower: test-only StubMapper not permitted in production (set AllowStubMapper for tests)")
	}
	if o.Allocator == nil {
		return errors.New("watchtower: Allocator is required")
	}
	if o.AgentID == "" {
		return errors.New("watchtower: AgentID is required")
	}
	if o.SessionID == "" {
		return errors.New("watchtower: SessionID is required")
	}
	if o.HMACKeyID == "" {
		return errors.New("watchtower: HMACKeyID is required")
	}
	if len(o.HMACSecret) == 0 {
		return errors.New("watchtower: HMAC secret is required")
	}
	// Mirror audit.NewSinkChain's precondition so a short key is
	// rejected at watchtower-load time with a watchtower-shaped error
	// rather than as a generic audit error mid-construction. audit
	// remains the canonical source of truth — if it tightens this
	// branch must be updated to match.
	if len(o.HMACSecret) < audit.MinKeyLength {
		return fmt.Errorf("watchtower: HMAC secret too short: got %d bytes, need at least %d (mirrors audit.MinKeyLength)", len(o.HMACSecret), audit.MinKeyLength)
	}
	switch o.HMACAlgorithm {
	case "", "hmac-sha256", "hmac-sha512":
		// "" defaults inside audit.NewSinkChain to hmac-sha256.
	default:
		return fmt.Errorf("watchtower: unsupported HMACAlgorithm %q (use hmac-sha256 or hmac-sha512)", o.HMACAlgorithm)
	}
	if o.BatchMaxBytes < 4096 {
		return errors.New("watchtower: BatchMaxBytes must be >= 4 KiB")
	}
	if o.BatchMaxRecords <= 0 {
		return errors.New("watchtower: BatchMaxRecords must be > 0")
	}
	if o.BatchMaxAge <= 0 {
		// time.NewTicker panics on a zero or negative duration; reject
		// here so the failure mode is a clear validate() error rather
		// than a panic deep inside runLive.
		return errors.New("watchtower: BatchMaxAge must be > 0")
	}
	if o.WALSegmentSize <= 0 {
		return errors.New("watchtower: WALSegmentSize must be > 0")
	}
	if o.WALMaxTotalSize <= 0 {
		return errors.New("watchtower: WALMaxTotalSize must be > 0")
	}
	if o.WALSegmentSize > o.WALMaxTotalSize/2 {
		return errors.New("watchtower: WALSegmentSize must be <= WALMaxTotalSize/2")
	}
	if o.DrainDeadline < 0 {
		return errors.New("watchtower: DrainDeadline must be >= 0")
	}
	if o.TLSCertFile != "" && o.AuthBearer != "" {
		return errors.New("watchtower: TLS client cert and bearer auth are mutually exclusive")
	}
	// TLS coherence: cert and key are paired — one without the other
	// is a configuration mistake. Surface here so the dialer (Task 27)
	// can assume they always arrive together.
	if (o.TLSCertFile == "") != (o.TLSKeyFile == "") {
		return errors.New("watchtower: TLSCertFile and TLSKeyFile must be set together")
	}
	if o.SinkChainOverrideForTests != nil && !o.AllowSinkChainOverrideForTests {
		return errors.New("watchtower: SinkChainOverrideForTests must be nil in production (set AllowSinkChainOverrideForTests in tests that need the seam)")
	}
	return nil
}
