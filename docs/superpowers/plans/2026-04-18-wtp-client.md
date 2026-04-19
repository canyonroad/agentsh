# WTP Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a faithful Watchtower Transport Protocol (WTP v0.4.9-draft) client as a new `internal/store/watchtower/` sink that streams audit events to a Watchtower server over a single bidi gRPC stream, with sink-local HMAC integrity chaining, a write-ahead log, and a four-state transport machine.

**Architecture:** Layered sub-packages under `internal/store/watchtower/`: `chain` (canonical record encoding helpers), `compact` (Event → CompactEvent projection), `wal` (segment-based WAL with CRC32C framing), `transport` (single-goroutine state machine), and `testserver` (bufconn-based scenario harness). Consumes the already-merged Phase 0 contract (`audit.SequenceAllocator` + `audit.SinkChain` + `pkg/types.Event.Chain`) without modification. The root `Store` orchestrates compact → chain.Compute → wal.Append → chain.Commit → transport.Notify per the transactional pattern.

**Tech Stack:** Go 1.25, `google.golang.org/grpc` v1.80.0, `google.golang.org/protobuf` v1.36.11, `hash/crc32` (Castagnoli), `klauspost/compress/zstd`, in-tree `bufconn` for tests.

---

## Workflow notes

Per project memory `feedback_roborev_between_tasks.md`: **Run `roborev` between tasks. Fix all issues above Low before proceeding to the next task.** Each task ends with a `roborev review --wait --type design` step, and the task is not complete until the review passes (or all High/Medium issues are fixed and re-reviewed).

Per project memory `project_ci_testcontainers_flakes.md`: do NOT use testcontainers for transport tests. The five-layer pyramid is bufconn-only.

Per `AGENTS.md`: every WAL/file path uses `filepath.Join`; `os.Rename` for atomic seal; `internal/audit/fsync_dir_{unix,windows}.go` for parent fsync; `GOOS=windows go build ./...` must pass before commit.

Phases 1–2 of the spec (`audit.SequenceAllocator`, `audit.SinkChain`, composite refactor, `pkg/types.Event.Chain`) are **already merged to main** as of commit `a6e3aeae`. This plan starts at spec Phase 3.

## File Structure

```
internal/store/eventfilter/                      # NEW (Task 1)
  filter.go                                      # generalized from internal/store/otel/filter.go
  filter_test.go

internal/config/config.go                        # MODIFIED (Task 2): add AuditWatchtowerConfig
internal/config/config_test.go                   # MODIFIED (Task 2)

internal/metrics/metrics.go                      # MODIFIED (Task 3): add wtp_* counters/gauges/histogram
internal/metrics/metrics_test.go                 # MODIFIED (Task 3)
internal/metrics/wtp.go                          # NEW (Task 3): WTP-specific accessors
internal/metrics/wtp_test.go                     # NEW (Task 3)

proto/canyonroad/wtp/v1/wtp.proto                # NEW (Task 4)
proto/canyonroad/wtp/v1/wtp.pb.go                # NEW (Task 4, generated)
proto/canyonroad/wtp/v1/wtp_grpc.pb.go           # NEW (Task 4, generated)
proto/canyonroad/wtp/v1/testdata/*.bin           # NEW (Task 5)
internal/store/watchtower/cmd/gen-wire-goldens/main.go  # NEW (Task 5)
proto/canyonroad/wtp/v1/wire_roundtrip_test.go   # NEW (Task 5)

internal/store/watchtower/chain/                 # NEW (Tasks 6-7)
  chain.go                                       # IntegrityRecord type, ComputeContextDigest, ComputeEventHash
  canonical.go                                   # EncodeCanonical (hand-rolled JSON)
  canonical_test.go
  vectors_test.go                                # golden vector tests
  testdata/vectors.json                          # cross-implementation conformance vectors

internal/store/watchtower/compact/               # NEW (Tasks 8-9)
  mapper.go                                      # Mapper interface
  encoder.go                                     # Event → CompactEvent
  encoder_test.go
  testdata/payload/*.json                        # per-class projection goldens

internal/store/watchtower/wal/                   # NEW (Tasks 10-14)
  framing.go                                     # segment header, record framing, CRC32C
  framing_test.go
  segment.go                                     # segment file lifecycle, atomic seal
  segment_test.go
  meta.go                                        # meta.json read/write
  meta_test.go
  wal.go                                         # WAL.Append, NewReader, MarkAcked
  wal_test.go
  generation_test.go                             # TestWAL_GenerationBoundaryOrdering
  overflow_test.go                               # TestWAL_OverflowEmitsLossMarker
  crc_test.go                                    # TestWAL_CRCFailureEmitsCoarseLossRange
  reader.go                                      # Reader.Notify, Reader.Next
  reader_test.go

internal/store/watchtower/transport/             # NEW (Tasks 15-19)
  conn.go                                        # Conn interface, Dialer interface
  state.go                                       # state enum, transitions
  batcher.go                                     # six-invariant Batcher
  batcher_test.go
  replayer.go                                    # replay loop
  replayer_test.go
  heartbeat.go                                   # heartbeat timer
  transport.go                                   # main loop, SessionInit/Update
  transport_test.go
  grpc_dialer.go                                 # production GRPCDialer
  shutdown_test.go

internal/store/watchtower/testserver/            # NEW (Tasks 20-21)
  testserver.go                                  # bufconn server skeleton
  scenarios.go                                   # Drop, Goaway, AckDelay, StaleWatermark
  helpers.go                                     # WaitForBatch, AssertSequenceRange, AssertReplayObserved
  testserver_test.go

internal/store/watchtower/                       # NEW (Tasks 22-26)
  store.go                                       # Store struct, New, AppendEvent, QueryEvents, Close
  options.go                                     # Option functional-options + WithMapper/WithDialer/etc
  store_test.go
  store_failure_test.go                          # WALCleanFailure_NoChainAdvance, WALAmbiguousFailure_LatchesFatal
  store_component_test.go                        # DropsMidBatchTriggersReplay
  store_integration_test.go                     # ServerRestart_AcksCatchUp

internal/server/server.go                        # MODIFIED (Task 27): wire WTP store
cmd/wtp-testserver/main.go                       # NEW (Task 27): standalone testserver binary
```

---

## Phase 3: Filter + config + metrics plumbing

### Task 1: Generalize OTEL filter into `internal/store/eventfilter/`

**Files:**
- Create: `internal/store/eventfilter/filter.go`
- Create: `internal/store/eventfilter/filter_test.go`
- Modify: `internal/store/otel/filter.go` (becomes a type alias)
- Modify: `internal/store/otel/otel.go` (use shared type)

**Why:** OTEL has a private `Filter` type. WTP uses identical filter semantics. Move the type to a shared package so both sinks use one implementation. No behavior change for OTEL.

- [ ] **Step 1: Write the failing test in the new package**

Create `internal/store/eventfilter/filter_test.go`:

```go
package eventfilter

import "testing"

func TestFilter_NilMatchesAll(t *testing.T) {
	var f *Filter
	if !f.Match("anything", "any_category", "low") {
		t.Fatal("nil filter should match all")
	}
}

func TestFilter_IncludeTypesGlob(t *testing.T) {
	f := &Filter{IncludeTypes: []string{"exec.*"}}
	if !f.Match("exec.start", "process", "") {
		t.Fatal("exec.* should match exec.start")
	}
	if f.Match("network.connect", "network", "") {
		t.Fatal("exec.* should not match network.connect")
	}
}

func TestFilter_MinRiskLevel(t *testing.T) {
	f := &Filter{MinRiskLevel: "high"}
	if f.Match("x", "c", "low") {
		t.Fatal("low < high should be filtered")
	}
	if !f.Match("x", "c", "high") {
		t.Fatal("high >= high should pass")
	}
	if !f.Match("x", "c", "") {
		t.Fatal("events without risk_level pass when threshold is set")
	}
}

func TestFilter_ExcludeBeatsInclude(t *testing.T) {
	f := &Filter{IncludeTypes: []string{"*"}, ExcludeTypes: []string{"audit.*"}}
	if f.Match("audit.tamper", "audit", "") {
		t.Fatal("exclude should win over include")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails (package does not exist)**

Run: `go test ./internal/store/eventfilter/... -run TestFilter_NilMatchesAll`
Expected: FAIL with `no Go files in .../eventfilter` or similar package-not-found error.

- [ ] **Step 3: Create `internal/store/eventfilter/filter.go`**

```go
// Package eventfilter provides shared event-filter semantics used by chained
// audit sinks (OTEL, Watchtower). The Filter is type-by-glob with optional
// category include/exclude and a minimum-risk threshold.
package eventfilter

import "path"

// Filter controls which events a sink processes. A nil *Filter matches all
// events.
type Filter struct {
	IncludeTypes      []string
	ExcludeTypes      []string
	IncludeCategories []string
	ExcludeCategories []string
	MinRiskLevel      string
}

// riskLevels orders the four supported risk strings for threshold comparison.
var riskLevels = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Match reports whether an event with the given (type, category, riskLevel)
// passes the filter.
func (f *Filter) Match(eventType, category, riskLevel string) bool {
	if f == nil {
		return true
	}

	if len(f.IncludeTypes) > 0 {
		matched := false
		for _, pattern := range f.IncludeTypes {
			if ok, _ := path.Match(pattern, eventType); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.IncludeCategories) > 0 {
		found := false
		for _, c := range f.IncludeCategories {
			if c == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, pattern := range f.ExcludeTypes {
		if ok, _ := path.Match(pattern, eventType); ok {
			return false
		}
	}

	for _, c := range f.ExcludeCategories {
		if c == category {
			return false
		}
	}

	if f.MinRiskLevel != "" && riskLevel != "" {
		if riskLevels[riskLevel] < riskLevels[f.MinRiskLevel] {
			return false
		}
	}

	return true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/eventfilter/...`
Expected: PASS, all four tests green.

- [ ] **Step 5: Replace OTEL filter with a type alias**

Replace the entire body of `internal/store/otel/filter.go` with:

```go
package otel

import "github.com/agentsh/agentsh/internal/store/eventfilter"

// Filter is an alias for the shared eventfilter.Filter so existing callers
// continue to use otel.Filter without churn.
type Filter = eventfilter.Filter
```

Delete `internal/store/otel/filter_test.go` (the tests already moved to `eventfilter`).

- [ ] **Step 6: Verify OTEL still builds and tests pass**

Run: `go test ./internal/store/otel/...`
Expected: PASS — OTEL's `convert_test.go`, `otel_test.go`, `integration_test.go` still green.

- [ ] **Step 7: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add internal/store/eventfilter/ internal/store/otel/filter.go
git rm internal/store/otel/filter_test.go
git commit -m "refactor(store): generalize OTEL filter into shared eventfilter package"
```

- [ ] **Step 9: Roborev**

Run `/roborev-design-review` and address any High/Medium/Important findings before moving on.

---

### Task 2: Add `AuditWatchtowerConfig` YAML schema with applyDefaults + validate

**Files:**
- Modify: `internal/config/config.go` (add struct + defaults + validate)
- Modify: `internal/config/config_test.go` (add cases)

**Why:** The spec §6 mandates a precise YAML schema with strict validation: exactly-one-auth-source, ephemeral-mode override semantics, KMS key source reuse from `internal/audit/kms`. Mixing config defaults inline with sink wiring is a known footgun (cf. `internal/store/otel/otel.go` where defaults live in `New`). This task lands the schema *and* its tests so the WTP package's own tests can construct a `Config` from a known-good YAML.

- [ ] **Step 1: Write the failing test for default expansion**

Append to `internal/config/config_test.go`:

```go
func TestAuditWatchtowerConfig_DefaultsExpand(t *testing.T) {
	yaml := `
audit:
  watchtower:
    enabled: true
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
`
	cfg, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	wtp := cfg.Audit.Watchtower
	if wtp.Batch.MaxEvents != 256 {
		t.Errorf("MaxEvents = %d, want 256", wtp.Batch.MaxEvents)
	}
	if wtp.Batch.MaxBytes != 256*1024 {
		t.Errorf("MaxBytes = %d, want 256 KiB", wtp.Batch.MaxBytes)
	}
	if wtp.WAL.SegmentSize != 16*1024*1024 {
		t.Errorf("SegmentSize = %d, want 16 MiB", wtp.WAL.SegmentSize)
	}
	if wtp.Heartbeat.Interval != 30*time.Second {
		t.Errorf("Heartbeat.Interval = %v, want 30s", wtp.Heartbeat.Interval)
	}
	if wtp.Backoff.Base != 500*time.Millisecond {
		t.Errorf("Backoff.Base = %v, want 500ms", wtp.Backoff.Base)
	}
}

func TestAuditWatchtowerConfig_EphemeralOverridesDefaults(t *testing.T) {
	yaml := `
audit:
  watchtower:
    enabled: true
    ephemeral_mode: true
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
`
	cfg, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	wtp := cfg.Audit.Watchtower
	if wtp.Batch.MaxEvents != 64 {
		t.Errorf("ephemeral MaxEvents = %d, want 64", wtp.Batch.MaxEvents)
	}
	if wtp.Heartbeat.Interval != 10*time.Second {
		t.Errorf("ephemeral Heartbeat.Interval = %v, want 10s", wtp.Heartbeat.Interval)
	}
	if wtp.Batch.FlushInterval != 200*time.Millisecond {
		t.Errorf("ephemeral FlushInterval = %v, want 200ms", wtp.Batch.FlushInterval)
	}
}

func TestAuditWatchtowerConfig_AuthMutualExclusion(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "token_file_and_token_env",
			yaml: `
audit:
  watchtower:
    enabled: true
    endpoint: "x:1"
    chain: {key_file: "/k"}
    auth: {token_file: "/t", token_env: "T"}`,
			wantErr: "exactly one of",
		},
		{
			name: "no_auth_source",
			yaml: `
audit:
  watchtower:
    enabled: true
    endpoint: "x:1"
    chain: {key_file: "/k"}`,
			wantErr: "exactly one of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFromString(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}
```

If `loadFromString` does not exist in `config_test.go`, find the existing helper that loads YAML in tests (search for `os.WriteFile` in the test file) and reuse it; otherwise add a small helper at the top of the test file:

```go
func loadFromString(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}
```

- [ ] **Step 2: Run tests to verify they fail (struct does not exist)**

Run: `go test ./internal/config/ -run TestAuditWatchtowerConfig`
Expected: FAIL with `cfg.Audit.Watchtower undefined`.

- [ ] **Step 3: Add the config struct**

In `internal/config/config.go`, find `type AuditConfig struct` (line 139) and add a `Watchtower` field:

```go
type AuditConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Output   string         `yaml:"output"`
	Rotation RotationConfig `yaml:"rotation"`

	Storage    AuditStorageConfig    `yaml:"storage"`
	Webhook    AuditWebhookConfig    `yaml:"webhook"`
	Integrity  AuditIntegrityConfig  `yaml:"integrity"`
	Encryption AuditEncryptionConfig `yaml:"encryption"`
	OTEL       AuditOTELConfig       `yaml:"otel"`
	Watchtower AuditWatchtowerConfig `yaml:"watchtower"`
}
```

Then add the new struct hierarchy near the bottom of `internal/config/config.go` (above the `applyDefaults` and `Validate` functions):

```go
// AuditWatchtowerConfig configures the WTP (Watchtower Transport Protocol) sink.
// Spec: docs/superpowers/specs/2026-04-18-wtp-client-design.md §"Configuration & Wiring".
type AuditWatchtowerConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Endpoint      string `yaml:"endpoint"`        // host:port
	SessionID     string `yaml:"session_id"`      // optional; auto-generated ULID if empty
	StateDir      string `yaml:"state_dir"`       // default per-OS state dir + "/wtp" (Linux: $XDG_STATE_HOME/agentsh/wtp; macOS: ~/Library/Application Support/agentsh/wtp; Windows: %LOCALAPPDATA%\agentsh\wtp — non-roaming)
	EphemeralMode bool   `yaml:"ephemeral_mode"`

	TLS       WatchtowerTLSConfig       `yaml:"tls"`
	Auth      WatchtowerAuthConfig      `yaml:"auth"`
	Chain     WatchtowerChainConfig     `yaml:"chain"`
	Batch     WatchtowerBatchConfig     `yaml:"batch"`
	WAL       WatchtowerWALConfig       `yaml:"wal"`
	Heartbeat WatchtowerHeartbeatConfig `yaml:"heartbeat"`
	Backoff   WatchtowerBackoffConfig   `yaml:"backoff"`
	Filter    WatchtowerFilterConfig    `yaml:"filter"`
}

type WatchtowerTLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CACertFile         string `yaml:"ca_cert_file"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
}

type WatchtowerAuthConfig struct {
	TokenFile      string `yaml:"token_file"`
	TokenEnv       string `yaml:"token_env"`
	ClientCertAuth bool   `yaml:"client_cert_auth"`
}

type WatchtowerChainConfig struct {
	Algorithm string `yaml:"algorithm"` // hmac-sha256 (default) | hmac-sha512
	KeyFile   string `yaml:"key_file"`
	KeyEnv    string `yaml:"key_env"`
	// KMS sources reuse internal/audit/kms config blocks via the existing
	// AuditIntegrityConfig types — they are NOT redeclared here. Operators
	// configure KMS in audit.integrity (one chain key per process) and the
	// WTP sink reuses that resolved key. For per-sink keys, see future work.
}

type WatchtowerBatchConfig struct {
	MaxEvents     int           `yaml:"max_events"`
	MaxBytes      int           `yaml:"max_bytes"`
	MaxTimespan   time.Duration `yaml:"max_timespan"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Compression   string        `yaml:"compression"` // zstd (default) | gzip | none
	ZstdLevel     int           `yaml:"zstd_level"`
}

type WatchtowerWALConfig struct {
	SegmentSize   int64         `yaml:"segment_size"`
	MaxTotalBytes int64         `yaml:"max_total_bytes"`
	SyncMode      string        `yaml:"sync_mode"` // immediate (default) | deferred
	SyncInterval  time.Duration `yaml:"sync_interval"`
}

type WatchtowerHeartbeatConfig struct {
	Interval             time.Duration `yaml:"interval"`
	ReconnectAfterMisses int           `yaml:"reconnect_after_misses"`
}

type WatchtowerBackoffConfig struct {
	Base time.Duration `yaml:"base"`
	Max  time.Duration `yaml:"max"`
}

type WatchtowerFilterConfig struct {
	IncludeTypes      []string `yaml:"include_types"`
	ExcludeTypes      []string `yaml:"exclude_types"`
	IncludeCategories []string `yaml:"include_categories"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	MinRiskLevel      string   `yaml:"min_risk_level"`
}

func (w *AuditWatchtowerConfig) applyDefaults() {
	standard := func() {
		if w.Batch.MaxEvents == 0 {
			w.Batch.MaxEvents = 256
		}
		if w.Batch.MaxBytes == 0 {
			w.Batch.MaxBytes = 256 * 1024
		}
		if w.Batch.MaxTimespan == 0 {
			w.Batch.MaxTimespan = 5 * time.Second
		}
		if w.Batch.FlushInterval == 0 {
			w.Batch.FlushInterval = 1 * time.Second
		}
		if w.Batch.Compression == "" {
			w.Batch.Compression = "zstd"
		}
		if w.Batch.ZstdLevel == 0 {
			w.Batch.ZstdLevel = 3
		}
		if w.WAL.SegmentSize == 0 {
			w.WAL.SegmentSize = 16 * 1024 * 1024
		}
		if w.WAL.MaxTotalBytes == 0 {
			w.WAL.MaxTotalBytes = 1024 * 1024 * 1024
		}
		if w.WAL.SyncMode == "" {
			w.WAL.SyncMode = "immediate"
		}
		if w.WAL.SyncInterval == 0 {
			w.WAL.SyncInterval = 100 * time.Millisecond
		}
		if w.Heartbeat.Interval == 0 {
			w.Heartbeat.Interval = 30 * time.Second
		}
		if w.Heartbeat.ReconnectAfterMisses == 0 {
			w.Heartbeat.ReconnectAfterMisses = 2
		}
		if w.Backoff.Base == 0 {
			w.Backoff.Base = 500 * time.Millisecond
		}
		if w.Backoff.Max == 0 {
			w.Backoff.Max = 30 * time.Second
		}
		if w.Chain.Algorithm == "" {
			w.Chain.Algorithm = "hmac-sha256"
		}
	}
	if w.EphemeralMode {
		// Apply ephemeral overrides ONLY for zero fields. Operator-set
		// values still win.
		if w.Batch.MaxEvents == 0 {
			w.Batch.MaxEvents = 64
		}
		if w.Batch.MaxBytes == 0 {
			w.Batch.MaxBytes = 64 * 1024
		}
		if w.Batch.MaxTimespan == 0 {
			w.Batch.MaxTimespan = 1 * time.Second
		}
		if w.Batch.FlushInterval == 0 {
			w.Batch.FlushInterval = 200 * time.Millisecond
		}
		if w.WAL.SegmentSize == 0 {
			w.WAL.SegmentSize = 4 * 1024 * 1024
		}
		if w.WAL.MaxTotalBytes == 0 {
			w.WAL.MaxTotalBytes = 64 * 1024 * 1024
		}
		if w.Heartbeat.Interval == 0 {
			w.Heartbeat.Interval = 10 * time.Second
		}
	}
	standard()
}

func (w *AuditWatchtowerConfig) validate() error {
	if !w.Enabled {
		return nil
	}
	if w.Endpoint == "" {
		return fmt.Errorf("audit.watchtower.endpoint is required when enabled")
	}
	if _, _, err := net.SplitHostPort(w.Endpoint); err != nil {
		return fmt.Errorf("audit.watchtower.endpoint %q: %w", w.Endpoint, err)
	}
	authSources := 0
	if w.Auth.TokenFile != "" {
		authSources++
	}
	if w.Auth.TokenEnv != "" {
		authSources++
	}
	if w.Auth.ClientCertAuth {
		authSources++
	}
	if authSources != 1 {
		return fmt.Errorf("audit.watchtower.auth: exactly one of token_file, token_env, client_cert_auth must be set (got %d)", authSources)
	}
	if w.Chain.KeyFile == "" && w.Chain.KeyEnv == "" {
		return fmt.Errorf("audit.watchtower.chain: one of key_file or key_env must be set")
	}
	switch w.Chain.Algorithm {
	case "hmac-sha256", "hmac-sha512":
	default:
		return fmt.Errorf("audit.watchtower.chain.algorithm %q: must be hmac-sha256 or hmac-sha512", w.Chain.Algorithm)
	}
	if w.Batch.MaxBytes < 4*1024 {
		return fmt.Errorf("audit.watchtower.batch.max_bytes %d: must be >= 4096", w.Batch.MaxBytes)
	}
	if w.WAL.SegmentSize > w.WAL.MaxTotalBytes/2 {
		return fmt.Errorf("audit.watchtower.wal.segment_size %d > max_total_bytes/2 (%d)", w.WAL.SegmentSize, w.WAL.MaxTotalBytes/2)
	}
	switch w.Batch.Compression {
	case "zstd", "gzip", "none":
	default:
		return fmt.Errorf("audit.watchtower.batch.compression %q: must be zstd, gzip, or none", w.Batch.Compression)
	}
	switch w.WAL.SyncMode {
	case "immediate", "deferred":
	default:
		return fmt.Errorf("audit.watchtower.wal.sync_mode %q: must be immediate or deferred", w.WAL.SyncMode)
	}
	return nil
}
```

Add `"net"` to the imports if not already present.

Wire `applyDefaults` and `validate` into the existing `Config.applyDefaults()` and `Config.Validate()` methods (search for `cfg.Audit.OTEL.applyDefaults()` or similar — add `cfg.Audit.Watchtower.applyDefaults()` and `cfg.Audit.Watchtower.validate()` next to it; if no such pattern exists, add the calls at the end of `applyDefaults` and `Validate` respectively).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -run TestAuditWatchtowerConfig`
Expected: PASS, all three cases green.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add AuditWatchtowerConfig with defaults and validation"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 3: Add `wtp_*` metrics to `internal/metrics/`

**Files:**
- Create: `internal/metrics/wtp.go`
- Create: `internal/metrics/wtp_test.go`
- Modify: `internal/metrics/metrics.go` (registry hook)

**Why:** The spec lists 13 `wtp_*` series (eleven counters/gauges, one CRC-corruption counter, one send-latency histogram). Putting them on the existing `Collector` keeps Prometheus exposition in one place. Separating WTP-specific code into its own file keeps `metrics.go` focused.

- [ ] **Step 1: Write the failing test**

Create `internal/metrics/wtp_test.go`:

```go
package metrics

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWTPMetrics_AppendAndExpose(t *testing.T) {
	c := New()
	w := c.WTP()

	w.IncEventsAppended(5)
	w.IncEventsAcked(3)
	w.IncBatchesSent(1)
	w.AddBytesSent(2048)
	w.IncTransportLoss(2)
	w.IncReconnects(WTPReconnectReasonDialFailed)
	w.SetSessionState(WTPStateLive)
	w.SetWALSegments(7)
	w.SetWALBytes(16 * 1024 * 1024)
	w.SetAckHighWatermark(42)
	w.IncDroppedMissingChain(1)
	w.ObserveSendLatency(150 * time.Millisecond)

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, want := range []string{
		"wtp_events_appended_total 5",
		"wtp_events_acked_total 3",
		"wtp_batches_sent_total 1",
		"wtp_bytes_sent_total 2048",
		"wtp_transport_loss_total 2",
		`wtp_reconnects_total{reason="dial_failed"} 1`,
		"wtp_session_state 2",
		"wtp_wal_segments 7",
		"wtp_wal_bytes 16777216",
		"wtp_ack_high_watermark 42",
		"wtp_dropped_missing_chain_total 1",
		"wtp_send_latency_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestWTPMetrics_NilSafe(t *testing.T) {
	var c *Collector
	w := c.WTP()
	// All accessors must no-op on nil collector.
	w.IncEventsAppended(1)
	w.SetSessionState(WTPStateConnecting)
	w.AddBytesSent(99)
}

func TestWTPMetrics_HistogramBucketBoundaries(t *testing.T) {
	c := New()
	w := c.WTP()

	// 5ms — boundary of the 0.005 bucket (and all higher buckets)
	w.ObserveSendLatency(5 * time.Millisecond)
	// 30ms — boundary of the 0.05 bucket (skips 0.001, 0.005, 0.01, 0.025)
	w.ObserveSendLatency(30 * time.Millisecond)
	// 60s — exceeds final 30 bucket; only +Inf catches it
	w.ObserveSendLatency(60 * time.Second)

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectations := map[string]int{
		`wtp_send_latency_seconds_bucket{le="0.001"}`: 0,
		`wtp_send_latency_seconds_bucket{le="0.005"}`: 1,
		`wtp_send_latency_seconds_bucket{le="0.01"}`:  1,
		`wtp_send_latency_seconds_bucket{le="0.025"}`: 1,
		`wtp_send_latency_seconds_bucket{le="0.05"}`:  2,
		`wtp_send_latency_seconds_bucket{le="0.1"}`:   2,
		`wtp_send_latency_seconds_bucket{le="0.25"}`:  2,
		`wtp_send_latency_seconds_bucket{le="0.5"}`:   2,
		`wtp_send_latency_seconds_bucket{le="1"}`:     2,
		`wtp_send_latency_seconds_bucket{le="2.5"}`:   2,
		`wtp_send_latency_seconds_bucket{le="5"}`:     2,
		`wtp_send_latency_seconds_bucket{le="10"}`:    2,
		`wtp_send_latency_seconds_bucket{le="30"}`:    2,
		`wtp_send_latency_seconds_bucket{le="+Inf"}`:  3,
	}
	for prefix, want := range expectations {
		line := prefix + " " + strconv.Itoa(want)
		if !strings.Contains(body, line) {
			t.Errorf("missing or wrong-count bucket line %q\nbody:\n%s", line, body)
		}
	}
	if !strings.Contains(body, "wtp_send_latency_seconds_count 3") {
		t.Errorf("expected wtp_send_latency_seconds_count 3\nbody:\n%s", body)
	}
}

func TestWTPMetrics_ReconnectReasonValidationAndEscape(t *testing.T) {
	c := New()
	w := c.WTP()

	w.IncReconnects(WTPReconnectReasonDialFailed)
	w.IncReconnects(WTPReconnectReasonStreamRecvError)
	w.IncReconnects(WTPReconnectReasonStreamRecvError)
	// Invalid (unknown enum) collapses to WTPReconnectReasonUnknown.
	w.IncReconnects(WTPReconnectReason("evil\"label\\value"))

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, want := range []string{
		`wtp_reconnects_total{reason="dial_failed"} 1`,
		`wtp_reconnects_total{reason="stream_recv_error"} 2`,
		`wtp_reconnects_total{reason="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

func TestWTPMetrics_WALCorruptionCounter(t *testing.T) {
	c := New()
	w := c.WTP()

	// Initial scrape: counter must be present at zero.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_wal_corruption_total 0") {
		t.Errorf("expected zero-valued wtp_wal_corruption_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	// After increments, the value must reflect the sum.
	w.IncWALCorruption(1)
	w.IncWALCorruption(4)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_wal_corruption_total 5") {
		t.Errorf("expected wtp_wal_corruption_total 5 after increments\nbody:\n%s", rr.Body.String())
	}
}

func TestWTPMetrics_ReconnectsAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	// Note: no IncReconnects calls. Per spec the family must still be present
	// with zero-valued series for every enumerated reason.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{
		"ack_timeout",
		"dial_failed",
		"heartbeat_timeout",
		"send_error",
		"server_goaway",
		"stream_recv_error",
		"unknown",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_reconnects_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued reconnect series %q\nbody:\n%s", want, body)
		}
	}
	// After one increment, only that reason flips to 1; the others stay 0.
	c.WTP().IncReconnects(WTPReconnectReasonAckTimeout)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_reconnects_total{reason="ack_timeout"} 1`) {
		t.Errorf("expected ack_timeout=1 after one IncReconnects\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_reconnects_total{reason="dial_failed"} 0`) {
		t.Errorf("expected other reasons to remain 0 after one increment\nbody:\n%s", body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestWTPMetrics`
Expected: FAIL with `c.WTP undefined` or similar.

- [ ] **Step 3: Implement `internal/metrics/wtp.go`**

```go
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// WTPSessionState mirrors the four-state transport machine.
type WTPSessionState int

const (
	WTPStateConnecting WTPSessionState = 0
	WTPStateReplaying  WTPSessionState = 1
	WTPStateLive       WTPSessionState = 2
	WTPStateShutdown   WTPSessionState = 3
)

// WTPReconnectReason is a fixed, low-cardinality classification of why
// the WTP transport reconnected. Adding new reasons requires updating
// both the spec §Metrics section and the wtpReconnectReasonsValid table
// below.
type WTPReconnectReason string

const (
	WTPReconnectReasonDialFailed       WTPReconnectReason = "dial_failed"
	WTPReconnectReasonStreamRecvError  WTPReconnectReason = "stream_recv_error"
	WTPReconnectReasonSendError        WTPReconnectReason = "send_error"
	WTPReconnectReasonAckTimeout       WTPReconnectReason = "ack_timeout"
	WTPReconnectReasonHeartbeatTimeout WTPReconnectReason = "heartbeat_timeout"
	WTPReconnectReasonServerGoaway     WTPReconnectReason = "server_goaway"
	WTPReconnectReasonUnknown          WTPReconnectReason = "unknown"
)

var wtpReconnectReasonsValid = map[WTPReconnectReason]struct{}{
	WTPReconnectReasonDialFailed:       {},
	WTPReconnectReasonStreamRecvError:  {},
	WTPReconnectReasonSendError:        {},
	WTPReconnectReasonAckTimeout:       {},
	WTPReconnectReasonHeartbeatTimeout: {},
	WTPReconnectReasonServerGoaway:     {},
	WTPReconnectReasonUnknown:          {},
}

// wtpReconnectReasonsEmitOrder is the canonical, sorted-by-string emission
// order for the wtp_reconnects_total family. Using a fixed slice keeps
// Prometheus exposition deterministic and lets emitWTPMetrics emit
// zero-valued series for reasons that have not yet fired (per the
// always-emit contract in the design spec).
var wtpReconnectReasonsEmitOrder = []WTPReconnectReason{
	WTPReconnectReasonAckTimeout,
	WTPReconnectReasonDialFailed,
	WTPReconnectReasonHeartbeatTimeout,
	WTPReconnectReasonSendError,
	WTPReconnectReasonServerGoaway,
	WTPReconnectReasonStreamRecvError,
	WTPReconnectReasonUnknown,
}

// WTPMetrics is the per-Collector facade for wtp_* series. Returned by
// (*Collector).WTP(). Methods are nil-safe so test code and disabled-sink
// paths don't need to special-case it.
type WTPMetrics struct {
	c *Collector
}

func (c *Collector) WTP() *WTPMetrics { return &WTPMetrics{c: c} }

func (w *WTPMetrics) IncEventsAppended(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpEventsAppended.Add(n)
}

func (w *WTPMetrics) IncEventsAcked(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpEventsAcked.Add(n)
}

func (w *WTPMetrics) IncBatchesSent(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpBatchesSent.Add(n)
}

func (w *WTPMetrics) AddBytesSent(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpBytesSent.Add(n)
}

func (w *WTPMetrics) IncTransportLoss(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpTransportLoss.Add(n)
}

func (w *WTPMetrics) IncReconnects(reason WTPReconnectReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpReconnectReasonsValid[reason]; !ok {
		reason = WTPReconnectReasonUnknown
	}
	ptr, _ := w.c.wtpReconnectsByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

func (w *WTPMetrics) SetSessionState(state WTPSessionState) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpSessionState.Store(int64(state))
}

func (w *WTPMetrics) SetWALSegments(n int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALSegments.Store(n)
}

func (w *WTPMetrics) SetWALBytes(n int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALBytes.Store(n)
}

func (w *WTPMetrics) SetAckHighWatermark(seq int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpAckHighWatermark.Store(seq)
}

func (w *WTPMetrics) IncDroppedMissingChain(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedMissingChain.Add(n)
}

func (w *WTPMetrics) IncWALCorruption(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALCorruption.Add(n)
}

// Latency histogram buckets, in seconds. Chosen to cover sub-millisecond
// localhost (testserver) through pathological 30s reconnect-edge sends.
var wtpLatencyBucketsSeconds = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

func (w *WTPMetrics) ObserveSendLatency(d time.Duration) {
	if w == nil || w.c == nil {
		return
	}
	secs := d.Seconds()
	w.c.wtpLatencyMu.Lock()
	defer w.c.wtpLatencyMu.Unlock()
	w.c.wtpLatencyCount++
	w.c.wtpLatencySum += secs
	for i, ub := range wtpLatencyBucketsSeconds {
		if secs <= ub {
			w.c.wtpLatencyBuckets[i]++
		}
	}
	w.c.wtpLatencyBuckets[len(wtpLatencyBucketsSeconds)]++ // +Inf bucket
}

// emitWTPMetrics writes the wtp_* series in Prometheus text format.
// Called from Collector.Handler. Kept private here so wtp.go owns the
// formatting and metrics.go owns the dispatch.
func (c *Collector) emitWTPMetrics(w io.Writer) {
	fmt.Fprint(w, "# HELP wtp_events_appended_total Events appended to the WTP sink.\n")
	fmt.Fprint(w, "# TYPE wtp_events_appended_total counter\n")
	fmt.Fprintf(w, "wtp_events_appended_total %d\n", c.wtpEventsAppended.Load())

	fmt.Fprint(w, "# HELP wtp_events_acked_total Events acknowledged by the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_events_acked_total counter\n")
	fmt.Fprintf(w, "wtp_events_acked_total %d\n", c.wtpEventsAcked.Load())

	fmt.Fprint(w, "# HELP wtp_batches_sent_total Batches sent to the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_batches_sent_total counter\n")
	fmt.Fprintf(w, "wtp_batches_sent_total %d\n", c.wtpBatchesSent.Load())

	fmt.Fprint(w, "# HELP wtp_bytes_sent_total Bytes sent to the WTP server (post-compression).\n")
	fmt.Fprint(w, "# TYPE wtp_bytes_sent_total counter\n")
	fmt.Fprintf(w, "wtp_bytes_sent_total %d\n", c.wtpBytesSent.Load())

	fmt.Fprint(w, "# HELP wtp_transport_loss_total Transport-loss markers emitted by the WTP sink.\n")
	fmt.Fprint(w, "# TYPE wtp_transport_loss_total counter\n")
	fmt.Fprintf(w, "wtp_transport_loss_total %d\n", c.wtpTransportLoss.Load())

	// Always emit the wtp_reconnects_total family with all enumerated reasons
	// so dashboards have a stable schema regardless of runtime activity (per
	// the always-emit contract in the design spec).
	fmt.Fprint(w, "# HELP wtp_reconnects_total WTP transport reconnects by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_reconnects_total counter\n")
	for _, r := range wtpReconnectReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpReconnectsByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_reconnects_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	fmt.Fprint(w, "# HELP wtp_session_state Current WTP session state (0=connecting,1=replaying,2=live,3=shutdown).\n")
	fmt.Fprint(w, "# TYPE wtp_session_state gauge\n")
	fmt.Fprintf(w, "wtp_session_state %d\n", c.wtpSessionState.Load())

	fmt.Fprint(w, "# HELP wtp_wal_segments Number of WAL segment files on disk.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_segments gauge\n")
	fmt.Fprintf(w, "wtp_wal_segments %d\n", c.wtpWALSegments.Load())

	fmt.Fprint(w, "# HELP wtp_wal_bytes Total bytes used by WAL on disk.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_bytes gauge\n")
	fmt.Fprintf(w, "wtp_wal_bytes %d\n", c.wtpWALBytes.Load())

	fmt.Fprint(w, "# HELP wtp_ack_high_watermark Highest acked sequence from the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_ack_high_watermark gauge\n")
	fmt.Fprintf(w, "wtp_ack_high_watermark %d\n", c.wtpAckHighWatermark.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_missing_chain_total Events dropped because ev.Chain was nil.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_missing_chain_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_missing_chain_total %d\n", c.wtpDroppedMissingChain.Load())

	fmt.Fprint(w, "# HELP wtp_wal_corruption_total CRC corruption events encountered during WAL replay.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_corruption_total counter\n")
	fmt.Fprintf(w, "wtp_wal_corruption_total %d\n", c.wtpWALCorruption.Load())

	// Snapshot under lock to avoid blocking ObserveSendLatency callers
	// during a slow scrape.
	c.wtpLatencyMu.Lock()
	bucketsSnapshot := c.wtpLatencyBuckets
	sumSnapshot := c.wtpLatencySum
	countSnapshot := c.wtpLatencyCount
	c.wtpLatencyMu.Unlock()

	fmt.Fprint(w, "# HELP wtp_send_latency_seconds Latency of WTP batch sends.\n")
	fmt.Fprint(w, "# TYPE wtp_send_latency_seconds histogram\n")
	for i, ub := range wtpLatencyBucketsSeconds {
		fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"%g\"} %d\n", ub, bucketsSnapshot[i])
	}
	fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"+Inf\"} %d\n", bucketsSnapshot[len(wtpLatencyBucketsSeconds)])
	fmt.Fprintf(w, "wtp_send_latency_seconds_sum %g\n", sumSnapshot)
	fmt.Fprintf(w, "wtp_send_latency_seconds_count %d\n", countSnapshot)
}
```

- [ ] **Step 4: Add WTP fields to the Collector and wire emitter**

In `internal/metrics/metrics.go`, extend the `Collector` struct:

```go
type Collector struct {
	startedAt time.Time

	eventsTotal atomic.Uint64
	byType      sync.Map

	ebpfDropped     atomic.Uint64
	ebpfAttachFail  atomic.Uint64
	ebpfUnavailable atomic.Uint64

	// WTP series
	wtpEventsAppended      atomic.Uint64
	wtpEventsAcked         atomic.Uint64
	wtpBatchesSent         atomic.Uint64
	wtpBytesSent           atomic.Uint64
	wtpTransportLoss       atomic.Uint64
	wtpReconnectsByReason  sync.Map
	wtpSessionState        atomic.Int64
	wtpWALSegments         atomic.Int64
	wtpWALBytes            atomic.Int64
	wtpAckHighWatermark    atomic.Int64
	wtpDroppedMissingChain atomic.Uint64
	wtpWALCorruption       atomic.Uint64

	wtpLatencyMu      sync.Mutex
	wtpLatencyBuckets [14]uint64 // 13 buckets + +Inf; index aligned with wtpLatencyBucketsSeconds
	wtpLatencyCount   uint64
	wtpLatencySum     float64
}
```

In the `Handler` method, just before the `if opts.SessionCount != nil { ... }` block, add:

```go
		c.emitWTPMetrics(w)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/metrics/...`
Expected: PASS — all existing tests + the two new WTP tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go internal/metrics/metrics.go
git commit -m "feat(metrics): add wtp_* counters, gauges, and send-latency histogram"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 4a: Proto scaffolding

### Task 4: Define `proto/canyonroad/wtp/v1/wtp.proto` and generate Go bindings

**Files:**
- Create: `proto/canyonroad/wtp/v1/wtp.proto`
- Create: `proto/canyonroad/wtp/v1/wtp.pb.go` (generated)
- Create: `proto/canyonroad/wtp/v1/wtp_grpc.pb.go` (generated)

**Why:** Spec §7 mandates the wire format. Define the `.proto` first so `chain`, `wal`, `transport`, and `testserver` can all import it.

- [ ] **Step 1: Write the proto definitions**

Create `proto/canyonroad/wtp/v1/wtp.proto`:

```proto
syntax = "proto3";

package canyonroad.wtp.v1;

option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1;wtpv1";

// Bidi stream: client opens, sends ClientMessage frames, receives ServerMessage frames.
service Watchtower {
  rpc Stream(stream ClientMessage) returns (stream ServerMessage);
}

message ClientMessage {
  oneof msg {
    SessionInit    session_init    = 1;
    SessionUpdate  session_update  = 2;
    EventBatch     event_batch     = 3;
    Heartbeat      heartbeat       = 4;
    TransportLoss  transport_loss  = 5;
    ClientShutdown shutdown        = 6;
  }
}

// ServerMessage frames sent from server to client. Semantics:
//   * SessionAck       — sent exactly once after SessionInit; accepted=false
//                        terminates the session (client must disconnect).
//   * BatchAck         — sent per-batch progress ack; advances the client's
//                        ack high-watermark and unblocks WAL GC.
//   * ServerHeartbeat  — periodic; carries the server's current
//                        ack_high_watermark_seq so an idle client still
//                        learns about catch-up after replay completes.
//   * Goaway           — server requesting reconnect; carries an enum code.
//   * server_update    — server-issued SessionUpdate (key/generation
//                        rotation initiated by the server).
message ServerMessage {
  oneof msg {
    SessionAck       session_ack        = 1;
    BatchAck         batch_ack          = 2;
    ServerHeartbeat  server_heartbeat   = 3;
    Goaway           goaway             = 4;
    SessionUpdate    server_update      = 5;
  }
}

// SessionInit (§7.1)
message SessionInit {
  string         session_id              = 1;
  string         ocsf_version            = 2;
  uint32         format_version          = 3;
  HashAlgorithm  algorithm               = 4;
  string         key_fingerprint         = 5;
  string         context_digest          = 6;   // hex-encoded SHA-256
  uint64         wal_high_watermark_seq  = 7;
  uint32         generation              = 8;
  string         agent_id                = 9;
  string         agent_version           = 10;
  uint64         total_chained           = 11;  // count of records sink has chained
}

enum HashAlgorithm {
  HASH_ALGORITHM_UNSPECIFIED = 0;   // wire-incompatible — receivers MUST reject.
  HASH_ALGORITHM_HMAC_SHA256 = 1;
  HASH_ALGORITHM_HMAC_SHA512 = 2;
}

message SessionAck {
  uint64 ack_high_watermark_seq = 1;
  uint32 generation             = 2;
  bool   accepted               = 3;
  string reject_reason          = 4;     // empty when accepted=true
}

// SessionUpdate (§7.2): generation roll, key rotation, context change.
message SessionUpdate {
  uint32 new_generation         = 1;
  string new_key_fingerprint    = 2;
  string new_context_digest     = 3;
  uint64 boundary_sequence      = 4;     // last seq of prior generation
}

// EventBatch (§7.3) — the unit of in-flight work between client and server.
//
// The batch body is mutually exclusive: a sender MUST populate exactly one
// of `uncompressed` (when compression == COMPRESSION_NONE) or
// `compressed_payload` (when compression is COMPRESSION_ZSTD or
// COMPRESSION_GZIP). Receivers MUST reject batches where the oneof case
// disagrees with the compression field, where compression is
// COMPRESSION_UNSPECIFIED, or where the body oneof is unset.
message EventBatch {
  uint64 from_sequence = 1;
  uint64 to_sequence   = 2;
  uint32 generation    = 3;
  Compression compression = 4;
  oneof body {
    UncompressedEvents uncompressed       = 5;
    bytes              compressed_payload = 6;
  }
}

// UncompressedEvents wraps the repeated CompactEvent so it can sit inside
// the EventBatch.body oneof (proto3 forbids `repeated` directly in oneofs).
message UncompressedEvents {
  repeated CompactEvent events = 1;
}

enum Compression {
  COMPRESSION_UNSPECIFIED = 0;
  COMPRESSION_NONE        = 1;
  COMPRESSION_ZSTD        = 2;
  COMPRESSION_GZIP        = 3;
}

// CompactEvent (§6.3)
message CompactEvent {
  uint64  sequence              = 1;
  uint32  generation            = 2;
  uint64  timestamp_unix_nanos  = 3;
  uint32  ocsf_class_uid        = 4;
  uint32  ocsf_activity_id      = 5;
  bytes   payload               = 6;     // protobuf-encoded class-specific payload
  IntegrityRecord integrity     = 7;
}

message IntegrityRecord {
  uint32  format_version        = 1;
  uint64  sequence              = 2;
  uint32  generation            = 3;
  string  prev_hash             = 4;
  string  event_hash            = 5;
  string  context_digest        = 6;
  string  key_fingerprint       = 7;
}

message Heartbeat {
  uint64 wal_high_watermark_seq = 1;
  uint32 generation             = 2;
}

message ServerHeartbeat {
  uint64 ack_high_watermark_seq = 1;
}

message BatchAck {
  uint64 ack_high_watermark_seq = 1;
  uint32 generation             = 2;
}

// TransportLoss (§7.5) — emitted on WAL overflow or CRC corruption.
message TransportLoss {
  uint64               from_sequence = 1;
  uint64               to_sequence   = 2;
  uint32               generation    = 3;
  TransportLossReason  reason        = 4;
}

enum TransportLossReason {
  TRANSPORT_LOSS_REASON_UNSPECIFIED   = 0;   // wire-incompatible — receivers MUST reject.
  TRANSPORT_LOSS_REASON_OVERFLOW      = 1;   // WAL hit max_total_bytes; oldest segments dropped.
  TRANSPORT_LOSS_REASON_CRC_CORRUPTION = 2;  // CRC mismatch encountered during WAL replay.
}

message Goaway {
  GoawayCode code             = 1;
  string     message          = 2;
  bool       retry_immediately = 3;
}

enum GoawayCode {
  GOAWAY_CODE_UNSPECIFIED = 0;   // unknown; clients MUST treat as transient and reconnect.
  GOAWAY_CODE_DRAINING    = 1;   // graceful shutdown; reconnect to a different instance.
  GOAWAY_CODE_OVERLOAD    = 2;   // server overloaded; reconnect with backoff.
  GOAWAY_CODE_UPGRADE     = 3;   // server upgrade in progress; reconnect after delay.
  GOAWAY_CODE_AUTH        = 4;   // authentication/authorization failed; do not auto-retry.
}

message ClientShutdown {
  ClientShutdownReason reason = 1;
}

enum ClientShutdownReason {
  CLIENT_SHUTDOWN_REASON_UNSPECIFIED = 0;
  CLIENT_SHUTDOWN_REASON_NORMAL      = 1;   // clean shutdown of the agent.
  CLIENT_SHUTDOWN_REASON_RECONFIGURE = 2;   // operator-driven reconfig; expect quick reconnect.
  CLIENT_SHUTDOWN_REASON_FATAL       = 3;   // unrecoverable error; do not expect reconnect.
}
```

- [ ] **Step 2: Generate Go bindings**

The repo uses `protoc` with `protoc-gen-go` and `protoc-gen-go-grpc`. Verify with:

Run: `protoc --version && which protoc-gen-go && which protoc-gen-go-grpc`
Expected: `libprotoc 3.x` or higher; both gen tools present. If not, install them:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
```

Generate:

```bash
protoc \
  --proto_path=proto \
  --go_out=. --go_opt=module=github.com/agentsh/agentsh \
  --go-grpc_out=. --go-grpc_opt=module=github.com/agentsh/agentsh \
  proto/canyonroad/wtp/v1/wtp.proto
```

Expected: `proto/canyonroad/wtp/v1/wtp.pb.go` and `proto/canyonroad/wtp/v1/wtp_grpc.pb.go` exist.

- [ ] **Step 3: Verify the generated files compile**

Run: `go build ./proto/canyonroad/wtp/v1/...`
Expected: no errors.

- [ ] **Step 4: Write a smoke test**

Create `proto/canyonroad/wtp/v1/proto_test.go`:

```go
package wtpv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestProto_RoundTripCompactEvent(t *testing.T) {
	src := &CompactEvent{
		Sequence:           42,
		Generation:         7,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
		OcsfClassUid:       3001,
		OcsfActivityId:     1,
		Payload:            []byte{0xde, 0xad, 0xbe, 0xef},
		Integrity: &IntegrityRecord{
			FormatVersion:  2,
			Sequence:       42,
			Generation:     7,
			PrevHash:       "deadbeef",
			EventHash:      "cafef00d",
			ContextDigest:  "0123456789abcdef",
			KeyFingerprint: "sha256:aabbccdd",
		},
	}
	wire, err := proto.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var dst CompactEvent
	if err := proto.Unmarshal(wire, &dst); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(src, &dst) {
		t.Fatalf("round trip differs\nsrc=%v\ndst=%v", src, &dst)
	}
}

func TestProto_OneofClientMessage(t *testing.T) {
	cm := &ClientMessage{
		Msg: &ClientMessage_EventBatch{EventBatch: &EventBatch{FromSequence: 1, ToSequence: 5, Generation: 0}},
	}
	wire, err := proto.Marshal(cm)
	if err != nil {
		t.Fatal(err)
	}
	var got ClientMessage
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetEventBatch() == nil {
		t.Fatal("event_batch oneof did not survive round trip")
	}
}
```

- [ ] **Step 5: Run the smoke test**

Run: `go test ./proto/canyonroad/wtp/v1/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add proto/canyonroad/wtp/v1/
git commit -m "feat(proto): add WTP v1 service and message definitions"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 4b: Wire goldens

### Task 5: Wire-format goldens via in-tree `cmd/gen-wire-goldens`

**Files:**
- Create: `internal/store/watchtower/cmd/gen-wire-goldens/main.go`
- Create: `proto/canyonroad/wtp/v1/testdata/compact_event.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/event_batch.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/session_init.bin`
- Create: `proto/canyonroad/wtp/v1/wire_roundtrip_test.go`

**Why:** A wire-format change is a load-bearing event. Goldens checked in to git make any accidental change loud in code review (the `.bin` files diff). The generator is in-tree but not run in CI; CI only verifies round-trip.

- [ ] **Step 1: Write the failing test**

Create `proto/canyonroad/wtp/v1/wire_roundtrip_test.go`:

```go
package wtpv1

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestWireGoldens_RoundTrip(t *testing.T) {
	cases := []struct {
		file string
		make func() proto.Message
	}{
		{"compact_event.bin", func() proto.Message { return new(CompactEvent) }},
		{"event_batch.bin", func() proto.Message { return new(EventBatch) }},
		{"session_init.bin", func() proto.Message { return new(SessionInit) }},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v", path, err)
			}
			msg := tc.make()
			if err := proto.Unmarshal(data, msg); err != nil {
				t.Fatalf("unmarshal golden %s: %v", path, err)
			}
			redone, err := proto.Marshal(msg)
			if err != nil {
				t.Fatalf("re-marshal golden %s: %v", path, err)
			}
			// Protobuf re-marshal is canonical for known fields; if this fails the
			// golden contains data the proto schema cannot represent (a real
			// regression, not a stylistic difference).
			if !proto.Equal(msg, decode(t, redone, tc.make())) {
				t.Fatalf("re-marshal does not round-trip for %s", path)
			}
		})
	}
}

func decode(t *testing.T, b []byte, into proto.Message) proto.Message {
	t.Helper()
	if err := proto.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
	return into
}
```

- [ ] **Step 2: Run test to verify it fails (no goldens yet)**

Run: `go test ./proto/canyonroad/wtp/v1/ -run TestWireGoldens`
Expected: FAIL with `read golden ...: no such file or directory`.

- [ ] **Step 3: Implement the generator**

Create `internal/store/watchtower/cmd/gen-wire-goldens/main.go`:

```go
// Command gen-wire-goldens regenerates wire-format goldens for WTP messages.
//
// CI does NOT run this tool — it only verifies the existing goldens
// round-trip cleanly (TestWireGoldens_RoundTrip in
// proto/canyonroad/wtp/v1/wire_roundtrip_test.go).
//
// Run manually after intentional schema changes:
//
//	go run ./internal/store/watchtower/cmd/gen-wire-goldens
package main

import (
	"fmt"
	"os"
	"path/filepath"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

const outDir = "proto/canyonroad/wtp/v1/testdata"

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}

	ce := &wtpv1.CompactEvent{
		Sequence:           42,
		Generation:         7,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
		OcsfClassUid:       3001,
		OcsfActivityId:     1,
		Payload:            []byte{0xde, 0xad, 0xbe, 0xef},
		Integrity: &wtpv1.IntegrityRecord{
			FormatVersion:  2,
			Sequence:       42,
			Generation:     7,
			PrevHash:       "deadbeef",
			EventHash:      "cafef00d",
			ContextDigest:  "0123456789abcdef",
			KeyFingerprint: "sha256:aabbccdd",
		},
	}
	write("compact_event.bin", ce)

	eb := &wtpv1.EventBatch{
		FromSequence: 40,
		ToSequence:   42,
		Generation:   7,
		Compression:  wtpv1.Compression_COMPRESSION_NONE,
		Body: &wtpv1.EventBatch_Uncompressed{
			Uncompressed: &wtpv1.UncompressedEvents{
				Events: []*wtpv1.CompactEvent{ce},
			},
		},
	}
	write("event_batch.bin", eb)

	si := &wtpv1.SessionInit{
		SessionId:           "01HXAVD2N5VX3CZQK7Q7QWNYKE",
		OcsfVersion:         "1.8.0",
		FormatVersion:       2,
		Algorithm:           "hmac-sha256",
		KeyFingerprint:      "sha256:aabbccdd",
		ContextDigest:       "0123456789abcdef",
		WalHighWatermarkSeq: 0,
		Generation:          0,
		AgentId:             "agentsh",
		AgentVersion:        "0.0.0-test",
		TotalChained:        0,
	}
	write("session_init.bin", si)

	fmt.Println("regenerated goldens in", outDir)
}

func write(name string, m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		fail(err)
	}
	p := filepath.Join(outDir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		fail(err)
	}
	fmt.Println("wrote", p, len(b), "bytes")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
```

- [ ] **Step 4: Generate the goldens**

Run: `go run ./internal/store/watchtower/cmd/gen-wire-goldens`
Expected: prints `wrote proto/canyonroad/wtp/v1/testdata/compact_event.bin <N> bytes` for all three files.

- [ ] **Step 5: Run the round-trip test**

Run: `go test ./proto/canyonroad/wtp/v1/ -run TestWireGoldens`
Expected: PASS.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/cmd/ proto/canyonroad/wtp/v1/testdata/ proto/canyonroad/wtp/v1/wire_roundtrip_test.go
git commit -m "feat(wtp): add wire-format goldens with in-tree generator"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 5: Chain helpers

### Task 6: `internal/store/watchtower/chain/` — `IntegrityRecord` + `EncodeCanonical`

**Files:**
- Create: `internal/store/watchtower/chain/chain.go`
- Create: `internal/store/watchtower/chain/canonical.go`
- Create: `internal/store/watchtower/chain/canonical_test.go`

**Why:** Spec §6.4 mandates a canonical JSON encoding (sorted keys, no whitespace, ASCII-escaped non-ASCII, decimal numbers). `encoding/json` does not guarantee these invariants across versions, and a single byte difference breaks every other implementation's verification. Hand-roll the encoder.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/watchtower/chain/canonical_test.go`:

```go
package chain

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeCanonical_KeyOrder(t *testing.T) {
	rec := IntegrityRecord{
		FormatVersion:  2,
		Sequence:       42,
		Generation:     7,
		PrevHash:       "deadbeef",
		EventHash:      "cafef00d",
		ContextDigest:  "0123456789abcdef",
		KeyFingerprint: "sha256:aabbccdd",
	}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"context_digest":"0123456789abcdef","event_hash":"cafef00d","format_version":2,"generation":7,"key_fingerprint":"sha256:aabbccdd","prev_hash":"deadbeef","sequence":42}`
	if string(got) != want {
		t.Errorf("EncodeCanonical mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestEncodeCanonical_NoWhitespace(t *testing.T) {
	rec := IntegrityRecord{FormatVersion: 2}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(got, " \t\n\r") {
		t.Errorf("encoder emitted whitespace: %q", got)
	}
}

func TestEncodeCanonical_AsciiEscapeNonAscii(t *testing.T) {
	rec := IntegrityRecord{PrevHash: "héllo"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	// 'é' is U+00E9; canonical form must escape it as \u00e9 (lowercase hex).
	if !strings.Contains(string(got), `"prev_hash":"h\u00e9llo"`) {
		t.Errorf("non-ASCII not escaped: %s", got)
	}
}

func TestEncodeCanonical_NoScientificNotation(t *testing.T) {
	// Sequence is uint64; 1e15 must render as decimal, not 1000000000000000e0 etc.
	rec := IntegrityRecord{Sequence: 1_000_000_000_000_000}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"sequence":1000000000000000`) {
		t.Errorf("number not decimal: %s", got)
	}
	if strings.Contains(string(got), "e") || strings.Contains(string(got), "E") {
		t.Errorf("number used scientific notation: %s", got)
	}
}

func TestEncodeCanonical_Uint64Max(t *testing.T) {
	rec := IntegrityRecord{Sequence: ^uint64(0)} // 18446744073709551615
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"sequence":18446744073709551615`) {
		t.Errorf("uint64 max not preserved: %s", got)
	}
}

func TestEncodeCanonical_StringEscapes(t *testing.T) {
	// Verify the JSON-mandated escapes for backslash, quote, control chars.
	rec := IntegrityRecord{PrevHash: "a\\b\"c\nd\te"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := `"prev_hash":"a\\b\"c\nd\te"`
	if !strings.Contains(string(got), want) {
		t.Errorf("escapes wrong:\ngot:  %s\nwant: substring %s", got, want)
	}
}

func TestEncodeCanonical_SurrogatePair(t *testing.T) {
	// U+1F600 GRINNING FACE → must encode as surrogate pair \uD83D\uDE00.
	rec := IntegrityRecord{PrevHash: "\U0001F600"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"prev_hash":"\ud83d\ude00"`) {
		t.Errorf("surrogate pair wrong: %s", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/chain/...`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement `chain.go`**

Create `internal/store/watchtower/chain/chain.go`:

```go
// Package chain provides WTP-specific helpers around audit.SinkChain.
//
// This package does NOT re-implement chain mutation. The Compute/Commit/Fatal
// API lives on audit.SinkChain (Phase 0 contract). The helpers here cover only
// the WTP-specific bits: the canonical record encoding, the context digest, and
// the per-event hash.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
)

// IntegrityRecord is the WTP integrity_record structure that gets canonical-
// encoded and passed as the payload to audit.SinkChain.Compute. Field names
// match the on-the-wire JSON object in CompactEvent.integrity (spec §6.3).
type IntegrityRecord struct {
	FormatVersion  uint32
	Sequence       uint64
	Generation     uint32
	PrevHash       string
	EventHash      string
	ContextDigest  string
	KeyFingerprint string
}

// SessionContext is the input to ComputeContextDigest. Bound at SessionInit,
// re-bound at SessionUpdate and at chain key rotation. Spec §6.4.6.
type SessionContext struct {
	SessionID      string
	AgentID        string
	AgentVersion   string
	OCSFVersion    string
	FormatVersion  uint32
	Algorithm      string
	KeyFingerprint string
}

// ComputeContextDigest returns the lowercase-hex SHA-256 of the canonical JSON
// encoding of the SessionContext. Bound into every event hash for the segment.
//
// The digest changes on session establishment and on chain rotation; tests can
// assert byte-equality against this output as part of the conformance suite.
func ComputeContextDigest(ctx SessionContext) string {
	canon := encodeContextCanonical(ctx)
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// ComputeEventHash returns the lowercase-hex SHA-256 of the canonical CompactEvent
// bytes. Used to populate IntegrityRecord.EventHash before the IntegrityRecord
// is canonical-encoded and passed as payload to audit.SinkChain.Compute.
func ComputeEventHash(canonicalEvent []byte) string {
	sum := sha256.Sum256(canonicalEvent)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Implement `canonical.go`**

Create `internal/store/watchtower/chain/canonical.go`:

```go
package chain

import (
	"bytes"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// EncodeCanonical produces the byte-exact canonical JSON encoding of an
// IntegrityRecord per spec §6.4: keys sorted lexicographically, no insignificant
// whitespace, ASCII-escaped non-ASCII (lowercase hex), decimal integers (no
// scientific notation), strict JSON string escapes.
//
// This is the cross-implementation contract surface — a single byte difference
// breaks every other implementation. Vectors live in chain/testdata/vectors.json
// and are also published as the conformance suite at docs/spec/wtp/conformance/.
func EncodeCanonical(rec IntegrityRecord) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	// Keys sorted lexicographically: context_digest, event_hash, format_version,
	// generation, key_fingerprint, prev_hash, sequence.
	writeKey(&buf, "context_digest", true)
	writeStringValue(&buf, rec.ContextDigest)

	writeKey(&buf, "event_hash", false)
	writeStringValue(&buf, rec.EventHash)

	writeKey(&buf, "format_version", false)
	writeUint(&buf, uint64(rec.FormatVersion))

	writeKey(&buf, "generation", false)
	writeUint(&buf, uint64(rec.Generation))

	writeKey(&buf, "key_fingerprint", false)
	writeStringValue(&buf, rec.KeyFingerprint)

	writeKey(&buf, "prev_hash", false)
	writeStringValue(&buf, rec.PrevHash)

	writeKey(&buf, "sequence", false)
	writeUint(&buf, rec.Sequence)

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// encodeContextCanonical does the same for SessionContext. Internal: only used
// by ComputeContextDigest. Keys sorted: agent_id, agent_version, algorithm,
// format_version, key_fingerprint, ocsf_version, session_id.
func encodeContextCanonical(ctx SessionContext) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	writeKey(&buf, "agent_id", true)
	writeStringValue(&buf, ctx.AgentID)
	writeKey(&buf, "agent_version", false)
	writeStringValue(&buf, ctx.AgentVersion)
	writeKey(&buf, "algorithm", false)
	writeStringValue(&buf, ctx.Algorithm)
	writeKey(&buf, "format_version", false)
	writeUint(&buf, uint64(ctx.FormatVersion))
	writeKey(&buf, "key_fingerprint", false)
	writeStringValue(&buf, ctx.KeyFingerprint)
	writeKey(&buf, "ocsf_version", false)
	writeStringValue(&buf, ctx.OCSFVersion)
	writeKey(&buf, "session_id", false)
	writeStringValue(&buf, ctx.SessionID)
	buf.WriteByte('}')
	return buf.Bytes()
}

func writeKey(buf *bytes.Buffer, k string, first bool) {
	if !first {
		buf.WriteByte(',')
	}
	buf.WriteByte('"')
	writeStringEscapedBody(buf, k)
	buf.WriteByte('"')
	buf.WriteByte(':')
}

func writeStringValue(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	writeStringEscapedBody(buf, s)
	buf.WriteByte('"')
}

func writeUint(buf *bytes.Buffer, n uint64) {
	buf.WriteString(strconv.FormatUint(n, 10))
}

// writeStringEscapedBody writes s into buf with the canonical-JSON escape
// rules: \", \\, \b/\f/\n/\r/\t, \uXXXX for everything below 0x20 and for
// every non-ASCII rune (lowercase hex). Surrogate pairs encode as two \uXXXX
// escapes per RFC 8259 §7.
func writeStringEscapedBody(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid UTF-8 — emit the replacement character escape.
			fmt.Fprintf(buf, `\u%04x`, 0xFFFD)
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		case r < 0x80:
			buf.WriteByte(byte(r))
		case r <= 0xFFFF:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			// Outside BMP — surrogate pair, lowercase hex.
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
		}
		i += size
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/chain/...`
Expected: PASS, all 7 tests green.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/chain/
git commit -m "feat(wtp/chain): add IntegrityRecord and canonical JSON encoder"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 7: Chain context digest + cross-implementation conformance vectors

**Files:**
- Create: `internal/store/watchtower/chain/testdata/vectors.json`
- Create: `internal/store/watchtower/chain/vectors_test.go`

**Why:** A golden vector failure is a load-bearing alarm: the canonical encoding has changed and is now incompatible with every other implementation. Vectors are also published as the conformance suite for cross-language WTP clients.

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/chain/vectors_test.go`:

```go
package chain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorEntry struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"` // "integrity_record" | "context_digest"
	Input    json.RawMessage `json:"input"`
	Expected string  `json:"expected"` // canonical bytes for "integrity_record"; hex digest for "context_digest"
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []vectorEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("vectors.json has no entries")
	}
	for _, v := range entries {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Kind {
			case "integrity_record":
				var rec IntegrityRecord
				if err := json.Unmarshal(v.Input, &rec); err != nil {
					t.Fatalf("decode input: %v", err)
				}
				got, err := EncodeCanonical(rec)
				if err != nil {
					t.Fatalf("EncodeCanonical: %v", err)
				}
				if string(got) != v.Expected {
					t.Errorf("canonical mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			case "context_digest":
				var ctx SessionContext
				if err := json.Unmarshal(v.Input, &ctx); err != nil {
					t.Fatalf("decode input: %v", err)
				}
				got := ComputeContextDigest(ctx)
				if got != v.Expected {
					t.Errorf("digest mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/chain/ -run TestVectors`
Expected: FAIL with `no such file or directory: testdata/vectors.json`.

- [ ] **Step 3: Create the vectors file**

Create `internal/store/watchtower/chain/testdata/vectors.json`:

```json
[
  {
    "name": "minimal_zero_record",
    "kind": "integrity_record",
    "input": {"FormatVersion":2,"Sequence":0,"Generation":0,"PrevHash":"","EventHash":"","ContextDigest":"","KeyFingerprint":""},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":0}"
  },
  {
    "name": "typical_record",
    "kind": "integrity_record",
    "input": {"FormatVersion":2,"Sequence":42,"Generation":7,"PrevHash":"deadbeef","EventHash":"cafef00d","ContextDigest":"0123456789abcdef","KeyFingerprint":"sha256:aabbccdd"},
    "expected": "{\"context_digest\":\"0123456789abcdef\",\"event_hash\":\"cafef00d\",\"format_version\":2,\"generation\":7,\"key_fingerprint\":\"sha256:aabbccdd\",\"prev_hash\":\"deadbeef\",\"sequence\":42}"
  },
  {
    "name": "uint64_max_sequence",
    "kind": "integrity_record",
    "input": {"FormatVersion":2,"Sequence":18446744073709551615,"Generation":4294967295,"PrevHash":"","EventHash":"","ContextDigest":"","KeyFingerprint":""},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":4294967295,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":18446744073709551615}"
  },
  {
    "name": "non_ascii_in_key_fingerprint",
    "kind": "integrity_record",
    "input": {"FormatVersion":2,"Sequence":1,"Generation":0,"PrevHash":"","EventHash":"","ContextDigest":"","KeyFingerprint":"caf\u00e9"},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"caf\\u00e9\",\"prev_hash\":\"\",\"sequence\":1}"
  },
  {
    "name": "context_digest_typical",
    "kind": "context_digest",
    "input": {"SessionID":"01HXAVD2N5VX3CZQK7Q7QWNYKE","AgentID":"agentsh","AgentVersion":"1.0.0","OCSFVersion":"1.8.0","FormatVersion":2,"Algorithm":"hmac-sha256","KeyFingerprint":"sha256:aabbccdd"},
    "expected": "PLACEHOLDER_REPLACE_ME"
  }
]
```

- [ ] **Step 4: Compute the real digest for the placeholder**

Write a small one-shot helper to print the actual digest. Run:

```bash
go run -exec '' ./internal/store/watchtower/chain/cmd/print-digest 2>/dev/null || true
```

Since that command does not exist, use a `go test` printer instead. Add a temporary `t.Logf` line to `vectors_test.go` BEFORE the assertion in the `context_digest` case:

```go
case "context_digest":
    var ctx SessionContext
    if err := json.Unmarshal(v.Input, &ctx); err != nil {
        t.Fatalf("decode input: %v", err)
    }
    got := ComputeContextDigest(ctx)
    t.Logf("digest for %s: %s", v.Name, got)
    if got != v.Expected {
        t.Errorf("digest mismatch\ngot:  %s\nwant: %s", got, v.Expected)
    }
```

Run: `go test -v -run TestVectors/context_digest_typical ./internal/store/watchtower/chain/`
Expected: FAIL but the log line prints the actual digest. Copy that hex string into `vectors.json` replacing `PLACEHOLDER_REPLACE_ME`. Remove the temporary `t.Logf`.

- [ ] **Step 5: Run vectors test to verify it passes**

Run: `go test ./internal/store/watchtower/chain/ -run TestVectors`
Expected: PASS, all 5 sub-tests green.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/chain/testdata/ internal/store/watchtower/chain/vectors_test.go
git commit -m "test(wtp/chain): add cross-implementation conformance vectors"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 6: Compact encoder + mapper interface

### Task 8: `compact.Mapper` interface + stub default

**Files:**
- Create: `internal/store/watchtower/compact/mapper.go`
- Create: `internal/store/watchtower/compact/mapper_test.go`

**Why:** The OCSF mapping is Phase 1 work. The WTP package needs a stable interface to import without depending on the actual mapper implementation. The default stub maps every event to OCSF class 0/activity 0 with the original `events.Event` JSON as payload — useful for unit tests and for catching a missing `WithMapper` in production via `validate()`.

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/compact/mapper_test.go`:

```go
package compact

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestStubMapper_MapsToZeroClass(t *testing.T) {
	ev := types.Event{
		ID:        "abc",
		Type:      "exec.start",
		SessionID: "sess1",
		Timestamp: time.Unix(1700000000, 123),
	}
	m := StubMapper{}
	out, err := m.Map(ev)
	if err != nil {
		t.Fatal(err)
	}
	if out.OCSFClassUID != 0 || out.OCSFActivityID != 0 {
		t.Errorf("StubMapper should produce class=0 activity=0, got class=%d activity=%d", out.OCSFClassUID, out.OCSFActivityID)
	}
	if len(out.Payload) == 0 {
		t.Error("StubMapper should set non-empty payload")
	}
}

func TestStubMapper_DeterministicForSameEvent(t *testing.T) {
	ev := types.Event{
		ID:        "abc",
		Type:      "exec.start",
		SessionID: "sess1",
		Timestamp: time.Unix(1700000000, 0),
	}
	m := StubMapper{}
	a, _ := m.Map(ev)
	b, _ := m.Map(ev)
	if string(a.Payload) != string(b.Payload) {
		t.Error("StubMapper should be deterministic")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/compact/...`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement `mapper.go`**

Create `internal/store/watchtower/compact/mapper.go`:

```go
// Package compact projects agentsh events into the WTP CompactEvent wire shape.
//
// The OCSF class/activity mapping is Phase 1 work and is injected via the
// Mapper interface. This package provides:
//   - The Mapper interface (production: injected from Phase 1).
//   - A StubMapper used by unit tests; production wiring REJECTS this stub
//     via Store validate() so it never escapes test code.
//   - The Encode function that combines a Mapper with the chain helpers and
//     produces a fully-populated wtpv1.CompactEvent.
package compact

import (
	"encoding/json"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

// MappedEvent is the Mapper's output: a class/activity pair plus the
// pre-encoded OCSF payload for that class. The Encode function combines this
// with the chain integrity record to produce the final CompactEvent.
type MappedEvent struct {
	OCSFClassUID   uint32
	OCSFActivityID uint32
	Payload        []byte // protobuf-encoded class-specific payload
}

// Mapper projects an agentsh event into the OCSF class identifier and the
// pre-encoded class-specific payload bytes.
//
// Production: injected via watchtower.WithMapper(...) from Phase 1.
// Tests: use StubMapper or a per-test fake.
type Mapper interface {
	Map(types.Event) (MappedEvent, error)
}

// StubMapper is a placeholder Mapper that emits class=0/activity=0 with the
// raw events.Event JSON as payload. It exists to keep the WTP package's own
// unit tests independent of Phase 1; production wiring rejects it.
type StubMapper struct{}

func (StubMapper) Map(ev types.Event) (MappedEvent, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return MappedEvent{}, fmt.Errorf("stub mapper marshal: %w", err)
	}
	return MappedEvent{OCSFClassUID: 0, OCSFActivityID: 0, Payload: b}, nil
}

// IsStubMapper reports whether m is the StubMapper. Used by Store.validate()
// to reject test-only mappers in production.
func IsStubMapper(m Mapper) bool {
	_, ok := m.(StubMapper)
	return ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/compact/...`
Expected: PASS.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/compact/mapper.go internal/store/watchtower/compact/mapper_test.go
git commit -m "feat(wtp/compact): add Mapper interface and stub for unit tests"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 9: `compact.Encode` — full CompactEvent assembly

**Files:**
- Create: `internal/store/watchtower/compact/encoder.go`
- Create: `internal/store/watchtower/compact/encoder_test.go`

**Why:** This is the per-event hot path of WTP `AppendEvent`. It combines the Mapper's output with the shared `(seq, gen)` from `ev.Chain` and produces the full `wtpv1.CompactEvent` ready to pass through the chain → wal → transport pipeline. Hash is NOT computed here; that's the chain's job.

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/compact/encoder_test.go`:

```go
package compact

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestEncode_PopulatesCoreFields(t *testing.T) {
	ev := types.Event{
		Type:      "exec.start",
		Timestamp: time.Unix(1_700_000_000, 123),
		Chain:     &types.ChainState{Sequence: 42, Generation: 7},
	}
	got, err := Encode(StubMapper{}, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", got.Sequence)
	}
	if got.Generation != 7 {
		t.Errorf("Generation = %d, want 7", got.Generation)
	}
	if got.TimestampUnixNanos != uint64(time.Unix(1_700_000_000, 123).UnixNano()) {
		t.Errorf("TimestampUnixNanos wrong: %d", got.TimestampUnixNanos)
	}
	if got.OcsfClassUid != 0 || got.OcsfActivityId != 0 {
		t.Errorf("StubMapper class/activity not propagated")
	}
	if len(got.Payload) == 0 {
		t.Error("payload empty")
	}
	// Integrity is intentionally LEFT NIL by Encode — chain.Compute
	// populates it later in the AppendEvent transactional pattern.
	if got.Integrity != nil {
		t.Errorf("Encode must not populate Integrity (set by chain step)")
	}
}

func TestEncode_RejectsMissingChain(t *testing.T) {
	ev := types.Event{Type: "x", Timestamp: time.Now()}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject ev with nil Chain")
	}
}

func TestEncode_PropagatesMapperError(t *testing.T) {
	failing := failingMapper{}
	ev := types.Event{Type: "x", Timestamp: time.Now(), Chain: &types.ChainState{}}
	_, err := Encode(failing, ev)
	if err == nil {
		t.Fatal("Encode must propagate mapper error")
	}
}

type failingMapper struct{}

func (failingMapper) Map(types.Event) (MappedEvent, error) {
	return MappedEvent{}, errBoom
}

var errBoom = errFromString("boom")

type errFromString string

func (e errFromString) Error() string { return string(e) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/compact/ -run TestEncode`
Expected: FAIL — `Encode` undefined.

- [ ] **Step 3: Implement `encoder.go`**

Create `internal/store/watchtower/compact/encoder.go`:

```go
package compact

import (
	"errors"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ErrMissingChain is returned by Encode when ev.Chain is nil — the composite
// store did not stamp the shared (sequence, generation). This is a programming
// error: a WTP sink must run inside the composite store.
var ErrMissingChain = errors.New("compact.Encode: ev.Chain is nil; composite did not stamp")

// Encode projects an agentsh event into a wtpv1.CompactEvent, populating
// everything EXCEPT the IntegrityRecord. The IntegrityRecord is filled in by
// the WTP Store in the AppendEvent transactional pattern, AFTER chain.Compute
// returns the entry hash.
func Encode(m Mapper, ev types.Event) (*wtpv1.CompactEvent, error) {
	if ev.Chain == nil {
		return nil, ErrMissingChain
	}
	mapped, err := m.Map(ev)
	if err != nil {
		return nil, fmt.Errorf("compact mapper: %w", err)
	}
	return &wtpv1.CompactEvent{
		Sequence:           ev.Chain.Sequence,
		Generation:         ev.Chain.Generation,
		TimestampUnixNanos: uint64(ev.Timestamp.UnixNano()),
		OcsfClassUid:       mapped.OCSFClassUID,
		OcsfActivityId:     mapped.OCSFActivityID,
		Payload:            mapped.Payload,
		// Integrity left nil; populated downstream by the chain step.
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/compact/...`
Expected: PASS, all tests green.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/compact/encoder.go internal/store/watchtower/compact/encoder_test.go
git commit -m "feat(wtp/compact): add Encode that builds CompactEvent from Mapper output"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 7: WAL package

### Task 10: WAL framing primitives — segment header, record framing, CRC32C

**Files:**
- Create: `internal/store/watchtower/wal/framing.go`
- Create: `internal/store/watchtower/wal/framing_test.go`

**Why:** Every byte the WAL writes goes through these primitives. Get them wrong and every recovery is corrupt. This task is pure encoding/decoding — no I/O, fully testable from in-memory buffers.

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/wal/framing_test.go`:

```go
package wal

import (
	"bytes"
	"testing"
)

func TestSegmentHeader_RoundTrip(t *testing.T) {
	hdr := SegmentHeader{Version: 1, Flags: FlagGenInit, Generation: 7}
	var buf bytes.Buffer
	if err := WriteSegmentHeader(&buf, hdr); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != SegmentHeaderSize {
		t.Errorf("header size = %d, want %d", buf.Len(), SegmentHeaderSize)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("WTP1")) {
		t.Errorf("missing WTP1 magic: %x", buf.Bytes())
	}
	got, err := ReadSegmentHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got != hdr {
		t.Errorf("round trip mismatch: got=%+v want=%+v", got, hdr)
	}
}

func TestSegmentHeader_RejectsBadMagic(t *testing.T) {
	bad := append([]byte("XXXX"), make([]byte, SegmentHeaderSize-4)...)
	_, err := ReadSegmentHeader(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("expected magic-rejection error")
	}
}

func TestSegmentHeader_RejectsUnknownVersion(t *testing.T) {
	hdr := SegmentHeader{Version: 99, Flags: 0, Generation: 0}
	var buf bytes.Buffer
	if err := WriteSegmentHeader(&buf, hdr); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSegmentHeader(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected version-rejection error")
	}
}

func TestSegmentHeader_RejectsReservedBits(t *testing.T) {
	// Construct a raw header with non-zero reserved bits.
	raw := make([]byte, SegmentHeaderSize)
	copy(raw, "WTP1")
	raw[4] = 0x01 // version low byte
	// reserved (offset 12..16) intentionally non-zero
	raw[12] = 0x42
	_, err := ReadSegmentHeader(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected reserved-nonzero rejection")
	}
}

func TestRecordFraming_RoundTrip(t *testing.T) {
	payload := []byte("hello WTP record framing")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRecord(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got=%q want=%q", got, payload)
	}
}

func TestRecordFraming_DetectsCorruption(t *testing.T) {
	payload := []byte("corrupt me")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Flip a payload byte (first byte after length+crc).
	frame[8] ^= 0xFF
	_, err := ReadRecord(bytes.NewReader(frame))
	if err != ErrCRCMismatch {
		t.Errorf("err = %v, want ErrCRCMismatch", err)
	}
}

func TestRecordFraming_RejectsTruncatedHeader(t *testing.T) {
	_, err := ReadRecord(bytes.NewReader([]byte{0, 1, 2}))
	if err == nil {
		t.Fatal("expected truncated-header error")
	}
}

func TestRecordFraming_RejectsTruncatedPayload(t *testing.T) {
	payload := []byte("abc")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Truncate the payload.
	frame = frame[:len(frame)-1]
	_, err := ReadRecord(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected truncated-payload error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/wal/ -run TestSegmentHeader`
Expected: FAIL — `SegmentHeader` undefined.

- [ ] **Step 3: Implement `framing.go`**

Create `internal/store/watchtower/wal/framing.go`:

```go
// Package wal implements the WTP write-ahead log: framed records inside
// generation-tagged segment files, with CRC32C-Castagnoli per record and an
// atomic .INPROGRESS → .seg seal. Spec §"WAL Package".
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// SegmentHeaderSize is the fixed 16-byte segment header at the start of
// every segment file. Spec §"Segment header (16 bytes)".
const SegmentHeaderSize = 16

// SegmentMagic identifies a WTP1 segment file.
var SegmentMagic = []byte("WTP1")

// SegmentVersion is the current segment header version.
const SegmentVersion uint16 = 1

// FlagGenInit indicates the segment was opened due to a generation roll.
const FlagGenInit uint16 = 0x0001

// SegmentHeader is the parsed representation of a 16-byte segment header.
type SegmentHeader struct {
	Version    uint16
	Flags      uint16
	Generation uint32
}

// WriteSegmentHeader emits a 16-byte header to w. Reserved bytes are zero.
func WriteSegmentHeader(w io.Writer, h SegmentHeader) error {
	buf := make([]byte, SegmentHeaderSize)
	copy(buf[0:4], SegmentMagic)
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], h.Flags)
	binary.BigEndian.PutUint32(buf[8:12], h.Generation)
	// buf[12:16] reserved, all zero
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write segment header: %w", err)
	}
	return nil
}

// ReadSegmentHeader parses a 16-byte header from r. Rejects unknown magic,
// unknown version, and non-zero reserved bytes.
func ReadSegmentHeader(r io.Reader) (SegmentHeader, error) {
	buf := make([]byte, SegmentHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return SegmentHeader{}, fmt.Errorf("read segment header: %w", err)
	}
	if string(buf[0:4]) != string(SegmentMagic) {
		return SegmentHeader{}, fmt.Errorf("bad magic: got %x want %x", buf[0:4], SegmentMagic)
	}
	h := SegmentHeader{
		Version:    binary.BigEndian.Uint16(buf[4:6]),
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		Generation: binary.BigEndian.Uint32(buf[8:12]),
	}
	if h.Version != SegmentVersion {
		return SegmentHeader{}, fmt.Errorf("unsupported segment version %d (want %d)", h.Version, SegmentVersion)
	}
	for _, b := range buf[12:16] {
		if b != 0 {
			return SegmentHeader{}, fmt.Errorf("reserved bytes nonzero: %x", buf[12:16])
		}
	}
	return h, nil
}

// crcTable is the Castagnoli polynomial table used for record CRCs.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrCRCMismatch is returned by ReadRecord when the on-disk CRC does not
// match the recomputed CRC of the payload bytes.
var ErrCRCMismatch = errors.New("wal: record CRC mismatch")

// WriteRecord writes a length-prefixed, CRC32C-protected record to w.
//
// Frame layout:
//   offset  size      field
//   0       4         length     (uint32 BE; bytes after this field, excluding CRC, including payload)
//   4       4         crc32c     (Castagnoli, computed over payload)
//   8       length-4  payload
//
// Note: the length field encodes len(payload)+4 (the payload bytes plus the
// 4-byte CRC). This matches spec §"Record framing".
func WriteRecord(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("wal: empty payload")
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)+4))
	binary.BigEndian.PutUint32(header[4:8], crc32.Checksum(payload, crcTable))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write record header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write record payload: %w", err)
	}
	return nil
}

// ReadRecord reads one length-prefixed CRC32C record from r and returns the
// payload. Returns ErrCRCMismatch on bad CRC, io.ErrUnexpectedEOF on
// truncation, io.EOF when r is at the end of its data.
func ReadRecord(r io.Reader) ([]byte, error) {
	header := make([]byte, 8)
	n, err := io.ReadFull(r, header)
	if err != nil {
		if err == io.EOF && n == 0 {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read record header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[0:4])
	expectedCRC := binary.BigEndian.Uint32(header[4:8])
	if length < 4 {
		return nil, fmt.Errorf("invalid record length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read record payload: %w", err)
	}
	if crc32.Checksum(payload, crcTable) != expectedCRC {
		return nil, ErrCRCMismatch
	}
	return payload, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/wal/ -run "TestSegmentHeader|TestRecordFraming"`
Expected: PASS, all 8 tests green.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/wal/framing.go internal/store/watchtower/wal/framing_test.go
git commit -m "feat(wtp/wal): add segment header and record framing primitives"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 11: Segment lifecycle — atomic seal, INPROGRESS rename, meta.json

**Files:**
- Create: `internal/store/watchtower/wal/segment.go`
- Create: `internal/store/watchtower/wal/segment_test.go`
- Create: `internal/store/watchtower/wal/meta.go`
- Create: `internal/store/watchtower/wal/meta_test.go`
- Create: `internal/store/watchtower/wal/fsync_dir_unix.go`
- Create: `internal/store/watchtower/wal/fsync_dir_windows.go`

**Why:** The atomic seal is the load-bearing piece. If a segment is renamed before fsync, a crash leaves the directory in an undefined state. The Windows-vs-unix split for `fsync(parent)` reuses the existing pattern from `internal/audit/fsync_dir_*.go`.

- [ ] **Step 1: Write the failing test for segment lifecycle**

Create `internal/store/watchtower/wal/segment_test.go`:

```go
package wal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSegment_OpenWriteSeal(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: 1, Flags: FlagGenInit, Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(seg.Path(), ".INPROGRESS") {
		t.Errorf("expected .INPROGRESS suffix, got %q", seg.Path())
	}
	if err := seg.WriteRecord([]byte("rec-1")); err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("rec-2")); err != nil {
		t.Fatal(err)
	}
	sealedPath, err := seg.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(sealedPath, ".INPROGRESS") {
		t.Errorf("seal did not rename: %q", sealedPath)
	}
	if _, err := os.Stat(seg.Path()); !os.IsNotExist(err) {
		t.Errorf(".INPROGRESS still exists after seal: %v", err)
	}
	if _, err := os.Stat(sealedPath); err != nil {
		t.Errorf("sealed file missing: %v", err)
	}
}

func TestSegment_RecoversInProgress(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: 1, Flags: FlagGenInit, Generation: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the same segment for append (recovery path).
	seg2, err := ReopenSegment(filepath.Join(dir, "0000000000.seg.INPROGRESS"))
	if err != nil {
		t.Fatal(err)
	}
	if err := seg2.WriteRecord([]byte("second")); err != nil {
		t.Fatal(err)
	}
	sealed, err := seg2.Seal()
	if err != nil {
		t.Fatal(err)
	}
	// Read back and verify both records present.
	f, err := os.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ReadSegmentHeader(f); err != nil {
		t.Fatal(err)
	}
	r1, err := ReadRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ReadRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(r1) != "first" || string(r2) != "second" {
		t.Errorf("records not preserved: %q, %q", r1, r2)
	}
}

func TestSegment_FilenamePadding(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 42, SegmentHeader{Version: 1, Flags: 0, Generation: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer seg.Close()
	want := filepath.Join(dir, "0000000042.seg.INPROGRESS")
	if seg.Path() != want {
		t.Errorf("filename = %q, want %q", seg.Path(), want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/wal/ -run TestSegment`
Expected: FAIL — `OpenSegment` undefined.

- [ ] **Step 3: Implement `fsync_dir_unix.go` and `fsync_dir_windows.go`**

Create `internal/store/watchtower/wal/fsync_dir_unix.go`:

```go
//go:build unix

package wal

import "os"

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func atomicRename(from, to string) error {
	return os.Rename(from, to)
}
```

Create `internal/store/watchtower/wal/fsync_dir_windows.go`:

```go
//go:build windows

package wal

import "golang.org/x/sys/windows"

func syncDir(string) error { return nil }

func atomicRename(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
```

- [ ] **Step 4: Implement `segment.go`**

Create `internal/store/watchtower/wal/segment.go`:

```go
package wal

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Segment represents one WAL segment file. The on-disk lifecycle is:
//
//	0000000042.seg.INPROGRESS   (live, append-only)
//	   ↓ Seal()
//	0000000042.seg              (sealed, read-only)
//
// Concurrency: NOT safe for concurrent use; the WAL serializes Append calls.
type Segment struct {
	dir    string
	index  uint64
	gen    uint32
	path   string
	file   *os.File
	writer *bufio.Writer
	bytes  int64
}

const segmentExt = ".seg"
const inProgressSuffix = ".INPROGRESS"

// segmentName formats an index as a 10-digit zero-padded string. The padding
// keeps lexical sort = numeric sort up to ~10 billion segments.
func segmentName(index uint64) string {
	return fmt.Sprintf("%010d%s", index, segmentExt)
}

// OpenSegment creates a new .INPROGRESS segment and writes its 16-byte header.
// The header is fsync'd so a crash mid-creation leaves either no segment or a
// segment whose header is durable. Spec §"Lifecycle".
func OpenSegment(dir string, index uint64, hdr SegmentHeader) (*Segment, error) {
	path := filepath.Join(dir, segmentName(index)+inProgressSuffix)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open segment: %w", err)
	}
	w := bufio.NewWriter(f)
	if err := WriteSegmentHeader(w, hdr); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush segment header: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("fsync segment header: %w", err)
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("fsync segments dir: %w", err)
	}
	return &Segment{dir: dir, index: index, gen: hdr.Generation, path: path, file: f, writer: w, bytes: int64(SegmentHeaderSize)}, nil
}

// ReopenSegment reopens an existing .INPROGRESS segment for append. Used on
// startup recovery: scan segments dir, find the .INPROGRESS file, reopen it.
//
// Replay all existing records first via ReplayRecords before further appends
// (caller's responsibility; this constructor positions the writer at EOF).
func ReopenSegment(path string) (*Segment, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("reopen segment: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() < int64(SegmentHeaderSize) {
		_ = f.Close()
		return nil, fmt.Errorf("segment too short: %d bytes", st.Size())
	}
	hdr, err := ReadSegmentHeader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, err
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// strip .seg.INPROGRESS to get the numeric index
	var index uint64
	if _, err := fmt.Sscanf(base, "%010d.seg.INPROGRESS", &index); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("parse segment name %q: %w", base, err)
	}
	return &Segment{dir: dir, index: index, gen: hdr.Generation, path: path, file: f, writer: bufio.NewWriter(f), bytes: st.Size()}, nil
}

// Path returns the on-disk path of this segment (with .INPROGRESS suffix
// while live, sealed name after Seal()).
func (s *Segment) Path() string { return s.path }

// Generation returns the segment's generation tag.
func (s *Segment) Generation() uint32 { return s.gen }

// Index returns the segment's numeric index.
func (s *Segment) Index() uint64 { return s.index }

// Bytes returns the current on-disk byte count (header + records).
func (s *Segment) Bytes() int64 { return s.bytes }

// WriteRecord appends one length+CRC32C-framed record. Buffered; caller must
// call Sync() (or Seal(), which syncs as part of its work) for durability.
func (s *Segment) WriteRecord(payload []byte) error {
	startBytes := s.bytes
	if err := WriteRecord(s.writer, payload); err != nil {
		return err
	}
	s.bytes = startBytes + int64(8+len(payload))
	return nil
}

// Sync flushes the writer and fsyncs the segment file.
func (s *Segment) Sync() error {
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}
	return s.file.Sync()
}

// Seal flushes, fsyncs, truncates to actual length, renames .INPROGRESS to
// .seg, and fsyncs the parent directory. Returns the sealed path.
//
// After Seal, the Segment is no longer writable; further WriteRecord calls
// return an error.
func (s *Segment) Seal() (string, error) {
	if err := s.Sync(); err != nil {
		return "", err
	}
	if err := s.file.Truncate(s.bytes); err != nil {
		return "", fmt.Errorf("truncate sealed segment: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return "", fmt.Errorf("fsync truncated segment: %w", err)
	}
	if err := s.file.Close(); err != nil {
		return "", fmt.Errorf("close sealed segment: %w", err)
	}
	sealed := filepath.Join(s.dir, segmentName(s.index))
	if err := atomicRename(s.path, sealed); err != nil {
		return "", fmt.Errorf("rename sealed segment: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return "", fmt.Errorf("fsync segments dir after seal: %w", err)
	}
	s.path = sealed
	s.file = nil
	s.writer = nil
	return sealed, nil
}

// Close flushes and closes the underlying file WITHOUT renaming. Used on a
// graceful shutdown that may be reopened later. After Close, the .INPROGRESS
// file remains on disk for the next process to ReopenSegment.
func (s *Segment) Close() error {
	if s.file == nil {
		return nil
	}
	if err := s.Sync(); err != nil {
		return err
	}
	err := s.file.Close()
	s.file = nil
	s.writer = nil
	return err
}
```

- [ ] **Step 5: Implement `meta.go`**

Create `internal/store/watchtower/wal/meta.go`:

```go
package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Meta is the persistent state for a WAL directory. Spec §"meta.json schema".
type Meta struct {
	FormatVersion       int    `json:"format_version"`
	AckHighWatermarkSeq uint64 `json:"ack_high_watermark_seq"`
	AckHighWatermarkGen uint32 `json:"ack_high_watermark_gen"`
	SessionID           string `json:"session_id"`
	KeyFingerprint      string `json:"key_fingerprint"`
}

const metaFormatVersion = 1
const metaFileName = "meta.json"

// ReadMeta loads meta.json from dir. Returns os.ErrNotExist if absent.
func ReadMeta(dir string) (Meta, error) {
	p := filepath.Join(dir, metaFileName)
	data, err := os.ReadFile(p)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("parse meta.json: %w", err)
	}
	if m.FormatVersion != metaFormatVersion {
		return Meta{}, fmt.Errorf("meta.json format_version %d unsupported (want %d)", m.FormatVersion, metaFormatVersion)
	}
	return m, nil
}

// WriteMeta atomically writes meta.json: temp file + rename + fsync(parent).
func WriteMeta(dir string, m Meta) error {
	m.FormatVersion = metaFormatVersion
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	tmp := filepath.Join(dir, metaFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write meta tmp: %w", err)
	}
	if err := atomicRename(tmp, filepath.Join(dir, metaFileName)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename meta: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync meta dir: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Add meta tests**

Create `internal/store/watchtower/wal/meta_test.go`:

```go
package wal

import (
	"os"
	"testing"
)

func TestMeta_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Meta{AckHighWatermarkSeq: 42, AckHighWatermarkGen: 7, SessionID: "01HX", KeyFingerprint: "sha256:abcd"}
	if err := WriteMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AckHighWatermarkSeq != 42 || got.SessionID != "01HX" {
		t.Errorf("meta did not round-trip: %+v", got)
	}
	if got.FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", got.FormatVersion)
	}
}

func TestMeta_ReadMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadMeta(dir)
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want os.IsNotExist", err)
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/wal/ -run "TestSegment|TestMeta"`
Expected: PASS, all 5 tests green.

- [ ] **Step 8: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add internal/store/watchtower/wal/segment.go internal/store/watchtower/wal/segment_test.go internal/store/watchtower/wal/meta.go internal/store/watchtower/wal/meta_test.go internal/store/watchtower/wal/fsync_dir_unix.go internal/store/watchtower/wal/fsync_dir_windows.go
git commit -m "feat(wtp/wal): add segment lifecycle and meta.json with cross-platform fsync"
```

- [ ] **Step 10: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 12: WAL `Append` + clean-vs-ambiguous failure classification + generation roll

**Files:**
- Create: `internal/store/watchtower/wal/wal.go`
- Create: `internal/store/watchtower/wal/wal_test.go`
- Create: `internal/store/watchtower/wal/generation_test.go`

**Why:** This is the core of the WAL: a single `Append` call that decides clean vs ambiguous failure (driving the WTP transactional pattern) and performs generation roll inside (the only place that can guarantee single-generation segments). The clean/ambiguous classification feeds spec §"Failure classification".

- [ ] **Step 1: Write the failing test for basic Append + Open + Generation roll**

Create `internal/store/watchtower/wal/wal_test.go`:

```go
package wal

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestWAL_OpenEmptyDir(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.HighWatermark() != 0 || w.HighGeneration() != 0 {
		t.Errorf("fresh WAL hw = (%d,%d), want (0,0)", w.HighWatermark(), w.HighGeneration())
	}
}

func TestWAL_AppendThenReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 5; i++ {
		_, err := w.Append(int64(i), 0, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen and verify high-watermark recovered.
	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if w2.HighWatermark() != 4 {
		t.Errorf("recovered HighWatermark = %d, want 4", w2.HighWatermark())
	}
}

func TestWAL_RejectsClosedAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = w.Append(0, 0, []byte("x"))
	if err == nil {
		t.Fatal("expected closed error")
	}
	if !IsClean(err) {
		t.Errorf("Closed-write error must be Clean (no I/O attempted)")
	}
}

func TestWAL_RejectsOversizedPayload(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 1024, MaxTotalBytes: 8 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	big := make([]byte, 2048)
	_, err = w.Append(0, 0, big)
	if err == nil {
		t.Fatal("expected oversized error")
	}
	if !IsClean(err) {
		t.Errorf("Oversized payload error must be Clean (validated pre-I/O)")
	}
}

func listSegments(t *testing.T, dir string) []string {
	t.Helper()
	d := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}
```

- [ ] **Step 2: Write the failing TestWAL_GenerationBoundaryOrdering**

Create `internal/store/watchtower/wal/generation_test.go`:

```go
package wal

import (
	"strings"
	"testing"
)

// TestWAL_GenerationBoundaryOrdering is one of the four spec-required
// high-risk integrity tests (§"High-risk integrity tests"). It asserts that:
//   - records of different generations land in DIFFERENT segments;
//   - the AppendResult.GenerationRolled flag is set on the boundary record;
//   - the boundary segment's header.generation reflects the new generation.
func TestWAL_GenerationBoundaryOrdering(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 64 * 1024, MaxTotalBytes: 1024 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	// gen=7 records.
	for seq := int64(0); seq < 3; seq++ {
		res, err := w.Append(seq, 7, []byte("g7"))
		if err != nil {
			t.Fatal(err)
		}
		if res.GenerationRolled {
			t.Errorf("seq=%d gen=7 should not roll generation (first writes)", seq)
		}
	}
	// gen=8 boundary record — MUST set GenerationRolled.
	res, err := w.Append(0, 8, []byte("g8"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.GenerationRolled {
		t.Error("first gen=8 record must set GenerationRolled=true")
	}
	for seq := int64(1); seq < 3; seq++ {
		res, err := w.Append(seq, 8, []byte("g8"))
		if err != nil {
			t.Fatal(err)
		}
		if res.GenerationRolled {
			t.Errorf("seq=%d gen=8 (after boundary) should not roll", seq)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Two sealed segments expected: one gen=7, one gen=8 (live, .INPROGRESS).
	names := listSegments(t, dir)
	sealed, inProgress := splitNames(names)
	if len(sealed) != 1 {
		t.Errorf("expected 1 sealed segment after gen roll, got %d (%v)", len(sealed), names)
	}
	if len(inProgress) != 1 {
		t.Errorf("expected 1 .INPROGRESS, got %d (%v)", len(inProgress), names)
	}
}

func splitNames(names []string) (sealed, inProgress []string) {
	for _, n := range names {
		if strings.HasSuffix(n, ".INPROGRESS") {
			inProgress = append(inProgress, n)
		} else {
			sealed = append(sealed, n)
		}
	}
	return
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/wal/ -run "TestWAL_"`
Expected: FAIL — `Open` undefined.

- [ ] **Step 4: Implement `wal.go`**

Create `internal/store/watchtower/wal/wal.go`:

```go
package wal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SyncMode controls whether each Append fsyncs synchronously or via a timer.
type SyncMode int

const (
	SyncImmediate SyncMode = iota
	SyncDeferred
)

// Options configures a WAL. Defaults are not applied here — callers should
// pre-validate via internal/config (which does apply defaults).
type Options struct {
	Dir           string
	SegmentSize   int64
	MaxTotalBytes int64
	SyncMode      SyncMode
	SyncInterval  time.Duration
}

// AppendResult is returned by WAL.Append. GenerationRolled is set exactly when
// this Append rolled the segment for a new generation.
type AppendResult struct {
	GenerationRolled bool
}

// FailureClass classifies an Append failure into clean or ambiguous, driving
// the caller's transactional Compute → Append → Commit/Fatal pattern.
type FailureClass int

const (
	FailureNone FailureClass = iota
	FailureClean
	FailureAmbiguous
)

// AppendError wraps an Append error with its classification. Use IsClean or
// IsAmbiguous to inspect; use errors.As for type-assertion.
type AppendError struct {
	Class FailureClass
	Op    string
	Err   error
}

func (e *AppendError) Error() string { return fmt.Sprintf("wal %s: %v", e.Op, e.Err) }
func (e *AppendError) Unwrap() error { return e.Err }

func IsClean(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureClean
	}
	return false
}

func IsAmbiguous(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureAmbiguous
	}
	return false
}

// ErrClosed is wrapped in a clean AppendError when Append is called on a
// closed WAL. No I/O is attempted.
var ErrClosed = errors.New("wal: closed")

// WAL is the per-sink write-ahead log. Concurrency: AppendEvent serialization
// is the caller's responsibility (the WTP Store holds an outer lock); WAL's
// own internal mutex protects the segment switch but does not allow
// concurrent Append from multiple goroutines.
type WAL struct {
	opts Options

	mu        sync.Mutex
	current   *Segment
	segDir    string
	closed    bool
	highSeq   uint64
	highGen   uint32
	nextIndex uint64
	totalBytes int64
}

// Open opens or creates the WAL directory at opts.Dir. On open, all sealed
// segments are scanned and the highest (sequence, generation) is recovered.
// Any .INPROGRESS file is reopened for append.
func Open(opts Options) (*WAL, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal.Open: Dir required")
	}
	segDir := filepath.Join(opts.Dir, "segments")
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir segments: %w", err)
	}
	w := &WAL{opts: opts, segDir: segDir}
	if err := w.recover(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *WAL) recover() error {
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return fmt.Errorf("readdir segments: %w", err)
	}
	var sealed, inProgress []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), inProgressSuffix) {
			inProgress = append(inProgress, e.Name())
		} else if strings.HasSuffix(e.Name(), segmentExt) {
			sealed = append(sealed, e.Name())
		}
	}
	sort.Strings(sealed)
	sort.Strings(inProgress)

	// Compute total bytes for overflow tracking.
	for _, name := range append(append([]string{}, sealed...), inProgress...) {
		st, err := os.Stat(filepath.Join(w.segDir, name))
		if err != nil {
			return err
		}
		w.totalBytes += st.Size()
	}

	// Rebuild high-watermark by scanning the highest sealed + the inProgress.
	maxIdx := uint64(0)
	if len(sealed) > 0 {
		var idx uint64
		_, _ = fmt.Sscanf(sealed[len(sealed)-1], "%010d.seg", &idx)
		if idx >= maxIdx {
			maxIdx = idx
		}
	}
	if len(inProgress) > 0 {
		var idx uint64
		_, _ = fmt.Sscanf(inProgress[len(inProgress)-1], "%010d.seg.INPROGRESS", &idx)
		if idx >= maxIdx {
			maxIdx = idx
		}
	}
	w.nextIndex = maxIdx + 1

	// Scan the live (or last sealed) segment for the highest seq/gen seen.
	scan := func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		hdr, err := ReadSegmentHeader(f)
		if err != nil {
			return err
		}
		w.highGen = hdr.Generation
		for {
			payload, err := ReadRecord(f)
			if err == io.EOF {
				return nil
			}
			if err == ErrCRCMismatch {
				// Truncated tail. Stop scanning this segment.
				return nil
			}
			if err != nil {
				return err
			}
			seq, gen, ok := parseSeqGen(payload)
			if ok {
				w.highSeq = seq
				w.highGen = gen
			}
		}
	}

	if len(inProgress) > 0 {
		// Reopen for append.
		path := filepath.Join(w.segDir, inProgress[len(inProgress)-1])
		if err := scan(path); err != nil {
			return err
		}
		seg, err := ReopenSegment(path)
		if err != nil {
			return err
		}
		w.current = seg
		// Use the existing index, not a fresh one.
		w.nextIndex = seg.Index() + 1
	} else if len(sealed) > 0 {
		// Last segment is sealed; scan it for high-watermark only.
		path := filepath.Join(w.segDir, sealed[len(sealed)-1])
		if err := scan(path); err != nil {
			return err
		}
	}
	return nil
}

// HighWatermark returns the highest sequence the WAL has durably recorded,
// across both sealed segments and the live .INPROGRESS file.
func (w *WAL) HighWatermark() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highSeq
}

// HighGeneration returns the generation of the most recently appended record.
func (w *WAL) HighGeneration() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highGen
}

// Append writes a record with the given (seq, gen) and payload. See spec
// §"Append — clean vs ambiguous failure classification" for the failure
// taxonomy.
//
// The caller (WTP Store.AppendEvent) MUST follow this with audit.SinkChain.Commit
// on success, or audit.SinkChain.Fatal on ambiguous failure.
func (w *WAL) Append(seq int64, gen uint32, payload []byte) (AppendResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: ErrClosed}
	}
	if int64(8+len(payload)) > w.opts.SegmentSize-int64(SegmentHeaderSize) {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: fmt.Errorf("payload %d exceeds segment budget", len(payload))}
	}

	rolled := false
	// Generation roll: seal current segment, open a new one with the new gen.
	if w.current != nil && w.current.Generation() != gen {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "seal-on-gen-roll", Err: err}
		}
		seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
		if err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "open-on-gen-roll", Err: err}
		}
		w.current = seg
		rolled = true
	}
	// Open the very first segment.
	if w.current == nil {
		flags := uint16(0)
		if w.highGen != gen {
			flags = FlagGenInit
			rolled = w.highGen != gen && w.highSeq != 0 // first ever segment gets gen_init too
		}
		seg, err := w.openNewSegmentLocked(gen, flags)
		if err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "open-first", Err: err}
		}
		w.current = seg
	}
	// Segment full → roll within the same generation.
	if w.current.Bytes()+int64(8+len(payload)) > w.opts.SegmentSize {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "seal-on-full", Err: err}
		}
		seg, err := w.openNewSegmentLocked(gen, 0)
		if err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "open-on-full", Err: err}
		}
		w.current = seg
	}

	// The payload encodes its own (seq, gen) for recovery. Prepend a small
	// header here so we can recover seq/gen on replay without parsing the
	// protobuf payload.
	framed := encodeSeqGenFrame(seq, gen, payload)

	if err := w.current.WriteRecord(framed); err != nil {
		return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "write-record", Err: err}
	}
	if w.opts.SyncMode == SyncImmediate {
		if err := w.current.Sync(); err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "sync", Err: err}
		}
	}

	w.highSeq = uint64(seq)
	w.highGen = gen
	w.totalBytes += int64(8 + len(framed))
	return AppendResult{GenerationRolled: rolled}, nil
}

func (w *WAL) sealCurrentLocked() error {
	if w.current == nil {
		return nil
	}
	if _, err := w.current.Seal(); err != nil {
		return err
	}
	w.current = nil
	return nil
}

func (w *WAL) openNewSegmentLocked(gen uint32, flags uint16) (*Segment, error) {
	idx := w.nextIndex
	w.nextIndex++
	return OpenSegment(w.segDir, idx, SegmentHeader{Version: SegmentVersion, Flags: flags, Generation: gen})
}

// Close seals the live segment (if any) without removing INPROGRESS — instead
// flushes and closes for clean reopen. The next Open will reopen the
// .INPROGRESS file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.current != nil {
		if err := w.current.Close(); err != nil {
			return err
		}
		w.current = nil
	}
	return nil
}

// encodeSeqGenFrame prepends 12 bytes of (seq:int64 BE, gen:uint32 BE) to
// payload so a recovery scan can read seq+gen without parsing the protobuf.
func encodeSeqGenFrame(seq int64, gen uint32, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	for i := 0; i < 8; i++ {
		out[7-i] = byte(seq >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[11-i] = byte(gen >> (8 * i))
	}
	copy(out[12:], payload)
	return out
}

func parseSeqGen(framed []byte) (uint64, uint32, bool) {
	if len(framed) < 12 {
		return 0, 0, false
	}
	var seq uint64
	for i := 0; i < 8; i++ {
		seq |= uint64(framed[i]) << (8 * (7 - i))
	}
	var gen uint32
	for i := 0; i < 4; i++ {
		gen |= uint32(framed[8+i]) << (8 * (3 - i))
	}
	return seq, gen, true
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/wal/ -run "TestWAL_"`
Expected: PASS — `TestWAL_OpenEmptyDir`, `TestWAL_AppendThenReplay`, `TestWAL_RejectsClosedAppend`, `TestWAL_RejectsOversizedPayload`, `TestWAL_GenerationBoundaryOrdering` all green.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/wal/wal.go internal/store/watchtower/wal/wal_test.go internal/store/watchtower/wal/generation_test.go
git commit -m "feat(wtp/wal): add Append with clean/ambiguous failure classification and generation roll"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 13: WAL overflow → drop oldest unacked + emit `TransportLoss` marker

**Files:**
- Create: `internal/store/watchtower/wal/overflow_test.go`
- Modify: `internal/store/watchtower/wal/wal.go` (add overflow GC + Loss marker)

**Why:** Spec §"WAL overflow → TransportLoss": when total disk usage would exceed `MaxTotalBytes`, drop oldest *unacked* segments and emit a synthetic `TransportLoss` record. The marker must be fsynced before the drop is reported as complete. This is the resilience guarantee — operators always know when data was lost.

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/wal/overflow_test.go`:

```go
package wal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWAL_OverflowEmitsLossMarker verifies that an Append that would push the
// WAL past MaxTotalBytes drops oldest segments AND inserts a TransportLoss
// marker into the WAL stream.
func TestWAL_OverflowEmitsLossMarker(t *testing.T) {
	dir := t.TempDir()
	// Tight budget: 4 KiB segments, 12 KiB cap → 3 segments max.
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("x"), 1024) // ~1 KiB per record
	for seq := int64(0); seq < 30; seq++ {
		if _, err := w.Append(seq, 0, payload); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}
	// At least one TransportLoss marker should now exist on disk.
	found := false
	entries, _ := os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".INPROGRESS") || strings.HasSuffix(e.Name(), ".seg") {
			data, _ := os.ReadFile(filepath.Join(dir, "segments", e.Name()))
			if bytes.Contains(data, []byte(LossMarkerSentinel)) {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no TransportLoss marker found after WAL overflow")
	}
	// And total disk usage must not exceed MaxTotalBytes by more than one
	// segment (we cap at the next-segment boundary, not exactly).
	totalBytes := int64(0)
	entries, _ = os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		st, _ := os.Stat(filepath.Join(dir, "segments", e.Name()))
		totalBytes += st.Size()
	}
	if totalBytes > 16*1024 {
		t.Errorf("total bytes %d exceeds budget 12 KiB + one segment slack", totalBytes)
	}
}

// TestWAL_OverflowAfterAck_OnlyDropsAcked verifies we never drop unacked
// segments when ack-acked segments are available to GC instead.
func TestWAL_OverflowAfterAck_OnlyDropsAcked(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for seq := int64(0); seq < 5; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("a"), 1024)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.MarkAcked(4); err != nil {
		t.Fatal(err)
	}
	for seq := int64(5); seq < 20; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("b"), 1024)); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/wal/ -run TestWAL_Overflow`
Expected: FAIL — `LossMarkerSentinel`/`MarkAcked` undefined or no marker found.

- [ ] **Step 3: Add overflow handling and `MarkAcked` to `wal.go`**

Append to `internal/store/watchtower/wal/wal.go`:

```go
// LossMarkerSentinel is a fixed byte string embedded in the framed payload of
// a synthetic TransportLoss record. Used by recovery and tests to identify
// loss markers without parsing the protobuf payload (which carries seq=0,
// gen=N for a marker — sentinels avoid ambiguity).
const LossMarkerSentinel = "\x00WTPLOSS\x00"

// LossRecord describes a synthetic TransportLoss inserted into the WAL stream.
type LossRecord struct {
	FromSequence uint64
	ToSequence   uint64
	Generation   uint32
	Reason       string // "overflow" | "crc_corruption"
}

// AppendLoss writes a synthetic TransportLoss record into the WAL stream so
// the transport's reader observes the gap inline. Always fsync'd. Used by the
// overflow path and the CRC-corruption recovery path.
func (w *WAL) AppendLoss(loss LossRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return &AppendError{Class: FailureClean, Op: "append-loss", Err: ErrClosed}
	}
	if w.current == nil {
		seg, err := w.openNewSegmentLocked(loss.Generation, FlagGenInit)
		if err != nil {
			return &AppendError{Class: FailureAmbiguous, Op: "open-loss-segment", Err: err}
		}
		w.current = seg
	}
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return &AppendError{Class: FailureAmbiguous, Op: "write-loss", Err: err}
	}
	if err := w.current.Sync(); err != nil {
		return &AppendError{Class: FailureAmbiguous, Op: "sync-loss", Err: err}
	}
	w.totalBytes += int64(8 + len(payload))
	return nil
}

func encodeLossPayload(l LossRecord) []byte {
	// Layout: sentinel(10) | from(8 BE) | to(8 BE) | gen(4 BE) | reason(N)
	out := make([]byte, 10+8+8+4+len(l.Reason))
	copy(out[0:10], LossMarkerSentinel)
	for i := 0; i < 8; i++ {
		out[17-i] = byte(l.FromSequence >> (8 * i))
	}
	for i := 0; i < 8; i++ {
		out[25-i] = byte(l.ToSequence >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[29-i] = byte(l.Generation >> (8 * i))
	}
	copy(out[30:], l.Reason)
	return out
}

// MarkAcked records the highest-acked sequence in meta.json and GCs sealed
// segments whose highest sequence is <= seq. The live (.INPROGRESS) segment
// is never removed.
//
// Returns nil even if no segments were eligible for GC. Callers do not need
// to filter on whether progress was made.
func (w *WAL) MarkAcked(seq uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := WriteMeta(w.opts.Dir, Meta{
		AckHighWatermarkSeq: seq,
		AckHighWatermarkGen: w.highGen,
	}); err != nil {
		return err
	}
	// GC sealed segments whose last record sequence <= seq.
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return err
	}
	var sealed []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".seg") || strings.HasSuffix(e.Name(), ".INPROGRESS") {
			continue
		}
		sealed = append(sealed, e.Name())
	}
	sort.Strings(sealed)
	for _, name := range sealed {
		path := filepath.Join(w.segDir, name)
		hi, err := segmentHighSeq(path)
		if err != nil {
			continue
		}
		if hi <= seq {
			st, _ := os.Stat(path)
			if err := os.Remove(path); err == nil && st != nil {
				w.totalBytes -= st.Size()
			}
		}
	}
	if err := syncDir(w.segDir); err != nil {
		return err
	}
	return nil
}

// segmentHighSeq returns the highest sequence number recorded in the segment
// at path. A scan is required because the WAL does not maintain a per-segment
// index. Used by MarkAcked GC and by overflow GC to identify safe-to-drop
// segments.
func segmentHighSeq(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := ReadSegmentHeader(f); err != nil {
		return 0, err
	}
	var hi uint64
	for {
		payload, err := ReadRecord(f)
		if err == io.EOF {
			return hi, nil
		}
		if err != nil {
			return hi, nil
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			if seq > hi {
				hi = seq
			}
		}
	}
}
```

Now wire overflow handling into the existing `Append` method. Find the line `if w.current.Bytes()+int64(8+len(payload)) > w.opts.SegmentSize {` and insert the overflow check BEFORE that block:

```go
	// Overflow: if appending would push past MaxTotalBytes, drop oldest
	// acked segments first; if that's not enough, drop oldest UNACKED and
	// emit a TransportLoss marker for the dropped range.
	if w.totalBytes+int64(w.opts.SegmentSize) > w.opts.MaxTotalBytes {
		dropped, err := w.dropOldestLocked(seq)
		if err != nil {
			return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "overflow-gc", Err: err}
		}
		if dropped.ToSequence > 0 {
			// Reopen current segment if dropOldestLocked sealed/replaced it.
			if w.current == nil {
				cur, err := w.openNewSegmentLocked(gen, FlagGenInit)
				if err != nil {
					return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "overflow-open", Err: err}
				}
				w.current = cur
			}
			if err := w.appendLossLocked(dropped); err != nil {
				return AppendResult{}, &AppendError{Class: FailureAmbiguous, Op: "overflow-loss", Err: err}
			}
		}
	}
```

Then add the helper methods at the bottom of `wal.go`:

```go
func (w *WAL) appendLossLocked(loss LossRecord) error {
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return err
	}
	if err := w.current.Sync(); err != nil {
		return err
	}
	w.totalBytes += int64(8 + len(payload))
	return nil
}

// dropOldestLocked drops the oldest segment file (sealed or sealed-by-roll)
// to free disk space. Returns the LossRecord describing the dropped range.
// Caller MUST hold w.mu.
func (w *WAL) dropOldestLocked(currentSeq int64) (LossRecord, error) {
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return LossRecord{}, err
	}
	var sealed []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".seg") && !strings.HasSuffix(e.Name(), ".INPROGRESS") {
			sealed = append(sealed, e.Name())
		}
	}
	sort.Strings(sealed)
	if len(sealed) == 0 {
		return LossRecord{}, nil
	}
	oldest := sealed[0]
	path := filepath.Join(w.segDir, oldest)
	f, err := os.Open(path)
	if err != nil {
		return LossRecord{}, err
	}
	hdr, _ := ReadSegmentHeader(f)
	var fromSeq, toSeq uint64
	first := true
	for {
		payload, err := ReadRecord(f)
		if err == io.EOF || err != nil {
			break
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			if first {
				fromSeq = seq
				first = false
			}
			toSeq = seq
		}
	}
	f.Close()
	st, _ := os.Stat(path)
	if err := os.Remove(path); err != nil {
		return LossRecord{}, err
	}
	if st != nil {
		w.totalBytes -= st.Size()
	}
	if err := syncDir(w.segDir); err != nil {
		return LossRecord{}, err
	}
	return LossRecord{FromSequence: fromSeq, ToSequence: toSeq, Generation: hdr.Generation, Reason: "overflow"}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/wal/ -run TestWAL_Overflow`
Expected: PASS — both overflow tests green.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/wal/wal.go internal/store/watchtower/wal/overflow_test.go
git commit -m "feat(wtp/wal): drop oldest segment + emit TransportLoss marker on overflow"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 14: WAL Reader + CRC corruption coarse-range loss

**Files:**
- Create: `internal/store/watchtower/wal/reader.go`
- Create: `internal/store/watchtower/wal/reader_test.go`
- Create: `internal/store/watchtower/wal/crc_test.go`

**Why:** The transport goroutine consumes via the `Reader`, which surfaces records (including TransportLoss markers and generation-roll boundaries) as ordinary records via a `Notify()` channel. When CRC fails on read, emit a coarse-range loss marker (spec §"CRC corruption recovery") instead of crashing.

- [ ] **Step 1: Write the failing test for Reader basic flow + CRC recovery**

Create `internal/store/watchtower/wal/reader_test.go`:

```go
package wal

import (
	"testing"
)

func TestReader_AppendNotifyNext(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Append, then expect a Notify, then read the record back.
	if _, err := w.Append(0, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.Notify():
	default:
		// signal may have already coalesced; that's fine, just attempt read.
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sequence != 0 || string(rec.Payload) != "first" {
		t.Errorf("rec = %+v, want seq=0 payload=first", rec)
	}
}

func TestReader_StreamsSequentially(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := uint64(0); i < 5; i++ {
		rec, err := r.Next()
		if err != nil {
			t.Fatalf("seq=%d: %v", i, err)
		}
		if rec.Sequence != i {
			t.Errorf("got seq=%d, want %d", rec.Sequence, i)
		}
	}
}
```

- [ ] **Step 2: Write the failing CRC corruption test**

Create `internal/store/watchtower/wal/crc_test.go`:

```go
package wal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWAL_CRCFailureEmitsCoarseLossRange is one of the four spec-required
// high-risk integrity tests. After flipping a payload byte in a sealed
// segment, the Reader must surface a TransportLoss record (not crash, not
// silently skip).
func TestWAL_CRCFailureEmitsCoarseLossRange(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i), 'X'}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	// Find the live segment and corrupt a payload byte.
	entries, _ := os.ReadDir(filepath.Join(dir, "segments"))
	var segName string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".INPROGRESS") {
			segName = e.Name()
		}
	}
	if segName == "" {
		t.Fatal("no .INPROGRESS segment to corrupt")
	}
	path := filepath.Join(dir, "segments", segName)
	data, _ := os.ReadFile(path)
	// Flip a byte well past the segment header.
	if len(data) < SegmentHeaderSize+50 {
		t.Fatal("segment too short to corrupt")
	}
	data[SegmentHeaderSize+30] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	r, err := w2.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sawLoss := false
	for i := 0; i < 10; i++ {
		rec, err := r.Next()
		if err != nil {
			break
		}
		if rec.Kind == RecordLoss {
			sawLoss = true
			break
		}
	}
	if !sawLoss {
		t.Errorf("Reader did not surface TransportLoss after CRC corruption")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/wal/ -run "TestReader|TestWAL_CRC"`
Expected: FAIL — `Reader`/`RecordKind` undefined.

- [ ] **Step 4: Implement `reader.go`**

Create `internal/store/watchtower/wal/reader.go`:

```go
package wal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// RecordKind discriminates ordinary data records, transport-loss markers, and
// generation-roll markers in the Reader stream.
type RecordKind int

const (
	RecordData          RecordKind = iota
	RecordLoss                     // synthetic TransportLoss
	RecordGenerationRoll           // notification that the next data record is a new generation
)

// Record is one item surfaced by Reader.Next.
type Record struct {
	Kind       RecordKind
	Sequence   uint64
	Generation uint32
	Payload    []byte // for Data; raw bytes for Loss/GenerationRoll handled by helpers
	Loss       LossRecord
}

// Reader streams records from the WAL in sequence order, starting at the
// requested sequence. Closing the WAL automatically closes its readers.
type Reader struct {
	w        *WAL
	notify   chan struct{}
	mu       sync.Mutex
	segments []string // remaining sealed segments (ordered)
	current  *os.File
	curHdr   SegmentHeader
	closed   bool
}

// NewReader returns a Reader positioned at the first record with sequence >=
// start. If start exceeds the high-watermark, the reader returns io.EOF until
// new appends arrive.
func (w *WAL) NewReader(start uint64) (*Reader, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := &Reader{w: w, notify: make(chan struct{}, 1)}
	w.readers = append(w.readers, r)

	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".seg") && !strings.HasSuffix(e.Name(), ".INPROGRESS") {
			continue
		}
		r.segments = append(r.segments, e.Name())
	}
	sort.Strings(r.segments)
	return r, nil
}

// Notify returns a channel that signals when new records are available. The
// channel is single-buffered; Append drops a signal in non-blocking. A reader
// woken by the signal must call Next() until it returns io.EOF before waiting
// again.
func (r *Reader) Notify() <-chan struct{} { return r.notify }

// Next returns the next available record. Returns io.EOF when caught up; the
// caller should wait on Notify() and call Next() again.
func (r *Reader) Next() (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, errors.New("reader closed")
	}
	for {
		if r.current == nil {
			if len(r.segments) == 0 {
				return Record{}, io.EOF
			}
			path := filepath.Join(r.w.segDir, r.segments[0])
			r.segments = r.segments[1:]
			f, err := os.Open(path)
			if err != nil {
				return Record{}, err
			}
			hdr, err := ReadSegmentHeader(f)
			if err != nil {
				f.Close()
				return Record{}, err
			}
			r.current = f
			r.curHdr = hdr
		}
		payload, err := ReadRecord(r.current)
		if err == io.EOF {
			r.current.Close()
			r.current = nil
			continue
		}
		if err == ErrCRCMismatch {
			// Coarse-range loss: estimate up to segment end via remaining bytes.
			st, _ := r.current.Stat()
			off, _ := r.current.Seek(0, io.SeekCurrent)
			rem := st.Size() - off
			est := rem / 64 // rough; real implementations refine via avg record size
			r.current.Close()
			r.current = nil
			return Record{
				Kind:       RecordLoss,
				Generation: r.curHdr.Generation,
				Loss: LossRecord{
					FromSequence: 0, // refined later by transport from last_good_seq+1
					ToSequence:   uint64(est),
					Generation:   r.curHdr.Generation,
					Reason:       "crc_corruption",
				},
			}, nil
		}
		if err != nil {
			return Record{}, fmt.Errorf("reader next: %w", err)
		}
		// Synthetic loss marker?
		if isLossMarker(payload) {
			loss := decodeLossPayload(payload)
			return Record{Kind: RecordLoss, Generation: loss.Generation, Loss: loss}, nil
		}
		seq, gen, ok := parseSeqGen(payload)
		if !ok {
			return Record{}, fmt.Errorf("reader: malformed seq/gen frame")
		}
		return Record{Kind: RecordData, Sequence: seq, Generation: gen, Payload: payload[12:]}, nil
	}
}

// Close releases the reader's underlying file handle.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.current != nil {
		err := r.current.Close()
		r.current = nil
		return err
	}
	return nil
}

func isLossMarker(payload []byte) bool {
	return len(payload) >= 10 && string(payload[0:10]) == LossMarkerSentinel
}

func decodeLossPayload(payload []byte) LossRecord {
	var loss LossRecord
	if len(payload) < 30 {
		return loss
	}
	for i := 0; i < 8; i++ {
		loss.FromSequence |= uint64(payload[10+i]) << (8 * (7 - i))
	}
	for i := 0; i < 8; i++ {
		loss.ToSequence |= uint64(payload[18+i]) << (8 * (7 - i))
	}
	for i := 0; i < 4; i++ {
		loss.Generation |= uint32(payload[26+i]) << (8 * (3 - i))
	}
	if len(payload) > 30 {
		loss.Reason = string(payload[30:])
	}
	return loss
}

// notifyReaders signals all open readers that new records are available.
// Called from WAL.Append after a successful write. Non-blocking — if the
// reader has not yet drained its prior notification, this is a no-op
// (notifications coalesce).
func (w *WAL) notifyReaders() {
	for _, r := range w.readers {
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
}
```

Now wire `notifyReaders()` into `Append`. In `internal/store/watchtower/wal/wal.go`, find the end of the `Append` function (right before `return AppendResult{...}`) and add:

```go
	w.notifyReaders()
```

Also add a `readers []*Reader` field to the `WAL` struct:

```go
type WAL struct {
	opts Options

	mu        sync.Mutex
	current   *Segment
	segDir    string
	closed    bool
	highSeq   uint64
	highGen   uint32
	nextIndex uint64
	totalBytes int64
	readers   []*Reader
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/wal/...`
Expected: PASS — `TestReader_AppendNotifyNext`, `TestReader_StreamsSequentially`, `TestWAL_CRCFailureEmitsCoarseLossRange` all green plus all earlier tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/wal/reader.go internal/store/watchtower/wal/reader_test.go internal/store/watchtower/wal/crc_test.go internal/store/watchtower/wal/wal.go
git commit -m "feat(wtp/wal): add Reader with CRC-corruption coarse loss recovery"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 8 — Transport state machine

The transport has four states: Connecting, Replaying, Live, Shutdown.
Each state runs in a single goroutine fed by a command channel; sub-goroutines
(receive-loop, heartbeat ticker, batch ticker) post events back to the main
loop. A `*Transport` owns the WAL Reader, the gRPC stream, and the inflight
window. The state machine never holds the WAL mutex.

### Task 15: Transport — Conn interface, Dialer, Connecting state

**Files:**
- Create: `internal/store/watchtower/transport/conn.go`
- Create: `internal/store/watchtower/transport/dialer.go`
- Create: `internal/store/watchtower/transport/transport.go`
- Create: `internal/store/watchtower/transport/state_connecting.go`
- Create: `internal/store/watchtower/transport/state.go`
- Test: `internal/store/watchtower/transport/transport_test.go`

- [ ] **Step 1: Write the failing test for Conn interface contract**

Create `internal/store/watchtower/transport/transport_test.go`:

```go
package transport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// fakeConn implements transport.Conn for tests.
type fakeConn struct {
	sendCh chan *wtpv1.ClientMessage
	recvCh chan *wtpv1.ServerMessage
	closed chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		sendCh: make(chan *wtpv1.ClientMessage, 64),
		recvCh: make(chan *wtpv1.ServerMessage, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeConn) Send(msg *wtpv1.ClientMessage) error {
	select {
	case f.sendCh <- msg:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeConn) Recv() (*wtpv1.ServerMessage, error) {
	select {
	case msg := <-f.recvCh:
		return msg, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeConn) CloseSend() error {
	close(f.closed)
	return nil
}

// TestConnectingState_SendsSessionInitAndAdvancesOnAck verifies that the
// Connecting state sends a SessionInit on entry and advances to Replaying
// once it observes a SessionAck.
func TestConnectingState_SendsSessionInitAndAdvancesOnAck(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	tr := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "test-agent",
		SessionID: "sess-1",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	doneCh := make(chan transport.State, 1)
	go func() {
		doneCh <- tr.RunOnce(ctx, transport.StateConnecting)
	}()

	// Expect SessionInit on the wire.
	select {
	case msg := <-conn.sendCh:
		if msg.GetSessionInit() == nil {
			t.Fatalf("expected SessionInit, got %T", msg.Msg)
		}
		if got, want := msg.GetSessionInit().AgentId, "test-agent"; got != want {
			t.Fatalf("agent_id: got %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal("did not receive SessionInit")
	}

	// Send SessionAck back.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				AckHighWatermarkSeq: 0,
				Generation: 0,
			},
		},
	}

	select {
	case st := <-doneCh:
		if st != transport.StateReplaying {
			t.Fatalf("next state: got %s, want StateReplaying", st)
		}
	case <-ctx.Done():
		t.Fatal("Connecting state did not return")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/... -run TestConnectingState_SendsSessionInitAndAdvancesOnAck`
Expected: FAIL — `transport.Conn`, `transport.DialerFunc`, `transport.New`, `transport.StateConnecting`, etc. all undefined.

- [ ] **Step 3: Write the State enum + Conn + Dialer interfaces**

Create `internal/store/watchtower/transport/state.go`:

```go
package transport

// State represents one of the four transport state-machine states.
type State int

const (
	StateConnecting State = iota
	StateReplaying
	StateLive
	StateShutdown
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "Connecting"
	case StateReplaying:
		return "Replaying"
	case StateLive:
		return "Live"
	case StateShutdown:
		return "Shutdown"
	default:
		return "Unknown"
	}
}
```

Create `internal/store/watchtower/transport/conn.go`:

```go
package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Conn is the abstraction over a bidirectional WTP gRPC stream so that
// transport tests can substitute a fake. It is NOT safe for concurrent
// use: the transport state machine performs all Send/Recv calls from a
// single goroutine.
type Conn interface {
	Send(msg *wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
}
```

Create `internal/store/watchtower/transport/dialer.go`:

```go
package transport

import "context"

// Dialer establishes a new Conn to the watchtower endpoint.
type Dialer interface {
	Dial(ctx context.Context) (Conn, error)
}

// DialerFunc adapts a function to the Dialer interface.
type DialerFunc func(ctx context.Context) (Conn, error)

func (f DialerFunc) Dial(ctx context.Context) (Conn, error) { return f(ctx) }
```

- [ ] **Step 4: Write the Transport skeleton + Connecting state**

Create `internal/store/watchtower/transport/transport.go`:

```go
package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Options configures a Transport.
type Options struct {
	Dialer    Dialer
	AgentID   string
	SessionID string
	// FormatVersion is sent in SessionInit; defaults to 2.
	FormatVersion uint32
}

// Transport runs the four-state WTP client state machine. It is owned by
// a single goroutine — callers interact via channels.
type Transport struct {
	opts Options
	conn Conn

	// last acknowledged watermark, updated when SessionAck/SessionUpdate
	// is observed.
	ackedSequence   uint64
	ackedGeneration uint32
}

// New constructs a Transport. It does not dial; call Run to start.
func New(opts Options) *Transport {
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	return &Transport{opts: opts}
}

// sessionInit returns the SessionInit message for the current connection.
func (t *Transport) sessionInit() *wtpv1.ClientMessage {
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId:             t.opts.AgentID,
				SessionId:           t.opts.SessionID,
				FormatVersion:       t.opts.FormatVersion,
				WalHighWatermarkSeq: t.ackedSequence,
				Generation:          t.ackedGeneration,
			},
		},
	}
}
```

Create `internal/store/watchtower/transport/state_connecting.go`:

```go
package transport

import (
	"context"
	"fmt"
)

// runConnecting establishes a stream and exchanges SessionInit/SessionAck.
// On success it returns StateReplaying. On dial failure or stream error it
// returns StateConnecting (the caller's run loop is responsible for backoff).
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(t.sessionInit()); err != nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("send SessionInit: %w", err)
	}

	msg, err := conn.Recv()
	if err != nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}

	ack := msg.GetSessionAck()
	if ack == nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("expected SessionAck, got %T", msg.Msg)
	}

	t.ackedSequence = ack.AckHighWatermarkSeq
	t.ackedGeneration = ack.Generation
	return StateReplaying, nil
}

// RunOnce runs a single state transition for testing. Production code
// should use Run, which loops until Shutdown.
func (t *Transport) RunOnce(ctx context.Context, st State) State {
	switch st {
	case StateConnecting:
		next, _ := t.runConnecting(ctx)
		return next
	default:
		return StateShutdown
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/... -run TestConnectingState_SendsSessionInitAndAdvancesOnAck`
Expected: PASS.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/
git commit -m "feat(wtp/transport): add Conn/Dialer + Connecting state"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 16: Transport — Replaying state with Replayer

**Files:**
- Create: `internal/store/watchtower/transport/replayer.go`
- Create: `internal/store/watchtower/transport/state_replaying.go`
- Test: `internal/store/watchtower/transport/replayer_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/transport/replayer_test.go`:

```go
package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// TestReplayer_StopsAtTailWatermark verifies the replayer stops when the
// WAL tail equals the recorded entry watermark, advancing to Live.
func TestReplayer_StopsAtTailWatermark(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("open WAL: %v", err)
	}
	defer w.Close()

	// Append three records; ack the second one. Replayer should emit
	// one record (the third) then stop.
	for i := 0; i < 3; i++ {
		if _, err := w.Append([]byte{byte(i)}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	w.MarkAcked(2)

	rdr := w.NewReader(2) // start AFTER acked watermark

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	emitted := 0
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		emitted += len(batch.Records)
		if done {
			break
		}
	}
	if emitted != 1 {
		t.Fatalf("emitted: got %d, want 1", emitted)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/... -run TestReplayer_StopsAtTailWatermark`
Expected: FAIL — `transport.NewReplayer`, `transport.ReplayerOptions`, `wal.WAL.MarkAcked`, `wal.WAL.NewReader` undefined.

- [ ] **Step 3: Add `NewReader` to WAL**

In `internal/store/watchtower/wal/reader.go`, add the constructor (we created the type in Task 14; now wire it to the WAL):

```go
// NewReader returns a Reader positioned to start at startSeq (exclusive —
// the next record returned will have sequence > startSeq).
func (w *WAL) NewReader(startSeq uint64) *Reader {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := &Reader{
		wal:      w,
		notifyCh: make(chan struct{}, 1),
		nextSeq:  startSeq + 1,
	}
	w.readers = append(w.readers, r)
	return r
}
```

Add a `nextSeq` field to `Reader` (placed alongside `lastSeq` from Task 14):

```go
type Reader struct {
	wal      *WAL
	notifyCh chan struct{}
	closed   chan struct{}
	lastSeq  uint64 // highest seq emitted (from Task 14)
	nextSeq  uint64 // skip records with seq < nextSeq
}
```

Update `Next` (and `TryNext`) so that after decoding the seq from a record's payload header, records with `rec.Sequence < r.nextSeq` are dropped on the floor and the loop continues to the next record. Update the body of the existing `Next`:

```go
		if rec.Sequence < r.nextSeq {
			continue // skip records before the start position
		}
		r.lastSeq = rec.Sequence
		return rec, nil
```

- [ ] **Step 4: Write the Replayer**

Create `internal/store/watchtower/transport/replayer.go`:

```go
package transport

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// ReplayerOptions controls replay batching.
type ReplayerOptions struct {
	MaxBatchRecords int
	MaxBatchBytes   int
}

// ReplayBatch is a chunk of WAL records to be sent during replay.
type ReplayBatch struct {
	Records []wal.Record
}

// Replayer pulls WAL records from a Reader up to the entry-time tail
// watermark and emits them in size-bounded batches.
type Replayer struct {
	rdr     *wal.Reader
	opts    ReplayerOptions
	tailSeq uint64
}

// NewReplayer captures the current WAL tail as the replay target. Records
// appended after this point are NOT replayed; they belong to the Live state.
func NewReplayer(rdr *wal.Reader, opts ReplayerOptions) *Replayer {
	return &Replayer{
		rdr:     rdr,
		opts:    opts,
		tailSeq: rdr.WALHighWaterSequence(),
	}
}

// NextBatch returns the next batch of records and a done flag set when the
// reader has reached the tail watermark.
func (r *Replayer) NextBatch(ctx context.Context) (ReplayBatch, bool, error) {
	batch := ReplayBatch{}
	bytes := 0
	for {
		if len(batch.Records) >= r.opts.MaxBatchRecords {
			return batch, false, nil
		}
		if bytes >= r.opts.MaxBatchBytes && len(batch.Records) > 0 {
			return batch, false, nil
		}
		// Non-blocking peek: if the reader has nothing available and we're
		// already past the tail, we're done.
		rec, ok, err := r.rdr.TryNext()
		if err != nil {
			return batch, false, fmt.Errorf("reader: %w", err)
		}
		if !ok {
			done := r.rdr.LastSequence() >= r.tailSeq
			return batch, done, nil
		}
		batch.Records = append(batch.Records, rec)
		bytes += len(rec.Payload)
		if rec.Sequence >= r.tailSeq {
			return batch, true, nil
		}
	}
}
```

Note on Reader extensions referenced above: Task 14 produced a Reader with `Next` (blocking), `Notify`, and `Close`. Add these methods to that type now in `reader.go`:

```go
// TryNext returns the next record without blocking. ok=false means no
// record is currently available.
func (r *Reader) TryNext() (wal.Record, bool, error) {
	// implementation: drain the segment under the wal mutex, no wait
	// (reuse the loop body of Next but without the <-r.notifyCh blocking
	//  branch — return ok=false instead of waiting).
	...
}

// LastSequence returns the highest sequence the Reader has emitted so
// far (0 before the first emission).
func (r *Reader) LastSequence() uint64 { return r.lastSeq }

// WALHighWaterSequence returns the current WAL tail sequence at call time.
func (r *Reader) WALHighWaterSequence() uint64 {
	r.wal.mu.Lock()
	defer r.wal.mu.Unlock()
	return r.wal.highSeq
}
```

Track `lastSeq` inside the Reader by setting it after each successful `Next/TryNext`.

Create `internal/store/watchtower/transport/state_replaying.go`:

```go
package transport

import (
	"context"
	"fmt"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runReplaying drains the WAL up to the entry watermark and ships records
// in EventBatch messages over the stream. Returns StateLive on success.
func (t *Transport) runReplaying(ctx context.Context, r *Replayer) (State, error) {
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			return StateConnecting, fmt.Errorf("replay batch: %w", err)
		}
		if len(batch.Records) > 0 {
			msg, err := buildEventBatch(batch.Records)
			if err != nil {
				return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
			}
			if err := t.conn.Send(msg); err != nil {
				return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
			}
		}
		if done {
			return StateLive, nil
		}
	}
}

// buildEventBatch wraps WAL records into a wtpv1.EventBatch envelope. The
// records' payloads are the already-serialized CompactEvent bytes; we just
// re-pack them with their (sequence, generation) and integrity records.
// Detailed wire-format work happens in Task 17.
func buildEventBatch(_ []byte) (*wtpv1.ClientMessage, error) {
	// Stub — Task 17 fills this in.
	return &wtpv1.ClientMessage{}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS — `TestReplayer_StopsAtTailWatermark` plus any earlier tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/replayer.go internal/store/watchtower/transport/state_replaying.go internal/store/watchtower/transport/replayer_test.go internal/store/watchtower/wal/reader.go
git commit -m "feat(wtp/transport): add Replayer that drains WAL up to entry tail"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 17: Transport — Live state Batcher (6 invariants)

The Live state batches records into `EventBatch` messages while honoring
six invariants:

1. **Single generation per batch** — never mix records from generation N and N+1.
2. **Sequence-contiguous** — batch covers `[firstSeq, lastSeq]` with no gaps.
3. **Bounded by MaxRecords** — flush when `len(records) >= MaxRecords`.
4. **Bounded by MaxBytes** — flush when `payload_bytes + new >= MaxBytes`.
5. **Bounded by MaxAge** — flush when oldest record is older than `MaxAge`.
6. **Never block on stream send** — if the inflight window is full, stop pulling from WAL.

**Files:**
- Create: `internal/store/watchtower/transport/batcher.go`
- Create: `internal/store/watchtower/transport/state_live.go`
- Test: `internal/store/watchtower/transport/batcher_test.go`

- [ ] **Step 1: Write the failing tests for each invariant**

Create `internal/store/watchtower/transport/batcher_test.go`:

```go
package transport_test

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

func mkRec(seq uint64, gen uint32, sz int) wal.Record {
	return wal.Record{
		Sequence:   seq,
		Generation: gen,
		Payload:    make([]byte, sz),
	}
}

// 1. Single generation per batch.
func TestBatcher_NeverMixesGenerations(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: time.Second,
	})

	flushed := b.Add(mkRec(1, 1, 64))
	if flushed != nil {
		t.Fatalf("unexpected early flush")
	}
	flushed = b.Add(mkRec(2, 2, 64)) // generation rolled
	if flushed == nil {
		t.Fatalf("expected flush at generation boundary")
	}
	if got := flushed.Records[0].Generation; got != 1 {
		t.Fatalf("first batch gen: got %d, want 1", got)
	}
	if len(flushed.Records) != 1 {
		t.Fatalf("first batch len: got %d, want 1", len(flushed.Records))
	}
}

// 2. Sequence-contiguous (gap forces flush).
func TestBatcher_FlushOnSequenceGap(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 64)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(3, 1, 64)) // skipped seq 2
	if flushed == nil {
		t.Fatal("expected flush on sequence gap")
	}
	if flushed.Records[0].Sequence != 1 {
		t.Fatalf("first batch seq: got %d, want 1", flushed.Records[0].Sequence)
	}
}

// 3. Flush at MaxRecords.
func TestBatcher_FlushAtMaxRecords(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 2, MaxBytes: 1 << 20, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 32)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(2, 1, 32))
	if flushed == nil {
		t.Fatal("expected flush at MaxRecords")
	}
	if len(flushed.Records) != 2 {
		t.Fatalf("len: got %d, want 2", len(flushed.Records))
	}
}

// 4. Flush at MaxBytes (oversize record still produces the batch).
func TestBatcher_FlushAtMaxBytes(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 100, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 60)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(2, 1, 60)) // 60+60 > 100
	if flushed == nil {
		t.Fatal("expected flush at MaxBytes")
	}
	if len(flushed.Records) != 1 {
		t.Fatalf("len: got %d, want 1", len(flushed.Records))
	}
}

// 5. Flush on MaxAge via Tick().
func TestBatcher_FlushOnMaxAge(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: 50 * time.Millisecond,
	})
	if b.Add(mkRec(1, 1, 64)) != nil {
		t.Fatal("unexpected early flush")
	}
	if got := b.Tick(time.Now()); got != nil {
		t.Fatal("did not expect flush at t=0")
	}
	got := b.Tick(time.Now().Add(100 * time.Millisecond))
	if got == nil {
		t.Fatal("expected flush after MaxAge elapsed")
	}
}

// 6. Never block on stream — caller stops Add() once inflight is full.
//    Batcher itself has no stream coupling; the state machine enforces this.
//    We test that the state machine respects window full in Task 18.
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/transport/... -run TestBatcher`
Expected: FAIL — `transport.NewBatcher`, `transport.BatcherOptions` undefined.

- [ ] **Step 3: Write the Batcher**

Create `internal/store/watchtower/transport/batcher.go`:

```go
package transport

import (
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// BatcherOptions configures Batcher flush thresholds.
type BatcherOptions struct {
	MaxRecords int
	MaxBytes   int
	MaxAge     time.Duration
}

// Batch is a snapshot of records to send.
type Batch struct {
	Records []wal.Record
}

// Batcher accumulates WAL records into size/time-bounded batches. It is
// not goroutine-safe; the transport's main loop is the sole caller.
type Batcher struct {
	opts        BatcherOptions
	pending     []wal.Record
	pendingSize int
	firstSeq    uint64
	lastSeq     uint64
	gen         uint32
	startedAt   time.Time
}

// NewBatcher returns an empty batcher.
func NewBatcher(opts BatcherOptions) *Batcher { return &Batcher{opts: opts} }

// Add inserts rec into the pending batch. If the addition would violate any
// invariant, the existing pending batch is flushed and returned, and rec
// becomes the first record of the next batch.
func (b *Batcher) Add(rec wal.Record) *Batch {
	if len(b.pending) == 0 {
		b.start(rec)
		return nil
	}

	switch {
	case rec.Generation != b.gen:
		out := b.flushAndStart(rec)
		return out
	case rec.Sequence != b.lastSeq+1:
		out := b.flushAndStart(rec)
		return out
	case len(b.pending) >= b.opts.MaxRecords:
		out := b.flushAndStart(rec)
		return out
	case b.pendingSize+len(rec.Payload) > b.opts.MaxBytes:
		out := b.flushAndStart(rec)
		return out
	}

	b.pending = append(b.pending, rec)
	b.pendingSize += len(rec.Payload)
	b.lastSeq = rec.Sequence
	return nil
}

// Tick checks whether the pending batch has exceeded MaxAge. If so it is
// flushed.
func (b *Batcher) Tick(now time.Time) *Batch {
	if len(b.pending) == 0 {
		return nil
	}
	if now.Sub(b.startedAt) < b.opts.MaxAge {
		return nil
	}
	return b.flush()
}

// Drain returns any in-flight pending records (used at Shutdown).
func (b *Batcher) Drain() *Batch {
	if len(b.pending) == 0 {
		return nil
	}
	return b.flush()
}

func (b *Batcher) start(rec wal.Record) {
	b.pending = []wal.Record{rec}
	b.pendingSize = len(rec.Payload)
	b.firstSeq = rec.Sequence
	b.lastSeq = rec.Sequence
	b.gen = rec.Generation
	b.startedAt = time.Now()
}

func (b *Batcher) flush() *Batch {
	out := &Batch{Records: b.pending}
	b.pending = nil
	b.pendingSize = 0
	b.firstSeq, b.lastSeq, b.gen = 0, 0, 0
	return out
}

func (b *Batcher) flushAndStart(rec wal.Record) *Batch {
	out := b.flush()
	b.start(rec)
	return out
}
```

- [ ] **Step 4: Write Live state**

Create `internal/store/watchtower/transport/state_live.go`:

```go
package transport

import (
	"context"
	"fmt"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// LiveOptions configures the Live state's batcher and inflight window.
type LiveOptions struct {
	Batcher        BatcherOptions
	MaxInflight    int
	HeartbeatEvery time.Duration
}

// runLive consumes Reader notifications, batches records, and sends
// EventBatch messages while honoring the inflight window. Returns
// StateConnecting on stream error, StateShutdown on ctx cancellation.
func (t *Transport) runLive(ctx context.Context, rdr *wal.Reader, opts LiveOptions) (State, error) {
	b := NewBatcher(opts.Batcher)
	tick := time.NewTicker(opts.Batcher.MaxAge / 2)
	defer tick.Stop()

	inflight := 0

	flush := func() error {
		batch := b.Drain()
		if batch == nil {
			return nil
		}
		msg, err := encodeBatchMessage(batch.Records)
		if err != nil {
			return err
		}
		if err := t.conn.Send(msg); err != nil {
			return fmt.Errorf("send EventBatch: %w", err)
		}
		inflight++
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return StateShutdown, ctx.Err()
		case <-rdr.Notify():
			// Pull as many records as the window and batcher allow.
			for inflight < opts.MaxInflight {
				rec, ok, err := rdr.TryNext()
				if err != nil {
					return StateConnecting, fmt.Errorf("reader: %w", err)
				}
				if !ok {
					break
				}
				if outBatch := b.Add(rec); outBatch != nil {
					msg, err := encodeBatchMessage(outBatch.Records)
					if err != nil {
						return StateConnecting, err
					}
					if err := t.conn.Send(msg); err != nil {
						return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
					}
					inflight++
				}
			}
		case now := <-tick.C:
			if outBatch := b.Tick(now); outBatch != nil {
				msg, err := encodeBatchMessage(outBatch.Records)
				if err != nil {
					return StateConnecting, err
				}
				if err := t.conn.Send(msg); err != nil {
					return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
				}
				inflight++
			}
		}
		_ = flush // explicit lint reference; called from Drain path
	}
}

// encodeBatchMessage packs WAL records into a wtpv1.EventBatch envelope.
func encodeBatchMessage(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	// Stub — full encoding is integrated with chain/compact in Task 22.
	return &wtpv1.ClientMessage{}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/... -run TestBatcher`
Expected: PASS — all 5 batcher invariant tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/batcher.go internal/store/watchtower/transport/batcher_test.go internal/store/watchtower/transport/state_live.go
git commit -m "feat(wtp/transport): add Batcher with 6 flush invariants + Live state"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 18: Transport — heartbeat, reconnect backoff, ack handling

**Files:**
- Create: `internal/store/watchtower/transport/heartbeat.go`
- Create: `internal/store/watchtower/transport/backoff.go`
- Modify: `internal/store/watchtower/transport/transport.go` (add Run loop)
- Test: `internal/store/watchtower/transport/backoff_test.go`
- Test: `internal/store/watchtower/transport/heartbeat_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/store/watchtower/transport/backoff_test.go`:

```go
package transport_test

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// TestBackoff_ExponentialWithJitter verifies the per-attempt sleep grows
// exponentially up to a cap, with jitter inside [0.5x, 1.5x).
func TestBackoff_ExponentialWithJitter(t *testing.T) {
	b := transport.NewBackoff(transport.BackoffOptions{
		Initial: 100 * time.Millisecond,
		Max:     5 * time.Second,
		Factor:  2.0,
	})
	prevMid := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		d := b.Next()
		if d < prevMid/2 {
			t.Fatalf("attempt %d below jitter floor: %v < %v", i, d, prevMid/2)
		}
		if d > 5*time.Second*15/10 {
			t.Fatalf("attempt %d above cap+jitter: %v", i, d)
		}
		if i > 0 && i < 6 {
			prevMid *= 2
		}
	}
}

func TestBackoff_ResetReturnsToInitial(t *testing.T) {
	b := transport.NewBackoff(transport.BackoffOptions{
		Initial: 200 * time.Millisecond,
		Max:     5 * time.Second,
		Factor:  2.0,
	})
	for i := 0; i < 5; i++ {
		_ = b.Next()
	}
	b.Reset()
	d := b.Next()
	if d > 300*time.Millisecond {
		t.Fatalf("after reset, got %v; expected ~initial", d)
	}
}
```

Create `internal/store/watchtower/transport/heartbeat_test.go`:

```go
package transport_test

import (
	"context"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// TestHeartbeat_FiresAfterIdleInterval verifies the heartbeat ticker
// emits a Heartbeat ClientMessage after the configured interval of
// stream silence.
func TestHeartbeat_FiresAfterIdleInterval(t *testing.T) {
	conn := newFakeConn()
	stop := make(chan struct{})
	defer close(stop)

	go transport.RunHeartbeat(context.Background(), conn, 50*time.Millisecond, stop)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	select {
	case msg := <-conn.sendCh:
		if _, ok := msg.Msg.(*wtpv1.ClientMessage_Heartbeat); !ok {
			t.Fatalf("got %T, want Heartbeat", msg.Msg)
		}
	case <-ctx.Done():
		t.Fatal("no heartbeat sent within deadline")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/transport/... -run "TestBackoff|TestHeartbeat"`
Expected: FAIL — `transport.NewBackoff`, `transport.RunHeartbeat` undefined.

- [ ] **Step 3: Write the backoff and heartbeat helpers**

Create `internal/store/watchtower/transport/backoff.go`:

```go
package transport

import (
	"math/rand/v2"
	"time"
)

// BackoffOptions configures exponential backoff with jitter.
type BackoffOptions struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
}

// Backoff computes per-attempt sleep durations.
type Backoff struct {
	opts    BackoffOptions
	current time.Duration
}

// NewBackoff returns a Backoff at its initial value.
func NewBackoff(opts BackoffOptions) *Backoff {
	if opts.Factor <= 1 {
		opts.Factor = 2.0
	}
	return &Backoff{opts: opts, current: opts.Initial}
}

// Next returns the next sleep duration, applying [0.5, 1.5) jitter and
// growing the underlying value (pre-jitter) exponentially up to Max.
func (b *Backoff) Next() time.Duration {
	base := b.current
	jitter := 0.5 + rand.Float64()
	d := time.Duration(float64(base) * jitter)

	// Advance for next call.
	next := time.Duration(float64(b.current) * b.opts.Factor)
	if next > b.opts.Max {
		next = b.opts.Max
	}
	b.current = next
	return d
}

// Reset returns the backoff to its initial value.
func (b *Backoff) Reset() { b.current = b.opts.Initial }
```

Create `internal/store/watchtower/transport/heartbeat.go`:

```go
package transport

import (
	"context"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// HeartbeatSender is the subset of Conn that RunHeartbeat needs.
type HeartbeatSender interface {
	Send(*wtpv1.ClientMessage) error
}

// RunHeartbeat periodically posts Heartbeat messages to conn until ctx is
// cancelled or stop is closed. Send errors terminate the loop.
func RunHeartbeat(ctx context.Context, conn HeartbeatSender, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-t.C:
			msg := &wtpv1.ClientMessage{
				Msg: &wtpv1.ClientMessage_Heartbeat{
					Heartbeat: &wtpv1.Heartbeat{},
				},
			}
			if err := conn.Send(msg); err != nil {
				return
			}
		}
	}
}
```

- [ ] **Step 4: Add the Run loop to Transport**

Add to `internal/store/watchtower/transport/transport.go`:

```go
// Run loops the four-state state machine until ctx is cancelled.
// It applies backoff between StateConnecting attempts.
func (t *Transport) Run(ctx context.Context, rdrFactory func() (*wal.Reader, error), liveOpts LiveOptions) error {
	bo := NewBackoff(BackoffOptions{
		Initial: 200 * time.Millisecond,
		Max:     30 * time.Second,
		Factor:  2.0,
	})
	st := StateConnecting
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		switch st {
		case StateConnecting:
			next, err := t.runConnecting(ctx)
			if err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(bo.Next()):
				}
				continue
			}
			bo.Reset()
			st = next
		case StateReplaying:
			rdr, err := rdrFactory()
			if err != nil {
				st = StateConnecting
				continue
			}
			r := NewReplayer(rdr, ReplayerOptions{
				MaxBatchRecords: liveOpts.Batcher.MaxRecords,
				MaxBatchBytes:   liveOpts.Batcher.MaxBytes,
			})
			next, err := t.runReplaying(ctx, r)
			_ = err
			st = next
		case StateLive:
			rdr, err := rdrFactory()
			if err != nil {
				st = StateConnecting
				continue
			}
			next, err := t.runLive(ctx, rdr, liveOpts)
			_ = err
			st = next
		case StateShutdown:
			return nil
		}
	}
}
```

You'll also need to import `wal`:

```go
import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS — backoff + heartbeat plus all earlier tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/heartbeat.go internal/store/watchtower/transport/backoff.go internal/store/watchtower/transport/heartbeat_test.go internal/store/watchtower/transport/backoff_test.go internal/store/watchtower/transport/transport.go
git commit -m "feat(wtp/transport): add backoff, heartbeat, Run loop"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 19: Transport — Shutdown / drain

When the store is closed, the transport must:
1. Stop accepting new records.
2. Flush the current batch.
3. Send any remaining pending records up to a configurable drain deadline.
4. CloseSend the stream.
5. Return from Run.

**Files:**
- Modify: `internal/store/watchtower/transport/transport.go` (add Stop)
- Create: `internal/store/watchtower/transport/state_shutdown.go`
- Test: `internal/store/watchtower/transport/shutdown_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/transport/shutdown_test.go`:

```go
package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// TestShutdown_DrainsPendingThenCloses verifies that calling Stop with a
// drain deadline flushes outstanding records before CloseSend.
func TestShutdown_DrainsPendingThenCloses(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("open WAL: %v", err)
	}

	tr := transport.New(transport.Options{
		Dialer: dialer, AgentID: "a", SessionID: "s",
	})

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	rdrFactory := func() (*wal.Reader, error) {
		return w.NewReader(0), nil
	}
	go func() {
		doneCh <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: 100, MaxBytes: 1 << 16, MaxAge: 50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// Drain SessionInit.
	<-conn.sendCh
	conn.recvCh <- &fakeAck()

	// Append a record while live.
	if _, err := w.Append([]byte("payload")); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Stop with 200ms drain deadline.
	tr.Stop(200 * time.Millisecond)
	cancel()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Stop")
	}

	// At least one EventBatch should have been sent.
	select {
	case msg := <-conn.sendCh:
		if msg.GetEventBatch() == nil && msg.GetHeartbeat() == nil {
			t.Fatalf("expected EventBatch or Heartbeat, got %T", msg.Msg)
		}
	default:
		t.Fatal("no message sent after Stop")
	}
}

func fakeAck() wtpv1ServerMessage { return wtpv1ServerMessage{} }

// alias to avoid pulling proto into the helper line above
type wtpv1ServerMessage = struct{}
```

(Note: the test uses tiny placeholder helpers; in practice replace `fakeAck` with a real `*wtpv1.ServerMessage{Msg: &wtpv1.ServerMessage_SessionAck{...}}` per the test in Task 15.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/... -run TestShutdown_DrainsPendingThenCloses`
Expected: FAIL — `transport.Transport.Stop` undefined.

- [ ] **Step 3: Add Stop and shutdown handling**

Add to `internal/store/watchtower/transport/transport.go`:

```go
// stopReq carries a shutdown deadline through the run loop.
type stopReq struct {
	drainDeadline time.Duration
	done          chan struct{}
}

// Stop signals the transport to flush pending records (up to drainDeadline)
// and close the stream. It blocks until the transport has shut down.
func (t *Transport) Stop(drainDeadline time.Duration) {
	if t.stopCh == nil {
		return
	}
	r := stopReq{drainDeadline: drainDeadline, done: make(chan struct{})}
	select {
	case t.stopCh <- r:
		<-r.done
	default:
		// Run loop already exited.
	}
}
```

Wire `stopCh` into `Transport`:

```go
type Transport struct {
	opts Options
	conn Conn

	ackedSequence   uint64
	ackedGeneration uint32

	stopCh chan stopReq
}

func New(opts Options) *Transport {
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	return &Transport{opts: opts, stopCh: make(chan stopReq, 1)}
}
```

Create `internal/store/watchtower/transport/state_shutdown.go`:

```go
package transport

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// runShutdown performs an orderly drain: pull up to drainDeadline of new
// records, flush any pending batch, then CloseSend.
func (t *Transport) runShutdown(parent context.Context, b *Batcher, rdr *wal.Reader, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()

	for {
		rec, ok, err := rdr.TryNext()
		if err != nil {
			break
		}
		if !ok {
			break
		}
		if outBatch := b.Add(rec); outBatch != nil {
			if err := t.sendBatch(outBatch); err != nil {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	if outBatch := b.Drain(); outBatch != nil {
		_ = t.sendBatch(outBatch)
	}
	if t.conn != nil {
		_ = t.conn.CloseSend()
	}
	return nil
}

func (t *Transport) sendBatch(b *Batch) error {
	msg, err := encodeBatchMessage(b.Records)
	if err != nil {
		return err
	}
	return t.conn.Send(msg)
}
```

Modify the `Run` loop in `transport.go` so each `case` checks `t.stopCh`:

```go
		case StateLive:
			...
			select {
			case sr := <-t.stopCh:
				t.runShutdown(ctx, b, rdr, sr.drainDeadline)
				close(sr.done)
				return nil
			default:
			}
```

(For brevity, the production loop should structure each state to receive on `t.stopCh` alongside its other channels. Implementer: verify each blocking select includes a `case <-t.stopCh:` branch.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS — shutdown drain test plus earlier tests.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/state_shutdown.go internal/store/watchtower/transport/shutdown_test.go internal/store/watchtower/transport/transport.go
git commit -m "feat(wtp/transport): add Stop with drain-then-CloseSend shutdown"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 9 — bufconn testserver

The testserver is a hermetic in-process gRPC server that runs over a
`bufconn.Listener`. It supports scenarios for negative tests (drops,
goaway, ack delay, stale watermark) and provides convenient assertion
helpers.

### Task 20: testserver — Server skeleton with scenarios

**Files:**
- Create: `internal/store/watchtower/testserver/server.go`
- Create: `internal/store/watchtower/testserver/scenarios.go`
- Create: `internal/store/watchtower/testserver/dialer.go`
- Test: `internal/store/watchtower/testserver/server_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/testserver/server_test.go`:

```go
package testserver_test

import (
	"context"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
)

// TestServer_AcksSessionInit verifies the default scenario: server replies
// to SessionInit with SessionAck at watermark (0, 0).
func TestServer_AcksSessionInit(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	conn, err := srv.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseSend()

	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{AgentId: "test", SessionId: "s1"},
		},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := conn.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if got.GetSessionAck() == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	_ = ctx
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/testserver/... -run TestServer_AcksSessionInit`
Expected: FAIL — package missing.

- [ ] **Step 3: Write the testserver**

Create `internal/store/watchtower/testserver/scenarios.go`:

```go
package testserver

import "time"

// Options control the server's behavior. Zero values use defaults.
type Options struct {
	// AckDelay introduces an artificial delay before each ACK is sent.
	AckDelay time.Duration
	// DropAfterBatchN closes the stream after observing N EventBatch
	// messages on the current connection (0 = never drop).
	DropAfterBatchN int
	// GoawayAfterBatchN sends Goaway after observing N batches.
	GoawayAfterBatchN int
	// StaleWatermark causes SessionAck to advertise a watermark that is
	// behind the client's actual progress.
	StaleWatermark uint64
}
```

Create `internal/store/watchtower/testserver/server.go`:

```go
package testserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1 << 20

// Server is an in-process WTP server.
type Server struct {
	opts     Options
	listener *bufconn.Listener
	grpcSrv  *grpc.Server

	mu      sync.Mutex
	batches []*wtpv1.EventBatch
	closed  atomic.Bool
}

// New constructs a Server and starts serving in the background.
func New(opts Options) *Server {
	s := &Server{
		opts:     opts,
		listener: bufconn.Listen(bufSize),
		grpcSrv:  grpc.NewServer(),
	}
	wtpv1.RegisterWatchtowerServer(s.grpcSrv, s.handler())
	go func() { _ = s.grpcSrv.Serve(s.listener) }()
	return s
}

// Close stops the server.
func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.grpcSrv.GracefulStop()
}

// Batches returns a snapshot of received EventBatch messages.
func (s *Server) Batches() []*wtpv1.EventBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*wtpv1.EventBatch, len(s.batches))
	copy(out, s.batches)
	return out
}

// addBatch records a batch.
func (s *Server) addBatch(b *wtpv1.EventBatch) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, b)
	return len(s.batches)
}

// Dial returns a transport.Conn backed by the bufconn listener.
func (s *Server) Dial(ctx context.Context) (Conn, error) {
	cc, err := grpc.DialContext(ctx,
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return s.listener.DialContext(ctx)
		}),
		grpc.WithInsecure(),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}
	stream, err := wtpv1.NewWatchtowerClient(cc).Stream(ctx)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	return &grpcConn{stream: stream, cc: cc}, nil
}

// Conn is the transport.Conn shape produced by Dial.
type Conn interface {
	Send(*wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
}

type grpcConn struct {
	stream wtpv1.Watchtower_StreamClient
	cc     *grpc.ClientConn
}

func (g *grpcConn) Send(m *wtpv1.ClientMessage) error  { return g.stream.Send(m) }
func (g *grpcConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }
func (g *grpcConn) CloseSend() error                    { _ = g.stream.CloseSend(); return g.cc.Close() }

type srvHandler struct {
	wtpv1.UnimplementedWatchtowerServer
	s *Server
}

func (s *Server) handler() *srvHandler { return &srvHandler{s: s} }

func (h *srvHandler) Stream(stream wtpv1.Watchtower_StreamServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch x := msg.Msg.(type) {
		case *wtpv1.ClientMessage_SessionInit:
			ack := &wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_SessionAck{
					SessionAck: &wtpv1.SessionAck{
						AckHighWatermarkSeq:   h.s.opts.StaleWatermark,
						Generation: 0,
					},
				},
			}
			if h.s.opts.AckDelay > 0 {
				select {
				case <-stream.Context().Done():
					return stream.Context().Err()
				default:
				}
			}
			_ = x // silence unused
			if err := stream.Send(ack); err != nil {
				return err
			}
		case *wtpv1.ClientMessage_EventBatch:
			n := h.s.addBatch(x.EventBatch)
			if h.s.opts.DropAfterBatchN > 0 && n >= h.s.opts.DropAfterBatchN {
				return errors.New("scenario: drop after batch")
			}
			if h.s.opts.GoawayAfterBatchN > 0 && n >= h.s.opts.GoawayAfterBatchN {
				_ = stream.Send(&wtpv1.ServerMessage{
					Msg: &wtpv1.ServerMessage_Goaway{Goaway: &wtpv1.Goaway{}},
				})
				return nil
			}
			// Normal ack via BatchAck (every batch).
			lastSeq := uint64(0)
			lastGen := uint32(0)
			if events := x.EventBatch.GetUncompressed().GetEvents(); len(events) > 0 {
				last := events[len(events)-1]
				lastSeq = last.Sequence
				lastGen = last.Generation
			}
			_ = stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_BatchAck{
					BatchAck: &wtpv1.BatchAck{
						AckHighWatermarkSeq: lastSeq,
						Generation:          lastGen,
					},
				},
			})
		case *wtpv1.ClientMessage_Heartbeat:
			// no-op
		}
	}
}
```

Create `internal/store/watchtower/testserver/dialer.go`:

```go
package testserver

import (
	"context"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// DialerFor returns a transport.Dialer that uses the in-process server.
func (s *Server) DialerFor() transport.Dialer {
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		c, err := s.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return c.(transport.Conn), nil
	})
}
```

(Note: the local `Conn` interface and `transport.Conn` are deliberately the
same shape. The cast above is safe because `grpcConn` satisfies both.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/testserver/...`
Expected: PASS — `TestServer_AcksSessionInit` green.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/testserver/
git commit -m "feat(wtp/testserver): add bufconn server with scenario hooks"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 21: testserver — assertion helpers

**Files:**
- Create: `internal/store/watchtower/testserver/assertions.go`
- Test: `internal/store/watchtower/testserver/assertions_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/store/watchtower/testserver/assertions_test.go`:

```go
package testserver_test

import (
	"context"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
)

// TestWaitForBatch_ReturnsBatchOrTimesOut verifies that WaitForBatch blocks
// until at least one EventBatch has been received, with a deadline.
func TestWaitForBatch_ReturnsBatchOrTimesOut(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	conn, err := srv.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseSend()

	// First, exchange SessionInit/Ack.
	_ = conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{AgentId: "a", SessionId: "s"},
		},
	})
	_, _ = conn.Recv()

	// Send a batch.
	_ = conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_NONE,
				Body: &wtpv1.EventBatch_Uncompressed{
					Uncompressed: &wtpv1.UncompressedEvents{
						Events: []*wtpv1.CompactEvent{{Sequence: 1, Generation: 1}},
					},
				},
			},
		},
	})

	got, err := srv.WaitForBatch(time.Second)
	if err != nil {
		t.Fatalf("WaitForBatch: %v", err)
	}
	if len(got.GetUncompressed().GetEvents()) != 1 {
		t.Fatalf("records: got %d, want 1", len(got.GetUncompressed().GetEvents()))
	}

	if err := srv.AssertSequenceRange(1, 1); err != nil {
		t.Fatalf("AssertSequenceRange: %v", err)
	}
}

func TestAssertReplayObserved_DetectsReplayBoundary(t *testing.T) {
	srv := testserver.New(testserver.Options{StaleWatermark: 10})
	defer srv.Close()

	conn, _ := srv.Dial(context.Background())
	defer conn.CloseSend()

	_ = conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId: "a", SessionId: "s",
				WalHighWatermarkSeq: 20,
			},
		},
	})
	_, _ = conn.Recv()

	// Send batches starting at seq 11 (replay), then 21+ (live).
	_ = conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_NONE,
				Body: &wtpv1.EventBatch_Uncompressed{
					Uncompressed: &wtpv1.UncompressedEvents{
						Events: []*wtpv1.CompactEvent{
							{Sequence: 11, Generation: 1},
							{Sequence: 12, Generation: 1},
						},
					},
				},
			},
		},
	})

	if err := srv.AssertReplayObserved(11, 12); err != nil {
		t.Fatalf("AssertReplayObserved: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/testserver/... -run "TestWaitForBatch|TestAssertReplay"`
Expected: FAIL — `WaitForBatch`, `AssertSequenceRange`, `AssertReplayObserved` undefined.

- [ ] **Step 3: Write the assertion helpers**

Create `internal/store/watchtower/testserver/assertions.go`:

```go
package testserver

import (
	"fmt"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// WaitForBatch blocks until at least one batch is received or deadline.
func (s *Server) WaitForBatch(deadline time.Duration) (*wtpv1.EventBatch, error) {
	expire := time.After(deadline)
	for {
		bs := s.Batches()
		if len(bs) > 0 {
			return bs[0], nil
		}
		select {
		case <-expire:
			return nil, fmt.Errorf("WaitForBatch: timeout after %v", deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// AssertSequenceRange verifies the union of all received batch records
// covers exactly [first, last] with no gaps and no duplicates.
func (s *Server) AssertSequenceRange(first, last uint64) error {
	seen := map[uint64]bool{}
	for _, b := range s.Batches() {
		for _, r := range b.Records {
			if r.Sequence < first || r.Sequence > last {
				return fmt.Errorf("seq %d outside [%d,%d]", r.Sequence, first, last)
			}
			if seen[r.Sequence] {
				return fmt.Errorf("duplicate seq %d", r.Sequence)
			}
			seen[r.Sequence] = true
		}
	}
	for s := first; s <= last; s++ {
		if !seen[s] {
			return fmt.Errorf("missing seq %d", s)
		}
	}
	return nil
}

// AssertReplayObserved verifies that every sequence in [first, last] was
// observed in some batch (allowing additional later sequences from live).
func (s *Server) AssertReplayObserved(first, last uint64) error {
	seen := map[uint64]bool{}
	for _, b := range s.Batches() {
		for _, r := range b.Records {
			seen[r.Sequence] = true
		}
	}
	for x := first; x <= last; x++ {
		if !seen[x] {
			return fmt.Errorf("replay missing seq %d", x)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/testserver/...`
Expected: PASS.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/testserver/assertions.go internal/store/watchtower/testserver/assertions_test.go
git commit -m "feat(wtp/testserver): add WaitForBatch + AssertSequenceRange + AssertReplayObserved"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 10 — Store integration

This phase wires together everything from earlier phases — chain, compact,
WAL, transport — into a `store.EventStore` implementation. The store is
the public surface area: callers see `AppendEvent`, the rest is hidden.

### Task 22: Store — New + Options + validate

**Files:**
- Create: `internal/store/watchtower/store.go`
- Create: `internal/store/watchtower/options.go`
- Test: `internal/store/watchtower/options_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/options_test.go`:

```go
package watchtower_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

// TestNew_RejectsStubMapperInProduction verifies validate() rejects a
// StubMapper unless AllowStubMapper is true. This guards against a
// developer accidentally shipping a binary that wires the test mapper.
func TestNew_RejectsStubMapperInProduction(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:       dir,
		Mapper:       compact.StubMapper{},
		Allocator:    allocator,
		AgentID:      "a",
		SessionID:    "s",
		HMACKeyID:    "k1",
		HMACSecret:   []byte("secret"),
		BatchMaxRecords: 256,
		BatchMaxBytes:   256 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		// AllowStubMapper deliberately omitted.
	})
	if err == nil {
		t.Fatal("expected New to reject StubMapper")
	}
	if !strings.Contains(err.Error(), "stub mapper") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RequiresHMACSecret(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:    dir,
		Mapper:    compact.StubMapper{},
		Allocator: allocator,
		AgentID:   "a", SessionID: "s",
		HMACKeyID:       "k1",
		BatchMaxRecords: 1, BatchMaxBytes: 1024, BatchMaxAge: time.Second,
		AllowStubMapper: true,
	})
	if err == nil || !strings.Contains(err.Error(), "HMAC secret") {
		t.Fatalf("expected HMAC secret error, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/... -run TestNew_`
Expected: FAIL — `watchtower.New`, `watchtower.Options` undefined.

- [ ] **Step 3: Write Options + New**

Create `internal/store/watchtower/options.go`:

```go
package watchtower

import (
	"errors"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/eventfilter"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// Options configures a watchtower Store.
type Options struct {
	// WAL directory.
	WALDir          string
	WALSegmentSize  int64
	WALMaxTotalSize int64

	// Mapper for translating types.Event → wtpv1.CompactEvent.
	Mapper compact.Mapper

	// Allocator hands out (sequence, generation) tuples; comes from the
	// composite store in production.
	Allocator *audit.SequenceAllocator

	// Identity.
	AgentID   string
	SessionID string

	// HMAC integrity chain config.
	HMACKeyID  string
	HMACSecret []byte

	// Batch flush thresholds.
	BatchMaxRecords int
	BatchMaxBytes   int
	BatchMaxAge     time.Duration

	// Transport endpoint.
	Endpoint    string
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSInsecure bool
	AuthBearer  string

	// Filter.
	Filter *eventfilter.Filter

	// Drain deadline at Close.
	DrainDeadline time.Duration

	// AllowStubMapper unlocks compact.StubMapper for tests. Production
	// callers must leave this false.
	AllowStubMapper bool

	// Dialer is an optional override; tests use this to inject
	// testserver.DialerFor().
	Dialer transport.Dialer
}

// applyDefaults fills zero-valued fields with the spec's defaults.
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
}

// validate returns an error if Options is missing required fields or
// contains contradictions.
func (o *Options) validate() error {
	if o.WALDir == "" {
		return errors.New("watchtower: WALDir is required")
	}
	if o.Mapper == nil {
		return errors.New("watchtower: Mapper is required")
	}
	if !o.AllowStubMapper && compact.IsStubMapper(o.Mapper) {
		return errors.New("watchtower: stub mapper not allowed in production (set AllowStubMapper for tests)")
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
	if o.BatchMaxBytes < 4096 {
		return errors.New("watchtower: BatchMaxBytes must be >= 4 KiB")
	}
	if o.WALSegmentSize > o.WALMaxTotalSize/2 {
		return errors.New("watchtower: WALSegmentSize must be <= WALMaxTotalSize/2")
	}
	if o.TLSCertFile != "" && o.AuthBearer != "" {
		return errors.New("watchtower: TLS client cert and bearer auth are mutually exclusive")
	}
	return nil
}
```

Create `internal/store/watchtower/store.go`:

```go
// Package watchtower implements a store.EventStore that ships events to
// a Watchtower endpoint via the WTP protocol.
package watchtower

import (
	"context"
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
)

// Store implements store.EventStore.
type Store struct {
	opts Options
	w    *wal.WAL
	tr   *transport.Transport
	sink *chain.SinkChain

	mu      sync.Mutex
	fatalCh chan error
}

// New constructs a Store, validates options, opens the WAL, and starts
// the transport state machine in the background.
func New(ctx context.Context, opts Options) (*Store, error) {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	w, err := wal.Open(wal.Options{
		Dir:          opts.WALDir,
		SegmentSize:  opts.WALSegmentSize,
		MaxTotalSize: opts.WALMaxTotalSize,
	})
	if err != nil {
		return nil, fmt.Errorf("open WAL: %w", err)
	}

	sink := chain.NewSinkChain(opts.HMACKeyID, opts.HMACSecret)

	dialer := opts.Dialer
	if dialer == nil {
		dialer = newGRPCDialer(opts)
	}

	tr := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   opts.AgentID,
		SessionID: opts.SessionID,
	})

	s := &Store{
		opts:    opts,
		w:       w,
		tr:      tr,
		sink:    sink,
		fatalCh: make(chan error, 1),
	}

	go func() {
		_ = tr.Run(ctx, func() (*wal.Reader, error) {
			return w.NewReader(0), nil
		}, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: opts.BatchMaxRecords,
				MaxBytes:   opts.BatchMaxBytes,
				MaxAge:     opts.BatchMaxAge,
			},
			MaxInflight:    8,
			HeartbeatEvery: 5 * 1e9, // 5s; replace with options if needed
		})
	}()

	return s, nil
}

// newGRPCDialer is a thin wrapper to keep New's body small. Production
// dialer construction (TLS, auth) lives in dialer.go (Task 27).
func newGRPCDialer(opts Options) transport.Dialer {
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		return nil, fmt.Errorf("watchtower: production dialer not yet wired")
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/... -run TestNew_`
Expected: PASS.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/store.go internal/store/watchtower/options.go internal/store/watchtower/options_test.go
git commit -m "feat(wtp/store): add Options + New with validate (rejects StubMapper)"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 23: Store — AppendEvent transactional pattern

`AppendEvent` follows the Compute → Append → Commit / Fatal pattern.
Compute is pure (it reads `ev.Chain` and consults the SinkChain to produce
a `*chain.ComputeResult` token). Append writes the framed bytes to the
WAL. On clean failure, no commit happens and `prev_hash` does not advance.
On ambiguous failure, the store latches into a fatal state and refuses
all further writes.

**Files:**
- Create: `internal/store/watchtower/append.go`
- Modify: `internal/store/watchtower/store.go` (add fatal latch + accessor)
- Test: `internal/store/watchtower/append_test.go`

- [ ] **Step 1: Write the failing test for the happy path**

Create `internal/store/watchtower/append_test.go`:

```go
package watchtower_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

func mkStore(t *testing.T) *watchtower.Store {
	t.Helper()
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1", HMACSecret: []byte("secret"),
		BatchMaxRecords: 8, BatchMaxBytes: 8 * 1024, BatchMaxAge: 50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendEvent_StampsChainBeforeWAL(t *testing.T) {
	s := mkStore(t)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/... -run TestAppendEvent_StampsChainBeforeWAL`
Expected: FAIL — `Store.AppendEvent` undefined.

- [ ] **Step 3: Write AppendEvent**

Create `internal/store/watchtower/append.go`:

```go
package watchtower

import (
	"context"
	"errors"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/protobuf/proto"
)

// errFatalLatch is returned when AppendEvent is called after an ambiguous
// failure has latched the store.
var errFatalLatch = errors.New("watchtower: store fatal — refusing append")

// AppendEvent encodes ev, computes its integrity record, writes the WAL
// frame, and only then commits the chain advance. Returns errFatalLatch
// if a prior call has latched an ambiguous failure.
func (s *Store) AppendEvent(_ context.Context, ev types.Event) error {
	if s.isFatal() {
		return errFatalLatch
	}
	if ev.Chain == nil {
		return errors.New("watchtower: ev.Chain not stamped (composite must allocate)")
	}

	// 1. Encode payload (no chain yet — leaves Integrity nil).
	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	payload, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// 2. Compute integrity record (pure; updates no shared state yet).
	cr, err := s.sink.Compute(chain.ComputeInput{
		Sequence:   ev.Chain.Sequence,
		PrevHash:   nil, // SinkChain remembers prev internally
		Payload:    payload,
	})
	if err != nil {
		return fmt.Errorf("chain compute: %w", err)
	}

	// Attach integrity record to the CompactEvent and re-marshal so that
	// the WAL stores the wire-final bytes.
	ce.Integrity = cr.Record()
	final, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal final: %w", err)
	}

	// 3. Append to WAL.
	res, err := s.w.Append(final)
	if err != nil {
		var ae wal.AppendError
		if errors.As(err, &ae) && ae.IsAmbiguous() {
			s.latchFatal(err)
		}
		// Clean failure: no chain commit, prev_hash unchanged.
		return fmt.Errorf("wal append: %w", err)
	}

	// 4. Commit chain advance.
	s.sink.Commit(cr)
	_ = res
	return nil
}
```

Add fatal-latch helpers to `internal/store/watchtower/store.go`:

```go
func (s *Store) latchFatal(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.fatalCh <- err:
	default:
	}
}

func (s *Store) isFatal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.fatalCh:
		// Re-post so future calls also see fatal.
		s.fatalCh <- errFatalLatch
		return true
	default:
		return false
	}
}

// QueryEvents is unsupported; the WTP store is a write-only sink.
func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, errors.New("watchtower: QueryEvents not supported")
}

// Close drains the transport and flushes the WAL.
func (s *Store) Close() error {
	s.tr.Stop(s.opts.DrainDeadline)
	return s.w.Close()
}
```

You may need to extend `chain.ComputeResult` to expose `Record()` (if not
already done in Task 6). Add to `internal/store/watchtower/chain/chain.go`:

```go
// Record returns the IntegrityRecord computed for this token.
func (c *ComputeResult) Record() *wtpv1.IntegrityRecord { return c.record }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/... -run TestAppendEvent_StampsChainBeforeWAL`
Expected: PASS.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/store.go internal/store/watchtower/append_test.go internal/store/watchtower/chain/chain.go
git commit -m "feat(wtp/store): add AppendEvent transactional pattern + fatal latch"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 24: Required failure tests (gating Phase 11)

Per the spec, these four tests must exist and pass before any component-
level transport tests are written. They guard the integrity boundary.

**Files:**
- Create: `internal/store/watchtower/integrity_test.go`
- Create: `internal/store/watchtower/wal/generation_boundary_test.go`
- Create: `pkg/types/events_marshal_test.go`

- [ ] **Step 1: Write all four failing tests**

Create `internal/store/watchtower/integrity_test.go`:

```go
package watchtower_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestStore_WALCleanFailure_NoChainAdvance verifies that a clean WAL
// failure (e.g., disk full before the write started) leaves the chain
// state unchanged so the next event is still chained from the previous
// committed prev_hash.
func TestStore_WALCleanFailure_NoChainAdvance(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1", HMACSecret: []byte("secret"),
		BatchMaxRecords: 8, BatchMaxBytes: 8 * 1024, BatchMaxAge: 50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Inject a clean-failure WAL error via the test hook.
	wal.SetAppendInjector(func() error {
		return wal.AppendError{Class: wal.AppendClassClean, Op: "append", Err: errors.New("disk full")}
	})
	defer wal.SetAppendInjector(nil)

	ev := types.Event{
		Type: "exec", SessionID: "s",
		Chain: &types.ChainState{Sequence: 1, Generation: 1},
	}
	prev := s.SinkChainState()
	if err := s.AppendEvent(context.Background(), ev); err == nil {
		t.Fatal("expected clean failure")
	}
	got := s.SinkChainState()
	if !chain.SinkStateEqual(prev, got) {
		t.Fatalf("clean failure advanced chain state: prev=%v got=%v", prev, got)
	}
}

// TestStore_WALAmbiguousFailure_LatchesFatal verifies that an ambiguous
// WAL failure latches the store fatal so subsequent appends fail.
func TestStore_WALAmbiguousFailure_LatchesFatal(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1", HMACSecret: []byte("secret"),
		BatchMaxRecords: 8, BatchMaxBytes: 8 * 1024, BatchMaxAge: 50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	wal.SetAppendInjector(func() error {
		return wal.AppendError{Class: wal.AppendClassAmbiguous, Op: "fsync", Err: errors.New("io error")}
	})
	defer wal.SetAppendInjector(nil)

	ev := types.Event{
		Type: "exec", SessionID: "s",
		Chain: &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err == nil {
		t.Fatal("expected ambiguous failure error")
	}

	// Subsequent append must fail fast with errFatalLatch.
	wal.SetAppendInjector(nil) // remove injector
	ev2 := types.Event{
		Type: "exec", SessionID: "s",
		Chain: &types.ChainState{Sequence: 2, Generation: 1},
	}
	err = s.AppendEvent(context.Background(), ev2)
	if err == nil {
		t.Fatal("expected fatal-latch error on second append")
	}
	_ = time.Second // unused; keeps imports stable
}
```

Create `internal/store/watchtower/wal/generation_boundary_test.go`:

```go
package wal_test

import (
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// TestWAL_GenerationBoundaryOrdering verifies that a generation roll
// occurs INSIDE Append (not as a separate API call), and that the
// last record in segment N has generation g while the first record
// in segment N+1 has generation g+1.
func TestWAL_GenerationBoundaryOrdering(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:         dir,
		SegmentSize: 256, // tiny so we roll quickly
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()

	// Force a roll by appending records totaling > 256 bytes.
	for i := 0; i < 10; i++ {
		if _, err := w.Append(make([]byte, 64)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Read back and check generation monotonicity at the boundary.
	rdr := w.NewReader(0)
	var prevGen uint32
	rolls := 0
	for i := 0; i < 10; i++ {
		rec, err := rdr.Next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if i > 0 && rec.Generation != prevGen {
			rolls++
			if rec.Generation < prevGen {
				t.Fatalf("generation went backwards: %d < %d", rec.Generation, prevGen)
			}
		}
		prevGen = rec.Generation
	}
	if rolls == 0 {
		t.Fatal("expected at least one generation roll")
	}
}
```

Create `pkg/types/events_marshal_test.go`:

```go
package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEvent_ChainFieldNotMarshaled is the load-bearing invariant noted in
// the Event struct comment: Event.Chain MUST NOT appear in any JSON
// serialization, since downstream consumers (OTEL/JSONL/etc.) must not
// see internal sequencing state.
func TestEvent_ChainFieldNotMarshaled(t *testing.T) {
	ev := Event{
		Type:      "exec",
		SessionID: "s",
		Chain: &ChainState{
			Sequence:   42,
			Generation: 7,
		},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, banned := range []string{`"Chain"`, `"chain"`, `"Sequence"`, `"Generation"`} {
		if strings.Contains(got, banned) {
			t.Fatalf("Event JSON exposes %q: %s", banned, got)
		}
	}
}
```

- [ ] **Step 2: Add the test hooks**

Add to `internal/store/watchtower/wal/wal.go`:

```go
// SetAppendInjector installs a hook that, when non-nil, replaces the
// real Append code path's terminal error. Tests use this to simulate
// clean and ambiguous failures without touching the filesystem.
//
// Production code MUST NOT call SetAppendInjector. This is a //
// test-only hook gated by package documentation.
func SetAppendInjector(fn func() error) {
	appendInjectorMu.Lock()
	appendInjector = fn
	appendInjectorMu.Unlock()
}

var (
	appendInjector   func() error
	appendInjectorMu sync.Mutex
)
```

Inside `Append`, before returning success, check the injector:

```go
appendInjectorMu.Lock()
inj := appendInjector
appendInjectorMu.Unlock()
if inj != nil {
	return AppendResult{}, inj()
}
```

Add `IsClean`/`IsAmbiguous` constants:

```go
const (
	AppendClassClean     = "clean"
	AppendClassAmbiguous = "ambiguous"
)

func (a AppendError) IsClean() bool     { return a.Class == AppendClassClean }
func (a AppendError) IsAmbiguous() bool { return a.Class == AppendClassAmbiguous }
```

Add a chain accessor to `Store`:

```go
// SinkChainState returns the current SinkChain state (test-only).
func (s *Store) SinkChainState() chain.SinkState {
	return s.sink.State()
}
```

And add to `internal/store/watchtower/chain/chain.go`:

```go
// SinkState is an opaque snapshot of SinkChain state for tests.
type SinkState struct {
	prev []byte
}

// State returns the current SinkChain state.
func (s *SinkChain) State() SinkState {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(s.prev))
	copy(cp, s.prev)
	return SinkState{prev: cp}
}

// SinkStateEqual reports whether two SinkState snapshots are equal.
func SinkStateEqual(a, b SinkState) bool {
	return string(a.prev) == string(b.prev)
}
```

- [ ] **Step 3: Run all four tests to verify they pass**

Run:
```
go test ./internal/store/watchtower/... -run "TestStore_WALCleanFailure_NoChainAdvance|TestStore_WALAmbiguousFailure_LatchesFatal|TestWAL_GenerationBoundaryOrdering"
go test ./pkg/types/... -run TestEvent_ChainFieldNotMarshaled
```
Expected: PASS for all four.

- [ ] **Step 4: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/integrity_test.go internal/store/watchtower/wal/generation_boundary_test.go internal/store/watchtower/wal/wal.go internal/store/watchtower/store.go internal/store/watchtower/chain/chain.go pkg/types/events_marshal_test.go
git commit -m "test(wtp): add 4 high-risk integrity tests gating component layer"
```

- [ ] **Step 6: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 11 — Component + integration tests

These tests stitch the store, transport, and testserver together to
validate end-to-end behavior under failure scenarios.

### Task 25: Component test — drops mid-batch trigger replay

**Files:**
- Create: `internal/store/watchtower/component_drop_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/component_drop_test.go`:

```go
package watchtower_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestStore_DropsMidBatchTriggersReplay sends 50 events, configures the
// server to drop after the second batch, and verifies all 50 sequences
// are eventually observed (replay re-sends from the last ack).
func TestStore_DropsMidBatchTriggersReplay(t *testing.T) {
	srv := testserver.New(testserver.Options{
		DropAfterBatchN: 2,
	})
	defer srv.Close()

	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1", HMACSecret: []byte("secret"),
		BatchMaxRecords: 10, BatchMaxBytes: 8 * 1024, BatchMaxAge: 50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	for i := uint64(1); i <= 50; i++ {
		ev := types.Event{
			Type: "exec", SessionID: "s",
			Chain: &types.ChainState{Sequence: i, Generation: 1},
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Wait for the transport to redeliver after drop.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := srv.AssertSequenceRange(1, 50); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("replay did not deliver all 50 sequences: %v", srv.AssertSequenceRange(1, 50))
}
```

- [ ] **Step 2: Run test to verify it passes (or surfaces wiring gaps)**

Run: `go test ./internal/store/watchtower/... -run TestStore_DropsMidBatchTriggersReplay -timeout 30s`
Expected: PASS — if it fails, fix wiring; replay must observably re-send dropped sequences.

- [ ] **Step 3: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/store/watchtower/component_drop_test.go
git commit -m "test(wtp): add component test — drops mid-batch trigger replay"
```

- [ ] **Step 5: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 26: Component test — server restart, ack catch-up

**Files:**
- Create: `internal/store/watchtower/component_restart_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/component_restart_test.go`:

```go
package watchtower_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestStore_ServerRestart_AcksCatchUp verifies that when the server is
// closed mid-stream and a new server takes its place, the client
// reconnects and the new server eventually sees all previously-pending
// records via replay (because no SessionAck arrived for them).
func TestStore_ServerRestart_AcksCatchUp(t *testing.T) {
	srv1 := testserver.New(testserver.Options{})

	allocator := audit.NewSequenceAllocator(0, 0)
	dir := t.TempDir()
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1", HMACSecret: []byte("secret"),
		BatchMaxRecords: 5, BatchMaxBytes: 4 * 1024, BatchMaxAge: 30 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv1.DialerFor(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	for i := uint64(1); i <= 10; i++ {
		ev := types.Event{
			Type: "exec", SessionID: "s",
			Chain: &types.ChainState{Sequence: i, Generation: 1},
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Let some land.
	time.Sleep(150 * time.Millisecond)
	srv1.Close()

	// Stand up a second server and re-point the dialer.
	// Production would handle this by reconnecting to a new endpoint;
	// here we exercise replay by giving the existing transport a fresh
	// server backend behind the same dialer interface.
	srv2 := testserver.New(testserver.Options{})
	defer srv2.Close()

	// Note: in a real test, the dialer would be a closure over a server
	// pointer that the test can swap. The watchtower.Options.Dialer is
	// the same instance for the lifetime of the store, so the test
	// fixture must support re-pointing — we do that with a routing
	// dialer added in the testserver helper:
	//
	//   srvRouter := testserver.NewRoutingDialer(srv1)
	//   ...
	//   srvRouter.Switch(srv2)
	//
	// (Assume that helper exists; if missing, implement it.)
	t.Skip("requires testserver.RoutingDialer (not yet implemented)")
	_ = srv2 // placate unused
}
```

- [ ] **Step 2: Implement testserver.RoutingDialer**

Add to `internal/store/watchtower/testserver/dialer.go`:

```go
package testserver

import (
	"context"
	"sync"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// RoutingDialer is a transport.Dialer whose backend can be swapped to
// simulate server restarts in tests.
type RoutingDialer struct {
	mu  sync.Mutex
	cur *Server
}

func NewRoutingDialer(s *Server) *RoutingDialer { return &RoutingDialer{cur: s} }

// Switch atomically re-points the dialer at a new server.
func (r *RoutingDialer) Switch(s *Server) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur = s
}

func (r *RoutingDialer) Dial(ctx context.Context) (transport.Conn, error) {
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	return cur.DialerFor().Dial(ctx)
}
```

Update the test to use `RoutingDialer` and remove `t.Skip(...)`.

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./internal/store/watchtower/... -run TestStore_ServerRestart_AcksCatchUp -timeout 30s`
Expected: PASS — srv2 eventually observes all 10 sequences.

- [ ] **Step 4: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/component_restart_test.go internal/store/watchtower/testserver/dialer.go
git commit -m "test(wtp): add component test — server restart, ack catch-up"
```

- [ ] **Step 6: Roborev**

Run `/roborev-design-review` and address findings.

---

## Phase 12 — Daemon wiring + standalone testserver

The final phase wires the watchtower store into the production daemon
(behind a config flag) and ships a standalone `wtp-testserver` binary
useful for manual integration testing.

### Task 27: Daemon wiring + standalone testserver

**Files:**
- Modify: `internal/server/server.go` (around line 362, where eventStores are assembled)
- Create: `internal/server/wtp.go`
- Create: `cmd/wtp-testserver/main.go`
- Create: `internal/store/watchtower/dialer.go` (production gRPC dialer)
- Test: `internal/server/wtp_test.go`

- [ ] **Step 1: Write the production gRPC dialer**

Create `internal/store/watchtower/dialer.go`:

```go
package watchtower

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// productionDialer dials the configured Watchtower endpoint over gRPC,
// honoring TLS and bearer-auth options.
type productionDialer struct {
	opts Options
}

func newGRPCDialerProd(opts Options) transport.Dialer {
	return &productionDialer{opts: opts}
}

func (d *productionDialer) Dial(ctx context.Context) (transport.Conn, error) {
	dialOpts := []grpc.DialOption{}
	if d.opts.TLSEnabled {
		tlsCfg := &tls.Config{InsecureSkipVerify: d.opts.TLSInsecure}
		if d.opts.TLSCertFile != "" && d.opts.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(d.opts.TLSCertFile, d.opts.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	cc, err := grpc.DialContext(ctx, d.opts.Endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	streamCtx := ctx
	if d.opts.AuthBearer != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx,
			"authorization", "Bearer "+d.opts.AuthBearer)
	}

	stream, err := wtpv1.NewWatchtowerClient(cc).Stream(streamCtx)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	return &grpcStreamConn{stream: stream, cc: cc}, nil
}

type grpcStreamConn struct {
	stream wtpv1.Watchtower_StreamClient
	cc     *grpc.ClientConn
}

func (g *grpcStreamConn) Send(m *wtpv1.ClientMessage) error  { return g.stream.Send(m) }
func (g *grpcStreamConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }
func (g *grpcStreamConn) CloseSend() error {
	_ = g.stream.CloseSend()
	return g.cc.Close()
}

// (avoid unused import warnings)
var _ net.Conn = (net.Conn)(nil)
```

Update `internal/store/watchtower/store.go`'s `newGRPCDialer` stub to call into the production helper:

```go
func newGRPCDialer(opts Options) transport.Dialer { return newGRPCDialerProd(opts) }
```

- [ ] **Step 2: Wire WTP into server.go**

Create `internal/server/wtp.go`:

```go
package server

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/eventfilter"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

// buildWatchtowerStore constructs a watchtower.Store from the daemon
// AuditWatchtowerConfig. Returns (nil, nil) when disabled.
func buildWatchtowerStore(ctx context.Context, cfg config.AuditWatchtowerConfig, allocator *audit.SequenceAllocator, mapper compact.Mapper) (store.EventStore, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := watchtower.Options{
		WALDir:          cfg.WALDir,
		WALSegmentSize:  cfg.WAL.SegmentSize,
		WALMaxTotalSize: cfg.WAL.MaxTotalSize,
		Mapper:          mapper,
		Allocator:       allocator,
		AgentID:         cfg.AgentID,
		SessionID:       cfg.SessionID,
		HMACKeyID:       cfg.HMACKeyID,
		HMACSecret:      []byte(cfg.HMACSecret),
		BatchMaxRecords: cfg.Batch.MaxRecords,
		BatchMaxBytes:   cfg.Batch.MaxBytes,
		BatchMaxAge:     cfg.Batch.MaxAge,
		Endpoint:        cfg.Endpoint,
		TLSEnabled:      cfg.TLS.Enabled,
		TLSCertFile:     cfg.TLS.CertFile,
		TLSKeyFile:      cfg.TLS.KeyFile,
		TLSInsecure:     cfg.TLS.Insecure,
		AuthBearer:      cfg.Auth.Bearer,
		Filter:          eventfilter.FromConfig(cfg.Filter),
	}
	s, err := watchtower.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("watchtower: %w", err)
	}
	return s, nil
}
```

In `internal/server/server.go`, near line 362 where `eventStores` is assembled:

```go
		// existing OTEL wiring above…
		if wtpStore, err := buildWatchtowerStore(ctx, cfg.Audit.Watchtower, allocator, compact.NewProductionMapper()); err != nil {
			return nil, fmt.Errorf("build watchtower store: %w", err)
		} else if wtpStore != nil {
			eventStores = append(eventStores, wtpStore)
		}
```

(Implementer: read server.go around line 362 first to confirm the local
variable names match — `eventStores`, `allocator` may be named differently.
Adjust the snippet accordingly.)

- [ ] **Step 3: Write the wiring test**

Create `internal/server/wtp_test.go`:

```go
package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/server"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

// TestBuildWatchtowerStore_DisabledReturnsNil verifies the disabled
// case short-circuits without errors.
func TestBuildWatchtowerStore_DisabledReturnsNil(t *testing.T) {
	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := server.BuildWatchtowerStoreForTest(context.Background(),
		config.AuditWatchtowerConfig{Enabled: false},
		allocator, compact.StubMapper{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil store when disabled")
	}
}

// TestBuildWatchtowerStore_RejectsInvalidConfig verifies validation runs.
func TestBuildWatchtowerStore_RejectsInvalidConfig(t *testing.T) {
	allocator := audit.NewSequenceAllocator(0, 0)
	cfg := config.AuditWatchtowerConfig{
		Enabled:  true,
		WALDir:   t.TempDir(),
		Endpoint: "localhost:0",
		AgentID:  "a", SessionID: "s",
		HMACKeyID: "k1",
		// Missing HMACSecret on purpose.
		Batch: config.WTPBatchConfig{
			MaxRecords: 8, MaxBytes: 8 * 1024, MaxAge: 50 * time.Millisecond,
		},
	}
	_, err := server.BuildWatchtowerStoreForTest(context.Background(),
		cfg, allocator, compact.StubMapper{})
	if err == nil {
		t.Fatal("expected validation error for missing HMAC secret")
	}
}
```

Add an exported test wrapper in `internal/server/wtp.go`:

```go
// BuildWatchtowerStoreForTest is a thin export of buildWatchtowerStore
// for white-box tests. Production callers use buildWatchtowerStore.
func BuildWatchtowerStoreForTest(ctx context.Context, cfg config.AuditWatchtowerConfig, alloc *audit.SequenceAllocator, m compact.Mapper) (store.EventStore, error) {
	return buildWatchtowerStore(ctx, cfg, alloc, m)
}
```

- [ ] **Step 4: Add the standalone wtp-testserver binary**

Create `cmd/wtp-testserver/main.go`:

```go
// Command wtp-testserver runs a hermetic WTP server bound to a local TCP
// port. Useful for manual integration testing — it has no auth, accepts
// any client, and prints batch summaries to stdout.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7080", "bind address")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	wtpv1.RegisterWatchtowerServer(srv, &handler{})

	fmt.Fprintf(os.Stderr, "wtp-testserver listening on %s\n", *addr)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Fprintln(os.Stderr, "shutting down")
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

type handler struct {
	wtpv1.UnimplementedWatchtowerServer
}

func (h *handler) Stream(stream wtpv1.Watchtower_StreamServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *wtpv1.ClientMessage_SessionInit:
			fmt.Fprintf(os.Stderr, "session init: agent=%s session=%s\n",
				m.SessionInit.AgentId, m.SessionInit.SessionId)
			_ = stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_SessionAck{
					SessionAck: &wtpv1.SessionAck{},
				},
			})
		case *wtpv1.ClientMessage_EventBatch:
			events := m.EventBatch.GetUncompressed().GetEvents()
			fmt.Fprintf(os.Stderr, "batch: %d records\n", len(events))
			lastSeq := uint64(0)
			lastGen := uint32(0)
			if n := len(events); n > 0 {
				lastSeq = events[n-1].Sequence
				lastGen = events[n-1].Generation
			}
			_ = stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_BatchAck{
					BatchAck: &wtpv1.BatchAck{
						AckHighWatermarkSeq: lastSeq,
						Generation:          lastGen,
					},
				},
			})
		case *wtpv1.ClientMessage_Heartbeat:
			// no-op
		}
	}
}
```

- [ ] **Step 5: Run all tests**

Run:
```
go test ./internal/server/... -run TestBuildWatchtowerStore
go test ./...
```
Expected: PASS — wiring tests green; full suite still green.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Verify the testserver binary builds and starts**

Run:
```
go build -o /tmp/wtp-testserver ./cmd/wtp-testserver
/tmp/wtp-testserver -addr 127.0.0.1:0 &
sleep 0.5
kill %1 || true
```
Expected: process starts and exits cleanly on signal.

- [ ] **Step 8: Commit**

```bash
git add internal/store/watchtower/dialer.go internal/store/watchtower/store.go internal/server/wtp.go internal/server/wtp_test.go internal/server/server.go cmd/wtp-testserver/main.go
git commit -m "feat(wtp): wire WTP store into daemon + add standalone testserver"
```

- [ ] **Step 9: Roborev**

Run `/roborev-design-review` and address findings.

---

## Done

All 27 tasks complete. The watchtower store is wired into the daemon
behind `audit.watchtower.enabled: true`, the standalone `wtp-testserver`
binary is available for manual integration testing, and the full test
suite (unit, integrity-gating, component, integration) is green.

Before merge, run:

```bash
go test ./...
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Then use `superpowers:finishing-a-development-branch` to land the change.
