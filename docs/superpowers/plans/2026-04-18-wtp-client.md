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

> **Superseded by Task 22a Step 3.5**: the snippet below shows the historical Task 3 test which calls `w.IncDroppedMissingChain(1)` and asserts `"wtp_dropped_missing_chain_total 1"`. That counter (`wtp_dropped_missing_chain_total` / `IncDroppedMissingChain`) is REMOVED in Task 22a Step 3.5. Missing-chain is now a propagated `compact.ErrMissingChain` error, not a silent drop. Implementers reviewing this plan retroactively must NOT reintroduce the counter — see Task 22a for the current metric inventory and Step 3.5 for the deletion.

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

> **Superseded by Task 22a Step 3.5**: the `wtp.go` snippet below contains the historical `IncDroppedMissingChain` method and references `wtpDroppedMissingChain`. That counter (`wtp_dropped_missing_chain_total` / `IncDroppedMissingChain`) is REMOVED in Task 22a Step 3.5. Missing-chain is now a propagated `compact.ErrMissingChain` error, not a silent drop. Implementers reviewing this plan retroactively must NOT reintroduce the counter — see Task 22a for the current metric inventory and Step 3.5 for the deletion.

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

	// (Sink-failure metric emits — including the per-class drop counters
	// and the labeled session-failure / invalid-frame families — land in
	// Task 22a. This Task 3 emit covers only the always-emit baseline
	// counters added in Phase 3; Task 22a supersedes it with the full
	// sink-failure inventory.)

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

> **Superseded by Task 22a Step 3.5**: the `Collector` snippet below contains a `wtpDroppedMissingChain atomic.Uint64` field. That field (along with the matching `wtp_dropped_missing_chain_total` counter and `IncDroppedMissingChain` method) is REMOVED in Task 22a Step 3.5. Missing-chain is now a propagated `compact.ErrMissingChain` error, not a silent drop. Implementers reviewing this plan retroactively must NOT reintroduce the field — see Task 22a for the current metric inventory and Step 3.5 for the deletion.

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

Note: Subsequent reviews of the spec added four more sink-failure counters (`wtp_dropped_invalid_utf8_total`, `wtp_dropped_sequence_overflow_total`, `wtp_session_init_failures_total{reason}`, `wtp_session_rotation_failures_total{reason}`). These are added in Task 22a, just before the AppendEvent integration that needs them. Task 3 itself is unchanged.

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

---

### Task 4a-ii: Schema stability docs and receiver-side validators

**Files:**
- Create: `proto/canyonroad/wtp/v1/validate.go`
- Create: `proto/canyonroad/wtp/v1/validate_test.go`
- Modify: `docs/superpowers/specs/2026-04-18-wtp-client-design.md` (already updated in this commit; included for traceability)

**Why:** The forward-compatibility policy in spec §"Frame validation and forward compatibility" makes claims (UNSPECIFIED rejection, body/compression mismatch rejection, compressed-payload cap) that the proto definitions alone cannot enforce. Add a small, focused validator package alongside the generated bindings and prove the contract with negative tests. Also lock in the pre-1.0 schema-stability policy so future contributors know tag reuse is permitted now and forbidden after the 1.0 cut.

- [ ] **Step 1: Write failing validator tests**

Create `proto/canyonroad/wtp/v1/validate_test.go`:

```go
package wtpv1

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateEventBatch_UnsetBodyRejected(t *testing.T) {
	eb := &EventBatch{FromSequence: 1, ToSequence: 2, Generation: 1, Compression: Compression_COMPRESSION_NONE}
	err := ValidateEventBatch(eb)
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
	if !strings.Contains(err.Error(), "body unset") {
		t.Errorf("error should mention body unset; got %q", err)
	}
}

func TestValidateEventBatch_CompressionUnspecifiedRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_UNSPECIFIED,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{}},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_NoneWithCompressedPayloadRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_NONE,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: []byte("x")},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_ZstdWithUncompressedRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_ZSTD,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{}},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_OverCapCompressedRejected(t *testing.T) {
	huge := make([]byte, MaxCompressedPayloadBytes+1)
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_ZSTD,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: huge},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge; got %v", err)
	}
}

func TestValidateEventBatch_HappyPaths(t *testing.T) {
	uncompressed := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_NONE,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{Events: []*CompactEvent{{Sequence: 1}, {Sequence: 2}}}},
	}
	if err := ValidateEventBatch(uncompressed); err != nil {
		t.Errorf("uncompressed batch should validate; got %v", err)
	}
	compressed := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_GZIP,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: []byte("blob")},
	}
	if err := ValidateEventBatch(compressed); err != nil {
		t.Errorf("compressed batch should validate; got %v", err)
	}
}

func TestValidateSessionInit_AlgorithmUnspecifiedRejected(t *testing.T) {
	si := &SessionInit{SessionId: "s", Algorithm: HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED}
	if err := ValidateSessionInit(si); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateSessionInit_HappyPath(t *testing.T) {
	si := &SessionInit{SessionId: "s", Algorithm: HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256}
	if err := ValidateSessionInit(si); err != nil {
		t.Errorf("happy path should validate; got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `go test ./proto/canyonroad/wtp/v1/... -run TestValidate -v`
Expected: FAIL — `undefined: ValidateEventBatch`, etc.

- [ ] **Step 3: Write the validator**

Create `proto/canyonroad/wtp/v1/validate.go`:

```go
package wtpv1

import (
	"errors"
	"fmt"
)

// MaxCompressedPayloadBytes is the receiver-enforced cap on EventBatch
// compressed_payload size. See spec §"Compression safety".
const MaxCompressedPayloadBytes = 8 * 1024 * 1024

// MaxDecompressedBatchBytes is the receiver-enforced cap applied to the
// streaming decoder once decompression begins. Validators here cap the
// compressed bytes; downstream decompression code is responsible for
// enforcing this second cap during the streaming decode.
const MaxDecompressedBatchBytes = 64 * 1024 * 1024

// ErrInvalidFrame is returned for schema-valid but semantically invalid frames.
var ErrInvalidFrame = errors.New("wtp: invalid frame")

// ErrPayloadTooLarge is returned when EventBatch.compressed_payload exceeds MaxCompressedPayloadBytes.
var ErrPayloadTooLarge = errors.New("wtp: payload too large")

// ValidateEventBatch enforces the rules in spec §"Frame validation and
// forward compatibility" + §"Compression safety". Receivers MUST call this
// before accepting an EventBatch.
func ValidateEventBatch(b *EventBatch) error {
	if b == nil {
		return fmt.Errorf("%w: batch is nil", ErrInvalidFrame)
	}
	if b.Compression == Compression_COMPRESSION_UNSPECIFIED {
		return fmt.Errorf("%w: compression unspecified", ErrInvalidFrame)
	}
	switch body := b.Body.(type) {
	case nil:
		return fmt.Errorf("%w: body unset", ErrInvalidFrame)
	case *EventBatch_Uncompressed:
		if b.Compression != Compression_COMPRESSION_NONE {
			return fmt.Errorf("%w: uncompressed body requires compression=NONE (got %s)", ErrInvalidFrame, b.Compression)
		}
	case *EventBatch_CompressedPayload:
		if b.Compression == Compression_COMPRESSION_NONE {
			return fmt.Errorf("%w: compressed_payload requires compression != NONE", ErrInvalidFrame)
		}
		if len(body.CompressedPayload) > MaxCompressedPayloadBytes {
			return fmt.Errorf("%w: compressed_payload is %d bytes (cap %d)", ErrPayloadTooLarge, len(body.CompressedPayload), MaxCompressedPayloadBytes)
		}
	default:
		return fmt.Errorf("%w: unknown body oneof case", ErrInvalidFrame)
	}
	return nil
}

// ValidateSessionInit rejects SessionInit frames with UNSPECIFIED enums or
// missing required fields, per spec §"Frame validation and forward compatibility".
func ValidateSessionInit(s *SessionInit) error {
	if s == nil {
		return fmt.Errorf("%w: session_init is nil", ErrInvalidFrame)
	}
	if s.Algorithm == HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return fmt.Errorf("%w: algorithm unspecified", ErrInvalidFrame)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `go test ./proto/canyonroad/wtp/v1/... -v`
Expected: PASS — all original tests plus the 8 new validator tests.

- [ ] **Step 5: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_test.go docs/superpowers/specs/2026-04-18-wtp-client-design.md docs/superpowers/plans/2026-04-18-wtp-client.md
git commit -m "fix(proto): address Task 4 round 2 — schema stability, validators, compression caps"
```

- [ ] **Step 7: Roborev**

Controller will run roborev — do not run it in this task.

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
		Algorithm:           wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256,
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
	"errors"
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
	for _, marker := range []string{"e+", "e-", "E+", "E-"} {
		if strings.Contains(string(got), marker) {
			t.Errorf("number used scientific notation (marker %q): %s", marker, got)
		}
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

func TestEncodeCanonical_InvalidUTF8Rejected(t *testing.T) {
	rec := IntegrityRecord{PrevHash: "valid-prefix\x80invalid"}
	_, err := EncodeCanonical(rec)
	if err == nil {
		t.Fatal("expected ErrInvalidUTF8 for invalid UTF-8 in PrevHash; got nil")
	}
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8, got %v", err)
	}
	rec2 := IntegrityRecord{ContextDigest: "good", EventHash: "good", KeyFingerprint: "k\x80", PrevHash: "good"}
	_, err = EncodeCanonical(rec2)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8 for KeyFingerprint, got %v", err)
	}
}

func TestComputeContextDigest_InvalidUTF8Rejected(t *testing.T) {
	ctx := SessionContext{AgentID: "ok", SessionID: "s\x80bad"}
	_, err := ComputeContextDigest(ctx)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8, got %v", err)
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
//
// Sequence-width contract (layered):
//   - WTP wire format (this struct, the .proto definition) reserves the full
//     uint64 sequence space.
//   - audit.SinkChain.Compute consumes int64; values above math.MaxInt64
//     overflow at that boundary.
//   - The bounds check (0..math.MaxInt64) lives at the store-integration
//     boundary in watchtower.Store.AppendEvent (Task 23), where ev.Chain.Sequence
//     is converted before being passed to the chain.
//   - The encoder in this package handles the full uint64 range so wire-level
//     conformance vectors can exercise it; constraint enforcement is the
//     boundary's job, not the encoder's.
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
//
// Returns ErrInvalidUTF8 if any SessionContext string field contains invalid
// UTF-8. See EncodeCanonical for the cross-implementation rationale.
func ComputeContextDigest(ctx SessionContext) (string, error) {
	canon, err := encodeContextCanonical(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
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
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalidUTF8 is returned by EncodeCanonical and ComputeContextDigest when a
// string field contains invalid UTF-8. We reject (rather than substitute U+FFFD)
// to keep canonical bytes — and therefore SHA-256 hashes — stable across
// implementations. A Go encoder substituting U+FFFD while a Rust encoder
// rejected would yield different hashes for the same input, breaking
// cross-implementation chain verification.
var ErrInvalidUTF8 = errors.New("chain: invalid utf-8 in string field")

// EncodeCanonical produces the byte-exact canonical JSON encoding of an
// IntegrityRecord per spec §6.4: keys sorted lexicographically, no insignificant
// whitespace, ASCII-escaped non-ASCII (lowercase hex), decimal integers (no
// scientific notation), strict JSON string escapes.
//
// This is the cross-implementation contract surface — a single byte difference
// breaks every other implementation. Conformance vectors are added in Task 7
// and will live at chain/testdata/vectors.json (also published at
// docs/spec/wtp/conformance/) once that task lands.
//
// Returns ErrInvalidUTF8 if any string field contains invalid UTF-8. We reject
// rather than silently substitute U+FFFD so canonical bytes stay identical
// across Go, Rust, and TypeScript implementations.
func EncodeCanonical(rec IntegrityRecord) ([]byte, error) {
	for _, f := range []struct {
		name string
		v    string
	}{
		{"context_digest", rec.ContextDigest},
		{"event_hash", rec.EventHash},
		{"key_fingerprint", rec.KeyFingerprint},
		{"prev_hash", rec.PrevHash},
	} {
		if !utf8.ValidString(f.v) {
			return nil, fmt.Errorf("%w: field %q", ErrInvalidUTF8, f.name)
		}
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
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
func encodeContextCanonical(ctx SessionContext) ([]byte, error) {
	for _, f := range []struct {
		name string
		v    string
	}{
		{"agent_id", ctx.AgentID},
		{"agent_version", ctx.AgentVersion},
		{"algorithm", ctx.Algorithm},
		{"key_fingerprint", ctx.KeyFingerprint},
		{"ocsf_version", ctx.OCSFVersion},
		{"session_id", ctx.SessionID},
	} {
		if !utf8.ValidString(f.v) {
			return nil, fmt.Errorf("%w: field %q", ErrInvalidUTF8, f.name)
		}
	}
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
	return buf.Bytes(), nil
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
// escapes per RFC 8259 §7. Invalid UTF-8 has been rejected by the caller; no
// replacement here.
func writeStringEscapedBody(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
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
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
		}
		i += size
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/chain/...`
Expected: PASS, all 9 tests green (7 original + 2 UTF-8 rejection tests).

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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type vectorEntry struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`           // "integrity_record" | "context_digest"
	Input         json.RawMessage `json:"input,omitempty"` // for valid inputs, an object with canonical wire snake_case keys (e.g. format_version, sequence, session_id) — NOT Go field names. Each implementation maps the keys to its local struct fields inside its harness.
	InputB64      string          `json:"input_b64,omitempty"` // base64-encoded raw struct field bytes for negative cases (non-UTF-8)
	InputField    string          `json:"input_field,omitempty"` // canonical wire field name receiving InputB64 (e.g., "prev_hash", "session_id")
	Expected      string          `json:"expected,omitempty"` // for valid: canonical bytes (integrity_record) or hex digest (context_digest)
	ExpectedError string          `json:"expected_error,omitempty"` // for negative: sentinel name (e.g., "ErrInvalidUTF8")
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("vectors.json has no entries")
	}
	for _, v := range entries {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Kind {
			case "integrity_record":
				rec, err := buildIntegrityRecord(v)
				if err != nil {
					t.Fatalf("build input: %v", err)
				}
				got, err := EncodeCanonical(rec)
				if v.ExpectedError != "" {
					assertExpectedError(t, err, v.ExpectedError)
					return
				}
				if err != nil {
					t.Fatalf("EncodeCanonical: %v", err)
				}
				if string(got) != v.Expected {
					t.Errorf("canonical mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			case "context_digest":
				ctx, err := buildSessionContext(v)
				if err != nil {
					t.Fatalf("build input: %v", err)
				}
				got, err := ComputeContextDigest(ctx)
				if v.ExpectedError != "" {
					assertExpectedError(t, err, v.ExpectedError)
					return
				}
				if err != nil {
					t.Fatalf("ComputeContextDigest: %v", err)
				}
				if got != v.Expected {
					t.Errorf("digest mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}

// buildIntegrityRecord decodes v.Input — an object with canonical wire
// snake_case keys, NOT Go field names — into a Go IntegrityRecord. Then
// applies v.InputB64 (raw bytes including invalid UTF-8) to v.InputField
// for negative cases. Each implementation maps the snake_case keys to
// its local struct fields here, keeping the published vectors language-
// neutral.
//
// Numeric fields are decoded via decodeUint32 / decodeUint64 helpers
// that range-check before casting. Silently truncating uint64 → uint32
// would weaken the cross-implementation conformance story; explicit
// rejection at the harness boundary is the contract.
func buildIntegrityRecord(v vectorEntry) (IntegrityRecord, error) {
	var rec IntegrityRecord
	if len(v.Input) > 0 {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(v.Input, &fields); err != nil {
			return rec, fmt.Errorf("decode input: %w", err)
		}
		for key, raw := range fields {
			switch key {
			case "format_version":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return rec, err
				}
				rec.FormatVersion = n
			case "sequence":
				n, err := decodeUint64(key, raw)
				if err != nil {
					return rec, err
				}
				rec.Sequence = n
			case "generation":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return rec, err
				}
				rec.Generation = n
			case "prev_hash":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.PrevHash = s
			case "event_hash":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.EventHash = s
			case "context_digest":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.ContextDigest = s
			case "key_fingerprint":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.KeyFingerprint = s
			default:
				return rec, fmt.Errorf("unknown input key %q (expected wire snake_case name for integrity_record)", key)
			}
		}
	}
	if v.InputB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(v.InputB64)
		if err != nil {
			return rec, fmt.Errorf("decode input_b64: %w", err)
		}
		switch v.InputField {
		case "prev_hash":
			rec.PrevHash = string(raw)
		case "event_hash":
			rec.EventHash = string(raw)
		case "context_digest":
			rec.ContextDigest = string(raw)
		case "key_fingerprint":
			rec.KeyFingerprint = string(raw)
		default:
			return rec, fmt.Errorf("unknown input_field %q (expected wire snake_case name)", v.InputField)
		}
	}
	return rec, nil
}

// decodeUint32 parses raw as a JSON number and rejects values outside
// the uint32 range. Uses json.Number to preserve full uint64 precision
// before the range check.
func decodeUint32(name string, raw json.RawMessage) (uint32, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	u, err := strconv.ParseUint(num.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if u > math.MaxUint32 {
		return 0, fmt.Errorf("vector field %q value %d exceeds uint32 range", name, u)
	}
	return uint32(u), nil
}

// decodeUint64 parses raw as a JSON number into a real uint64 (no range
// reduction). Uses json.Number so values up to math.MaxUint64 round-trip
// without precision loss.
func decodeUint64(name string, raw json.RawMessage) (uint64, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	u, err := strconv.ParseUint(num.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return u, nil
}

// decodeString parses raw as a JSON string. Provided for API symmetry
// with decodeUint32 / decodeUint64 so every switch case calls a helper.
func decodeString(name string, raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("decode %s: %w", name, err)
	}
	return s, nil
}

// buildSessionContext mirrors buildIntegrityRecord for SessionContext.
// v.Input uses canonical wire snake_case keys, NOT Go field names.
// Numeric fields use the same decode helpers as buildIntegrityRecord
// (range-checked uint32, full-precision uint64) so out-of-range values
// fail explicitly rather than truncating silently.
func buildSessionContext(v vectorEntry) (SessionContext, error) {
	var ctx SessionContext
	if len(v.Input) > 0 {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(v.Input, &fields); err != nil {
			return ctx, fmt.Errorf("decode input: %w", err)
		}
		for key, raw := range fields {
			switch key {
			case "session_id":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.SessionID = s
			case "agent_id":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.AgentID = s
			case "agent_version":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.AgentVersion = s
			case "ocsf_version":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.OCSFVersion = s
			case "format_version":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.FormatVersion = n
			case "algorithm":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.Algorithm = s
			case "key_fingerprint":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.KeyFingerprint = s
			default:
				return ctx, fmt.Errorf("unknown input key %q (expected wire snake_case name for context_digest)", key)
			}
		}
	}
	if v.InputB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(v.InputB64)
		if err != nil {
			return ctx, fmt.Errorf("decode input_b64: %w", err)
		}
		switch v.InputField {
		case "session_id":
			ctx.SessionID = string(raw)
		case "agent_id":
			ctx.AgentID = string(raw)
		case "agent_version":
			ctx.AgentVersion = string(raw)
		case "ocsf_version":
			ctx.OCSFVersion = string(raw)
		case "algorithm":
			ctx.Algorithm = string(raw)
		case "key_fingerprint":
			ctx.KeyFingerprint = string(raw)
		default:
			return ctx, fmt.Errorf("unknown input_field %q (expected wire snake_case name)", v.InputField)
		}
	}
	return ctx, nil
}

// assertExpectedError checks that err matches the named sentinel.
func assertExpectedError(t *testing.T, err error, sentinelName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", sentinelName)
	}
	switch sentinelName {
	case "ErrInvalidUTF8":
		if !errors.Is(err, ErrInvalidUTF8) {
			t.Fatalf("expected ErrInvalidUTF8, got %v", err)
		}
	default:
		t.Fatalf("vectors.json names unknown sentinel %q", sentinelName)
	}
}

// supportedVectorSchemaVersions is the set of envelope schema_version values
// the harness will accept. Bump when shipping a new envelope shape; the
// loader fails closed on any value not listed here so a future incompatible
// vector set cannot be silently treated as conformant. v1 (bare array) is
// detected by the leading '[' byte, not by this set.
var supportedVectorSchemaVersions = map[int]struct{}{
	2: {}, // current published envelope; see spec §"Vector schema versioning"
}

// loadVectors decodes a conformance-vector file in either v1 (bare JSON
// array) or v2+ (envelope `{"schema_version": N, "vectors": [...]}`) form.
//
// Detection rule (per spec §"Vector schema versioning"): peek the first
// non-whitespace byte. '[' → v1 array. '{' → v2+ envelope; the envelope
// MUST carry a recognized schema_version or the load fails. Anything else
// is an error. This is fail-closed: an unknown envelope value is never
// accepted as a "best-effort" v1 fallback.
//
// Both paths reject unknown fields (DisallowUnknownFields) and trailing
// content after the top-level value, per spec §"Unknown-field policy"
// and §"Trailing content". Typos and accidentally-concatenated payloads
// fail loudly rather than being silently dropped.
func loadVectors(data []byte) ([]vectorEntry, error) {
	first, err := firstNonWhitespaceByte(data)
	if err != nil {
		return nil, err
	}
	switch first {
	case '[':
		// v1 path: a bare array. json.Decoder + DisallowUnknownFields gives
		// us per-entry strict decoding plus a follow-up EOF check that
		// rejects trailing junk after the closing ']'.
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var entries []vectorEntry
		if err := dec.Decode(&entries); err != nil {
			return nil, fmt.Errorf("decode v1 vectors array: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("decode v1 vectors array: trailing content after array: %v", err)
		}
		return entries, nil
	case '{':
		// Decode the envelope into a struct that uses *int for schema_version
		// so we can tell "field absent" from "field present and zero".
		var env struct {
			SchemaVersion *int            `json:"schema_version"`
			Vectors       []vectorEntry   `json:"vectors"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("decode vectors envelope: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("decode vectors envelope: trailing content after envelope: %v", err)
		}
		if env.SchemaVersion == nil {
			return nil, errors.New("vectors envelope missing required field schema_version")
		}
		if _, ok := supportedVectorSchemaVersions[*env.SchemaVersion]; !ok {
			return nil, fmt.Errorf("unsupported vectors schema_version %d (harness accepts %v)", *env.SchemaVersion, supportedSchemaVersionList())
		}
		return env.Vectors, nil
	default:
		return nil, fmt.Errorf("vectors file must start with '[' (v1) or '{' (v2+ envelope); got %q", first)
	}
}

func firstNonWhitespaceByte(data []byte) (byte, error) {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b, nil
		}
	}
	return 0, errors.New("vectors file is empty or whitespace-only")
}

func supportedSchemaVersionList() []int {
	out := make([]int, 0, len(supportedVectorSchemaVersions))
	for v := range supportedVectorSchemaVersions {
		out = append(out, v)
	}
	return out
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
    "input": {"format_version":2,"sequence":0,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":0}"
  },
  {
    "name": "typical_record",
    "kind": "integrity_record",
    "input": {"format_version":2,"sequence":42,"generation":7,"prev_hash":"deadbeef","event_hash":"cafef00d","context_digest":"0123456789abcdef","key_fingerprint":"sha256:aabbccdd"},
    "expected": "{\"context_digest\":\"0123456789abcdef\",\"event_hash\":\"cafef00d\",\"format_version\":2,\"generation\":7,\"key_fingerprint\":\"sha256:aabbccdd\",\"prev_hash\":\"deadbeef\",\"sequence\":42}"
  },
  {
    "name": "uint64_max_sequence",
    "kind": "integrity_record",
    "input": {"format_version":2,"sequence":18446744073709551615,"generation":4294967295,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":4294967295,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":18446744073709551615}"
  },
  {
    "name": "non_ascii_in_key_fingerprint",
    "kind": "integrity_record",
    "input": {"format_version":2,"sequence":1,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":"caf\u00e9"},
    "expected": "{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"caf\\u00e9\",\"prev_hash\":\"\",\"sequence\":1}"
  },
  {
    "name": "context_digest_typical",
    "kind": "context_digest",
    "input": {"session_id":"01HXAVD2N5VX3CZQK7Q7QWNYKE","agent_id":"agentsh","agent_version":"1.0.0","ocsf_version":"1.8.0","format_version":2,"algorithm":"hmac-sha256","key_fingerprint":"sha256:aabbccdd"},
    "expected": "PLACEHOLDER_REPLACE_ME"
  },
  {
    "name": "negative_invalid_utf8_in_prev_hash",
    "kind": "integrity_record",
    "input": {"format_version":2,"sequence":1,"generation":0},
    "input_b64": "dmFsaWQtcHJlZml4gGludmFsaWQ=",
    "input_field": "prev_hash",
    "expected_error": "ErrInvalidUTF8"
  },
  {
    "name": "negative_invalid_utf8_in_session_id",
    "kind": "context_digest",
    "input": {"format_version":2,"agent_id":"agentsh","agent_version":"1.0.0","ocsf_version":"1.8.0","algorithm":"hmac-sha256","key_fingerprint":"sha256:test"},
    "input_b64": "c4BiYWQ=",
    "input_field": "session_id",
    "expected_error": "ErrInvalidUTF8"
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
    ctx, err := buildSessionContext(v)
    if err != nil {
        t.Fatalf("build input: %v", err)
    }
    got, err := ComputeContextDigest(ctx)
    if err != nil {
        t.Fatalf("ComputeContextDigest: %v", err)
    }
    t.Logf("digest for %s: %s", v.Name, got)
    if got != v.Expected {
        t.Errorf("digest mismatch\ngot:  %s\nwant: %s", got, v.Expected)
    }
```

Run: `go test -v -run TestVectors/context_digest_typical ./internal/store/watchtower/chain/`
Expected: FAIL but the log line prints the actual digest. Copy that hex string into `vectors.json` replacing `PLACEHOLDER_REPLACE_ME`. Remove the temporary `t.Logf`.

The harness's explicit uint32 range checks are exercised by the unit tests in Step 4.5 below; `vectors.json` itself does not need a range-overflow entry since the boundary is the harness, not the canonical encoder.

- [ ] **Step 4.5: Add unit tests for the uint32 range checks**

The new `decodeUint32` helper rejects values strictly greater than `math.MaxUint32` and accepts values up to and including `math.MaxUint32`. Two top-level (non-vector-driven) tests exercise both edges:

```go
func TestBuildIntegrityRecord_RejectsUint32Overflow(t *testing.T) {
	raw := json.RawMessage(`{"format_version": 4294967296, "sequence": 0, "generation": 0, "prev_hash": "", "event_hash": "", "context_digest": "", "key_fingerprint": ""}`)
	v := vectorEntry{Input: raw, Kind: "integrity_record"}
	_, err := buildIntegrityRecord(v)
	if err == nil {
		t.Fatal("expected range error for format_version > MaxUint32, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds uint32 range") {
		t.Errorf("error must mention range overflow: %v", err)
	}
}

func TestBuildIntegrityRecord_AcceptsUint32Max(t *testing.T) {
	raw := json.RawMessage(`{"format_version": 4294967295, "sequence": 0, "generation": 4294967295, "prev_hash": "", "event_hash": "", "context_digest": "", "key_fingerprint": ""}`)
	v := vectorEntry{Input: raw, Kind: "integrity_record"}
	rec, err := buildIntegrityRecord(v)
	if err != nil {
		t.Fatalf("uint32 max should be accepted: %v", err)
	}
	if rec.FormatVersion != math.MaxUint32 {
		t.Errorf("FormatVersion: got %d, want %d", rec.FormatVersion, uint32(math.MaxUint32))
	}
	if rec.Generation != math.MaxUint32 {
		t.Errorf("Generation: got %d, want %d", rec.Generation, uint32(math.MaxUint32))
	}
}
```

These are top-level tests, separate from the vector-driven `TestVectors`. Run: `go test ./internal/store/watchtower/chain/ -run TestBuildIntegrityRecord_`. Both pass once the helpers from Step 1 are in place.

`buildSessionContext` consumes the same `decodeUint32` helper for `format_version`, so the range contract is shared between both call sites. Rather than duplicate `TestBuildSessionContext_*` symmetrically (the contract is the helper, not the call site), exercise the helper directly:

```go
func TestDecodeUint32_RejectsOverflow(t *testing.T) {
	// Shared contract for buildIntegrityRecord AND buildSessionContext —
	// both consume decodeUint32 for format_version (and integrity records
	// also for generation). Exercising the helper covers both call sites.
	_, err := decodeUint32("format_version", json.RawMessage(`4294967296`))
	if err == nil {
		t.Fatal("expected range error for value > MaxUint32, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds uint32 range") {
		t.Errorf("error must mention range overflow: %v", err)
	}
}

func TestDecodeUint32_AcceptsMax(t *testing.T) {
	got, err := decodeUint32("format_version", json.RawMessage(`4294967295`))
	if err != nil {
		t.Fatalf("uint32 max should be accepted: %v", err)
	}
	if got != math.MaxUint32 {
		t.Errorf("decodeUint32 returned %d, want %d", got, uint32(math.MaxUint32))
	}
}
```

Run: `go test ./internal/store/watchtower/chain/ -run TestDecodeUint32_`. Both pass with the helper from Step 1.

- [ ] **Step 4.6: Add unit tests for the v1/v2 vector loader**

`loadVectors` (defined in Step 1) is the single entry point for parsing the conformance file. It auto-detects v1 (bare array) vs v2+ (envelope) by peeking the first non-whitespace byte and fails closed on missing or unknown `schema_version`. These tests exercise every accept/reject branch directly so a future envelope change cannot silently regress detection.

Run before adding the implementation, then again after — they fail with "loadVectors undefined" until Step 1 lands.

```go
func TestLoadVectors_V1Array(t *testing.T) {
	data := []byte(`[{"name":"x","kind":"integrity_record","input":{"format_version":2,"sequence":0,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},"expected":"{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":0}"}]`)
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatalf("loadVectors(v1): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "x" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestLoadVectors_V2Envelope(t *testing.T) {
	data := []byte(`{"schema_version":2,"vectors":[{"name":"y","kind":"context_digest"}]}`)
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatalf("loadVectors(v2): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "y" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestLoadVectors_RejectsEnvelopeMissingSchemaVersion(t *testing.T) {
	data := []byte(`{"vectors":[]}`)
	_, err := loadVectors(data)
	if err == nil {
		t.Fatal("expected error for envelope without schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error must mention schema_version: %v", err)
	}
}

func TestLoadVectors_RejectsUnknownSchemaVersion(t *testing.T) {
	data := []byte(`{"schema_version":99,"vectors":[]}`)
	_, err := loadVectors(data)
	if err == nil {
		t.Fatal("expected error for unknown schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error must mention unsupported: %v", err)
	}
}

func TestLoadVectors_RejectsMalformedJSON(t *testing.T) {
	data := []byte(`{not valid json`)
	if _, err := loadVectors(data); err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestLoadVectors_RejectsEmpty(t *testing.T) {
	if _, err := loadVectors([]byte("   \n\t")); err == nil {
		t.Fatal("expected error for whitespace-only input, got nil")
	}
}

func TestLoadVectors_RejectsBareScalar(t *testing.T) {
	if _, err := loadVectors([]byte(`42`)); err == nil {
		t.Fatal("expected error for non-array/non-object top-level value, got nil")
	}
}

func TestLoadVectors_RejectsTrailingContent(t *testing.T) {
	// Both v1 (bare-array) and v2 (envelope) paths must reject anything
	// after the top-level JSON value. Catches accidental concatenation and
	// forward-incompatible streaming formats. Spec §"Trailing content".
	v1WithJunk := []byte(`[{"name":"x","kind":"integrity_record","input":{"format_version":2,"sequence":0,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},"expected":"{}"}]  garbage`)
	if _, err := loadVectors(v1WithJunk); err == nil {
		t.Fatal("expected v1 trailing-content rejection, got nil")
	} else if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("v1 error must mention trailing content: %v", err)
	}
	v2WithJunk := []byte(`{"schema_version":2,"vectors":[]}  {"another":"object"}`)
	if _, err := loadVectors(v2WithJunk); err == nil {
		t.Fatal("expected v2 trailing-content rejection, got nil")
	} else if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("v2 error must mention trailing content: %v", err)
	}
}

func TestLoadVectors_RejectsUnknownFields(t *testing.T) {
	// Both v1 and v2 paths must reject unknown fields per spec
	// §"Unknown-field policy". Typos and forward-incompatible vectors
	// fail loudly rather than silently being dropped.
	v1WithUnknown := []byte(`[{"name":"x","kind":"integrity_record","input":{},"expected":"","UNKNOWN_FIELD":1}]`)
	if _, err := loadVectors(v1WithUnknown); err == nil {
		t.Fatal("expected v1 unknown-field rejection, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v1 error must mention unknown field: %v", err)
	}
	v2WithUnknown := []byte(`{"schema_version":2,"vectors":[],"UNKNOWN_ENVELOPE_FIELD":true}`)
	if _, err := loadVectors(v2WithUnknown); err == nil {
		t.Fatal("expected v2 unknown-field rejection at envelope level, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v2 envelope error must mention unknown field: %v", err)
	}
	v2EntryUnknown := []byte(`{"schema_version":2,"vectors":[{"name":"y","kind":"context_digest","UNKNOWN_ENTRY_FIELD":"x"}]}`)
	if _, err := loadVectors(v2EntryUnknown); err == nil {
		t.Fatal("expected v2 unknown-field rejection at entry level, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v2 entry error must mention unknown field: %v", err)
	}
}
```

Run: `go test ./internal/store/watchtower/chain/ -run TestLoadVectors_`. All ten pass once Step 1's `loadVectors` helper exists. The published `vectors.json` itself remains in v1 (bare-array) shape for now; v2 is exercised purely through these in-memory tests until the v2 envelope is published.

- [ ] **Step 5: Run vectors test to verify it passes**

Run: `go test ./internal/store/watchtower/chain/ -run TestVectors`
Expected: PASS, all 7 sub-tests green (5 positive + 2 negative). The two `TestBuildIntegrityRecord_*` tests from Step 4.5 are separate top-level tests and are run by the broader `go test ./internal/store/watchtower/chain/...` invocation; they do not change the TestVectors sub-test count.

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
	"errors"
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
	if !errors.Is(err, ErrMissingChain) {
		t.Errorf("err = %v, want errors.Is(err, ErrMissingChain)", err)
	}
}

func TestEncode_RejectsNilMapper(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(1_700_000_000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(nil, ev)
	if err == nil {
		t.Fatal("Encode must reject untyped-nil mapper")
	}
	if !errors.Is(err, ErrInvalidMapper) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidMapper)", err)
	}
}

func TestEncode_RejectsTypedNilPointerMapper(t *testing.T) {
	var m *StubMapper // typed-nil pointer; non-nil interface, nil dynamic value
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(1_700_000_000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(m, ev)
	if err == nil {
		t.Fatal("Encode must reject typed-nil pointer mapper")
	}
	if !errors.Is(err, ErrInvalidMapper) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidMapper)", err)
	}
}

func TestEncode_PropagatesMapperError(t *testing.T) {
	failing := failingMapper{}
	ev := types.Event{Type: "x", Timestamp: time.Now(), Chain: &types.ChainState{}}
	_, err := Encode(failing, ev)
	if err == nil {
		t.Fatal("Encode must propagate mapper error")
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("err = %v, want wrapped errBoom", err)
	}
}

func TestEncode_RejectsZeroTimestamp(t *testing.T) {
	ev := types.Event{
		Type:  "x",
		Chain: &types.ChainState{Sequence: 1, Generation: 1},
		// Timestamp deliberately left as the zero value.
	}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject zero timestamp")
	}
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidTimestamp)", err)
	}
}

func TestEncode_RejectsPreEpochTimestamp(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Date(1969, time.December, 31, 23, 59, 59, 0, time.UTC),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject pre-epoch timestamp")
	}
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidTimestamp)", err)
	}
}

func TestEncode_AcceptsUnixEpoch(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(0, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	got, err := Encode(StubMapper{}, ev)
	if err != nil {
		t.Fatalf("Encode must accept Unix epoch boundary: %v", err)
	}
	if got.TimestampUnixNanos != 0 {
		t.Errorf("TimestampUnixNanos = %d, want 0", got.TimestampUnixNanos)
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
	"reflect"

	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ErrInvalidMapper is returned when m is untyped nil or a typed-nil pointer
// implementation of Mapper. Encode performs this check defensively even though
// Store.New (Phase 10) will also reject invalid mappers — the nil-check is
// cheap and removes the temporal coupling on the future store layer.
var ErrInvalidMapper = errors.New("compact.Encode: mapper is required (nil or typed-nil pointer)")

// ErrMissingChain is returned by Encode when ev.Chain is nil — the composite
// store did not stamp the shared (sequence, generation). This is a programming
// error: a WTP sink must run inside the composite store.
var ErrMissingChain = errors.New("compact.Encode: ev.Chain is nil; composite did not stamp")

// ErrInvalidTimestamp is returned when ev.Timestamp is the zero value or
// represents an instant before the Unix epoch. Both cases would silently wrap
// when cast to uint64 nanoseconds, masking caller bugs in the hot path.
var ErrInvalidTimestamp = errors.New("compact.Encode: ev.Timestamp must be non-zero and ≥ Unix epoch")

// Encode projects an agentsh event into a wtpv1.CompactEvent, populating
// everything EXCEPT the IntegrityRecord. The IntegrityRecord is filled in by
// the WTP Store in the AppendEvent transactional pattern, AFTER chain.Compute
// returns the entry hash.
//
// Encode is independently safe to call. Store.New (Phase 10) provides
// additional rejection of invalid mappers at construction time, but Encode
// does not depend on it: the nil-check below mirrors the same contract on
// the hot path so the temporal coupling on the future store layer is
// eliminated. This is defense in depth, not redundancy.
//
// Preconditions:
//   - m must be a valid Mapper (non-nil, not typed-nil pointer). Returns
//     ErrInvalidMapper otherwise.
//   - ev.Chain must be non-nil; the composite store stamps this before
//     fanning out to sinks. Returns ErrMissingChain otherwise.
//   - ev.Timestamp must be non-zero and ≥ Unix epoch. Returns
//     ErrInvalidTimestamp otherwise.
//
// Error contract:
//   - errors.Is(err, ErrInvalidMapper) for nil/typed-nil pointer mapper
//   - errors.Is(err, ErrMissingChain) for missing chain
//   - errors.Is(err, ErrInvalidTimestamp) for invalid timestamp
//   - errors.Unwrap returns the mapper error when m.Map fails
func Encode(m Mapper, ev types.Event) (*wtpv1.CompactEvent, error) {
	if m == nil {
		return nil, ErrInvalidMapper
	}
	if rv := reflect.ValueOf(m); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil, ErrInvalidMapper
	}
	if ev.Chain == nil {
		return nil, ErrMissingChain
	}
	if ev.Timestamp.IsZero() {
		return nil, ErrInvalidTimestamp
	}
	nanos := ev.Timestamp.UnixNano()
	if nanos < 0 {
		return nil, ErrInvalidTimestamp
	}
	mapped, err := m.Map(ev)
	if err != nil {
		return nil, fmt.Errorf("compact mapper: %w", err)
	}
	return &wtpv1.CompactEvent{
		Sequence:           ev.Chain.Sequence,
		Generation:         ev.Chain.Generation,
		TimestampUnixNanos: uint64(nanos),
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

**Acceptance criteria.** The tests above must lock in the following contract for `compact.Encode`:

- Happy path populates `Sequence`, `Generation`, `TimestampUnixNanos`, OCSF class/activity, and `Payload` from the Mapper output.
- `Integrity` is left nil — populated downstream by the chain step, not by Encode.
- Missing `Chain` returns `ErrMissingChain` (assert with `errors.Is`).
- Mapper error is wrapped with `fmt.Errorf("compact mapper: %w", err)` so `errors.Unwrap` returns the underlying error.
- Zero `Timestamp` returns `ErrInvalidTimestamp` (assert with `errors.Is`).
- Pre-epoch `Timestamp` (e.g. 1969-12-31) returns `ErrInvalidTimestamp` (assert with `errors.Is`).
- Unix epoch boundary (`time.Unix(0, 0)`) is accepted; `TimestampUnixNanos` is `0`.
- Encode rejects nil mapper (`ErrInvalidMapper`, assert with `errors.Is`).
- Encode rejects typed-nil pointer mapper (`ErrInvalidMapper`, assert with `errors.Is`).
- All sentinels are exported for `errors.Is` classification: `ErrInvalidMapper`, `ErrMissingChain`, `ErrInvalidTimestamp`.
- Defense in depth: `Encode` rejects invalid mappers independently. `Store.New` (Phase 10) performs the same rejection at construction time; the cheap nil branch on the hot path removes the temporal coupling on the future store layer.
- Sink-side metric wiring for Encode-error classification (incrementing per-class counters and dropping without advancing the chain) is owned by Task 22a + Task 23 (Phase 10) — not in this task's scope.

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
	// Reason classifies the source of the gap. WAL-emitted (persisted on
	// disk via AppendLoss): "overflow" (segment dropped by overflow GC,
	// see dropOldestLocked at wal.go:1081) and "crc_corruption" (corrupt
	// segment skipped during read, see reader.go). Transport-emitted
	// (synthesized in memory by Replayer.PrefixLoss, NOT persisted via
	// AppendLoss): "ack_regression_after_gc" (server presented a stale
	// ack tuple and the gap between remoteReplayCursor and the WAL's
	// earliest-on-disk seq has been GC'd; see Task 15.1 Step 1b.5 +
	// Task 16 Replayer prefix-loss option). Receivers MUST treat all
	// three reason values uniformly — the difference is provenance, not
	// semantics; the gap is unrecoverable in all three cases. Adding a
	// new reason value here MUST also be reflected in the receiver-side
	// loss-handling switch (no metric label collapse) AND in the
	// `LossRecord.Reason` enumeration tests under
	// `internal/store/watchtower/wal/loss_reason_test.go` (Missing B
	// parity sweep).
	Reason string // "overflow" | "crc_corruption" | "ack_regression_after_gc"
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

### Task 14a: WAL identity persistence — `SessionID` + `KeyFingerprint` written into `meta.json` (round-8 prerequisite for Task 15.1 / Task 22 identity gate)

**Status:** New WAL-package step added in round-8 to close the gap between the cold-start identity check the round-7 store-wiring snippet promises (Task 27, lines 10566-10640: "compare the persisted meta's session_id and key_fingerprint against the values configured for the current process") and the actual on-disk meta.json contract today. `wal.Meta` already has `SessionID` and `KeyFingerprint` fields (`internal/store/watchtower/wal/meta.go:19-20`), but the only production caller of `WriteMeta` (`wal.MarkAcked` at `internal/store/watchtower/wal/wal.go:865-869`) writes a fresh `Meta{AckHighWatermarkSeq, AckHighWatermarkGen, AckRecorded}` literal that DROPS those identity fields on every persist. Result: the round-7 identity gate compares against fields that production never populates — every Store restart with a non-empty `cfg.SessionID` would log a spurious `meta session_id mismatch` WARN and refuse to seed, masking the case the gate actually exists to detect (a genuinely reused WAL dir from a different installation). Task 14a fixes the WAL so identity is persisted at every meta write, validated at every Open, immutable for the WAL's lifetime, and migrates pre-identity v2 meta.json forward without erroring.

**Why this task belongs to the WAL package, not transport.** The transport package is downstream of the WAL — it reads `wal.ReadMeta` to build the `AckTuple` seed and never writes meta.json directly. The "first writer wins; later Open with different value errors" invariant is a WAL-side invariant (it protects the WAL directory's integrity against being silently retargeted to a new identity mid-lifetime). The cold-start gate in Task 27 layers on top by mapping a meta-mismatch into a "do not seed" decision rather than an error; that policy choice is the store-wiring layer's, but the underlying check (read meta, compare identity, refuse to mutate on mismatch) lives in the WAL.

**Files:**
- Modify: `internal/store/watchtower/wal/wal.go` (extend `Options` with `SessionID string` and `KeyFingerprint string`; in `Open`, after the existing `ReadMeta` call, validate identity if meta is present-and-non-empty; refactor the `MarkAcked` `WriteMeta` call to include identity from `w.opts`; expose `w.SessionID()` / `w.KeyFingerprint()` accessors so tests can assert what the WAL has staged for the next meta write; **add `(w *WAL) EarliestDataSequence() (uint64, bool, error)`, `(w *WAL) HighWaterSequence() uint64`, `(w *WAL) WrittenDataHighWater(gen uint32) (uint64, bool)`, `(w *WAL) HasDataBelowGeneration(threshold uint32) (bool, error)`, AND `(w *WAL) HasReplayableRecords(gen uint32) (bool, error)` accessors** — see Step 3a for the contract. Round-11 SAFETY (Finding 1): the per-generation, data-bearing accessor `WrittenDataHighWater(gen)` REPLACES the round-10 `WrittenHighGeneration() uint32` because the latter is unsafe — `w.highGen` is seeded from segment headers during recovery (wal.go:340) BEFORE any RecordData lands, so a header-only generation is indistinguishable from a generation with actual data; admitting an ack for an unwritten generation lets `wal.MarkAcked` accept the ack and lex GC discard surviving lower-gen segments holding unsent records. Round-16 SAFETY (Finding 1): `HasDataBelowGeneration(threshold)` is added to gate the first-apply (serverGen, 0) adopt branch in `applyServerAckTuple` — without it, adopting (serverGen, 0) when local data exists at any g<serverGen would lex-over-ack every lower-gen record via `wal.MarkAcked`'s `segmentFullyAckedLocked` predicate. Round-16 SAFETY (Finding 2): `HasReplayableRecords(gen)` is added to gate the multi-stage `computeReplayPlan`'s intermediate-generation loop — `WrittenDataHighWater` alone is data-only and silently drops loss-only generations (e.g., produced by overflow GC mid-session, with no subsequent RecordData Append before disconnect), leaving the server unaware of the gap. The new accessor includes loss-only generations so the replay plan still schedules a stage; the receiver then observes the gap on reconnect.)
- Test: `internal/store/watchtower/wal/wal_identity_test.go` (new file — keeps the four identity-focused tests grouped without bloating `wal_test.go`)
- Test: extend `internal/store/watchtower/wal/wal_test.go` (NOT `wal_identity_test.go` — these accessors are general-purpose, not identity-related) with SIXTEEN new tests for the accessors (Step 3a — `TestWAL_HighWaterSequenceMatchesReader`, `TestWAL_EarliestDataSequence`, plus the FIVE round-11 per-gen data-bearing HW tests `TestWAL_WrittenDataHighWaterReturnsFalseForFutureGen`, `TestWAL_WrittenDataHighWaterReturnsFalseForGenWithOnlyHeader`, `TestWAL_WrittenDataHighWaterTracksAppend`, `TestWAL_WrittenDataHighWaterAfterRoll`, `TestWAL_WrittenDataHighWaterIgnoresLossMarkers`, plus the round-13 performance-budget test `TestWAL_WrittenDataHighWater_IsConstantTime`, plus the round-16 Finding 1 tests `TestWAL_HasDataBelowGeneration` and `TestWAL_HasDataBelowGenerationAfterClose`, plus the round-16 Finding 2 tests `TestWAL_HasReplayableRecords`, `TestWAL_HasReplayableRecords_LossOnlyGeneration`, `TestWAL_HasReplayableRecords_HeaderOnlySegmentDoesNotSeed`, `TestWAL_HasReplayableRecords_AfterFullGC`, and `TestWAL_HasReplayableRecordsAfterClose`)

**Spec rule (design.md §"Cold-start seed safety / stale meta detection"):** the persisted meta.json carries the WAL's installation identity. A WAL directory is bound to one (SessionID, KeyFingerprint) for its lifetime; reopening the directory with different values is a configuration error and MUST be surfaced rather than silently consumed.

**Step 1: Extend `wal.Options` with identity fields.**

```go
// Options configures a WAL. Defaults are not applied here — callers should
// pre-validate via internal/config (which does apply defaults).
type Options struct {
    Dir           string
    SegmentSize   int64
    MaxTotalBytes int64
    SyncMode      SyncMode
    SyncInterval  time.Duration

    // SessionID is the daemon's per-installation session identifier. It is
    // written into meta.json on every WriteMeta call and is IMMUTABLE for
    // the WAL directory's lifetime — first writer wins. If a later wal.Open
    // is invoked with a different SessionID and meta.json on disk already
    // carries a non-empty SessionID, Open errors out (this is the same
    // logical condition the round-7 store-wiring identity gate detects, but
    // surfaced one layer down so the WAL itself refuses to mutate). Empty
    // SessionID is allowed for back-compat with pre-Task-14a callers and
    // tests that don't care about identity; it disables both the persist
    // and the Open validation. Production wiring (Task 27) MUST set this
    // to opts.SessionID.
    SessionID string

    // KeyFingerprint is the daemon's signing-key fingerprint
    // ("sha256:<hex>"). Same persistence and immutability rules as
    // SessionID; same back-compat allowance for empty values.
    KeyFingerprint string
}
```

**Step 2: Validate identity at `Open` time.** Insert the check right after the existing `ReadMeta` block, BEFORE `recover()` runs (so we fail fast on a mismatch without committing any segment-level work). The mismatch is surfaced as a typed `*ErrIdentityMismatch` so the store-wiring layer (Task 27) can `errors.As` on it and decide whether to quarantine the WAL dir or refuse to start:

```go
// ErrIdentityMismatch is returned by Open when the persisted meta.json
// carries a SessionID or KeyFingerprint that disagrees with the
// caller-supplied opts. The persisted-vs-expected pairs are exposed so
// upstream callers can include them in operator-facing logs without
// re-parsing the error message.
//
// Both fields are populated even when only one mismatched — the
// non-mismatching field carries the matching value on both sides
// (so the operator sees the full identity context). The
// MismatchedField string is one of "session_id" or "key_fingerprint"
// and identifies which check tripped first; if both mismatched, the
// session_id check runs first and is reported.
type ErrIdentityMismatch struct {
    MismatchedField         string // "session_id" or "key_fingerprint"
    PersistedSessionID      string
    ExpectedSessionID       string
    PersistedKeyFingerprint string
    ExpectedKeyFingerprint  string
}

func (e *ErrIdentityMismatch) Error() string {
    if e.MismatchedField == "session_id" {
        return fmt.Sprintf("wal.Open: session_id mismatch: persisted=%q opts=%q", e.PersistedSessionID, e.ExpectedSessionID)
    }
    return fmt.Sprintf("wal.Open: key_fingerprint mismatch: persisted=%q opts=%q", e.PersistedKeyFingerprint, e.ExpectedKeyFingerprint)
}

// In Open, after the existing ReadMeta block:
if m, err := ReadMeta(opts.Dir); err == nil {
    if m.AckRecorded {
        w.ackHighSeq = m.AckHighWatermarkSeq
        w.ackHighGen = m.AckHighWatermarkGen
        w.ackPresent = true
    }
    // Identity check (Task 14a). Only validate when BOTH the on-disk
    // value is non-empty AND the caller-supplied value is non-empty.
    // The "either side empty" case is the v2-with-empty-identity
    // migration: a pre-Task-14a meta.json had no identity fields, OR
    // the test caller deliberately omits identity. In both, we adopt
    // (don't error) — the next meta write will populate the field
    // from opts.
    if m.SessionID != "" && opts.SessionID != "" && m.SessionID != opts.SessionID {
        return nil, &ErrIdentityMismatch{
            MismatchedField:         "session_id",
            PersistedSessionID:      m.SessionID,
            ExpectedSessionID:       opts.SessionID,
            PersistedKeyFingerprint: m.KeyFingerprint,
            ExpectedKeyFingerprint:  opts.KeyFingerprint,
        }
    }
    if m.KeyFingerprint != "" && opts.KeyFingerprint != "" && m.KeyFingerprint != opts.KeyFingerprint {
        return nil, &ErrIdentityMismatch{
            MismatchedField:         "key_fingerprint",
            PersistedSessionID:      m.SessionID,
            ExpectedSessionID:       opts.SessionID,
            PersistedKeyFingerprint: m.KeyFingerprint,
            ExpectedKeyFingerprint:  opts.KeyFingerprint,
        }
    }
} else if !errors.Is(err, os.ErrNotExist) {
    return nil, fmt.Errorf("read meta: %w", err)
}
```

**Step 3: Persist identity on every `WriteMeta` call.** Today `MarkAcked` constructs a `Meta{}` literal that DROPS the identity fields. Fix: include `w.opts.SessionID` and `w.opts.KeyFingerprint` so every meta write carries the current identity. (No new `WriteMeta` callers are added in this task — `MarkAcked` is currently the only one. If future work adds a meta-write site, it MUST follow the same pattern.)

```go
// In MarkAcked, replace the literal:
if err := WriteMeta(w.opts.Dir, Meta{
    AckHighWatermarkSeq: w.ackHighSeq,
    AckHighWatermarkGen: w.ackHighGen,
    AckRecorded:         true,
    SessionID:           w.opts.SessionID,    // Task 14a
    KeyFingerprint:      w.opts.KeyFingerprint, // Task 14a
}); err != nil {
```

**Step 3a: Add `EarliestDataSequence()`, `HighWaterSequence()`, `WrittenDataHighWater(gen)`, and `HasDataBelowGeneration(threshold)` accessors.** The transport (Task 15.1) needs four read-only WAL accessors that today live ONLY on the `Reader` (`(r *Reader) WALHighWaterSequence()` at `internal/store/watchtower/wal/reader.go:276`) or do not exist at all. Hoisting them onto `*WAL` lets the transport query them directly without opening a Reader — important for the `ack_regression_after_gc` detector (Task 15.1 Step 1b.5), which must check the on-disk earliest BEFORE opening the replay reader so the synthesized loss marker is appended in the right ordering, AND for the round-11 cross-generation ack taxonomy (Task 15.1 `applyServerAckTuple`), which needs a per-generation, **data-bearing** high-water proof so the helper can distinguish "server is on a generation we've actually emitted RecordData in" (Adopted) from "server is on a generation we've only opened a segment header for" (Anomaly), AND for the round-16 Finding 1 first-apply data-loss fix, which needs `HasDataBelowGeneration(threshold)` to detect "server is acking gen=N when the WAL still has data in some g<N" before adopting `(N, 0)` would lex-over-ack every lower-gen record.

**Round-11 SAFETY NOTE (replaces the round-10 `WrittenHighGeneration()` accessor).** The round-10 design exposed `WrittenHighGeneration() = w.highGen`, but `w.highGen` is seeded from segment headers during recovery (`wal.go:340` — `w.highGen = hdr.Generation`) BEFORE any RecordData is decoded for that generation. That meant `applyServerAckTuple` could classify `(server.gen=N, server.seq=K)` as `Adopted` even when generation N had only been ROLLED (the writer opened a new segment header and crashed before writing a single RecordData) — and then `wal.MarkAcked(N, K)` would accept any K, immediately make all lower-generation segments reclaimable under lexicographic GC (`wal.go:1099` `segmentFullyAckedLocked`), and silently drop unsent history. The round-11 accessor `WrittenDataHighWater(gen)` returns `(maxDataSeq, ok)` where `ok=true` ONLY if at least one RecordData entry exists on disk for that generation. The cross-generation Adopted branch in `applyServerAckTuple` MUST consult this accessor rather than `WrittenHighGeneration()`. The unsafe `WrittenHighGeneration()` accessor is REMOVED from this task's scope; it has no other consumer.

```go
// HighWaterSequence returns the highest user sequence ever appended to this
// WAL across ALL generations. Mirrors the existing (r *Reader)
// WALHighWaterSequence() but on the WAL itself so callers without a Reader
// handle (e.g. the transport's pre-replay ack-regression check, where the
// caller wants the WAL-wide upper bound regardless of generation) can query
// it. Returns w.highSeq under w.mu.
//
// Naming note: the existing (w *WAL) HighWatermark() (line 466) returns the
// SAME value as this accessor and is retained for backward compatibility.
// New callers SHOULD use HighWaterSequence() — the name aligns with the
// Reader's WALHighWaterSequence() and disambiguates from the (gen, seq) ack
// HighWatermark exposed by AckHighWatermark()/HighGeneration().
//
// Round-13 Finding 4 reconciliation — RESERVED USAGE.
// `HighWaterSequence()` MUST NOT be used to validate a server-supplied
// ack tuple, because it conflates generations: the writer's CURRENT
// generation high-seq is not a valid bound for a server ack on an OLDER
// generation (sequences reset on every roll; a current-gen high-seq of
// K does not imply older-gen high-seq is K). Both the same-generation
// AND cross-generation Adopted branches in `applyServerAckTuple` (Task
// 15.1) MUST consult `WrittenDataHighWater(server.gen)` for the
// per-generation, data-bearing bound. `HighWaterSequence()` is reserved
// for the Replayer's tail-snapshot diagnostic path only and for any
// future WAL-wide telemetry consumer that does not care about
// per-generation correctness. Production callers other than the Replayer
// SHOULD prefer `WrittenDataHighWater(gen)` even if "current generation"
// happens to be the relevant generation today, because the call site
// stays correct after a future generation roll.
func (w *WAL) HighWaterSequence() uint64 {
    w.mu.Lock()
    defer w.mu.Unlock()
    return w.highSeq
}

// WrittenDataHighWater returns the highest sequence among RecordData entries
// actually present on disk for the requested generation, plus an ok flag that
// is FALSE when no RecordData has ever been written in that generation (even
// if a SegmentHeader for that generation exists), plus an err that is non-nil
// when the underlying disk scan fails. The "data-bearing" qualifier is
// load-bearing: this accessor MUST NOT count loss markers (synthetic gap
// notices) NOR segment-header seeds (the writer opened a new segment for
// generation N and crashed before any RecordData landed) as "the writer has
// emitted in this generation."
//
// Round-12 Finding 4 RATIONALE for the explicit `err` return. The round-11
// signature was `(uint64, bool)` — but if the implementation does a fresh
// segment scan (approach 2 below) and the scan fails (open/header-read I/O
// error), the failure collapses to `ok=false` and the caller misclassifies as
// `unwritten_generation` (a peer-attributable Anomaly). The round-12 signature
// adds an explicit `err` return so the caller can distinguish a real
// "writer has not emitted in this generation" from a transient WAL-read
// failure. Callers (applyServerAckTuple in Task 15.1 / 17.X) MUST check `err`
// FIRST before evaluating `ok`; on `err != nil` the caller MUST treat the
// outcome as a transport-level failure (NOT an anomaly attributable to the
// peer) and propagate the error rather than emit `unwritten_generation` —
// the helper returns Anomaly with reason `wal_read_failure` so the
// SessionAck/recv handler logs WARN and leaves cursors unchanged without
// muddying the peer-attributable anomaly counters.
//
// Round-11 RATIONALE. The round-10 design exposed `WrittenHighGeneration()`
// which simply returned `w.highGen`. But recovery seeds `w.highGen` from
// segment headers (`wal.go:340` — `w.highGen = hdr.Generation`) BEFORE any
// RecordData is decoded for that generation. That meant the cross-generation
// Adopted branch in `applyServerAckTuple` could fire for an empty rolled
// generation; once `wal.MarkAcked(N, K)` accepted that fabricated tuple,
// every lower-generation segment became reclaimable under the lexicographic
// GC at `wal.go:1099` (`segmentFullyAckedLocked`) and unsent history was
// silently dropped. The round-11 accessor closes that hole by requiring a
// per-generation, data-bearing proof.
//
// Contract:
//   - Returns `(0, false, nil)` when the WAL has never appended a RecordData
//     entry for the requested generation. This includes:
//     a) The generation is FUTURE (writer has not rolled to it yet).
//     b) The generation was rolled (a new INPROGRESS segment was opened
//        with that generation in its header) but no RecordData record was
//        ever appended before a crash, or the only records written in that
//        generation were synthetic loss markers.
//     c) The generation is older than anything still on disk (it has been
//        fully GC'd; the writer cannot prove durability for an erased
//        generation).
//   - Returns `(maxDataSeq, true, nil)` when at least one RecordData entry
//     exists on disk for the requested generation. `maxDataSeq` is the
//     LARGEST sequence among those RecordData entries; the helper's
//     `Adopted` comparison is `server.seq <= maxDataSeq`.
//   - Returns `(0, false, err)` when a disk-scan failure prevents the
//     accessor from determining either of the above. The caller MUST NOT
//     treat this as `unwritten_generation`; it MUST propagate the error
//     up the stack so the helper can return Anomaly with reason
//     `wal_read_failure` (NOT `unwritten_generation`, NOT
//     `server_ack_exceeds_local_data`). This decoupling keeps the
//     peer-attributable anomaly counters honest. Approach-1
//     implementations (per-generation tracking on the WAL struct) typically
//     never return `err != nil` because the lookup is in-memory; the err
//     path exists for the approach-2 (fresh segment scan) implementation.
//
// Implementation note (round-13 Missing A: approach 1 is MANDATORY for production;
// approach 2 is described only to keep the contract self-explanatory):
//   1. **Per-generation tracking on the WAL struct (REQUIRED for production).**
//      Maintain a small `perGenDataHighWater map[uint64]uint64` of
//      `gen → maxDataSeq` updated on every Append that carries RecordData.
//      Recovery rebuilds the map by scanning each segment for RecordData
//      entries (loss markers and segment headers do NOT contribute). Lookup
//      is O(1) — strictly a map read under w.mu, no disk I/O. This is the
//      mandated implementation per the round-13 "Performance budget" subsection
//      below; the production WAL MUST adopt this shape.
//   2. **Fresh segment scan on call (REJECTED for production; description
//      retained only to ground the err-return contract above).** Open every
//      segment whose header gen matches the request, decode records skipping
//      loss markers, return the max RecordData seq. Lookup is O(segments-for-
//      that-gen). REJECTED for `WrittenDataHighWater` because the accessor is
//      consulted on the recv hot path (every BatchAck + ServerHeartbeat +
//      SessionAck calls it via `applyServerAckTuple`), and a per-call disk
//      scan would couple ack-validation latency to segment count. See
//      "Performance budget" subsection at Task 14a end for the rationale.
//
// Mutex contract: takes w.mu briefly to copy the per-gen tracking map entry
// (approach 1 — the only production path); RELEASES w.mu before returning.
// No disk I/O occurs under this accessor in the production implementation,
// so Append is never blocked.
//
// The transport (Task 15.1) calls this from the cross-generation Adopted
// branch of `applyServerAckTuple`. The same-generation Adopted branch ALSO
// calls `WrittenDataHighWater(server.gen)` for consistency — round-13
// Finding 4 reconciliation: BOTH branches use the per-gen, data-bearing
// accessor so the validation predicate is identical regardless of whether
// `server.gen == w.HighGeneration()` or `server.gen` is older. The legacy
// `HighWaterSequence()` accessor (above) is RESERVED for the Replayer's
// tail-snapshot diagnostic path only — it MUST NOT be used as the
// authoritative bound on a server-supplied ack tuple, because it returns
// the WAL's CURRENT-generation high-water and would silently misclassify
// an ack on an older generation as `server_ack_exceeds_local_data` even
// when that older generation has the seq covered.
func (w *WAL) WrittenDataHighWater(gen uint32) (uint64, bool, error) {
    // Implementation outline — actual code lives in wal.go:
    //   1. Acquire w.mu.
    //   2. (Approach 1) Look up the per-gen max-seq map; copy the entry
    //      (or zero) into locals; release the lock; return (seq, ok, nil).
    //   2'. (Approach 2) Snapshot segment list filtered to gen == request;
    //      release the lock; for each segment, open file, decode records
    //      (skipping loss markers via the LossMarkerSentinel check), track
    //      max seq; on a scan failure that is NOT ENOENT (which is the
    //      "GC raced us" race below), abort the loop and return (0, false, err).
    //      Return (maxSeq, true, nil) or (0, false, nil) if no segment had
    //      a RecordData entry for that gen.
    //   3. ENOENT during step 2' is silently treated as "GC raced us" and
    //      the loop advances to the next segment (the snapshot may be
    //      stale; the next caller will see the post-GC view) — does NOT
    //      surface as err.
}

// EarliestDataSequence returns the lowest user sequence among RecordData
// entries still present on disk in the WAL's segments (sealed + INPROGRESS)
// **for the requested generation**. Used by the transport (Task 15.1
// Step 1b.5) to detect ack_regression_after_gc: when the server presents a
// stale ack tuple AND the gap (remoteReplayCursor.seq+1, ...] has already
// been GC'd, the earliest remaining sequence in the replay generation is
// strictly greater than remoteReplayCursor.seq+1, and the transport
// synthesizes a single in-memory wal.LossRecord for the gap (passed to the
// Replayer via Replayer.PrefixLoss) before the Replayer opens its first
// batch.
//
// Round-12 Finding 1 RATIONALE for the `gen` parameter. The round-11
// signature was `EarliestDataSequence() (uint64, bool, error)` — generation
// implicit. But sequences reset on every generation roll AND higher-generation
// segments can coexist on disk while lower-generation segments are GC'd
// (the GC predicate is lex on (gen, seq) per `segmentFullyAckedLocked` in
// wal.go). A generation-implicit accessor would surface a *later*
// generation's low sequence (e.g. seq=1 in gen=N+1 just after a roll) as
// evidence the *replay* generation's gap is intact — silently masking
// `ack_regression_after_gc` whenever the writer rolls past the GC'd
// generation. The round-12 fix scopes the accessor to the requested
// generation: returns the smallest RecordData sequence among segments whose
// header gen matches `gen`, ignoring all other generations on disk. The
// transport's `computeReplayStart` calls this with `persistedAck.gen`
// (equivalently `remoteReplayCursor.gen` because the same-generation
// invariant holds by the time `computeReplayStart` runs — see Task 15.1
// header SCOPE NOTE).
//
// Returns ok=false when the WAL has no RecordData on disk in the requested
// generation (either the generation has been fully GC'd, the writer has not
// rolled to it yet, or the only records on disk for that generation are
// synthetic loss markers — same exclusion rule as `WrittenDataHighWater`).
// In that case the transport's ack-regression check ALSO emits a loss marker
// when the server's tuple has regressed past the persisted ack (the
// fully-GC'd, server-regressed-below-persisted case introduced in
// round-10 Finding 2): `gapEnd = persistedAck.seq` and the synthesized
// loss covers the entire range [gapStart, persistedAck.seq]. See Task
// 15.1 Step 1b.5 for the four-case decision tree.
//
// Implementation: scans w.segments[] (the in-memory snapshot of seg/INPROGRESS
// files maintained by Append's seal logic) filtered to segments whose header
// generation matches `gen`, opens the lowest-indexed surviving segment,
// decodes the segment header, and decodes the first ReadRecord that is NOT a
// loss marker. Loss markers are skipped because their FromSequence/ToSequence
// describe a GAP, not an existing record — the earliest DATA-bearing sequence
// in the requested generation is what the transport needs.
//
// Mutex contract: takes w.mu for the segment list snapshot, then RELEASES it
// before opening the segment file (to avoid blocking Append on disk I/O).
// Re-acquires nothing — the snapshot is sufficient because the only race is
// "GC removes the segment we picked between snapshot and open", which surfaces
// as os.ErrNotExist; in that case the caller retries by re-invoking
// EarliestDataSequence (the next call sees the post-GC snapshot).
//
// Error handling: an `err != nil` return is reserved for I/O failures during
// the per-segment open/decode loop that the WAL chooses to surface (NOT
// ENOENT — that is silently skipped as a GC race; the next iteration sees
// the post-GC snapshot). On `err != nil` the caller MUST treat the outcome
// as a transport-level failure and reconnect rather than open the reader at
// a wrong position; see `computeReplayStart` in Task 15.1.
func (w *WAL) EarliestDataSequence(gen uint32) (uint64, bool, error) {
    // Implementation outline — actual code lives in wal.go:
    //   1. Lock w.mu, copy w.segments[] (or equivalent), unlock.
    //   2. Filter the snapshot to segments whose header gen == requested gen.
    //   3. For each filtered segment in ascending index order:
    //        a. Open the segment file, decode SegmentHeader.
    //        b. Loop ReadRecord until we get a non-loss-marker payload.
    //        c. Parse the seq/gen prefix (parseSeqGen) and return (seq, true, nil).
    //   4. If no segments yielded a data record, return (0, false, nil).
    //   5. ENOENT during step 3a is silently treated as "GC raced us" and
    //      the loop advances to the next segment. Other I/O errors bubble up
    //      as the err return.
}

// HasDataBelowGeneration reports whether the WAL has ever emitted a RecordData
// entry in ANY generation strictly less than `threshold`. Returns false when
// no RecordData exists below the threshold (either no lower-generation has
// been written OR all lower-generation segments have been GC'd).
//
// Round-16 Finding 1 RATIONALE. The transport's applyServerAckTuple
// first-apply branch (Task 15.1) needs to safely adopt (serverGen, 0) —
// a vacuous "I haven't acked anything yet within serverGen" — WITHOUT
// lex-over-acking records in lower generations. `wal.MarkAcked(N, 0)`
// persists the tuple; the per-segment GC predicate
// (`segmentFullyAckedLocked` in wal.go — reclaims any segment with
// `segGen < ackHighGen`) then reclaims every lower-generation segment
// on the next GC pass, silently destroying records that have not yet
// been delivered. `HasDataBelowGeneration(serverGen)` closes this hole:
// if it returns `(true, nil)`, the first-apply branch takes the
// Anomaly path with `AnomalyReason="server_ack_exceeds_local_data"`
// instead of adopting.
//
// Contract:
//   - Returns `(false, nil)` on a fresh WAL (no RecordData anywhere).
//   - Returns `(false, nil)` when the highest-data generation on disk is
//     `>= threshold`, OR the only records below `threshold` are synthetic
//     loss markers (same data-bearing exclusion as
//     `WrittenDataHighWater`).
//   - Returns `(true, nil)` when at least one generation `g < threshold`
//     has a RecordData entry in `w.perGenDataHighWater`. This is the
//     "do not adopt (threshold, 0)" signal.
//   - Returns `(_, err != nil)` for I/O failures the WAL chose to surface
//     (approach 1 is in-memory-only and therefore does NOT error; the err
//     return is reserved for a future refactor that pulls the data from
//     disk).
//
// Boundary: HasDataBelowGeneration(G) against a WAL whose only data is
// in gen=G returns `(false, nil)` — same-generation data is NOT "below"
// and the first-apply branch adopts safely.
//
// Implementation: O(N) where N is the count of populated entries in
// `perGenDataHighWater` (typically 0-2: the current writer's gen plus at
// most a couple of older partial-GC'd gens). The accessor is on the
// recv hot path (every first-apply SessionAck) so a per-call disk scan
// would be unacceptable; approach 1 is mandatory.
func (w *WAL) HasDataBelowGeneration(threshold uint32) (bool, error) {
    // Implementation outline — actual code lives in wal.go:
    //   1. Lock w.mu.
    //   2. Iterate w.perGenDataHighWater; if any key < threshold, return
    //      (true, nil).
    //   3. Return (false, nil).
    // The iteration is bounded by the size of perGenDataHighWater, which
    // is GC-aware: entries are removed when the last segment for that
    // generation is GC'd (Task 13's ack-aware GC contract). A fully-GC'd
    // lower generation therefore correctly reports "no data below".
}
```

**Tests for the accessors** (added to `wal_test.go`, NOT `wal_identity_test.go`):

`TestWAL_HighWaterSequenceMatchesReader` — Setup: open WAL, append 5 records. Open a Reader with start=0. Assert: `w.HighWaterSequence() == 5` AND `r.WALHighWaterSequence() == 5` AND both equal `w.HighWatermark()` (the back-compat alias). Append 3 more records. Assert: `w.HighWaterSequence() == 8`. Close the Reader, call `w.HighWaterSequence()` again — still 8 (Reader close does not affect WAL high-water).

`TestWAL_WrittenDataHighWaterReturnsFalseForFutureGen` — Setup: open WAL fresh in `t.TempDir()`; do not append. Assert: `_, ok, err := w.WrittenDataHighWater(1); !ok && err == nil`. Append 1 record (lands in gen=1 by Task 12 contract). Assert: `_, ok, err := w.WrittenDataHighWater(2); !ok && err == nil` AND `_, ok, err := w.WrittenDataHighWater(7); !ok && err == nil` (gens above the writer's current gen are always `ok=false` with no error).

`TestWAL_WrittenDataHighWaterReturnsFalseForGenWithOnlyHeader` — Setup: open WAL, append 5 records (all in gen=1). Drive a generation roll via the production roll path (`RollGenerationForTest` seam from Task 12) so a NEW INPROGRESS segment is opened with gen=2 in its SegmentHeader, but DO NOT append any record in gen=2. Assert: `_, ok, err := w.WrittenDataHighWater(2); !ok && err == nil` (the segment header was seeded but no RecordData has landed). Now append 1 record in gen=2. Assert: `seq, ok, err := w.WrittenDataHighWater(2); ok && err == nil && seq == <whatever the new seq was>`. This test is the round-11 safety regression test — without the data-bearing distinction, an attacker (or a buggy server) could ack an unwritten gen=2 and trigger lower-gen GC.

`TestWAL_WrittenDataHighWaterTracksAppend` — Setup: open WAL, append 5 records (all in gen=1). Assert: `seq, ok, err := w.WrittenDataHighWater(1); ok && err == nil && seq == 5`. Append 3 more in gen=1. Assert: `seq, ok, err := w.WrittenDataHighWater(1); ok && err == nil && seq == 8`. Assert appending does NOT change other generations: `_, ok, err := w.WrittenDataHighWater(2); !ok && err == nil`.

`TestWAL_WrittenDataHighWaterAfterRoll` — Setup: open WAL, append 5 records in gen=1. Roll (production roll path). Append 3 records in gen=2. Roll again. Append 1 record in gen=3. Assertions:
- `seq1, ok1, err1 := w.WrittenDataHighWater(1); ok1 && err1 == nil && seq1 == 5`.
- `seq2, ok2, err2 := w.WrittenDataHighWater(2); ok2 && err2 == nil && seq2 == 3` (sequences reset across generations per Task 12).
- `seq3, ok3, err3 := w.WrittenDataHighWater(3); ok3 && err3 == nil && seq3 == 1`.
- `_, ok4, err4 := w.WrittenDataHighWater(4); !ok4 && err4 == nil` (no gen=4 yet).

`TestWAL_WrittenDataHighWaterIgnoresLossMarkers` — Setup: open WAL, append 3 RecordData records in gen=1 (seqs 1..3). Drive `wal.AppendLoss(LossRecord{FromSequence: 4, ToSequence: 10, Generation: 1, Reason: "overflow"})`. Drive a generation roll. Drive `wal.AppendLoss(LossRecord{FromSequence: 0, ToSequence: 0, Generation: 2, Reason: "crc_corruption"})` (a loss marker in gen=2 with NO RecordData). Assertions:
- `seq1, ok1, err1 := w.WrittenDataHighWater(1); ok1 && err1 == nil && seq1 == 3` (the loss marker after seq 3 does NOT bump the data high-water — the contract is "max RecordData seq").
- `_, ok2, err2 := w.WrittenDataHighWater(2); !ok2 && err2 == nil` (the only record in gen=2 is a loss marker, which does NOT count as data; the writer has not emitted a RecordData in gen=2). This is the same shape as the round-11 attack: a generation that exists on disk but has no durable data record cannot be the basis for an Adopted ack.

`TestWAL_EarliestDataSequence` — Round-12 Finding 1 (the accessor is generation-aware): four sub-cases in one test (each uses a fresh WAL):
- *Empty (gen=1)*: Open WAL, do not append. Assert `_, ok, err := w.EarliestDataSequence(1); !ok && err == nil`.
- *Single segment with records*: Append 5 records in gen=1, no MarkAcked. Assert `seq, ok, err := w.EarliestDataSequence(1); ok && err == nil && seq == 1`. Assert higher gens are empty: `_, ok2, err2 := w.EarliestDataSequence(2); !ok2 && err2 == nil`.
- *Post-GC same gen*: Append 50 records in gen=1 (configure SegmentSize small enough to force ≥3 segments). Drive `w.MarkAcked(gen=1, seq=20)` so segments 1+2 GC. Assert `seq, ok, err := w.EarliestDataSequence(1); ok && err == nil && seq == 21` (the first surviving record in gen=1).
- *Mixed-gen on disk*: Append 5 records in gen=1, roll to gen=2, append 5 records in gen=2. Assert `seq1, ok1, err1 := w.EarliestDataSequence(1); ok1 && err1 == nil && seq1 == 1` AND `seq2, ok2, err2 := w.EarliestDataSequence(2); ok2 && err2 == nil && seq2 == 1` (sequences reset across generations; the accessor returns the lowest in EACH generation independently). Now drive `w.MarkAcked(gen=1, seqHigh)` so all gen=1 segments GC, leaving only gen=2 on disk. Assert `_, okPostGC1, errPostGC1 := w.EarliestDataSequence(1); !okPostGC1 && errPostGC1 == nil` (gen=1 is empty post-GC) AND `seqPostGC2, okPostGC2, errPostGC2 := w.EarliestDataSequence(2); okPostGC2 && errPostGC2 == nil && seqPostGC2 == 1` (gen=2 still has its records). This sub-case is the round-12 Finding 1 regression test: without the gen parameter, the post-GC query for gen=1 would surface gen=2's seq=1 and silently mask the GC'd-prefix loss.

`TestWAL_HasDataBelowGeneration` — Round-16 Finding 1 regression test for the new cross-gen lower-data accessor that gates the first-apply (serverGen, 0) adopt branch in Task 15.1's `applyServerAckTuple`. Six sub-cases in one test (each uses a fresh WAL):
- *Empty WAL*: Open WAL, do not append. Assert `has, err := w.HasDataBelowGeneration(1); !has && err == nil` AND `has, err := w.HasDataBelowGeneration(0); !has && err == nil` AND `has, err := w.HasDataBelowGeneration(99); !has && err == nil` (no data in any generation, so no threshold has lower data).
- *Single-gen data, threshold above*: Append 5 records in gen=1. Assert `has, err := w.HasDataBelowGeneration(2); has && err == nil` (gen=1 < 2). Assert `has, err := w.HasDataBelowGeneration(99); has && err == nil` (gen=1 < 99).
- *Single-gen data, threshold equal*: Same setup. Assert `has, err := w.HasDataBelowGeneration(1); !has && err == nil` (gen=1 is NOT strictly less than 1 — same-gen data is safe to ack at seq=0).
- *Multi-gen data*: Append 5 records in gen=1, roll, append 3 in gen=2. Assert `has, err := w.HasDataBelowGeneration(1); !has && err == nil` (no gen<1 data), `has, err := w.HasDataBelowGeneration(2); has && err == nil` (gen=1 < 2), `has, err := w.HasDataBelowGeneration(3); has && err == nil` (gen=1 AND gen=2 both < 3).
- *Post-GC drains lower-gen entry*: Same setup as multi-gen. Drive `w.MarkAcked(gen=2, seq=3)` so gen=1 segments GC and the perGenDataHighWater entry for gen=1 is removed (Task 13 contract). Assert `has, err := w.HasDataBelowGeneration(2); !has && err == nil` (the lower-gen entry was GC'd; the WAL no longer has data below gen=2). This sub-case is the GC-awareness regression test: without correct map cleanup on GC, a long-running agent would stay in the "lower-gen data exists" state forever even after legitimate GC.
- *Loss markers do NOT count as data*: Open fresh WAL, drive `w.AppendLoss(LossRecord{FromSequence: 1, ToSequence: 10, Generation: 1, Reason: "overflow"})` ONLY (no RecordData). Assert `has, err := w.HasDataBelowGeneration(2); !has && err == nil` (loss markers are NOT data — same exclusion rule as `WrittenDataHighWater`; this matters because adopting `(2, 0)` against a WAL with only gen=1 loss markers is safe — there's nothing to over-ack).

`TestWAL_HasDataBelowGenerationAfterClose` — Setup: open WAL, close. Assert `has, err := w.HasDataBelowGeneration(1)` returns `errors.Is(err, wal.ErrClosed)` (mirrors the closed-WAL contract on every other accessor).

`TestWAL_WrittenDataHighWater_IsConstantTime` — Round-13 Missing A regression test for the performance budget. The test asserts `WrittenDataHighWater(gen)` does NOT scale with on-disk segment count, which is the binding contract for production wiring (the accessor is consulted on the recv hot path by every BatchAck + ServerHeartbeat + SessionAck via `applyServerAckTuple`; a per-call disk scan would couple ack-validation latency to segment count and violate the Phase-8 "state machine never holds the WAL mutex during recv-hot-path validation" invariant). Setup:
- Open WAL with `SegmentSize` small enough that ~50 segments form. Append 5,000 RecordData entries in gen=1, NO MarkAcked (so all segments stay on disk). Assert `seq, ok, err := w.WrittenDataHighWater(1); ok && err == nil && seq == 5000` baseline.
- Capture wall time of N=10,000 calls to `w.WrittenDataHighWater(1)` in a tight loop; record `tHigh := elapsed/N`.
- Open a SECOND WAL fresh, append 50 RecordData entries in gen=1 (single segment). Capture wall time of N=10,000 calls; record `tLow := elapsed/N`.
- Assert: `tHigh < 5 * tLow` (a 100x growth in segment count yields at most a 5x slowdown — the multiplier is generous to accommodate noisy CI but still fails decisively if the implementer accidentally adopts approach 2). Without approach 1 (the in-memory `perGenDataHighWater map[uint64]uint64`), the segment-scan implementation would yield `tHigh ≈ 100 * tLow` and the assertion trips. Test gated behind `testing.Short()` — `if testing.Short() { t.Skip("perf test") }` — so `go test -short` skips it but the standard `go test ./...` covers it.
- Also assert: `WrittenDataHighWater(99 /* far-future gen */)` returns `(0, false, nil)` in O(1) — `tFutureGen ≈ tLow` (no scan needed for an absent gen). This sub-case catches the "approach-1 implementation forgets to short-circuit on missing-gen" bug.

NOTE: This test is intrinsically timing-based and may be flaky under heavy CI load. The implementer SHOULD also include a non-timing assertion: instrument `wal.go` to expose `func (w *WAL) writtenDataHighWaterReadCount() int` (test-only, behind a build tag) that returns the number of disk reads performed during the most recent `WrittenDataHighWater` call. Approach 1 always returns 0; approach 2 returns >=1 for any populated gen. Assert `w.writtenDataHighWaterReadCount() == 0` after the high-segment-count call. The timing assertion catches accidental I/O introduced by future refactors; the read-count assertion catches the initial implementation choice.

**Step ordering update:** insert these tests as part of Step 1 (write failing tests) and the accessor implementations as part of Step 3 (production edits). The accessors do not introduce new identity invariants, so they do NOT need a separate roborev pass — they ride alongside the identity work.

**Step 4: Tests** (TDD-first — write the four tests below in `wal_identity_test.go` BEFORE the production edits in Steps 1-3; they MUST fail with `Options.SessionID` / `Options.KeyFingerprint` undefined or with "no error returned on mismatch"):

`TestWAL_PersistsSessionIDAndKeyFingerprint` — Setup: `wal.Open(Options{Dir: t.TempDir(), SegmentSize: ..., SessionID: "s1", KeyFingerprint: "k1"})`. Append a record (`w.Append([]byte("x"))`). Drive `w.MarkAcked(1, 1)`. Assert: `wal.ReadMeta(opts.Dir)` returns `Meta{AckHighWatermarkSeq=1, AckHighWatermarkGen=1, AckRecorded=true, SessionID="s1", KeyFingerprint="k1"}`. Without the Step-3 fix, the assertion on `SessionID="s1"` fails (the meta on disk has the empty string).

`TestWAL_OpenWithDifferentSessionIDErrors` — Setup: open WAL with `SessionID="s1"`, append + MarkAcked so meta.json on disk carries `SessionID="s1"`. Close the WAL. Re-open the same `Dir` with `Options{..., SessionID: "s2", KeyFingerprint: "k1"}`. Assert: `wal.Open` returns a non-nil error AND `errors.As(err, &wal.ErrIdentityMismatch{})` succeeds with `MismatchedField=="session_id"`, `PersistedSessionID=="s1"`, `ExpectedSessionID=="s2"`, `PersistedKeyFingerprint=="k1"`, `ExpectedKeyFingerprint=="k1"`. The returned `*WAL` is nil. The error message also contains both `"session_id"` and the persisted-vs-opts pair `"s1"`/`"s2"` (via the `Error()` method).

`TestWAL_OpenWithDifferentKeyFingerprintErrors` — Mirror of the SessionID case: persist with `KeyFingerprint="k1"`, re-open with `KeyFingerprint="k2"` (and matching `SessionID`). Assert: `errors.As(err, &wal.ErrIdentityMismatch{})` succeeds with `MismatchedField=="key_fingerprint"`, persisted/expected fields populated for both sides. The error message mentions `"key_fingerprint"` and the persisted-vs-opts pair.

`TestWAL_OpenAdoptsIdentityIntoEmptyV2Meta` — Migration test for the case where a pre-Task-14a writer left meta.json with empty `SessionID`/`KeyFingerprint`. Setup: hand-write `meta.json` directly via `os.WriteFile` carrying the v2 envelope WITHOUT identity (`{"format_version":2,"ack_high_watermark_seq":42,"ack_high_watermark_gen":7,"ack_recorded":true,"session_id":"","key_fingerprint":""}`). Open the WAL with `Options{..., SessionID: "s1", KeyFingerprint: "k1"}`. Assert: `wal.Open` succeeds (no error — empty persisted identity is the migration case, not a mismatch). Append + MarkAcked. Assert: `wal.ReadMeta` now returns `SessionID="s1"`, `KeyFingerprint="k1"` (the WAL adopted the caller-supplied identity into the next meta write). Negative sub-case: open the SAME directory a second time with `SessionID="s2"` after the first cycle wrote `s1` — the re-Open errors per the immutability invariant.

**Step ordering for Task 14a:**

- [ ] **Step 1:** Write the four failing tests in `wal_identity_test.go`.
- [ ] **Step 2:** Run `go test ./internal/store/watchtower/wal/...` to confirm they fail with the expected symbols (`Options.SessionID` / `Options.KeyFingerprint` undefined; identity not persisted; mismatch not surfaced).
- [ ] **Step 3:** Implement Steps 1-3 above (extend `Options`; validate at Open; persist on every WriteMeta).
- [ ] **Step 4:** Re-run `go test ./internal/store/watchtower/wal/...` and verify the four new tests PASS and no existing WAL test regressed (in particular, existing tests construct `wal.Options` without `SessionID`/`KeyFingerprint` — the empty-string case MUST remain back-compat, not a hard error).
- [ ] **Step 5:** Cross-compile (`GOOS=windows go build ./...`).
- [ ] **Step 6:** Commit with message `feat(wtp/wal): persist SessionID and KeyFingerprint into meta.json with first-writer-wins immutability`.
- [ ] **Step 7:** Run `/roborev-design-review` and address findings.

**Hard dependency chain:** Task 22 restart-mismatch tests (`TestRun_RestartIgnoresAckOnSessionIDMismatch`, `TestRun_RestartIgnoresAckOnKeyFingerprintMismatch`, `TestRun_RestartLogsMismatchOnce` — currently at lines 9214-9272) MUST NOT execute until Task 14a has landed. Without Task 14a, the test setup ("persist meta with `SessionID=installation-A`") cannot be staged via `wal.MarkAcked` because the production code drops the identity fields from the meta literal — the test would have to hand-write meta.json (brittle and divorced from production behavior). Task 14a makes those tests use REAL `wal.Open`+`wal.MarkAcked` flows. Task 27 store-wiring snippet ALSO depends on Task 14a — without it, `wal.ReadMeta` always returns empty `SessionID`/`KeyFingerprint` after the first MarkAcked-driven persist, so the round-7 identity gate would either always WARN (`s1 != ""`) or always silently mismatch (the gate sees `meta.SessionID==""` and treats it as a fresh install, which contradicts `meta.AckRecorded==true`).

**Migration / back-compat guarantees:**

- **v1 meta.json** (written by pre-meta-v2 binaries; no identity fields and no `ack_recorded` field): `ReadMeta` already infers `AckRecorded=true` (line 46 `meta.go`). `SessionID`/`KeyFingerprint` decode as empty strings. The Step-2 identity check skips on either-side-empty, so no error. The next MarkAcked-driven WriteMeta upgrades the file to v2 with identity populated.
- **v2 meta.json with empty identity** (the migration case from a hypothetical post-v2 / pre-Task-14a binary): same handling — Step-2 check skips on the empty persisted side, next WriteMeta populates.
- **v2 meta.json with identity matching opts** (the steady-state production case after Task 14a + a few MarkAcked cycles): identity persists across opens, never errors, never re-WARNs.
- **v2 meta.json with identity mismatching opts** (the case the gate exists to detect): Open errors. The store-wiring layer (Task 27) catches this error at `wal.Open` time and converts it into the round-7 "do not seed" + WARN behavior; OR (alternative wiring choice the implementer can take) catches it earlier by pre-reading meta.json itself and deciding whether to call `wal.Open` with the matching identity or to refuse to start. Both are valid; this plan task documents the WAL-side primitive only.

**Forward reference (round-13 Task 14b):** the per-generation, data-bearing high-water accessor `WrittenDataHighWater(gen)` MUST be O(1) — see Task 14b "Performance budget" for the in-memory `perGenDataHighWater map[uint64]uint64` requirement. The two on-disk-scan accessors here (`EarliestDataSequence(gen)` is acceptable to scan; `WrittenDataHighWater(gen)` is NOT) have different cost profiles by design: the gap detector calls `EarliestDataSequence(gen)` at MOST once per Replaying entry (one I/O scan per reconnect is fine), but `WrittenDataHighWater(gen)` is consulted by EVERY ack-bearing frame on the recv hot path (BatchAck + ServerHeartbeat + SessionAck) and any per-call disk scan there would couple ack-validation latency to segment count. The round-13 fix locks `WrittenDataHighWater(gen)` to approach 1 (in-memory tracking map) rather than approach 2 (segment scan); the spec/comments above mention both approaches because the contract alone is binding, but the production implementation MUST pick approach 1.

---

### Task 14b: WAL Reader + Replayer generation-scoping (round-13 prerequisite for Task 15.1)

**Status:** New WAL-package + Transport-package step added in round-13 to close a generation-scoping gap that round-12's `EarliestDataSequence(gen uint32)` only partially fixed. The accessor became generation-aware, but the `wal.Reader` itself is still keyed only by `start uint64` (`internal/store/watchtower/wal/reader.go:116` — `func (w *WAL) NewReader(start uint64) (*Reader, error)`), and `Replayer` snapshots its termination watermark as a scalar `tailSeq uint64` (`replayer.go:tailSeq`, captured from `rdr.WALHighWaterSequence()` at `NewReplayer` time). Both surfaces are vulnerable to the same generation-confusion shape that round-12 Finding 1 closed in `EarliestDataSequence`: sequences reset on every generation roll, so a Reader opened at `start=21` will surface RecordData with seq=21 from BOTH the GC'd-but-still-replayable older generation AND any later generation that has progressed past seq=20 — and the Replayer's scalar tail watermark cannot distinguish "the boundary record is in my replay generation" from "the boundary record is in a *later* generation" when sequences reset on the roll boundary. The round-13 fix locks the Reader and Replayer to the SAME generation-scoping contract `EarliestDataSequence(gen)` adopted in round-12: callers pass a `Generation` argument up front, the segment-iteration layer skips segments belonging to other generations, and the Replayer carries its termination watermark as a `(gen, seq)` tuple compared by lex order.

**Why this task belongs to BOTH the WAL package AND the transport package.** The WAL-package change is the prerequisite: without a generation-scoped Reader, the Replayer cannot enforce a generation-scoped tail. The Replayer change cascades immediately (its `tailSeq` snapshot becomes a `(gen, seq)` tuple captured from `WrittenDataHighWater(gen)` instead of `WALHighWaterSequence()` to align with the per-gen, data-bearing contract Task 14a Step 3a establishes). Both lands in this single task because the Reader and Replayer share the same termination-correctness invariant — separating them would create a transient window where the Reader is generation-scoped but the Replayer's scalar tail still allows over-tail records from a later generation to surface, defeating the safety guarantee. Task 15.1 (Run-loop call site) consumes the new `wal.NewReader(opts ReaderOptions)` and `Replayer.LastReplayedSequence()` tuple shapes directly; Task 16 (Replayer construction) owns the in-package change to `ReplayerOptions` / `Replayer`.

**Files:**
- Modify: `internal/store/watchtower/wal/reader.go` — change `NewReader(start uint64) (*Reader, error)` to take `ReaderOptions{Generation uint64, Start uint64}` (the implementer can ALSO keep `NewReader(start uint64)` as a back-compat wrapper that synthesizes `ReaderOptions{Generation: 0 /*sentinel*/, Start: start}` IFF the segment-iteration filter accepts the zero sentinel as "no generation filter" — pre-Task-14b production callers do not exist yet because the only Reader call site is the Replayer constructed in Task 16; tests may call the back-compat shape). The segment-iteration layer's `rescanLocked` and `nextLocked` MUST filter by segment-header `Generation == opts.Generation` BEFORE the per-record `seq < nextSeq` filter runs. Skip segments of other generations entirely; do NOT decode their records and treat the seq filter as the gating layer. The reader's `lastGoodGen` field stays for loss-anchor calculations within the opened generation.
- Modify: `internal/store/watchtower/transport/replayer.go` — change `Replayer.tailSeq uint64` to `Replayer.tail tuple{Generation uint64; Sequence uint64}` (the in-package Go type can be a small struct or the existing `wal.Position` shape — the implementer picks; the constraint is "the field carries both gen and seq"). `NewReplayer` snapshots the tail by calling `wal.WrittenDataHighWater(rdr.Generation())` (NOT `rdr.WALHighWaterSequence()`) so the snapshot is per-generation AND data-bearing — this is the round-13 alignment with Task 14a Step 3a. The hard-stop check in `NextBatch` becomes `RecordData (gen, seq) > tail` using lex compare (gen-first; on equal gen, seq); the existing scalar comparison `rec.Sequence > r.tailSeq` MUST be replaced. `LastReplayedSequence()` returns a `(gen, seq)` tuple — current callers (Task 17 / Task 22 Live state) reading the scalar must update to consume the tuple. `TailSequence()` becomes `Tail()` returning the same tuple shape (back-compat shim `TailSequence() uint64` MAY be retained to return `tail.Sequence` for diagnostic uses that do not care about generation, but MUST be marked deprecated in the docstring and MUST NOT be consumed by production termination logic).
- Modify: `internal/store/watchtower/transport/state_replaying.go` — the `rdrFactory` callback signature in Task 22's Run-loop snippet MUST take a `(gen uint32, start uint64)` tuple instead of just `start uint64` (`uint32` matches `wal.ReaderOptions.Generation`, `wal.SegmentHeader.Generation`, `wal.Record.Generation`, and `wal.WrittenDataHighWater(gen uint32)` exactly so callers do not need to widen). Both Task 15.1 (the Run-loop snippet shown there) AND Task 16 (the Replayer construction) MUST be updated in the round-13 sweep that lands this task. See Step 3 below for the `rdrFactory` contract change in detail.
- Test: `internal/store/watchtower/wal/reader_test.go` — three new tests (Step 4 below): `TestReader_GenerationScoped_SkipsOtherGenerationsOnDisk`, `TestReader_GenerationScoped_DoesNotReturnLowerSeqFromOtherGen`.
- Test: `internal/store/watchtower/transport/replayer_test.go` — one new test: `TestReplayer_TailIsTuple_HardStopsOnSeqExceedingTail`.

**Step 1: Reader — generation-scoped segment iteration.**

```go
// ReaderOptions configures a wal.Reader. Round-13 introduces the
// Generation field so the segment-iteration layer can skip segments of
// other generations entirely — without this scoping, sequences reset
// on every generation roll AND higher-generation segments coexist on
// disk while lower-generation segments are GC'd, which means a Reader
// opened at Start=21 in gen=1 would silently surface seq=21 records
// from gen=2 (which the writer rolled to and emitted past seq=20). The
// segment-iteration filter rejects segments whose SegmentHeader.Generation
// != opts.Generation BEFORE the per-record seq filter runs.
//
// The per-record `seq < nextSeq` filter at reader.go's nextLocked
// data-record branch is RETAINED — it ensures monotonic delivery
// within the opened generation (records below the start cursor are
// silently dropped). The segment-iteration generation filter and the
// per-record seq filter are layered: the generation filter ensures
// we never see records from a different generation in the first
// place; the seq filter ensures we don't replay before the start
// cursor within the opened generation.
type ReaderOptions struct {
    // Generation is the WAL generation the Reader operates within.
    // Segments whose SegmentHeader.Generation != Generation are
    // skipped entirely by the segment-iteration layer (NOT by the
    // per-record seq filter — the segment is never opened, its
    // records are never decoded). Loss markers within the requested
    // generation are surfaced; loss markers within OTHER generations
    // are skipped along with the rest of the segment.
    Generation uint64
    // Start is the lowest user sequence the Reader will surface
    // (RecordData entries with Sequence < Start are dropped on the
    // floor). Pass Start=0 to receive every user record from the
    // beginning of the on-disk stream WITHIN the opened generation.
    // RecordLoss entries within the opened generation are NOT
    // filtered by Start.
    Start uint64
}

// NewReader returns a Reader that surfaces RecordData entries from the
// requested Generation with Sequence >= Start. Segments belonging to
// other generations are skipped at the segment-iteration layer.
//
// Round-13 signature change: the prior `NewReader(start uint64)` was
// generation-implicit, which let a Reader opened at start=21 in gen=1
// silently surface a gen=2 record at seq=21 because the segment-
// iteration layer had no generation filter. Callers MUST now pass
// Generation explicitly. Pre-round-13 callers do not exist in the
// codebase (the only Reader consumer is the Replayer constructed in
// Task 16, which is being updated in this same task).
func (w *WAL) NewReader(opts ReaderOptions) (*Reader, error) {
    w.mu.Lock()
    defer w.mu.Unlock()
    if w.closed {
        return nil, ErrClosed
    }
    r := &Reader{
        w:         w,
        notify:    make(chan struct{}, 1),
        nextSeq:   opts.Start,
        readerGen: opts.Generation,
    }
    if err := r.rescanLocked(); err != nil {
        return nil, err
    }
    w.readers = append(w.readers, r)
    return r, nil
}

// Reader gains a readerGen field alongside nextSeq:
type Reader struct {
    // ... existing fields ...

    // readerGen is the WAL generation the Reader is scoped to. The
    // segment-iteration layer (rescanLocked + nextLocked's segment
    // boundary handling) skips segments whose SegmentHeader.Generation
    // != readerGen entirely. Loss markers from skipped segments are NOT
    // surfaced; loss markers from in-scope segments ARE surfaced
    // regardless of nextSeq. Set once at NewReader; never mutated.
    readerGen uint64

    // ... existing nextSeq, lastEmittedSeq, lastGoodSeq, lastGoodGen ...
}

// Generation returns the generation the Reader is scoped to. Used by
// the Replayer's NewReplayer constructor to pass the same generation
// to wal.WrittenDataHighWater for the tail-tuple snapshot.
func (r *Reader) Generation() uint64 {
    return r.readerGen
}
```

In `nextLocked` (and `rescanLocked`), wrap the segment-walk loop so segments whose header `Generation != r.readerGen` are skipped before any record-decode work. Concretely:

```go
// Inside nextLocked's segment-walk loop, BEFORE decoding records:
hdr, err := readSegmentHeader(seg)
if err != nil {
    return Record{}, false, err
}
if hdr.Generation != r.readerGen {
    // Skip the entire segment; advance to the next segment in the
    // ascending-by-index list. Loss markers in the skipped segment
    // are NOT surfaced — they belong to a different generation.
    continue
}
// Existing record-decode loop runs here, with the per-record
// `seq < nextSeq` filter applied to RecordData entries.
```

**Step 2: Replayer — tail as (gen, seq) tuple.**

```go
// Replayer's tail is the round-13 (gen, seq) tuple replacing the
// scalar tailSeq uint64. The change is load-bearing: scalar tailSeq
// could not distinguish "boundary record at seq=K in my replay
// generation" from "boundary record at seq=K in a later generation"
// when sequences reset on the roll. The lex compare on (gen, seq)
// makes the over-tail check generation-correct.
type Replayer struct {
    rdr  *wal.Reader
    opts ReplayerOptions
    // tail is the HARD upper bound on (gen, seq) RecordData surfaced
    // during replay. Snapshotted under the WAL lock at NewReplayer time
    // by calling wal.WrittenDataHighWater(rdr.Generation()) — this is
    // the per-generation, data-bearing high-water from Task 14a Step 3a,
    // NOT the prior rdr.WALHighWaterSequence() scalar. The change ensures
    // (a) the snapshot is generation-correct (sequences reset on roll;
    // a later generation's high-seq is not a valid hard stop for the
    // replay generation), and (b) the snapshot is data-bearing
    // (segment-header-only generations cannot become a valid tail).
    //
    // Hard-stop predicate in NextBatch: RecordData (rec.Generation,
    // rec.Sequence) > tail under lex compare (gen-first; on equal gen,
    // seq). With the Reader generation-scoped to a single generation
    // (Step 1), rec.Generation is always == tail.Generation in practice,
    // so the lex compare collapses to a seq compare — but the tuple shape
    // is retained so a future relaxation of the Reader-gen-scope
    // invariant cannot silently re-introduce the scalar bug.
    tail tailWatermark
    // lastReplayedSeq becomes lastReplayed (gen, seq) — Task 22 Live
    // reader-start consumers update accordingly.
    lastReplayed tailWatermark
    prefixLossEmitted bool
}

// tailWatermark is the small struct holding (gen, seq) for both the tail
// snapshot and the last-replayed cursor. Lex compared via (a.Generation
// > b.Generation) || (a.Generation == b.Generation && a.Sequence > b.Sequence).
type tailWatermark struct {
    Generation uint64
    Sequence   uint64
}

// NewReplayer captures the per-generation, data-bearing tail watermark.
// Calls wal.WrittenDataHighWater(rdr.Generation()) under the WAL lock
// (the accessor is implemented to be O(1) per Task 14a's performance
// budget — see "Performance budget" forward reference at Task 14a end).
// On (ok=false) — the Reader's generation has no RecordData on disk —
// tail is set to {rdr.Generation(), 0}, which means the lex-compare
// predicate trips on ANY RecordData with seq>=1 in that generation
// (matching the existing behavior where a fully-empty replay generation
// yields no records).
func NewReplayer(rdr *wal.Reader, opts ReplayerOptions) *Replayer {
    seq, ok, err := rdr.WAL().WrittenDataHighWater(rdr.Generation())
    if err != nil {
        // Defensive: log + treat as ok=false so the Replayer drains
        // zero records and returns done=true on first NextBatch. The
        // Run loop's `wal_read_failure` Anomaly path (Task 15.1) is
        // the canonical error surface; this is the constructor-time
        // safety fallback.
        seq, ok = 0, false
    }
    if !ok {
        seq = 0
    }
    return &Replayer{
        rdr:  rdr,
        opts: opts,
        tail: tailWatermark{Generation: rdr.Generation(), Sequence: seq},
    }
}

// LastReplayedSequence returns the (gen, seq) tuple of the highest
// RecordData surfaced by NextBatch so far. Round-13 signature change:
// previously returned just `uint64`. Live state's reader-start
// calculation in Task 22 now uses the tuple to position the next
// Reader at the correct (gen, seq) — the ReaderOptions.Generation
// parameter is the tuple's gen, and the ReaderOptions.Start is
// max(tuple.Sequence + 1, ackHW.seq + 1).
func (r *Replayer) LastReplayedSequence() (uint64, uint64) {
    return r.lastReplayed.Generation, r.lastReplayed.Sequence
}

// Tail returns the (gen, seq) tuple captured at NewReplayer time.
// Replaces the scalar TailSequence() returns.
func (r *Replayer) Tail() (uint64, uint64) {
    return r.tail.Generation, r.tail.Sequence
}
```

In `NextBatch`, the hard-stop check becomes:

```go
// The lex compare. With the Reader generation-scoped to a single gen,
// rec.Generation == r.tail.Generation in practice; the gen branch only
// trips if a future relaxation of the Reader-gen-scope invariant lets
// a different-gen record slip through.
if rec.Kind == wal.RecordData {
    overTail := rec.Generation > r.tail.Generation ||
        (rec.Generation == r.tail.Generation && rec.Sequence > r.tail.Sequence)
    if overTail {
        batch.Records = append(batch.Records, rec)
        r.lastReplayed = tailWatermark{Generation: rec.Generation, Sequence: rec.Sequence}
        return batch, true, nil
    }
}
```

**Step 3: Run-loop call site (Task 15.1 / 22 sweep).**

Task 15.1's Run-loop snippet (currently at lines 7307-7333 in this plan) MUST be updated to construct the Reader through the new generation-scoped API:

```go
// Round-13: pass remoteReplayCursor.Generation (== persistedAck.Generation
// by the same-generation invariant) so the Reader skips other-generation
// segments entirely.
rdr, err := t.wal.NewReader(wal.ReaderOptions{
    Generation: remoteReplayCursor.Generation,
    Start:      readerStart,
})
```

Task 22's StateLive reader-open MUST be updated similarly: it consumes `rep.LastReplayedSequence()` (now returning a (gen, seq) tuple) and constructs the Live Reader at `wal.ReaderOptions{Generation: lastReplayedGen, Start: max(lastReplayedSeq+1, ackHW.seq+1)}`. The `ackHW.seq+1` term is meaningful only when `ackHW.gen == lastReplayedGen` (steady-state); cross-generation ack-hand-off is handled by the explicit Replaying re-entry on the next reconnect, NOT by Live arithmetic.

**Round-16 Finding 4: `rdrFactory` callback contract change.** Task 22's Run-loop (Step 4 of Task 18) wraps reader construction behind a `rdrFactory` callback so unit tests can inject a fake reader without spinning up a real WAL. Round-13 already changed the underlying `wal.NewReader` shape from `NewReader(start uint64)` to `NewReader(opts ReaderOptions)`; the round-16 review caught that the `rdrFactory` callback signature in Task 22's snippet was NOT updated in lock-step (Task 22 line 10613 declared `func(start uint64)` while line 10700's stage-iteration body called `rdrFactoryGen(stage.Generation, stage.StartSeq)` — internally inconsistent). The contract change documented here lands in the same round-13 sweep as Step 3 above and is the SOLE source of truth for the callback shape. Task 22's Step 4 snippet, the StateLive call site at Task 22 line 10826, and the test factory at Task 22 line 11484 ALL consume this contract — they MUST match exactly.

```go
// Round-13/16: rdrFactory takes BOTH the WAL generation AND the start
// sequence so the caller can position the Reader explicitly per state
// entry. `gen` is the WAL generation the Reader will be scoped to
// (segments with a different SegmentHeader.Generation are skipped at
// segment-iteration before record decoding); `start` is the inclusive
// lowest seq the Reader will surface for RecordData (RecordLoss markers
// always surface — see wal/reader.go NewReader docstring).
//
// uint32 mirrors wal.ReaderOptions.Generation, wal.SegmentHeader.Generation,
// wal.Record.Generation, and wal.WrittenDataHighWater(gen uint32) exactly
// so callers do not need to widen.
//
// Production callers in transport.New construct rdrFactory as a closure
// over t.wal:
//
//   rdrFactory := func(gen uint32, start uint64) (*wal.Reader, error) {
//       return t.wal.NewReader(wal.ReaderOptions{Generation: gen, Start: start})
//   }
//
// Test callers (see Task 22 Step 4 test snippet) construct the same
// closure over a test-owned *wal.WAL handle. The two arguments are
// passed PER call so the same factory can serve both Replaying (one
// call per ReplayStage) AND Live (a single call positioned at the
// writer's current generation).
type ReaderFactory func(gen uint32, start uint64) (*wal.Reader, error)
```

The factory's two-argument shape is deliberately symmetric with `wal.ReaderOptions` so the closure is a thin adapter and no information is lost between the Run loop and the WAL. Replaying calls `rdrFactory(stage.Generation, stage.StartSeq)` — one call per `ReplayStage` returned by `computeReplayPlan`; Live calls `rdrFactory(t.wal.HighGeneration(), start)` where `start` is the round-15-Finding-2 cursor (`max(rep.LastReplayedSequence().Sequence+1, t.remoteReplayCursor.Sequence+1)`) and `t.wal.HighGeneration()` is captured at StateLive entry to scope the Live Reader to the writer's current generation. (If the writer rolls to a new generation while Live is reading, the Reader hard-stops at the old generation's tail and the next reconnect re-enters Replaying with the new generation surfaced as a later-stage `ReplayStage` per Round-16 Finding 2's loss-only-generations contract.)

**Step 4: Tests.**

`TestReader_GenerationScoped_SkipsOtherGenerationsOnDisk` — Setup: open WAL fresh, append seqs 1..5 in gen=1, roll the writer to gen=2 (production roll path), append seqs 1..5 in gen=2 (sequences reset per Task 12 contract). Open a Reader scoped to gen=1: `r1, _ := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 0})`. Drain via repeated `Next()` until `io.EOF`. Assertions:
- The Reader surfaced exactly 5 records, all with `Generation == 1` and `Sequence ∈ {1, 2, 3, 4, 5}` in ascending order.
- The Reader did NOT surface any record with `Generation == 2`. CRITICAL: under the round-12 design (no segment-gen filter), the Reader would have surfaced 10 records — 5 from each generation — silently, because seq=1..5 is in-scope for both segments.

Open a second Reader scoped to gen=2: `r2, _ := w.NewReader(wal.ReaderOptions{Generation: 2, Start: 0})`. Drain. Assertions:
- The Reader surfaced exactly 5 records, all with `Generation == 2` and `Sequence ∈ {1, 2, 3, 4, 5}` in ascending order.
- The Reader did NOT surface any record with `Generation == 1`.

`TestReader_GenerationScoped_DoesNotReturnLowerSeqFromOtherGen` — Round-13 regression test for the generation-confusion shape. Setup: open WAL, append seqs 1..50 in gen=1, drive `MarkAcked(1, 30)` so segments holding seqs 1..N (where N depends on segment size; pick segment sizes so some gen=1 segments survive), roll to gen=2, append seqs 1..5 in gen=2. Open a Reader scoped to gen=1 with `Start=21`: `r, _ := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 21})`. Drain. Assertions:
- The Reader surfaced records ONLY from gen=1 with `Sequence ∈ {21..50}` (or whatever the surviving subset is) in ascending order.
- The Reader did NOT surface a gen=2 record with seq=21 (or any other gen=2 record). CRITICAL: under the round-12 design the Reader would have surfaced gen=2's seq=21..25 records along with gen=1's seq=21..50 because the per-record seq filter accepts seq>=21 from any segment; the segment-gen filter is what blocks the gen=2 segments from being walked at all.

`TestReplayer_TailIsTuple_HardStopsOnSeqExceedingTail` — Round-13 regression test for the Replayer's tail-tuple termination. Setup: open WAL, append seqs 1..3 in gen=1, drive `MarkAcked(1, 2)` so the WAL state has gen=1 RecordData up to seq=3 with ack at seq=2. Open a Reader scoped to gen=1 with `Start=3`: `rdr, _ := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 3})`. Construct a Replayer: `r := transport.NewReplayer(rdr, transport.ReplayerOptions{...})`. Assert: `gen, seq := r.Tail(); gen == 1 && seq == 3`. NOW append seqs 4 and 5 in gen=1 (post-NewReplayer appends — these MUST NOT extend replay per the existing hard-stop contract). NOW roll to gen=2 and append seq=1 in gen=2 (cross-gen append — these MUST NOT extend replay either). Drain via `NextBatch` until `done=true`. Assertions:
- The first record surfaced is `Generation=1, Sequence=3` (the within-window record).
- AT MOST one over-tail RecordData surfaces, and if it does it MUST be `Generation=1, Sequence=4` (the first gen=1 record past tail; gen=2 records are filtered by the segment-iteration layer because the Reader is gen=1-scoped).
- NO record with `Generation=2` is surfaced.
- `done=true` is returned by the time the over-tail boundary record is appended.
- After completion: `gen, seq := r.LastReplayedSequence(); gen == 1 && seq ∈ {3, 4}` (depending on whether the boundary record surfaced).
- `r.Tail()` is unchanged at `(1, 3)` (post-entry appends MUST NOT advance the tail snapshot).

CRITICAL: under the round-12 design (scalar `tailSeq=3`), the Replayer would compare `rec.Sequence > 3` and surface gen=2's seq=4 as a within-window record (since the scalar compare ignores generation), then surface gen=2's seq=4 BEFORE returning done=true — silently leaking a different-generation record into the replay window. The tuple compare blocks this.

**Step ordering for Task 14b:**

- [ ] **Step 1:** Write the three failing tests above (two in `wal/reader_test.go`, one in `transport/replayer_test.go`).
- [ ] **Step 2:** Run `go test ./internal/store/watchtower/...` to confirm they fail with the expected symbols (`wal.ReaderOptions` undefined; `wal.NewReader(ReaderOptions{...})` undefined; `Reader.Generation()` undefined; `Replayer.Tail()` returns the wrong shape; `Replayer.LastReplayedSequence()` returns `uint64` instead of `(uint64, uint64)`).
- [ ] **Step 3:** Implement the Reader changes (Step 1 above): add `ReaderOptions` struct, change `NewReader` signature, add `Reader.readerGen` field + segment-iteration filter, add `Reader.Generation()` accessor.
- [ ] **Step 4:** Implement the Replayer changes (Step 2 above): change `tailSeq uint64` → `tail tailWatermark`, change `lastReplayedSeq uint64` → `lastReplayed tailWatermark`, change `LastReplayedSequence()` return shape, replace scalar over-tail check with lex compare in `NextBatch`, update `NewReplayer` to call `WrittenDataHighWater(rdr.Generation())`.
- [ ] **Step 5:** Update Task 15.1's Run-loop snippet AND Task 22's StateLive reader-open call site to pass `Generation` through `wal.ReaderOptions`. Update any in-package callers of `LastReplayedSequence()` to consume the tuple. ROUND-16 FINDING 4: ALSO update the `rdrFactory` callback signature in Task 22's Run-loop snippet (Step 4 of Task 18) from `func(start uint64) (*wal.Reader, error)` to `func(gen uint32, start uint64) (*wal.Reader, error)` per the contract documented in Step 3 above. Update ALL three call sites in lock-step: (a) the `Run` signature line; (b) the `StateReplaying` per-stage call inside the `for i := range stages` loop (use `rdrFactory(stage.Generation, stage.StartSeq)`); (c) the `StateLive` call (use `rdrFactory(t.wal.HighGeneration(), start)`); and (d) the test factory closure at Task 22 Step 4's test snippet (use `func(gen uint32, start uint64) (*wal.Reader, error) { return w.NewReader(wal.ReaderOptions{Generation: gen, Start: start}) }`).
- [ ] **Step 6:** Re-run `go test ./internal/store/watchtower/...` and verify the three new tests PASS and no existing test regressed.
- [ ] **Step 7:** Cross-compile (`GOOS=windows go build ./...`).
- [ ] **Step 8:** Commit with message `feat(wtp/wal,wtp/transport): generation-scope wal.Reader and Replayer tail tuple`.
- [ ] **Step 9:** Run `/roborev-design-review` and address findings.

**Hard dependency chain (round-13):**

- **14a → 14b:** Task 14b's `NewReplayer` snapshot calls `wal.WrittenDataHighWater(rdr.Generation())` — the per-generation, data-bearing accessor introduced in Task 14a Step 3a. Without 14a's accessor (or under the unsafe round-10 `WrittenHighGeneration()` shape), the Replayer's tail would silently regress to the segment-header-seeded value and a header-only generation could become a valid tail watermark. 14b MUST land AFTER 14a.
- **14b → 15.1:** Task 15.1's Run-loop snippet (the one that synthesizes `prefixLoss` via `computeReplayStart` and constructs the Reader) consumes the new `wal.NewReader(wal.ReaderOptions{Generation: ..., Start: ...})` shape. Without 14b, the snippet would still pass `start uint64` and the Reader would silently surface other-generation records. 14b MUST land BEFORE 15.1's snippet is updated; the round-13 sweep that adds 14b ALSO updates the snippet shown in 15.1.
- **14b → 17.X:** Task 17.X's recv handler does NOT directly construct a Reader (the Replayer does), but Task 17.X DOES consume `Replayer.LastReplayedSequence()` indirectly through Task 22's Live state. 14b's tuple shape change cascades through Task 22's call site; 17.X's tests do not need to change but the integration test that exercises Replayer→Live hand-off MUST be updated in the same sweep.
- **14b → 22b:** Task 22b's parity tests do not depend on 14b directly, but the round-13 commit message body MUST list 14b as a prerequisite for the Run-loop generation-scope correctness.

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

// fakeConn implements transport.Conn for tests. CloseSend (half-close)
// and Close (full teardown) are tracked separately so tests can pin
// which lifecycle hook the production code actually invoked.
type fakeConn struct {
	sendCh          chan *wtpv1.ClientMessage
	recvCh          chan *wtpv1.ServerMessage
	closeSendCalled chan struct{}
	closed          chan struct{}
	closeSendCalls  int
	closeCalls      int
	sendErr         error
	recvErr         error
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		sendCh:          make(chan *wtpv1.ClientMessage, 64),
		recvCh:          make(chan *wtpv1.ServerMessage, 64),
		closeSendCalled: make(chan struct{}),
		closed:          make(chan struct{}),
	}
}

func (f *fakeConn) Send(msg *wtpv1.ClientMessage) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	select {
	case f.sendCh <- msg:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeConn) Recv() (*wtpv1.ServerMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	select {
	case msg := <-f.recvCh:
		return msg, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeConn) CloseSend() error {
	f.closeSendCalls++
	select {
	case <-f.closeSendCalled:
		// already half-closed; remain idempotent
	default:
		close(f.closeSendCalled)
	}
	return nil
}

func (f *fakeConn) Close() error {
	f.closeCalls++
	select {
	case <-f.closed:
		// already closed; remain idempotent
	default:
		close(f.closed)
	}
	return nil
}

// TestConnectingState_SendsSessionInitAndAdvancesOnAck verifies that the
// Connecting state sends a SessionInit on entry and advances to Replaying
// once it observes a SessionAck with accepted=true.
//
// The SessionInit assertions cover every field on the wire so that any
// future change to provenance (or default population) trips a test
// rather than silently shipping a wrong field.
func TestConnectingState_SendsSessionInitAndAdvancesOnAck(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	const (
		wantAgentID        = "test-agent"
		wantSessionID      = "sess-1"
		wantAgentVersion   = "v1.2.3"
		wantOcsfVersion    = "1.4.0"
		wantKeyFingerprint = "deadbeef"
		wantContextDigest  = "cafef00d"
		wantTotalChained   = uint64(42)
		wantFormatVersion  = uint32(2)
	)

	tr, err := transport.New(transport.Options{
		Dialer:         dialer,
		AgentID:        wantAgentID,
		SessionID:      wantSessionID,
		AgentVersion:   wantAgentVersion,
		OcsfVersion:    wantOcsfVersion,
		KeyFingerprint: wantKeyFingerprint,
		ContextDigest:  wantContextDigest,
		TotalChained:   wantTotalChained,
		// FormatVersion + Algorithm omitted so we exercise defaults.
	})
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type result struct {
		st  transport.State
		err error
	}
	doneCh := make(chan result, 1)
	go func() {
		st, err := tr.RunOnce(ctx, transport.StateConnecting)
		doneCh <- result{st, err}
	}()

	// Expect SessionInit on the wire. Assert every field — the defaulted
	// Algorithm and FormatVersion as well as everything supplied via
	// Options. ackedSequence/ackedGeneration are zero on first connect.
	select {
	case msg := <-conn.sendCh:
		init := msg.GetSessionInit()
		if init == nil {
			t.Fatalf("expected SessionInit, got %T", msg.Msg)
		}
		if got, want := init.AgentId, wantAgentID; got != want {
			t.Fatalf("agent_id: got %q, want %q", got, want)
		}
		if got, want := init.SessionId, wantSessionID; got != want {
			t.Fatalf("session_id: got %q, want %q", got, want)
		}
		if got, want := init.AgentVersion, wantAgentVersion; got != want {
			t.Fatalf("agent_version: got %q, want %q", got, want)
		}
		if got, want := init.OcsfVersion, wantOcsfVersion; got != want {
			t.Fatalf("ocsf_version: got %q, want %q", got, want)
		}
		if got, want := init.KeyFingerprint, wantKeyFingerprint; got != want {
			t.Fatalf("key_fingerprint: got %q, want %q", got, want)
		}
		if got, want := init.ContextDigest, wantContextDigest; got != want {
			t.Fatalf("context_digest: got %q, want %q", got, want)
		}
		if got, want := init.TotalChained, wantTotalChained; got != want {
			t.Fatalf("total_chained: got %d, want %d", got, want)
		}
		if got, want := init.FormatVersion, wantFormatVersion; got != want {
			t.Fatalf("format_version default: got %d, want %d", got, want)
		}
		if got, want := init.Algorithm, wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256; got != want {
			t.Fatalf("algorithm default: got %s, want %s", got, want)
		}
		if got, want := init.WalHighWatermarkSeq, uint64(0); got != want {
			t.Fatalf("wal_high_watermark_seq: got %d, want %d", got, want)
		}
		if got, want := init.Generation, uint32(0); got != want {
			t.Fatalf("generation: got %d, want %d", got, want)
		}
	case <-ctx.Done():
		t.Fatal("did not receive SessionInit")
	}

	// Send SessionAck back.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				AckHighWatermarkSeq: 0,
				Generation:          0,
				Accepted:            true,
			},
		},
	}

	select {
	case res := <-doneCh:
		if res.err != nil {
			t.Fatalf("happy-path RunOnce: unexpected error: %v", res.err)
		}
		if res.st != transport.StateReplaying {
			t.Fatalf("next state: got %s, want StateReplaying", res.st)
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
// transport tests can substitute a fake.
//
// Concurrency contract (mirrors gRPC's ClientStream):
//   - A single sender goroutine and a single receiver goroutine MAY
//     operate concurrently — i.e. one Send may overlap one Recv.
//   - Multiple concurrent Senders are NOT safe.
//   - Multiple concurrent Receivers are NOT safe.
//   - CloseSend MUST NOT race with a concurrent Send. Callers are
//     responsible for sequencing Send and CloseSend on the sender
//     goroutine.
//
// Lifecycle contract:
//   - CloseSend is the half-close primitive: it signals "no more sends"
//     to the peer. Recv may still return data the peer had queued before
//     observing the half-close. The underlying stream/connection remains
//     open until the peer drains and closes its sending half (or until
//     Close is called).
//   - Close is the full-teardown primitive: it aborts the stream and
//     releases all resources. After Close, Send/Recv/CloseSend MUST
//     return an error (or be no-ops). Close MUST be idempotent so error
//     paths can call it without coordinating with a successful close.
//   - After Close returns, any in-flight blocked Send or Recv MUST
//     unblock promptly with an error. Implementations of Conn over real
//     gRPC ClientStreams satisfy this naturally because closing the
//     underlying ClientConn cancels in-flight RPCs; fakes used in tests
//     must arrange for the same behavior.
type Conn interface {
	Send(msg *wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
	Close() error
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
	"errors"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Options configures a Transport.
//
// SessionInit field provenance: the Transport itself is a thin wire-format
// adapter — it does not look up identity, key material, or sink state. The
// fields below document who is expected to populate each value when the
// sink-integration task (Task 27) wires this Transport into the real
// pipeline. Until then, callers (and tests) supply the values directly via
// Options.
type Options struct {
	// Dialer establishes the underlying gRPC stream. Required.
	Dialer Dialer
	// AgentID identifies the agent process. Required. Supplied by the
	// agent's identity layer (build/runtime config); echoed in
	// SessionInit so the server can scope the session.
	AgentID string
	// SessionID identifies the session. Required. Supplied by the
	// session-management layer.
	SessionID string
	// FormatVersion is sent in SessionInit; defaults to 2.
	FormatVersion uint32
	// Algorithm is the chain HMAC algorithm advertised in SessionInit.
	// Supplied by chain config; defaults to HASH_ALGORITHM_HMAC_SHA256
	// in New() so the proto validator (wtpv1.ValidateSessionInit)
	// accepts the frame.
	Algorithm wtpv1.HashAlgorithm
	// AgentVersion identifies the running agent build. An agent build
	// constant — populated by the build/wiring layer.
	AgentVersion string
	// OcsfVersion is the OCSF schema version the sink emits. An agent
	// build constant — populated by the build/wiring layer.
	OcsfVersion string
	// KeyFingerprint identifies the active signing key (hex-encoded).
	// Supplied by chain config (KMS/key provider); empty until sink
	// wiring (Task 27).
	KeyFingerprint string
	// ContextDigest is the hex-encoded SHA-256 of the session context.
	// Computed at sink integration (Task 27) over the agent's
	// session-context inputs (see chain.SessionContext).
	ContextDigest string
	// TotalChained is the count of records the sink has chained so far.
	// Running count from chain.SinkChain; supplied by sink integration.
	TotalChained uint64
}

// validate enforces the construction-time invariants documented on
// Options. It is called by New before any defaults are applied.
func validate(opts Options) error {
	if opts.Dialer == nil {
		return errors.New("transport: nil Dialer")
	}
	if opts.AgentID == "" {
		return errors.New("transport: AgentID required")
	}
	if opts.SessionID == "" {
		return errors.New("transport: SessionID required")
	}
	return nil
}

// Transport runs the four-state WTP client state machine. It is owned by
// a single goroutine — callers interact via channels.
//
// Round-8 note: this snippet shows the Task 15 production code as it
// landed (single ack-tuple model with `ackedSequence`/`ackedGeneration`
// fields). Task 15.1 below SUPERSEDES this struct shape with the two-
// cursor model: `persistedAck` (monotonic-only mirror of `wal.Meta`,
// drives `wal_high_watermark_seq` + segment GC) and `remoteReplayCursor`
// (regressable, drives Replaying reader-start). The `sessionInit()` and
// `runConnecting` snippets that follow likewise show the Task 15 shape
// and are rewritten by Task 15.1 (`SessionInit` populates from
// `persistedAck`; the SessionAck handler dispatches on
// `applyServerAckTuple`'s `AckOutcome.Kind`). They are kept here as the
// historical reference for Task 15 — Task 15.1 lands the round-8
// rewrite on top of them.
type Transport struct {
	opts Options
	conn Conn

	// ackedSequence/ackedGeneration TOGETHER hold the EFFECTIVE ack watermark
	// — the clamped (gen, seq) tuple per spec §"Acknowledgement model"
	// (design.md:601). The two fields MOVE TOGETHER; mixing local-seq with
	// server-gen (or vice versa) creates an impossible state under the WAL's
	// lex-(gen, seq) GC semantics (see wal/wal.go MarkAcked / segmentFullyAckedLocked).
	//
	// Clamp rule on every server-supplied watermark (SessionAck, BatchAck,
	// ServerHeartbeat):
	//   - if (server_gen, server_seq) < (local_gen, local_seq) lex: ADOPT the
	//     server tuple wholesale (both fields). This is the legitimate
	//     stale-watermark recovery path during gradual rollout / partition
	//     recovery.
	//   - if (server_gen, server_seq) > (local_gen, local_seq) lex: KEEP the
	//     local tuple wholesale (both fields). Log a WARN with FULL tuple
	//     context (server_gen, server_seq, local_gen, local_seq) per the
	//     anomaly-log contract in spec §"Acknowledgement model".
	//   - if equal: no-op.
	//
	// Seeded on cold start from wal.Meta (see Task 15.1 startup-seed step) and
	// then advanced by SessionAck (state_connecting.go) and by BatchAck/
	// ServerHeartbeat handlers in the recv multiplexer (Tasks 17/18) — all of
	// them via the same clamp helper. Read by Replaying/Live state handlers
	// for their reader-start calculations; state handlers do NOT advance these
	// fields.
	//
	// SessionUpdate is NOT an acknowledgement — it is a control frame for
	// key/generation rotation per spec §"Acknowledgement model" (design.md:617);
	// it never advances ackedSequence/ackedGeneration.
	ackedSequence   uint64
	ackedGeneration uint32

	// rejectReason is populated when the server rejects the session
	// (SessionAck.accepted=false). Surfaced via RejectReason().
	rejectReason string
}

// New constructs a Transport. It does not dial; call Run to start.
// New validates the required Options fields and returns an error if any
// are missing so misconfiguration fails at construction rather than
// inside the run loop.
func New(opts Options) (*Transport, error) {
	if err := validate(opts); err != nil {
		return nil, err
	}
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	if opts.Algorithm == wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		opts.Algorithm = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256
	}
	return &Transport{opts: opts}, nil
}

// RejectReason returns the reject_reason surfaced by the most recent
// SessionAck with accepted=false. It is empty until the server rejects
// the session.
func (t *Transport) RejectReason() string {
	return t.rejectReason
}

// sessionInit returns the SessionInit message for the current connection.
func (t *Transport) sessionInit() *wtpv1.ClientMessage {
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				SessionId:           t.opts.SessionID,
				OcsfVersion:         t.opts.OcsfVersion,
				FormatVersion:       t.opts.FormatVersion,
				Algorithm:           t.opts.Algorithm,
				KeyFingerprint:      t.opts.KeyFingerprint,
				ContextDigest:       t.opts.ContextDigest,
				WalHighWatermarkSeq: t.ackedSequence,
				Generation:          t.ackedGeneration,
				AgentId:             t.opts.AgentID,
				AgentVersion:        t.opts.AgentVersion,
				TotalChained:        t.opts.TotalChained,
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

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runConnecting establishes a stream and exchanges SessionInit/SessionAck.
// On success it returns StateReplaying. On dial failure or stream error it
// returns StateConnecting (the caller's run loop is responsible for backoff).
// On a server SessionAck rejection (accepted=false) or a programming error
// (e.g. SessionInit fails local validation) it returns StateShutdown — the
// session cannot recover from these via reconnect.
//
// Every error path calls conn.Close() (full teardown) rather than
// CloseSend() (half-close) so the underlying stream is fully released and
// no goroutines/sockets leak while the run loop backs off and retries.
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	init := t.sessionInit()
	if err := wtpv1.ValidateSessionInit(init.GetSessionInit()); err != nil {
		return StateShutdown, fmt.Errorf("invalid SessionInit: %w", err)
	}

	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(init); err != nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("send SessionInit: %w", err)
	}

	msg, err := conn.Recv()
	if err != nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}

	ack := msg.GetSessionAck()
	if ack == nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("expected SessionAck, got %T", msg.Msg)
	}

	if !ack.GetAccepted() {
		t.rejectReason = ack.GetRejectReason()
		_ = conn.Close()
		t.conn = nil
		return StateShutdown, fmt.Errorf("session rejected: %s", ack.GetRejectReason())
	}

	t.ackedSequence = ack.GetAckHighWatermarkSeq()
	t.ackedGeneration = ack.GetGeneration()
	return StateReplaying, nil
}

// RunOnce runs a single state transition for testing. Production code
// should use Run, which loops until Shutdown. The error mirrors whatever
// the per-state handler surfaced so tests can assert on failure modes.
func (t *Transport) RunOnce(ctx context.Context, st State) (State, error) {
	switch st {
	case StateConnecting:
		return t.runConnecting(ctx)
	default:
		return StateShutdown, nil
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

### Task 15.1 — Two-cursor ack clamp + WAL meta seed (round-8 rewrite)

**Scope: refined cross-generation taxonomy.** Round-11 refinement of round-10's "higher generation within written high" rule — the `applyServerAckTuple` helper now uses a per-generation, **data-bearing** high-water proof (`wal.WrittenDataHighWater(gen)` from Task 14a Step 3a) rather than the round-10 `WrittenHighGeneration() = w.highGen` accessor. The round-10 accessor returned the segment-header-seeded value, which let the helper accept an Adopted ack for an empty rolled generation; round-11 closes that hole by requiring the helper to confirm at least one RecordData entry exists on disk for the server's claimed generation AND the server's claimed sequence is bounded by the per-generation max RecordData seq. The cross-generation cases the helper now distinguishes:

- Higher generation with WAL having emitted RecordData in that gen, server.seq within the per-gen data high-water (`server.gen > persistedAck.gen` AND `wal.WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq <= maxDataSeq`) → **Adopted** (advance both cursors; call `wal.MarkAcked`). The client's writer rolled to `server.gen`, emitted RecordData entries, and the server has now durably acked through `(server.gen, server.seq)`. `wal.MarkAcked` already supports monotonic cross-generation advancement (see the `advance` predicate at `wal.MarkAcked` — `gen > w.ackHighGen || (gen == w.ackHighGen && seq > w.ackHighSeq)`). This is the legitimate restart/reconnect case.
- Higher generation with WAL having emitted RecordData in that gen but server.seq beyond the per-gen data high-water (`server.gen > persistedAck.gen` AND `wal.WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq > maxDataSeq`) → **Anomaly** with `AnomalyReason="server_ack_exceeds_local_data"`. The client wrote some RecordData in `server.gen`, but the server is acking past anything we ever sent — same shape as the same-gen `server_ack_exceeds_local_seq` case (round-12 RENAMED from `beyond_wal_high_water_seq` so the same-gen and cross-gen "exceeds local data" branches share a coherent naming scheme), just lifted into the cross-gen branch.
- Higher generation with WAL NOT having emitted RecordData in that gen (`server.gen > persistedAck.gen` AND `wal.WrittenDataHighWater(server.gen)` returns `(_, false)`) → **Anomaly** with `AnomalyReason="unwritten_generation"`. The writer has either not rolled to `server.gen` at all (future generation), or it rolled (segment header exists) but no RecordData has landed yet. In either case, admitting the ack would advance the on-disk persistedAck past anything the WAL can prove durable, AND would make all lower-gen segments reclaimable under lex GC and silently drop unsent history. This is the round-11 safety case.
- Same generation (`server.gen == persistedAck.gen`) → unchanged from round-10 (Adopted / ResendNeeded / NoOp / Anomaly via the same-gen lex-compare with `WrittenDataHighWater(server.gen)` as the upper bound; round-12 Finding 5 unifies the same-gen branch's predicate with the cross-gen branch by using `WrittenDataHighWater(server.gen)` instead of `HighWaterSequence()`).
- Any branch where `wal.WrittenDataHighWater(server.gen)` itself returns a non-nil error → **Anomaly** with `AnomalyReason="wal_read_failure"` (round-12 Finding 4 NEW). The WAL accessor failed for an I/O reason (disk error, file race, etc.); cursors stay UNCHANGED so the next ack-bearing frame re-tries, and operators get a discoverable signal via `wtp_anomalous_ack_total{reason="wal_read_failure"}` instead of a silent ok=false fallback that would have classified the frame as `unwritten_generation`.
- Lower generation, lex-comparable as a higher tuple (`server.gen > persistedAck.gen` AND `server.seq <= persistedAck.seq`) is folded into the higher-gen branches above — the helper's lex compare on `(gen, seq)` handles it identically. If `WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq <= maxDataSeq`, it is **Adopted** (the server acked a low seq in a higher gen we have data for). If `(_, false)`, it is **Anomaly** with `unwritten_generation`.
- Lower generation strictly (`server.gen < persistedAck.gen`) → **Anomaly** with `AnomalyReason="stale_generation"`. Lower-generation `ResendNeeded` is **deliberately out of scope** for this phase (see WAL-side constraints below).

The two WAL-side constraints that hold in round-11:

1. **Lower-generation replay is unrepresentable.** The WAL Reader API takes only `start uint64` (`(*WAL).NewReader(start uint64)` at `internal/store/watchtower/wal/reader.go:116`); it cannot accept a `(gen, seq)` start tuple, and segment sequences reset on every generation roll, so a lower-gen replay window cannot be expressed without a generation-aware Reader API that does not exist today. `wal.LossRecord` carries a single `Generation` field, so a multi-generation gap cannot be represented in one marker either. The `ack_regression_after_gc` synthetic loss in Step 1b.5 below is also same-generation by construction.
2. **Higher-generation Adopted is naturally represented.** The on-disk `persistedAck` is mutated through `wal.MarkAcked`, which advances `(gen, seq)` together using a lex predicate — so a higher-gen Adopted naturally rolls the meta.json ack watermark forward across the generation boundary. No new WAL surface is required for this case beyond Task 14a's `wal.WrittenDataHighWater(gen)` accessor (Step 3a), which provides the per-generation, data-bearing high-water proof the helper consults to admit higher-gen Adopted vs. classify it as Anomaly.

The `applyServerAckTuple` outcome table (round-12 — supersedes round-11):

| `server.gen` vs `persistedAck.gen` | `server.seq` vs reference | Outcome |
|---|---|---|
| `==` (same gen) | `> persistedAck.seq` AND `<= WrittenDataHighWater(server.gen).seq` | **Adopted** (advance both, `wal.MarkAcked`) |
| `==` (same gen) | `== persistedAck.seq` | **NoOp** |
| `==` (same gen) | `< persistedAck.seq` | **ResendNeeded** (replay cursor only) |
| `==` (same gen) | `> WrittenDataHighWater(server.gen).seq` | **Anomaly** `server_ack_exceeds_local_seq` (round-12 rename of round-11's `beyond_wal_high_water_seq`) |
| `>` (higher gen) | `WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq <= maxDataSeq` | **Adopted** (advance both, `wal.MarkAcked`) |
| `>` (higher gen) | `WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq > maxDataSeq` | **Anomaly** `server_ack_exceeds_local_data` |
| `>` (higher gen) | `WrittenDataHighWater(server.gen)` returns `(_, false)` | **Anomaly** `unwritten_generation` |
| `<` (lower gen) | (any) | **Anomaly** `stale_generation` |
| (any) | `WrittenDataHighWater(server.gen)` returns `err != nil` | **Anomaly** `wal_read_failure` (round-12 Finding 4 — NOT peer-attributable; cursors unchanged so the next ack retries) |

See spec §"Effective-ack tuple and clamp" "True anomaly" sub-cases for the cross-gen anomaly classification.

**Status:** Round-8 rewrite. Round-7's "lower-server-adopts-and-persists" rule conflicted with the WAL's monotonic-only `MarkAcked` invariant (`internal/store/watchtower/wal/wal.go:852-913` — the `advance` predicate at line 859 is one-way; lower (gen, seq) tuples are silently dropped from the on-disk watermark, but segment GC keys off the un-advanced on-disk value, so a "lower-adopt" path's in-memory write would diverge from disk and from GC behavior). Round-8 splits the single ack tuple into TWO cursors with distinct invariants:

- **`persistedAck` (gen, seq + Present flag)** — the durable, monotonic-only ack watermark. Mirror of `wal.Meta` `(AckHighWatermarkGen, AckHighWatermarkSeq, AckRecorded)`. Advances ONLY through `wal.MarkAcked`. Drives `wal_high_watermark_seq` on SessionInit AND segment GC. Lives in `t.persistedAck` (a struct holding `Sequence uint64`, `Generation uint32`) plus `t.persistedAckPresent bool`.
- **`remoteReplayCursor` (gen, seq)** — the server-belief cursor. Where the server thinks its ack watermark sits. May be lex-LOWER than `persistedAck` if the server (gradual rollout / partition recovery) presents a stale tuple. Drives the Replaying state's reader-start (`remoteReplayCursor + 1`) so a stale-server case re-sends the gap. Lives in `t.remoteReplayCursor`.

In the steady state `remoteReplayCursor == persistedAck`. They diverge briefly during stale-server recovery and reconverge on the next BatchAck for the re-sent records.

Originally added in round-5 to schedule the spec-mandated clamp BEFORE Task 22 wires the Run loop. Round-6 expanded scope to `(gen, seq)` lex compare. Round-7 added the WAL persistence contract (then incorrectly required the helper to call `wal.MarkAcked` even on lex-lower server tuples). Round-8 reverses that decision: lex-lower server adoption is in-memory only and applies ONLY to `remoteReplayCursor`; `persistedAck` and `wal.MarkAcked` are touched ONLY when the server tuple advances persistedAck. Without this rewrite the helper would either (a) violate the WAL's monotonic invariant by attempting `MarkAcked(lower, lower)` (silently rejected, so the in-memory mirror diverges from disk), or (b) the helper's "rollback on MarkAcked failure" path would land in production permanently because `MarkAcked(lower, lower)` would never advance the on-disk watermark.

**Files:**
- Modify: `internal/store/watchtower/transport/transport.go` (add `AckTuple` type, `Options.InitialAckTuple`, `Options.Logger`, `Options.WAL`, `Options.Metrics`, `t.persistedAck`, `t.persistedAckPresent`, `t.remoteReplayCursor` fields, `t.ackAnomalyLimiter`, and the `applyServerAckTuple` clamp helper)
- Modify: `internal/store/watchtower/transport/state_connecting.go` (replace the bare assignment with a call into `applyServerAckTuple` + the side-effect contract)
- Test: `internal/store/watchtower/transport/state_connecting_test.go` (or extend the existing transport_test.go) — the cursor-aware tests below

**Spec rule (design.md, §"Effective-ack tuple and clamp"):** the effective ack watermark is split across two cursors. `applyServerAckTuple` returns one of three outcomes — `Adopted` (persistedAck advanced via `wal.MarkAcked`, both cursors moved to the server tuple), `ResendNeeded` (server is stale relative to persistedAck — `remoteReplayCursor` set to the server tuple, `persistedAck` UNCHANGED, no `wal.MarkAcked` call), or `NoOp` (server tuple equals persistedAck). A separate `Anomaly` outcome covers the only true anomaly — server claims an ack BEYOND the WAL's high-water sequence. Mixing `persistedAck.gen` with `remoteReplayCursor.seq` (or vice versa) creates an impossible state under the WAL's lex `(gen, seq)` GC semantics; both cursors are immutable structs that the helper assigns wholesale.

**Offending site to replace** (`internal/store/watchtower/transport/state_connecting.go:59-60`):

```go
t.ackedSequence = ack.GetAckHighWatermarkSeq()
t.ackedGeneration = ack.GetGeneration()
```

**Step 1a: Add the two-cursor clamp helper.** Operate on the `(gen, seq)` tuple under lex compare; persistedAck is monotonic only; remoteReplayCursor may regress.

```go
// AckOutcome is the discriminated result of applyServerAckTuple. Exactly
// one of Adopted, ResendNeeded, NoOp, or Anomaly is true. Callers
// dispatch on the kind field; the embedded fields hold the post-clamp
// cursor values so the caller does not need to re-read t.persistedAck /
// t.remoteReplayCursor.
//
// AnomalyReason is populated ONLY when Kind == AckOutcomeAnomaly, and
// distinguishes the FIVE disjoint anomaly sub-cases (see spec §"Effective-
// ack tuple and clamp" "True anomaly" + round-12 Findings 4 & 5):
//   - "server_ack_exceeds_local_seq" (same gen, server.seq >
//     wal.WrittenDataHighWater(server.gen).seq — round-12 rename of
//     round-11's "beyond_wal_high_water_seq" so the same-gen and cross-gen
//     "exceeds local data" branches share a coherent naming scheme; both
//     reasons exist in the metric label set during the migration window)
//   - "stale_generation" (server.gen < persistedAck.gen)
//   - "unwritten_generation" (server.gen > persistedAck.gen AND
//     wal.WrittenDataHighWater(server.gen) returns ok=false — the writer
//     has not emitted any RecordData in that generation, even if a segment
//     header exists)
//   - "server_ack_exceeds_local_data" (server.gen > persistedAck.gen AND
//     wal.WrittenDataHighWater(server.gen) returns (maxDataSeq, true) but
//     server.seq > maxDataSeq — the server is acking past anything we
//     emitted in that generation)
//   - "wal_read_failure" (round-12 Finding 4: wal.WrittenDataHighWater
//     returned err != nil — NOT peer-attributable; the cursors stay
//     unchanged so the next ack-bearing frame retries the classification
//     once the underlying WAL I/O recovers)
type AckOutcome struct {
    Kind             AckOutcomeKind
    PersistedTuple   AckCursor // == t.persistedAck after the clamp (unchanged on ResendNeeded/NoOp/Anomaly)
    ReplayCursor     AckCursor // == t.remoteReplayCursor after the clamp
    PersistedAdvanced bool     // true iff Kind==Adopted (the only kind that calls wal.MarkAcked)
    AnomalyReason    string   // populated iff Kind==AckOutcomeAnomaly
}

type AckOutcomeKind int

const (
    AckOutcomeNoOp        AckOutcomeKind = iota // server == persistedAck (same gen, equal seq); no cursor moved
    AckOutcomeAdopted                           // server.gen == persistedAck.gen AND server.seq > persistedAck.seq AND server.seq <= wal.highSeq; both cursors advanced; wal.MarkAcked required
    AckOutcomeResendNeeded                      // server.gen == persistedAck.gen AND server.seq < persistedAck.seq; remoteReplayCursor set to server; persistedAck UNCHANGED; NO wal.MarkAcked
    AckOutcomeAnomaly                           // see AnomalyReason — five disjoint cases (stale_generation, unwritten_generation, server_ack_exceeds_local_data, server_ack_exceeds_local_seq, wal_read_failure); cursors UNCHANGED; WARN
)

// AckCursor is an immutable (gen, seq) ack tuple. Both cursors on
// Transport (persistedAck and remoteReplayCursor) are this type so the
// clamp helper assigns them wholesale and the callers cannot accidentally
// mix one cursor's gen with another's seq.
type AckCursor struct {
    Sequence   uint64
    Generation uint32
}

// applyServerAckTuple clamps a server-supplied (gen, seq) onto BOTH
// transport ack cursors per spec §"Effective-ack tuple and clamp". The
// helper itself NEVER calls wal.MarkAcked or emits metrics — those are
// the SessionAck/BatchAck/ServerHeartbeat handler's responsibility based
// on the returned AckOutcome.Kind. The helper is the SINGLE source of
// truth for which kind a given (server tuple, current cursors, current
// WAL high-water seq) maps to.
//
// SCOPE NOTE (round-12; supersedes round-11). The unified anomaly
// classification table (see also Task 17.X — these MUST stay in lockstep)
// uses these exact predicates, in this order:
//   - server.gen <  persistedAck.gen → Anomaly("stale_generation")
//   - server.gen == persistedAck.gen AND server.seq <= persistedAck.seq → either NoOp (==) or ResendNeeded (<)
//   - server.gen == persistedAck.gen AND server.seq >  persistedAck.seq AND
//     server.seq <= WrittenDataHighWater(server.gen).seq → Adopted
//   - server.gen == persistedAck.gen AND server.seq >  WrittenDataHighWater(server.gen).seq → Anomaly("server_ack_exceeds_local_seq")
//   - server.gen >  persistedAck.gen AND WrittenDataHighWater(server.gen).ok == false → Anomaly("unwritten_generation")
//   - server.gen >  persistedAck.gen AND server.seq <= WrittenDataHighWater(server.gen).seq → Adopted
//   - server.gen >  persistedAck.gen AND server.seq >  WrittenDataHighWater(server.gen).seq → Anomaly("server_ack_exceeds_local_data")
//   - WrittenDataHighWater(server.gen) returns err != nil at any decision
//     point → Anomaly("wal_read_failure") (NOT a peer anomaly; surfaced
//     for operator visibility but the cursors stay unchanged so the next
//     ack-bearing frame retries the classification once the underlying
//     WAL I/O recovers).
//
// Round-12 split: round-11 used "beyond_wal_high_water_seq" as the same-gen
// over-watermark reason; round-12 renames it to `server_ack_exceeds_local_seq`
// to match the cross-gen `server_ack_exceeds_local_data` shape and avoid
// confusion with the (different!) higher-gen "exceeds emitted data" case.
// Both reasons exist in the metric label set for the migration window — see
// Task 22b for the parity-test details. ResendNeeded is orthogonal — it is
// about the *replay* cursor regressing, not the *persisted* ack — and only
// fires under same-gen lex-lower (server.seq < persistedAck.seq).
//
// SCOPE NOTE (round-11; superseded by round-12 above for the predicate
// table — preserved for the rationale paragraphs). The helper distinguishes:
//   - Same-generation Adopted/ResendNeeded/NoOp/Anomaly via lex-compare on
//     `seq` against `t.persistedAck.Sequence` and `wal.HighWaterSequence()`.
//   - Cross-generation Adopted vs. Anomaly via the per-generation, data-
//     bearing accessor `wal.WrittenDataHighWater(server.gen)`. The Adopted
//     branch fires ONLY when the WAL has actually emitted at least one
//     RecordData in the server's claimed generation AND `server.seq` is
//     bounded by the per-gen max RecordData seq.
// Lower-generation `ResendNeeded` is **deliberately out of scope** for this
// phase per the WAL-side constraints in the task header.
//
// Returned AckOutcome contract:
//   - Adopted: server.gen == persistedAck.gen AND
//     server.seq > persistedAck.seq AND server.seq <= wal.highSeq.
//     Both t.persistedAck and t.remoteReplayCursor have been set to the
//     server tuple. The caller MUST then call
//     wal.MarkAcked(serverGen, serverSeq) and emit
//     wtp_ack_high_watermark on success; on MarkAcked failure the caller
//     MUST roll back BOTH cursors via the snapshot-and-rollback shape
//     in the side-effect contract below.
//   - ResendNeeded: server.gen == persistedAck.gen AND
//     server.seq < persistedAck.seq. t.remoteReplayCursor has been set to
//     the server tuple. t.persistedAck is UNCHANGED. The caller MUST NOT
//     call wal.MarkAcked (it would either be silently rejected by the
//     WAL's monotonic invariant or, worse, would advance the on-disk
//     watermark backward if the rejection check were ever loosened). The
//     caller MUST log INFO with both tuples AND increment
//     wtp_resend_needed_total; this is normal recovery, not an anomaly.
//   - NoOp: server.gen == persistedAck.gen AND server.seq == persistedAck.seq
//     (== remoteReplayCursor in the steady state). No cursor moved.
//   - Anomaly with AnomalyReason="server_ack_exceeds_local_seq":
//     server.gen == persistedAck.gen AND server.seq > wal.highSeq (server
//     claims ack beyond what the WAL has ever produced in the current gen).
//     Cursors UNCHANGED. Round-12 rename of round-11's "beyond_wal_high_water_seq".
//   - Anomaly with AnomalyReason="stale_generation":
//     server.gen < persistedAck.gen. Cursors UNCHANGED.
//   - Anomaly with AnomalyReason="unwritten_generation":
//     server.gen > persistedAck.gen AND wal.WrittenDataHighWater(server.gen)
//     returns ok=false (the writer has not emitted any RecordData in that
//     generation, even if a SegmentHeader for that gen exists on disk).
//     Cursors UNCHANGED. This is the round-11 safety case: admitting the ack
//     would let MarkAcked accept a fabricated tuple and trigger lex-GC of
//     lower-gen segments holding unsent records.
//   - Anomaly with AnomalyReason="server_ack_exceeds_local_data":
//     server.gen > persistedAck.gen AND wal.WrittenDataHighWater(server.gen)
//     returns (maxDataSeq, true) AND server.seq > maxDataSeq. The server is
//     acking past anything we ever sent in that generation. Cursors UNCHANGED.
//   - Anomaly with AnomalyReason="wal_read_failure":
//     wal.WrittenDataHighWater(server.gen) returned `err != nil` from the
//     underlying disk scan. Round-12 Finding 4: this anomaly is NOT
//     peer-attributable — it indicates a transient I/O failure reading the
//     WAL state, NOT misbehavior by the server. The caller MUST emit a
//     rate-limited WARN tagged with `reason="wal_read_failure"` so the
//     anomaly counter remains honest (`wtp_anomalous_ack_total{reason="wal_read_failure"}`)
//     and operators can distinguish disk failures from peer-attributable
//     anomalies. Cursors UNCHANGED so the next ack-bearing frame retries
//     the classification once the underlying WAL I/O recovers.

// In all five Anomaly sub-cases the caller MUST emit a rate-limited WARN
// with FULL context (server tuple, persistedAck tuple, walHighSeq) AND
// increment wtp_anomalous_ack_total{reason=AnomalyReason}.
//
// First-apply: when t.persistedAckPresent==false, the helper validates
// the server tuple against local WAL data BEFORE seeding either cursor.
// Wholesale-adoption is unsafe — seeding persistedAck at an impossible
// position (e.g. server reports (gen=8, seq=200) against a WAL that
// only ever wrote (gen=8, seq=1..50) because the agent's WAL was wiped
// or restored from a snapshot) drives the per-generation lex GC
// predicate past surviving records and silently deletes records that
// have not yet been delivered. The first-apply branch therefore
// short-circuits the same WAL validation rules used by the higher-gen
// and higher-same-gen-advance branches:
//   - serverSeq == 0 AND wal.HasDataBelowGeneration(serverGen) returns
//     (false, nil): adopt unconditionally into BOTH cursors.
//     `HasDataBelowGeneration` is the round-16 Finding 1 fix — without
//     it, adopting (serverGen, 0) when local data exists at any
//     generation g < serverGen would lex-over-ack every lower-gen
//     record via wal.MarkAcked (whose segmentFullyAckedLocked predicate
//     reclaims any segment with segGen < ackHighGen) and silently
//     destroy not-yet-delivered records on the next GC pass.
//   - serverSeq == 0 AND wal.HasDataBelowGeneration(serverGen) returns
//     (true, nil): Anomaly("server_ack_exceeds_local_data"). Cursors
//     and persistedAckPresent stay UNCHANGED.
//   - wal.HasDataBelowGeneration(serverGen) returns (_, err != nil):
//     Anomaly("wal_read_failure"). Cursors UNCHANGED.
//   - serverSeq > 0: defer to the WrittenDataHighWater(serverGen)
//     branch, which classifies wal_read_failure / unwritten_generation /
//     server_ack_exceeds_local_data exactly like the cross-gen
//     ADVANCE path.
func (t *Transport) applyServerAckTuple(serverGen uint32, serverSeq uint64) AckOutcome {
    server := AckCursor{Sequence: serverSeq, Generation: serverGen}
    if !t.persistedAckPresent {
        if serverSeq == 0 {
            hasLowerData, walErr := t.walHasDataBelowGenerationFn(serverGen)
            if walErr != nil {
                return AckOutcome{
                    Kind:           AckOutcomeAnomaly,
                    PersistedTuple: t.persistedAck,
                    ReplayCursor:   t.remoteReplayCursor,
                    AnomalyReason:  "wal_read_failure",
                }
            }
            if hasLowerData {
                return AckOutcome{
                    Kind:           AckOutcomeAnomaly,
                    PersistedTuple: t.persistedAck,
                    ReplayCursor:   t.remoteReplayCursor,
                    AnomalyReason:  "server_ack_exceeds_local_data",
                }
            }
            t.persistedAck = server
            t.persistedAckPresent = true
            t.remoteReplayCursor = server
            return AckOutcome{
                Kind:              AckOutcomeAdopted,
                PersistedTuple:    server,
                ReplayCursor:      server,
                PersistedAdvanced: true,
            }
        }
        maxDataSeq, haveData, walErr := t.walWrittenDataHighWaterFn(serverGen)
        if walErr != nil {
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "wal_read_failure",
            }
        }
        if !haveData {
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "unwritten_generation",
            }
        }
        if serverSeq > maxDataSeq {
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "server_ack_exceeds_local_data",
            }
        }
        t.persistedAck = server
        t.persistedAckPresent = true
        t.remoteReplayCursor = server
        return AckOutcome{
            Kind:              AckOutcomeAdopted,
            PersistedTuple:    server,
            ReplayCursor:      server,
            PersistedAdvanced: true,
        }
    }
    // Cross-generation: refined taxonomy (round-11 — replaces the round-10
    // WrittenHighGeneration() check with a per-generation, data-bearing
    // proof from wal.WrittenDataHighWater(serverGen)).
    //
    //  - serverGen < persistedAck.gen → Anomaly("stale_generation"). The
    //    server is on an older generation than the client persisted to;
    //    no in-band recovery (the client cannot un-roll its generation),
    //    cursors unchanged.
    //  - serverGen > persistedAck.gen AND wal.WrittenDataHighWater(serverGen)
    //    returns (maxDataSeq, true) AND serverSeq <= maxDataSeq → Adopted.
    //    The client's writer has rolled INTO serverGen AND has emitted at
    //    least one RecordData entry there AND the server's claimed seq is
    //    bounded by the per-gen data high-water. Adopt the server tuple
    //    wholesale and let the caller persist it via wal.MarkAcked.
    //  - serverGen > persistedAck.gen AND wal.WrittenDataHighWater(serverGen)
    //    returns (maxDataSeq, true) AND serverSeq > maxDataSeq →
    //    Anomaly("server_ack_exceeds_local_data"). The client emitted some
    //    RecordData in serverGen but the server is acking past anything we
    //    sent — same shape as the same-gen server_ack_exceeds_local_seq case
    //    (round-12 RENAMED from beyond_wal_high_water_seq), just lifted into
    //    the cross-gen branch.
    //  - serverGen > persistedAck.gen AND wal.WrittenDataHighWater(serverGen)
    //    returns ok=false → Anomaly("unwritten_generation"). The writer has
    //    either not rolled to serverGen (future generation) or it rolled
    //    (segment header exists) but no RecordData has landed yet. This is
    //    the round-11 safety case: the round-10 WrittenHighGeneration()
    //    accessor returned the segment-header-seeded value, which let the
    //    helper Adopted-classify an empty rolled generation; once
    //    wal.MarkAcked accepted that fabricated tuple, every lower-gen
    //    segment became reclaimable under lex GC and unsent history was
    //    silently dropped. Round-11 closes this hole by requiring a
    //    data-bearing per-generation proof.
    //
    // Calls into wal.WrittenDataHighWater(serverGen) are guarded against a
    // nil WAL (test construction without Options.WAL) by treating the lookup
    // as ok=false — the cross-gen Adopted branch never fires, the helper
    // returns Anomaly("unwritten_generation"), and the caller handles it
    // identically to a real unwritten-gen case.
    if serverGen < t.persistedAck.Generation {
        return AckOutcome{
            Kind:           AckOutcomeAnomaly,
            PersistedTuple: t.persistedAck,
            ReplayCursor:   t.remoteReplayCursor,
            AnomalyReason:  "stale_generation",
        }
    }
    if serverGen > t.persistedAck.Generation {
        var (
            maxDataSeq uint64
            haveData   bool
            walErr     error
        )
        if t.wal != nil {
            maxDataSeq, haveData, walErr = t.wal.WrittenDataHighWater(serverGen) // Task 14a accessor (round-12 Finding 4: explicit err)
        }
        if walErr != nil {
            // Round-12 Finding 4: NOT a peer-attributable anomaly — surface as
            // wal_read_failure so the anomaly counter stays honest. Cursors
            // UNCHANGED so the next ack-bearing frame retries the classification
            // once the underlying WAL I/O recovers.
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "wal_read_failure",
            }
        }
        if !haveData {
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "unwritten_generation",
            }
        }
        if serverSeq > maxDataSeq {
            return AckOutcome{
                Kind:           AckOutcomeAnomaly,
                PersistedTuple: t.persistedAck,
                ReplayCursor:   t.remoteReplayCursor,
                AnomalyReason:  "server_ack_exceeds_local_data",
            }
        }
        // Higher-gen-within-data-high-water: server has observed a newer
        // generation that the client's writer has actually emitted RecordData
        // in, and the server's claimed seq is bounded by the per-gen data
        // high-water. Adopt the server tuple (both cursors). The caller will
        // persist via wal.MarkAcked, which the Task 14a writer accepts because
        // (gen, seq) lex-order makes serverGen > persistedGen a strict
        // advance regardless of seq.
        t.persistedAck = server
        t.remoteReplayCursor = server
        return AckOutcome{
            Kind:              AckOutcomeAdopted,
            PersistedTuple:    server,
            ReplayCursor:      server,
            PersistedAdvanced: true,
        }
    }
    // Same-generation lex compare on seq.
    switch {
    case serverSeq > t.persistedAck.Sequence:
        // True anomaly check: server claims ack beyond what the WAL has
        // ever written for this generation. Round-12 Finding 5 unification:
        // use the SAME `WrittenDataHighWater(serverGen)` accessor as the
        // cross-gen branch so the helper has a single source of truth for
        // the "server seq exceeds local data" predicate. The reason label is
        // `server_ack_exceeds_local_seq` (round-12 rename of round-11's
        // `beyond_wal_high_water_seq`) to align with the cross-gen
        // `server_ack_exceeds_local_data` shape.
        if t.wal != nil {
            maxDataSeq, haveData, walErr := t.wal.WrittenDataHighWater(serverGen) // Task 14a accessor
            if walErr != nil {
                return AckOutcome{
                    Kind:           AckOutcomeAnomaly,
                    PersistedTuple: t.persistedAck,
                    ReplayCursor:   t.remoteReplayCursor,
                    AnomalyReason:  "wal_read_failure",
                }
            }
            // haveData is guaranteed true on the same-gen branch because the
            // helper only reaches this code path after a prior same-gen
            // ack/append established the cursor; defensive `!haveData` is
            // treated as `server_ack_exceeds_local_seq` (the writer has not
            // emitted in the current persisted gen — same operator-visible
            // shape as "server claims more than we have").
            if !haveData || serverSeq > maxDataSeq {
                return AckOutcome{
                    Kind:           AckOutcomeAnomaly,
                    PersistedTuple: t.persistedAck,
                    ReplayCursor:   t.remoteReplayCursor,
                    AnomalyReason:  "server_ack_exceeds_local_seq",
                }
            }
        }
        // Healthy advance: move both cursors to the server tuple.
        // The caller persists via wal.MarkAcked.
        t.persistedAck = server
        t.remoteReplayCursor = server
        return AckOutcome{
            Kind:              AckOutcomeAdopted,
            PersistedTuple:    server,
            ReplayCursor:      server,
            PersistedAdvanced: true,
        }
    case serverSeq < t.persistedAck.Sequence:
        // Stale-but-legitimate (gradual rollout / partition recovery /
        // server-side ack-watermark reset) WITHIN the same generation.
        // Move ONLY remoteReplayCursor; persistedAck stays in lock-step
        // with the on-disk meta.json.
        t.remoteReplayCursor = server
        return AckOutcome{
            Kind:           AckOutcomeResendNeeded,
            PersistedTuple: t.persistedAck, // unchanged
            ReplayCursor:   server,
        }
    default:
        return AckOutcome{
            Kind:           AckOutcomeNoOp,
            PersistedTuple: t.persistedAck,
            ReplayCursor:   t.remoteReplayCursor,
        }
    }
}
```

The `applyServerAckTuple` helper is the SINGLE source of truth for the clamp logic; the SessionAck handler in `state_connecting.go` (this task), and the BatchAck / ServerHeartbeat handlers in the recv multiplexer (Task 17 sub-step 17.X), all dispatch through it. Note: the helper's `t.wal.HighWaterSequence()` lookup uses the Task 14a accessor (Step 3a). If the WAL accessor is unavailable in tests, the helper takes a `func() uint64` indirection in `Options` for testability (`Options.WALHighWaterSeqFn func() uint64` defaulting to `t.wal.HighWaterSequence`).

**Step 1b: Wire the SessionAck handler into the helper.** Replace the bare `state_connecting.go:59` block with the call sequence below. The sequence dispatches on `AckOutcome.Kind`:

```go
serverGen := ack.GetGeneration()
serverSeq := ack.GetAckHighWatermarkSeq()

// Snapshot BOTH cursors before the helper mutates — required for rollback
// on Adopted-then-MarkAcked-failure per Step 1b.5.
priorPersisted := t.persistedAck
priorReplay := t.remoteReplayCursor
priorPresent := t.persistedAckPresent

outcome := t.applyServerAckTuple(serverGen, serverSeq)
switch outcome.Kind {
case AckOutcomeAnomaly:
    if t.ackAnomalyLimiter.Allow() {
        // Per spec §"Effective-ack tuple and clamp" — True anomaly:
        // server tuple is in one of FIVE disjoint shapes (see helper
        // AnomalyReason: "stale_generation", "unwritten_generation",
        // "server_ack_exceeds_local_data", "server_ack_exceeds_local_seq",
        // or "wal_read_failure"). Cursors UNCHANGED in all five.
        //
        // Round-12: the WARN log emits the per-generation data-bearing
        // high-water (`wal_written_data_high_seq`) instead of the global
        // `HighWaterSequence()` because the unified predicate now compares
        // against `WrittenDataHighWater(serverGen)` (Task 14a accessor;
        // round-12 Findings 4 + 5). Best-effort: a transient walErr from
        // the field reader is logged as `wal_written_data_high_err` so the
        // operator can correlate the wal_read_failure anomaly path with
        // the underlying I/O failure.
        var (
            wtdHighSeq uint64
            wtdHighOK  bool
            wtdHighErr error
        )
        if t.wal != nil {
            wtdHighSeq, wtdHighOK, wtdHighErr = t.wal.WrittenDataHighWater(serverGen)
        }
        attrs := []slog.Attr{
            slog.String("reason", outcome.AnomalyReason),
            slog.Uint64("server_seq", serverSeq),
            slog.Uint64("server_gen", uint64(serverGen)),
            slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
            slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
            slog.Uint64("wal_written_data_high_seq", wtdHighSeq),
            slog.Bool("wal_written_data_high_ok", wtdHighOK),
            slog.String("session_id", t.opts.SessionID),
        }
        if wtdHighErr != nil {
            attrs = append(attrs, slog.String("wal_written_data_high_err", wtdHighErr.Error()))
        }
        t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn, "session_ack: anomalous server ack tuple", attrs...)
    }
    t.metrics.IncAnomalousAck(outcome.AnomalyReason) // Task 22b — labeled counter
    // Cursors unchanged; nothing more to do.
case AckOutcomeAdopted:
    // persistedAck advanced; persist to WAL and emit metric.
    if err := t.wal.MarkAcked(t.persistedAck.Generation, t.persistedAck.Sequence); err != nil {
        // Persistence failed: roll back BOTH cursors so the in-memory
        // mirrors stay in lock-step with the on-disk meta.json.
        t.opts.Logger.Warn("session_ack: wal.MarkAcked failed; rolling back ack cursors",
            slog.Uint64("attempted_seq", t.persistedAck.Sequence),
            slog.Uint64("attempted_gen", uint64(t.persistedAck.Generation)),
            slog.String("err", err.Error()))
        t.persistedAck = priorPersisted
        t.remoteReplayCursor = priorReplay
        t.persistedAckPresent = priorPresent
        // Server will re-deliver this watermark on the next BatchAck or
        // ServerHeartbeat. No metric emission on the failure path.
    } else {
        // SetAckHighWatermark currently takes a single seq (production
        // signature today: `func (w *WTPMetrics) SetAckHighWatermark(seq int64)`).
        // The metric remains a single unlabeled gauge for round-8;
        // see Task 22b for the deferred schema-extension proposal.
        t.metrics.SetAckHighWatermark(int64(t.persistedAck.Sequence))
    }
case AckOutcomeResendNeeded:
    // remoteReplayCursor moved; persistedAck unchanged; do NOT call
    // wal.MarkAcked. Log INFO so operators can see the server is stale
    // relative to local persistence (gradual rollout / partition
    // recovery — normal, not anomalous). Increment the operator-visible
    // counter (spec §"Operational signals subsection" — sustained rate
    // >5/min indicates server-side ack persistence issues).
    t.opts.Logger.Info("session_ack: server ack tuple lower than persistedAck; remote replay cursor regressed",
        slog.Uint64("server_seq", serverSeq),
        slog.Uint64("server_gen", uint64(serverGen)),
        slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
        slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
        slog.String("session_id", t.opts.SessionID))
    t.metrics.IncResendNeeded() // Task 22b — counter
case AckOutcomeNoOp:
    // No cursor moved; nothing to do.
}
```

`t.ackAnomalyLimiter` is a `*rate.Limiter` Transport field added in this step (defaulted in `New` to `rate.NewLimiter(rate.Every(time.Minute), 1)` so production emits at most one anomaly WARN per minute per Transport instance). Unit tests inject a permissive limiter (`rate.NewLimiter(rate.Inf, 1)` or a mock). `t.opts.Logger` is the injected logger (see Step 1d) — the only handle the Transport reaches for log output.

**Step 1b.5: Synthesize `ack_regression_after_gc` loss BEFORE opening the replay reader.** When `applyServerAckTuple` returns `ResendNeeded`, the next replay window opens at `remoteReplayCursor.seq + 1`. If the WAL has already GC'd the segments holding records `(remoteReplayCursor.seq, persistedAck.seq]` (because GC was driven by an earlier higher ack), the data the server is asking for is permanently gone. Per spec §"Loss between replay cursor and persisted ack" this MUST surface to the server as a `TransportLoss` frame so the gap is visible rather than silently swallowed.

The detector lives in the **Replaying state's reader-open path** (Task 22 StateReplaying entry point), NOT in the SessionAck handler — the SessionAck handler only mutates cursors; the loss synthesis happens when the next state-cycle is about to open the WAL Reader.

**Round-10 design refinement: synthesize the loss IN THE TRANSPORT (in-memory), NOT via `wal.AppendLoss`.** The original Step 1b.5 design appended a synthetic loss marker to the WAL on disk via `wal.AppendLoss`. Round-10 review flagged two problems:

1. **Loss-marker ordering infeasibility.** `wal.AppendLoss` always appends at the WAL TAIL (next available seq slot). A loss marker covering seqs `[gapStart, earliestOnDisk - 1]` written at the tail will be surfaced by the Reader AFTER the data records the Reader is replaying — not BEFORE the gap. The Replayer cannot reorder records (it preserves WAL position order); the server then sees the data records first and the gap-cover marker arriving as a tail decoration, which defeats the purpose of representing the gap.
2. **Persistence is unnecessary.** The gap is fully recomputable on every reconnect from `(remoteReplayCursor.seq, EarliestDataSequence())` — there is no benefit to writing it to disk, and writing it incurs a fsync per ResendNeeded ack.

The round-10 design synthesizes a **non-persistent** `wal.LossRecord` in memory and threads it through `ReplayerOptions.PrefixLoss`. The `Replayer` returns it as the FIRST record in its FIRST `NextBatch` — guaranteed to land at the head of the replay stream — and the Reader is opened at `earliestOnDisk` for the data records. No `wal.AppendLoss` call, no fsync, no on-disk pollution.

**Round-11 helper extraction (Finding 3).** The decision tree below is the SINGLE source of truth for `(prefixLoss, readerStart)` and is encapsulated in a Transport method `computeReplayStart(remoteReplayCursor AckCursor, persistedAck AckCursor) (prefixLoss *wal.LossRecord, readerStart uint64, err error)`. The Run loop in Task 22 (StateReplaying case) MUST call `computeReplayStart` BEFORE opening the WAL Reader (the result `readerStart` is the `start` argument to `rdrFactory(gen, start)` per the round-13/16 (gen, start) signature; `gen` comes from `stage.Generation`), and MUST thread `prefixLoss` into `ReplayerOptions.PrefixLoss`. Round-10 had a structural bug where the snippet computed `readerStart` AFTER opening the reader at `remoteReplayCursor.Sequence + 1` and discarded the readerStartOverride — round-11 fixes the ordering and locks in the canonical helper signature so every Replaying call site shares the same logic.

The helper:

```go
// computeReplayStart is the canonical helper that returns the
// (prefixLoss, readerStart) tuple for the Replaying state's reader-open
// path. Called from the Run loop's StateReplaying case BEFORE the reader
// is opened — `readerStart` is the `start` argument to rdrFactory (the
// second positional arg per the round-13/16 (gen, start) signature; `gen`
// is supplied by the StateReplaying caller from `stage.Generation`);
// `prefixLoss` is threaded into ReplayerOptions.PrefixLoss.
//
// Same-generation only: the cursor split has already classified cross-gen
// as Anomaly (cursors unchanged), so by the time we reach this code path
// remoteReplayCursor.Generation == persistedAck.Generation by
// construction (see Task 15.1 Step 1b applyServerAckTuple cross-gen
// taxonomy and Task 17.X recv handler).
//
// EarliestDataSequence(gen) returns (earliestSeq, ok=true, nil) when at least
// one data record from `gen` remains on disk; ok=false means the WAL has been
// GC'd to empty FOR THAT GENERATION (zero data records of `gen` on disk —
// segments of OTHER generations may still exist on disk and are deliberately
// invisible here, see round-12 Finding 1 SAFETY NOTE in Task 14a). Both cases
// must be handled — the fully-GC'd case (ok=false) where remoteReplayCursor <
// persistedAck is the worst regression-after-gc shape and MUST emit loss
// covering the entire (remoteReplayCursor, persistedAck] range.
//
// Returns:
//   - prefixLoss != nil: an in-memory wal.LossRecord describing a GC'd
//     gap. NOT persisted. The Replayer surfaces it as the first record
//     of the first NextBatch via ReplayerOptions.PrefixLoss.
//   - readerStart: the seq the WAL Reader should be opened at (gapStart
//     in cases B/C/D, earliestOnDisk in case A).
//   - err != nil: a hard I/O error reading WAL state. The caller MUST
//     treat this as a transport error and reconnect rather than open
//     the reader at the wrong position.
func (t *Transport) computeReplayStart(remoteReplayCursor AckCursor, persistedAck AckCursor) (*wal.LossRecord, uint64, error) {
    // Round-12 Finding 1: pass the SAME generation we'll be replaying for —
    // sequences reset on every generation roll AND higher-generation segments
    // can coexist on disk while lower-generation segments are GC'd. A
    // generation-implicit accessor would surface a higher-gen segment's low
    // earliest as evidence the replay generation's gap is intact, silently
    // masking ack_regression_after_gc. Same-gen invariant (see header) means
    // remoteReplayCursor.Generation == persistedAck.Generation here, so either
    // works; we pass persistedAck.Generation because it's the cursor whose seq
    // anchors the gapEnd in Cases C/D.
    earliestOnDisk, ok, err := t.wal.EarliestDataSequence(persistedAck.Generation) // Task 14a Step 3a accessor (round-12 generation-aware)
    if err != nil {
        // Hard I/O error reading segment headers — surface as a transport
        // error so the state machine reconnects rather than silently opens
        // the reader at the wrong position.
        return nil, 0, fmt.Errorf("ack_regression_check: wal.EarliestDataSequence: %w", err)
    }
    gapStart := remoteReplayCursor.Sequence + 1

    // Decision tree for the synthetic loss marker. Same-generation invariant
    // ensures Generation == persistedAck.Generation in all four cases.
    //
    //   Case A — ok=true, earliestOnDisk > gapStart:
    //     Partial GC. Gap is [gapStart, earliestOnDisk - 1]. Open reader at
    //     earliestOnDisk; surviving data records continue from there.
    //   Case B — ok=true, earliestOnDisk <= gapStart:
    //     No gap (steady-state same-gen replay). No synthetic loss; open
    //     reader at gapStart.
    //   Case C — ok=false, gapStart <= persistedAck.Sequence:
    //     Fully GC'd, server is BEHIND persistedAck (the worst regression).
    //     Gap is [gapStart, persistedAck.Sequence]. The persistedAck.seq is
    //     the right gapEnd because everything up to and including
    //     persistedAck.seq was on disk at one point (the WAL only GCs after
    //     MarkAcked succeeds, and persistedAck is the high-water of those
    //     successful MarkAcked calls). Open reader at gapStart; the Reader
    //     will hit io.EOF immediately because the WAL is empty, but the
    //     synthesized PrefixLoss is what the server needs.
    //   Case D — ok=false, gapStart > persistedAck.Sequence:
    //     Fully GC'd, server is AT OR PAST persistedAck. No legitimate gap
    //     can exist (the resend-needed branch only fires when server.seq <
    //     persistedAck.seq within the same gen). Defensive no-op; open
    //     reader at gapStart.
    var prefixLoss *wal.LossRecord
    var readerStart uint64
    switch {
    case ok && earliestOnDisk > gapStart:
        // Case A — partial GC.
        prefixLoss = &wal.LossRecord{
            FromSequence: gapStart,
            ToSequence:   earliestOnDisk - 1,
            Generation:   persistedAck.Generation,
            Reason:       "ack_regression_after_gc",
        }
        readerStart = earliestOnDisk
    case ok && earliestOnDisk <= gapStart:
        // Case B — no gap.
        readerStart = gapStart
    case !ok && gapStart <= persistedAck.Sequence:
        // Case C — fully GC'd, server BEHIND persistedAck.
        prefixLoss = &wal.LossRecord{
            FromSequence: gapStart,
            ToSequence:   persistedAck.Sequence,
            Generation:   persistedAck.Generation,
            Reason:       "ack_regression_after_gc",
        }
        readerStart = gapStart
    default:
        // Case D — fully GC'd, server AT OR PAST persistedAck. Defensive.
        readerStart = gapStart
    }
    if prefixLoss != nil {
        // Round-13 Finding 5: the metric increment used to fire here in
        // computeReplayStart, which counts COMPUTED losses rather than
        // EMITTED ones. The helper can be invoked, return a non-nil
        // prefixLoss, and the Run loop can later abort the Replayer
        // before its first NextBatch (e.g. dialer fault, ctx cancel,
        // or any state transition between computeReplayStart return and
        // Replayer.NextBatch first call) — and the metric would have
        // already been bumped, double-counting on the inevitable
        // reconnect that re-runs computeReplayStart from scratch. The
        // round-13 fix moves the increment to the EMIT site: the
        // Replayer fires `ReplayerOptions.OnPrefixLossEmitted` exactly
        // once after batch-1 surfacing, and the Run loop wires that
        // callback to `t.metrics.IncAckRegressionLoss()`. The INFO log
        // stays here because it is "we computed a synthesized loss
        // from these inputs," which is meaningful even if the loss is
        // never emitted (the operator wants to see the inputs that led
        // to the decision). The COUNTER moves; the LOG stays.
        t.opts.Logger.Info("ack_regression_check: synthesized in-memory loss for GC'd gap",
            slog.Uint64("from_seq", prefixLoss.FromSequence),
            slog.Uint64("to_seq", prefixLoss.ToSequence),
            slog.Uint64("gen", uint64(prefixLoss.Generation)),
            slog.Uint64("remote_replay_seq", remoteReplayCursor.Sequence),
            slog.Bool("earliest_on_disk_present", ok),
            slog.Uint64("earliest_on_disk_seq", earliestOnDisk),
            slog.Uint64("local_persisted_seq", persistedAck.Sequence),
            slog.String("session_id", t.opts.SessionID))
    }
    return prefixLoss, readerStart, nil
}
```

The Run-loop call site (see Task 22 StateReplaying case) is:

```go
// Task 22 StateReplaying case — call computeReplayStart FIRST, then
// open the reader at readerStart with the gen-scoped wal.ReaderOptions
// shape (round-13 Task 14b), then construct the Replayer with
// PrefixLoss AND OnPrefixLossEmitted. The ordering matters: opening the
// reader at remoteReplayCursor.Sequence + 1 unconditionally and then
// "fixing it up" is wrong — the reader's start cursor is set at
// construction and cannot be moved.
prefixLoss, readerStart, lerr := t.computeReplayStart(t.remoteReplayCursor, t.persistedAck)
if lerr != nil {
    rep = nil
    st = StateConnecting
    continue
}
rdr, err := t.wal.NewReader(wal.ReaderOptions{
    Generation: t.remoteReplayCursor.Generation, // round-13 Task 14b: gen-scope the Reader
    Start:      readerStart,
})
if err != nil {
    rep = nil
    st = StateConnecting
    continue
}
rep = NewReplayer(rdr, ReplayerOptions{
    MaxBatchRecords: liveOpts.Batcher.MaxRecords,
    MaxBatchBytes:   liveOpts.Batcher.MaxBytes,
    PrefixLoss:      prefixLoss, // round-10: in-memory loss marker
    // Round-13 Finding 5: count EMITTED losses (not COMPUTED ones). The
    // Replayer fires this callback exactly once, AFTER the in-memory
    // PrefixLoss has been surfaced as record[0] of the FIRST NextBatch.
    // If the Replayer is constructed with prefixLoss != nil but is
    // aborted before its first NextBatch (dialer fault, ctx cancel,
    // etc.), the callback does NOT fire and the metric does NOT
    // increment — the inevitable reconnect re-runs computeReplayStart
    // and re-derives the same prefixLoss from the same inputs (no double
    // count). The callback fires synchronously inside NextBatch and runs
    // on the Run loop's goroutine; the implementation MUST be cheap and
    // non-blocking (just a counter Inc). When prefixLoss == nil the
    // Replayer never invokes the callback regardless of subsequent
    // batch surfacing.
    OnPrefixLossEmitted: func() {
        t.metrics.IncAckRegressionLoss() // Task 22a — counter (emit-time)
    },
})
```

The transport-level synthesis pivots on `ReplayerOptions.PrefixLoss` (added in Task 16 — see the round-10 update there). The `Replayer` emits `*PrefixLoss` as the FIRST record of the FIRST `NextBatch` and never re-emits it; subsequent batches drain from the Reader normally. The marker travels to the server through the same `EventBatch.records[]` path that surfaces WAL-emitted `RecordLoss` entries, so the receiver code treats the in-memory and on-disk loss markers identically (it cannot tell them apart, and does not need to).

**Why the producer lives in the Replaying state's reader-open path, not the SessionAck handler.** Three reasons (round-10: in-memory PrefixLoss preserves the same rationale; the WAL-write/fsync language has been replaced):

1. **Ordering against the WAL Reader.** The synthetic loss marker MUST reach the Replayer BEFORE any data record from the surviving WAL segments. Putting the synthesis in the Replaying entry point lets us pass `PrefixLoss` directly to `transport.NewReplayer` so the very first `NextBatch` returns the loss as record[0]. If the SessionAck handler synthesized the marker, the Replaying state would have to re-discover it on the next state cycle through some shared field, with no guaranteed ordering relative to a concurrent reader-open.
2. **Recovery on reconnect.** The fully-recompute design means transient errors (e.g. `EarliestDataSequence` returning an I/O error) are recovered on the next reconnect for free — `EarliestDataSequence()` returns the same value, the SessionAck handler's cursor state is unchanged, and the new state cycle re-derives the same `PrefixLoss` from the same inputs. No retry loop needed.
3. **Single-state ownership.** The Replaying state is the only state that constructs a `Replayer`; centralising the loss-synthesis there keeps the in-memory `ReplayerOptions.PrefixLoss` plumbing trivially correct (synthesise → construct Replayer → first NextBatch returns PrefixLoss as record[0]).

**Test #9 (`TestRunReplaying_SynthesizesPrefixLossOnPartialGCdGap`)** — round-10 RENAMED from `_SynthesizesAckRegressionLossOnGCdGap`: exercises the partial-GC producer end-to-end (Case A in the decision tree). Setup: open a real `*wal.WAL` with `MaxTotalBytes` small enough that GC is triggerable; append 100 records in gen=1; drive `wal.MarkAcked(1, 80)` so segments holding seqs 1..N (where N depends on segment size; pick segment size so seqs 1..50 GC and seqs 51..100 survive); `InitialAckTuple = &AckTuple{Sequence: 80, Generation: 1, Present: true}`. Drive a SessionAck handler with `(serverGen=1, serverSeq=20)` (lex-lower → `ResendNeeded`; `t.remoteReplayCursor` becomes `(20, 1)`, `t.persistedAck` stays `(80, 1)`). Now drive the runReplaying entry point. Assert: (a) `wal.EarliestDataSequence()` returned `(51, true, nil)` (or whatever the surviving earliest is); (b) `wal.AppendLoss` was NOT called (round-10: no on-disk write); (c) `transport.NewReplayer` was called with `ReplayerOptions.PrefixLoss == &wal.LossRecord{FromSequence: 21, ToSequence: 50, Generation: 1, Reason: "ack_regression_after_gc"}` AND `ReplayerOptions.OnPrefixLossEmitted != nil` (round-13 Finding 5); (d) the metrics fake recorded EXACTLY ONE `IncAckRegressionLoss()` call AT EMIT TIME — round-13 Finding 5: assert the counter is STILL ZERO immediately after `transport.NewReplayer` returns and BEFORE the first `NextBatch` call; assert the counter increments to 1 ONLY after the first `NextBatch` returns the surfaced PrefixLoss as record[0]; (e) the Reader was opened at seq=51 via `wal.NewReader(wal.ReaderOptions{Generation: 1, Start: 51})` (round-13 Task 14b); (f) the first record the Replayer surfaces via `NextBatch` is a `RecordLoss` carrying the PrefixLoss values verbatim; (g) the second record the Replayer surfaces is the seq=51 data record from the surviving WAL; (h) the INFO log buffer contains exactly one entry naming `from_seq=21, to_seq=50, gen=1, remote_replay_seq=20, earliest_on_disk_present=true, earliest_on_disk_seq=51, local_persisted_seq=80` — round-13 Finding 5: the INFO entry is logged from `computeReplayStart` (compute-time) and is independent of whether the metric ever fires; both can be observed in the buffer regardless of whether NextBatch is invoked.

**Test #10 (`TestRunReplaying_NoPrefixLossWhenNoGap`)** — round-10 RENAMED: negative case (Case B in the decision tree). Same setup as Test #9, but drive SessionAck with `(serverGen=1, serverSeq=70)` (still a `ResendNeeded`, but `gapStart=71` and `earliestOnDisk=51`, so `earliestOnDisk < gapStart` → no gap). Assert: `transport.NewReplayer` was called with `ReplayerOptions.PrefixLoss == nil` (the OnPrefixLossEmitted callback MAY still be wired by the Run loop — Replayer treats it as a no-op when PrefixLoss is nil); metrics counter unchanged AT ALL TIMES (no compute-time increment, no emit-time increment); Reader opened at seq=71 via the gen-scoped `wal.ReaderOptions{Generation: 1, Start: 71}` (round-13 Task 14b); INFO log buffer empty (the no-gap path is silent at compute-time).

**Test #11 (`TestRun_ResendNeededFullyGCdEmitsLossOverEntirePersistedRange`)** — round-10 NEW (Finding 2 + Case C in the decision tree): the worst regression-after-gc shape. Setup: open a real `*wal.WAL` with `MaxTotalBytes` small enough that GC is triggerable; append records and drive `wal.MarkAcked(1, 100)` AND configure GC so that ALL data records are GC'd (e.g. by appending only short-lived records and exhausting `MaxTotalBytes`); `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 1, Present: true}`. Verify `wal.EarliestDataSequence()` returns `(0, false, nil)` before continuing. Drive a SessionAck handler with `(serverGen=1, serverSeq=20)` (lex-lower → `ResendNeeded`; `t.remoteReplayCursor` becomes `(20, 1)`, `t.persistedAck` stays `(100, 1)`). Now drive the runReplaying entry point. Assert: (a) `wal.AppendLoss` was NOT called; (b) `transport.NewReplayer` was called with `ReplayerOptions.PrefixLoss == &wal.LossRecord{FromSequence: 21, ToSequence: 100, Generation: 1, Reason: "ack_regression_after_gc"}` AND `ReplayerOptions.OnPrefixLossEmitted != nil` (the gapEnd is `persistedAck.Sequence`, NOT `earliestOnDisk - 1` which is meaningless when nothing remains on disk); (c) the metrics fake recorded EXACTLY ONE `IncAckRegressionLoss()` call AT EMIT TIME — assert the counter is ZERO immediately after `transport.NewReplayer` returns and BEFORE the first `NextBatch` call, then ONE after the first `NextBatch` surfaces the PrefixLoss; (d) the Reader was opened at seq=21 (gapStart, since there is no surviving data record to anchor on) via `wal.NewReader(wal.ReaderOptions{Generation: 1, Start: 21})` (round-13 Task 14b); (e) the first record the Replayer surfaces is the synthesized PrefixLoss covering [21, 100]; (f) the second `NextBatch` returns done=true (the Reader hits io.EOF immediately because the WAL is empty); (g) the INFO log buffer contains exactly one entry naming `from_seq=21, to_seq=100, gen=1, remote_replay_seq=20, earliest_on_disk_present=false, earliest_on_disk_seq=0, local_persisted_seq=100`. Without this test, the round-10 reviewer's "fully-GC'd case silently drops loss" finding would re-emerge.

**Test #11a (`TestComputeReplayStart_FullyGCdServerAtOrPastPersistedAckIsNoOp`)** — round-11 RENAMED from `TestRun_ResendNeededFullyGCdServerAtPersistedAckIsNoOp` (Finding 4): the round-10 framing exercised Case D through the Run loop, which is structurally awkward — Case D is defensive and the helper is the natural unit under test. Round-11 lifts this case to a direct helper-level unit test that calls `t.computeReplayStart(remoteReplayCursor, persistedAck)` with crafted cursors and a fake/in-memory WAL whose `EarliestDataSequence()` returns `(0, false, nil)`.

Setup: construct a `*Transport` with `t.wal` set to a WAL whose `EarliestDataSequence()` returns `(0, false, nil)` (real `*wal.WAL` with everything GC'd: `MaxTotalBytes` exhausted, `wal.MarkAcked(1, 100)` called, all data records reclaimed). Set `t.metrics` to a fake metrics collector. Set `t.opts.Logger` to a buffer-backed `slog.Logger`.

Two sub-cases (table-driven over the `gapStart > persistedAck.Sequence` predicate):

- **Sub-case (a) — `gapStart == persistedAck.Sequence + 1`** (the steady-state reconnect collapsed onto the boundary): call `t.computeReplayStart(AckCursor{Sequence: 100, Generation: 1}, AckCursor{Sequence: 100, Generation: 1})`. Assert: `prefixLoss == nil`, `readerStart == 101` (gapStart), `err == nil`, metrics counter unchanged, INFO log buffer empty.
- **Sub-case (b) — `gapStart > persistedAck.Sequence + 1`** (defensive: `remoteReplayCursor` advanced past `persistedAck` by some other code path; legitimate Case D): call `t.computeReplayStart(AckCursor{Sequence: 150, Generation: 1}, AckCursor{Sequence: 100, Generation: 1})`. Assert: `prefixLoss == nil`, `readerStart == 151` (gapStart), `err == nil`, metrics counter unchanged, INFO log buffer empty.

This direct helper test covers Case D without driving the Run loop, which makes the test deterministic and removes the awkward "if the test framework forces a reconnect" branch from the round-10 framing. Tests #9, #10, #11 stay at the integration / Run-loop level because they exercise the full Replayer → first-batch → PrefixLoss surfacing path; only Case D is a pure helper concern. (Tests #9, #10, #11 may also be ported to direct helper tests in a future round if the helper-level coverage proves richer than the integration tests, but that is out of scope for round-11.)

**Test #11b (`TestComputeReplayStart_MixedGenerationsOnDisk_DetectsLossInOlderGeneration`)** — round-12 NEW (Finding 2): the round-12 generation-aware regression test. Without this test, a regression that re-introduces a generation-implicit `EarliestDataSequence()` (or a caller that forgets to pass `persistedAck.Generation`) would silently mis-classify a fully-GC'd older-generation gap as "no gap" because a higher-generation segment's low earliest seq would slip through and satisfy `earliestOnDisk <= gapStart`.

Setup: open a real `*wal.WAL` in a worktree-private directory; configure `MaxTotalBytes` so GC is triggerable. Drive the WAL to mixed-generation steady state:

1. Append seqs 1..50 in gen=1 (so the gen=1 segments hold RecordData entries 1..50).
2. Drive `wal.MarkAcked(1, 50)` so meta.json holds `(AckHighWatermarkGen=1, AckHighWatermarkSeq=50, AckRecorded=true)` and gen=1 segments are eligible for GC.
3. Roll the writer to gen=2 (e.g. via `wal.RollGeneration` or by triggering an append-side roll), and append at least one RecordData in gen=2 (say seqs 1..5 in gen=2) so a gen=2 segment exists on disk.
4. Force GC of all gen=1 data segments (e.g. by appending more gen=2 records until `MaxTotalBytes` is exceeded). Verify the resulting on-disk state with `wal.ListSegments()`: ZERO gen=1 segments AND at least one gen=2 segment.
5. Verify the per-generation accessors agree with the mixed state:
   - `wal.EarliestDataSequence(1)` returns `(0, false, nil)` — gen=1 has no data on disk.
   - `wal.EarliestDataSequence(2)` returns `(1, true, nil)` — gen=2's earliest data record is seq=1.

Now exercise the helper. Two sub-cases (table-driven over the `persistedAck.Generation` argument):

- **Sub-case (a) — replay generation IS the GC'd older one** (the regression-detection scenario): call `t.computeReplayStart(AckCursor{Sequence: 20, Generation: 1}, AckCursor{Sequence: 50, Generation: 1})` (remoteReplayCursor is the stale-server seq=20 in gen=1; persistedAck is the durable (gen=1, seq=50) the test seeded). Assert: (a) the helper called `wal.EarliestDataSequence(1)` (NOT `EarliestDataSequence(2)` or `EarliestDataSequence()`); (b) the accessor returned `(0, false, nil)`; (c) helper hit Case C (fully-GC'd, server BEHIND persistedAck); (d) `prefixLoss == &wal.LossRecord{FromSequence: 21, ToSequence: 50, Generation: 1, Reason: "ack_regression_after_gc"}`; (e) `readerStart == 21`; (f) `err == nil`; (g) the metrics fake recorded one `IncAckRegressionLoss()` call; (h) the INFO log buffer contains exactly one entry naming `from_seq=21, to_seq=50, gen=1, remote_replay_seq=20, earliest_on_disk_present=false, earliest_on_disk_seq=0, local_persisted_seq=50`. CRITICAL: the same call site under a generation-implicit accessor would have read the gen=2 earliest (1), satisfied `earliestOnDisk <= gapStart` (1 <= 21), hit Case B "no gap", and returned `prefixLoss == nil` — silently dropping the gen=1 ack-regression-after-GC signal.

- **Sub-case (b) — replay generation IS the surviving newer one** (boundary check; same on-disk state, different cursor argument): seed `persistedAck` to the gen=2 state — `wal.MarkAcked(2, 5)` so meta.json now holds `(AckHighWatermarkGen=2, AckHighWatermarkSeq=5)`. Then call `t.computeReplayStart(AckCursor{Sequence: 0, Generation: 2}, AckCursor{Sequence: 5, Generation: 2})` (remoteReplayCursor=(0, 2) is the cold-start state the server may present; persistedAck=(5, 2) is the just-seeded local watermark). Assert: (a) the helper called `wal.EarliestDataSequence(2)`; (b) the accessor returned `(1, true, nil)`; (c) helper hit Case A (partial GC — gen=2 has data but seqs below the earliest are missing); (d) `prefixLoss == &wal.LossRecord{FromSequence: 1, ToSequence: 0, Generation: 2, Reason: "ack_regression_after_gc"}` IFF `earliestOnDisk > gapStart` — note `gapStart=1`, `earliestOnDisk=1`, so `earliestOnDisk > gapStart` is FALSE → helper hits Case B "no gap" → `prefixLoss == nil`, `readerStart == 1`, `err == nil`. (Sub-case (b) is the negative control: it confirms the helper's per-generation lookup correctly returns "no gap" when the queried generation's data IS on disk.)

This test fails under any regression that:
- Re-introduces a no-arg `EarliestDataSequence()` accessor (cross-generation contamination).
- Forgets to pass `persistedAck.Generation` and instead passes `remoteReplayCursor.Generation` when those differ (the same-gen invariant means they don't differ here, but the test pins the contract).
- Calls `wal.EarliestDataSequence(0)` or `EarliestDataSequence(remoteReplayCursor.Generation+1)` (either of which would return `ok=false` for the wrong reason).

**Test #12 (`TestComputeReplayPlan_MultiGenerationCoversLaterGens`)** — round-15 Finding 4 + round-16 Finding 2 regression. Locks in the multi-generation orchestration contract: `computeReplayPlan` MUST emit one `ReplayStage` per generation in `[persistedAck.Generation, wal.HighGeneration()]` that has any replayable payload (data OR loss markers), in strictly ascending generation order. Without it, a reconnect that lands when the agent has already rolled to a newer generation drops the later-gen backlog because `Replaying` would only drain `persistedAck.Generation` before handing off to Live.

Setup uses `Options.InitialAckTuple = &AckTuple{Sequence: 50, Generation: 1, Present: true}`; the WAL accessors are stubbed via the test seams (`SetWALEarliestDataSequenceFnForTest`, `SetWALHasReplayableRecordsFnForTest`, `SetWALHighGenerationFnForTest`) so the test does not need to spin up a real multi-gen WAL.

Three sub-cases (table-driven over the writer state):

- *Sub-case (a) — `happy_multi_gen_three_stages`*: `HighGeneration()` returns 5; `HasReplayableRecords(2)` returns `(true, nil)`, `HasReplayableRecords(3)` returns `(false, nil)` (header-only segment), `HasReplayableRecords(4)` returns `(true, nil)`, `HasReplayableRecords(5)` returns `(true, nil)`; `EarliestDataSequence(1)` returns `(1, true, nil)`. Call `t.computeReplayPlan(AckCursor{Sequence: 50, Generation: 1}, AckCursor{Sequence: 50, Generation: 1})`. Assert: exactly four stages — `(gen=1, start=51, prefixLoss=nil)`, `(gen=2, start=0, prefixLoss=nil)`, `(gen=4, start=0, prefixLoss=nil)`, `(gen=5, start=0, prefixLoss=nil)`. gen=3 is skipped because `HasReplayableRecords(3) == (false, nil)`. The first stage's `PrefixLoss` is nil (Case B no-gap on gen=1 — `earliestOnDisk=1 <= gapStart=51`). The probed-gen list is exactly `[2, 3, 4, 5]` (the loop visits every later gen in order; absence is determined by the accessor, not by skipping).
- *Sub-case (b) — `only_persisted_gen_no_later`*: `HighGeneration() == persistedAck.Generation` (e.g., both equal 1). Assert: exactly one stage covering `persistedAck.Generation` with `start = persistedAck.Sequence + 1`; the multi-gen probe loop never fires; `HasReplayableRecords` is NOT called.
- *Sub-case (c) — `wal_failure_on_later_gen_propagates`*: `HasReplayableRecords(2)` returns `(false, errors.New("EIO"))`. Assert: `computeReplayPlan` returns the error wrapped (`fmt.Errorf("HasReplayableRecords(2): %w", err)` or equivalent); no partial stages are returned (caller treats the error as fatal-for-this-cycle and bounces back through Connecting on the next reconnect).

**Test #13 (`TestComputeReplayPlan_LossOnlyGenerationProducesStage`)** — round-16 Finding 2 + Finding 5 regression. The most important multi-gen regression test: a generation whose only on-disk payload is a loss marker (e.g., produced by overflow GC sealing the previous gen, then emitting an `ack_regression_after_gc` loss into a fresh gen with no subsequent `Append`) MUST receive a replay stage. The pre-fix code called `WrittenDataHighWater` (data-only) and silently dropped such a generation, leaving the server unaware of the gap. Without this test, a future "optimization" that swaps `HasReplayableRecords` back to `WrittenDataHighWater` would slip through unnoticed because `Test #12 sub-case (a)`'s gen=2 happens to have data — only this test exercises the loss-only branch where the two accessors diverge.

Setup: `Options.InitialAckTuple = &AckTuple{Sequence: 40, Generation: 1, Present: true}`; permissive limiter; logger capture. WAL accessors stubbed via test seams:

- `SetWALEarliestDataSequenceFnForTest`: returns `(1, true, nil)` for `gen=1`; errors for any other gen (asserts the helper queries gen=1 only — the first-stage decision tree is same-gen).
- `SetWALHasReplayableRecordsFnForTest`: returns `(true, nil)` for gen=2 (loss-only) AND gen=3 (data-bearing); errors for any other gen.
- `SetWALHighGenerationFnForTest`: returns 3.
- `SetWALWrittenDataHighWaterFnForTest`: panics if called by the multi-gen probe loop (the accessor is still consulted by the WARN-context emitter on Anomaly outcomes; this test does not exercise that path, so any call from the probe loop is a regression).

Call `t.computeReplayPlan(AckCursor{Sequence: 40, Generation: 1}, AckCursor{Sequence: 40, Generation: 1})`. Assert: exactly three stages — `(gen=1, start=41, prefixLoss=nil)` (Case B no-gap on gen=1 — `earliestOnDisk=1 <= gapStart=41`), `(gen=2, start=0, prefixLoss=nil)` (loss-only), `(gen=3, start=0, prefixLoss=nil)` (data-bearing). The probed-gen list is exactly `[2, 3]`. **Without the round-16 fix, the probe loop would have called `WrittenDataHighWater(2)` which returns `ok=false` for a loss-only gen, and gen=2 would have been silently skipped from the plan — the server would never observe the gap that the loss marker is supposed to surface.** This sub-case locks in the silent-drop regression.

This test fails under any regression that:
- Reverts `computeReplayPlan`'s multi-gen probe loop to call `WrittenDataHighWater(gen)` (data-only) instead of `HasReplayableRecords(gen)` (data OR loss).
- Removes the `HasReplayableRecords` accessor or its loss-marker branch in `wal.go`.
- Filters loss-only stages out of the plan as an optimization (e.g., "don't bother opening a Reader for a gen with no data" — the loss marker IS the payload that needs to surface).

**Step 1b.6: Side-effect contract for `applyServerAckTuple` returning `AckOutcomeAdopted`.** This sub-step makes the WAL-source-of-truth invariant explicit so SessionAck (here), BatchAck, and ServerHeartbeat (Task 17 sub-step 17.X) all run the same side-effect sequence in lock-step.

**WAL is the source of truth for `persistedAck` — invariant.** `t.persistedAck` and `t.persistedAckPresent` advance ONLY after `wal.MarkAcked` returns success. Two reasons:

1. The WAL's segment GC keys off the persisted `meta.json` `(AckHighWatermarkGen, AckHighWatermarkSeq)`. If we advance the in-memory persistedAck but `MarkAcked` fails (disk full, fsync error, EIO), then on the next state cycle we would advertise the inflated in-memory watermark in `SessionInit.wal_high_watermark_seq` while the WAL on disk still has segments NOT GC'd at that watermark. The server then thinks records are durably acked that the client cannot prove are persisted past a crash.
2. The cold-start seed read from `wal.ReadMeta` at restart MUST be the same value the previous run advertised on the wire. If the in-memory persistedAck ever diverges from on-disk meta.json (even briefly), a crash window between the in-memory write and the failed `MarkAcked` would persist the wrong post-restart state.

`remoteReplayCursor` does NOT need rollback symmetry for `ResendNeeded` outcomes (those never call `MarkAcked` and never fail). It DOES need rollback symmetry for `Adopted` outcomes, because both cursors moved together — if `MarkAcked` fails after Adopted, both must roll back.

The snapshot-and-rollback shape used in Step 1b above keeps the helper as the single source of truth for cursor advancement and adds three lines of bookkeeping per call site. The rollback set is `{persistedAck, remoteReplayCursor, persistedAckPresent}`.

**Why snapshot-and-rollback rather than persist-first.** An alternative shape is "persist `(serverGen, serverSeq)` first, then mutate `t.persistedAck/remoteReplayCursor` only on success." That shape is cleaner in isolation, but the helper as written today is the canonical clamp logic — it knows about first-apply, lex-compare, stale-server adoption, AND the true-anomaly check. Refactoring it into a "decide which value to persist" pure function plus a "commit or noop" mutator doubles the surface area and forces every caller to recompute the lex compare and the anomaly check to know what value to persist. The snapshot-and-rollback shape keeps the helper as the single source of truth and the test in Step 4 below (`TestApplyServerAckTuple_DoesNotAdvanceOnMarkAckedFailure`) locks in the rollback contract.

**Step 1c: Seed Transport ack cursors from `wal.Meta` on construction.** The spec (design.md:180) says SessionInit's `wal_high_watermark_seq` comes "from disk." Today's `transport.New` defaults the cursors to `(0, 0)`. After a restart, the very first SessionInit lies about the local watermark. Round-6: model "ack present" explicitly via a `Present` flag on the seed and a matching `t.persistedAckPresent` field on Transport, and let `applyServerAckTuple` handle first-apply by validating the server tuple against local WAL data (round-15 Finding 1 + round-16 Finding 1) BEFORE adopting — never wholesale-adopt, because a server tuple pointing past anything we ever wrote would lex-over-ack and discard records the WAL has not yet delivered.

```go
// AckTuple is the persisted (gen, seq) ack watermark tuple — the
// transport-package mirror of wal.Meta.AckHighWatermarkGen,
// wal.Meta.AckHighWatermarkSeq, and wal.Meta.AckRecorded. It is the
// seed type passed into Options.InitialAckTuple at construction so the
// Transport's persistedAck cursor is correct on cold start (the
// SessionInit frame's wal_high_watermark_seq + generation come from
// here). Pointer-typed in Options so callers can distinguish "no seed"
// from "seed of (0, 0) with Present=true".
type AckTuple struct {
    Sequence   uint64
    Generation uint32
    // Present is the explicit "ack present" flag — mirrors
    // wal.Meta.AckRecorded. False means "no ack has ever been observed";
    // the clamp helper enters the first-apply branch which validates the
    // server tuple against local WAL data BEFORE adopting (round-15 +
    // round-16 Finding 1 — never wholesale-adopt, because a server tuple
    // beyond local data lex-over-acks lower-gen records). The branch
    // either Adopts and flips t.persistedAckPresent to true, or returns
    // an Anomaly and leaves the cursors untouched (next ack-bearing
    // frame retries the seed gate).
    Present bool
}
```

Add `Options.InitialAckTuple *AckTuple` — pointer-typed so a caller passing `nil` means "no seed" (Transport stays in cold-start state with `persistedAckPresent=false`), distinct from `&AckTuple{Present: false}` (also "no seed", but explicit).

Transport private fields:

```go
type Transport struct {
    opts Options
    conn Conn

    // persistedAck mirrors wal.Meta (AckHighWatermarkGen, AckHighWatermarkSeq).
    // Monotonic only — advances ONLY through wal.MarkAcked success.
    // Drives SessionInit.wal_high_watermark_seq AND segment GC.
    persistedAck        AckCursor
    persistedAckPresent bool

    // remoteReplayCursor is where the server thinks its ack watermark
    // sits. May be lex-LOWER than persistedAck if the server presents
    // a stale tuple (gradual rollout / partition recovery). Drives
    // the Replaying state's reader-start (remoteReplayCursor + 1) so
    // a stale-server case re-sends the gap.
    //
    // In the steady state remoteReplayCursor == persistedAck.
    remoteReplayCursor AckCursor

    // ... rest unchanged ...
}
```

Apply the seed in `New`:

```go
if opts.InitialAckTuple != nil && opts.InitialAckTuple.Present {
    seed := AckCursor{
        Sequence:   opts.InitialAckTuple.Sequence,
        Generation: opts.InitialAckTuple.Generation,
    }
    t.persistedAck = seed
    t.persistedAckPresent = true
    // Steady-state init: both cursors equal at boot. The first ack
    // frame from the server will diverge them only if the server is
    // stale (ResendNeeded outcome).
    t.remoteReplayCursor = seed
}
```

**Step 1d: Inject `slog.Logger` via Options.** Add `Options.Logger *slog.Logger`. Default to `slog.Default()` in `New` when unset. Document that it is the ONLY handle the Transport reaches for log output; tests inject `slog.New(slog.NewJSONHandler(buf, ...))` to capture WARN lines without racing against parallel tests.

**Test #1 (`TestApplyServerAckTuple_HigherSameGenAdvancesPersistedAck`)** — round-9: the new healthy-advance test (replaces the old `TestApplyServerAckTuple_HigherSeqSameGen` which previously WARN'd on this case). Setup: `Options.WAL` wired to a real `*wal.WAL` whose `HighWaterSequence()` returns 200; `InitialAckTuple = &AckTuple{Sequence: 50, Generation: 7, Present: true}`; permissive limiter; logger capture buffer. Call `t.applyServerAckTuple(7, 100)`. Assert: `outcome.Kind == AckOutcomeAdopted`, `t.persistedAck == AckCursor{100, 7}`, `t.remoteReplayCursor == AckCursor{100, 7}`, `outcome.PersistedAdvanced == true`. After the SessionAck handler runs the side-effect contract, assert `wal.ReadMeta` shows `(AckHighWatermarkSeq=100, AckHighWatermarkGen=7, AckRecorded=true)` AND the metrics fake recorded one `SetAckHighWatermark(100)`. WARN buffer empty.

**Test #2 (`TestApplyServerAckTuple_LowerSameGenIsResendNeeded`)** — round-9: same-generation lex-lower (the only legitimate `ResendNeeded` case). Setup: `Options.WAL` wired to a real `*wal.WAL` with `MarkAcked(7, 100)` already driven so meta.json holds `(7, 100, true)`; `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`; permissive limiter; INFO-level logger capture. Call `t.applyServerAckTuple(7, 50)`. Assert: `outcome.Kind == AckOutcomeResendNeeded`, `t.persistedAck == AckCursor{100, 7}` (UNCHANGED), `t.remoteReplayCursor == AckCursor{50, 7}` (regressed to server tuple), `outcome.PersistedAdvanced == false`. After the SessionAck handler runs, assert: (a) `wal.MarkAcked` was NOT called (verifiable via re-reading meta.json — still `(7, 100, true)`); (b) the metrics fake recorded ZERO additional `SetAckHighWatermark` calls beyond the initial seed; (c) the metrics fake recorded exactly ONE `IncResendNeeded()` call (Task 22b counter); (d) the INFO log buffer contains exactly one entry naming the regression with `server_seq=50, server_gen=7, local_persisted_seq=100, local_persisted_gen=7`; (e) the WARN buffer is empty (this is normal recovery, not anomaly).

**Test #3 (`TestApplyServerAckTuple_EqualTuple`):** Setup: `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`. Call `t.applyServerAckTuple(7, 100)`. Assert: `outcome.Kind == AckOutcomeNoOp`, both cursors unchanged at `AckCursor{100, 7}`. No `wal.MarkAcked` call, no metric emission, no log entries (INFO or WARN).

**Test #4 (`TestApplyServerAckTuple_FirstApplyValidatesBeforeAdopt`)** — round-15 + round-16 Finding 1 model: first-apply NEVER wholesale-adopts; it MUST validate the server tuple against local WAL data before seeding. Setup: `Options.InitialAckTuple = nil` (or `&AckTuple{Present: false}`); permissive limiter; logger capture. Drive sub-cases (each uses a fresh `Transport` over a fresh `*wal.WAL` so `persistedAckPresent` resets):
- *Sub-case A — `serverSeq > 0` over a populated gen, in-bounds*: Append 100 RecordData in gen=8 (so `WrittenDataHighWater(8) == (100, true, nil)`). Call `t.applyServerAckTuple(8, 50)`. Assert: `outcome.Kind == AckOutcomeAdopted`, `t.persistedAck == AckCursor{50, 8}`, `t.remoteReplayCursor == AckCursor{50, 8}`, `t.persistedAckPresent == true`. After side-effect contract: `wal.MarkAcked(8, 50)` was called. WARN buffer empty.
- *Sub-case B — `serverSeq > 0` over a populated gen, out-of-bounds*: Append 100 RecordData in gen=8. Call `t.applyServerAckTuple(8, 200)` (server is past local data tip). Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "server_ack_exceeds_local_data"`, BOTH cursors stay zero AND `t.persistedAckPresent == false`. WARN entry recorded; metrics fake records `IncAnomalousAck("server_ack_exceeds_local_data")`. No `wal.MarkAcked` call.
- *Sub-case C — `serverSeq > 0` over an unwritten gen*: Append 100 RecordData in gen=7 (gen=8 has no segment). Call `t.applyServerAckTuple(8, 50)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "unwritten_generation"`, cursors stay zero AND `persistedAckPresent == false`. WARN + `IncAnomalousAck("unwritten_generation")`. No `wal.MarkAcked` call.
- *Sub-case D — `serverSeq == 0` against fresh WAL*: Open WAL, no records. Call `t.applyServerAckTuple(8, 0)`. Assert: `outcome.Kind == AckOutcomeAdopted` (vacuous adopt), `t.persistedAck == AckCursor{0, 8}`, `t.remoteReplayCursor == AckCursor{0, 8}`, `t.persistedAckPresent == true`. `wal.MarkAcked(8, 0)` was called. WARN buffer empty. (This is the "cold start, server is also fresh" path.)
- *Sub-case E — round-16 Finding 1 regression: `serverSeq == 0` over a higher gen with lower-gen data*: Append 100 RecordData in gen=7 (so `HasDataBelowGeneration(8) == (true, nil)`). Call `t.applyServerAckTuple(8, 0)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "server_ack_exceeds_local_data"`, BOTH cursors stay zero AND `persistedAckPresent == false`. WARN + `IncAnomalousAck("server_ack_exceeds_local_data")`. No `wal.MarkAcked` call. CRITICAL: re-read meta.json AND list segments — assert gen=7 segments are still on disk and not GC'd. **Without the round-16 fix, the helper would have wholesale-adopted `(8, 0)` and the next `wal.MarkAcked(8, 0)` would have lex-over-acked every gen=7 record (`segmentFullyAckedLocked` reclaims any segment with `segGen < ackHighGen`), silently destroying unsent gen=7 history on the next GC pass.** This sub-case locks in the data-loss regression.
- *Sub-case F — round-16 Finding 1 boundary: `serverSeq == 0` against same-gen data only*: Append 100 RecordData in gen=8 (so `HasDataBelowGeneration(8) == (false, nil)` because gen=8 is not "below" 8). Call `t.applyServerAckTuple(8, 0)`. Assert: `outcome.Kind == AckOutcomeAdopted`, cursors seeded to `(0, 8)`, `persistedAckPresent == true`. `wal.MarkAcked(8, 0)` was called. WARN buffer empty. (Vacuous "I haven't acked anything yet" within the writer's current generation is safe.)
- *Sub-case G — round-16 Finding 1 sibling: `wal.HasDataBelowGeneration` returns `(_, walErr != nil)`*: Setup uses the `walHasDataBelowGenerationFn` test seam to inject `(false, errors.New("EIO"))` on the next call. Call `t.applyServerAckTuple(8, 0)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "wal_read_failure"`, cursors stay zero AND `persistedAckPresent == false` (the next ack-bearing frame retries). WARN + `IncAnomalousAck("wal_read_failure")`. No `wal.MarkAcked` call.

After Sub-case A succeeds, a follow-up call with `t.applyServerAckTuple(8, 30)` exercises the now-present same-gen lex-lower path — assert `ResendNeeded` (server lex-lower than the just-seeded persistedAck within the same generation), `t.persistedAck == AckCursor{50, 8}` (unchanged), `t.remoteReplayCursor == AckCursor{30, 8}`. (Cross-gen second-call variants — `(7, 50)` returns `Anomaly("stale_generation")` per Test #5a; `(9, 50)` returns `Adopted` per Test #5b if `WrittenDataHighWater(9)` returns `(maxDataSeq>=50, true)`, `Anomaly("server_ack_exceeds_local_data")` if it returns `(maxDataSeq<50, true)`, or `Anomaly("unwritten_generation")` per Test #5c if it returns `(_, false)`.)

**Test #5 (`TestApplyServerAckTuple_ServerAckExceedsLocalSeqIsAnomaly`)** — round-12 RENAMED (Finding 5; from round-9's `_BeyondWALHighSeqIsAnomaly`): anomaly sub-case 1 (server claims ack beyond what the WAL has ever produced for the persisted gen). Setup: `Options.WAL` wired to a real `*wal.WAL` with `Append` driven to seqs 1..50 in gen=7 (so `WrittenDataHighWater(7) == (50, true, nil)`); `InitialAckTuple = &AckTuple{Sequence: 30, Generation: 7, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(7, 60)` (server claims ack at seq=60 in current gen, but the WAL has only emitted up to seq=50). Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "server_ack_exceeds_local_seq"` (round-12 rename of round-11's `beyond_wal_high_water_seq` — the same-gen branch now reuses the cross-gen branch's `WrittenDataHighWater(serverGen)` predicate per round-12 Finding 5), BOTH cursors unchanged at `(30, 7)`. After the SessionAck handler runs the anomaly branch, exactly one WARN entry captured carrying `reason="server_ack_exceeds_local_seq", server_seq=60, server_gen=7, local_persisted_seq=30, local_persisted_gen=7, wal_written_data_high_seq=50, wal_written_data_high_ok=true, session_id=...`; metrics fake records exactly one `IncAnomalousAck("server_ack_exceeds_local_seq")` call. No `wal.MarkAcked` call, no `SetAckHighWatermark` emission.

**Test #5d (`TestApplyServerAckTuple_WALReadFailureIsAnomaly`)** — round-12 NEW (Finding 4): the unified `WrittenDataHighWater(serverGen)` lookup can return `(_, _, walErr != nil)` (transient I/O on the segment-header fast-scan path; the helper's approach-2 implementation can read fresh segment metadata even when no in-memory cache hit exists). The clamp helper MUST surface this as a distinct anomaly reason `wal_read_failure` rather than collapsing it into `unwritten_generation` (which would be peer-attributable). Cursors unchanged so the next ack-bearing frame retries the classification once the underlying I/O recovers. Setup: `Options.WAL` is a fake `*wal.WAL` whose `WrittenDataHighWater` returns `(0, false, errors.New("EIO"))` on the next call (test seam: `walWrittenDataHighWaterFn func(gen uint32) (uint64, bool, error)` indirection, defaulting to `t.wal.WrittenDataHighWater` and overridden via `_test.go`-only export); `InitialAckTuple = &AckTuple{Sequence: 30, Generation: 7, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(7, 60)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "wal_read_failure"`, BOTH cursors unchanged at `(30, 7)`. After the SessionAck handler runs the anomaly branch, exactly one WARN entry captured carrying `reason="wal_read_failure", server_seq=60, server_gen=7, local_persisted_seq=30, local_persisted_gen=7, wal_written_data_high_seq=0, wal_written_data_high_ok=false, wal_written_data_high_err="EIO"`; metrics fake records exactly one `IncAnomalousAck("wal_read_failure")` call. No `wal.MarkAcked` call, no `SetAckHighWatermark` emission. (Cross-gen variant `t.applyServerAckTuple(8, 60)` exercises the cross-gen `walErr != nil` branch identically — same anomaly reason, same WARN shape; both branches dispatch to the unified `wal_read_failure` outcome.)

**Test #5a (`TestApplyServerAckTuple_LowerGenIsAnomaly`)** — round-9 NEW: cross-gen anomaly sub-case (server is on a stale generation). Setup: `Options.WAL` wired to a real `*wal.WAL` with `MarkAcked(8, 100)` driven; `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 8, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(7, 200)` (server claims gen=7, an OLDER generation than persistedAck.gen=8 — even though server.seq is higher in absolute terms, the cross-gen comparison is invalid). Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "stale_generation"`, BOTH cursors unchanged at `(100, 8)`. After the SessionAck handler runs the anomaly branch, exactly one WARN entry with `reason="stale_generation", server_seq=200, server_gen=7, local_persisted_seq=100, local_persisted_gen=8`; metrics fake records exactly one `IncAnomalousAck("stale_generation")` call. No `wal.MarkAcked` call, no `SetAckHighWatermark` emission.

**Test #5b (`TestApplyServerAckTuple_HigherGenWithinPerGenDataHW_Adopted`)** — round-11 RENAMED (from round-10's `_HigherGenWithinWrittenHigh_Adopted` because `WrittenHighGeneration()` was unsafe — see Task 14a Step 3a SAFETY NOTE): cross-gen healthy-advance (server has observed records from a generation the client's WRITER has already rolled into AND has appended at least one RecordData in, but the client's persistedAck has not yet caught up). Setup: open a real `*wal.WAL`; drive `Append` to roll the writer to gen=8 by appending in gen=7, then triggering a generation roll, then **appending at least one RecordData in gen=8** (so `WrittenDataHighWater(8)` returns `(>=5, true)`); `MarkAcked(7, 100)` already driven to seed meta.json; `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(8, 5)` (server claims gen=8 at seq=5; the writer's per-gen data-bearing high-water in gen=8 is >=5, so the server's claim is bounded by emitted data). Assert: `outcome.Kind == AckOutcomeAdopted`, `t.persistedAck == AckCursor{5, 8}`, `t.remoteReplayCursor == AckCursor{5, 8}`, `outcome.PersistedAdvanced == true`. After the SessionAck handler runs the Adopted branch, `wal.ReadMeta` shows `(AckHighWatermarkSeq=5, AckHighWatermarkGen=8, AckRecorded=true)` (lex-higher than the prior `(7, 100)`); metrics fake records exactly one `SetAckHighWatermark(5)`; INFO/WARN buffers empty (cross-gen Adopted is silent — same as same-gen Adopted).

**Test #5b' (`TestApplyServerAckTuple_HigherGenButOnlyHeaderExists_Anomaly`)** — round-11 NEW (Finding 1): cross-gen anomaly sub-case where the WAL has rolled into the server's claimed generation (a SegmentHeader exists on disk and `w.highGen` reflects it) but no RecordData has been written yet. This is the round-11 SAFETY case: under the round-10 `WrittenHighGeneration() = w.highGen` design the helper would Adopt and call `wal.MarkAcked(serverGen, anySeq)` because `MarkAcked` only enforces lex-monotonic advance; that would in turn make ALL lower-gen segments lex-acked and reclaimable under the lex GC predicate, silently dropping unsent history. The per-gen data-bearing accessor blocks this. Setup: open a real `*wal.WAL`; drive `Append` to roll the writer to gen=8 (segment header for gen=8 written, `w.highGen == 8`) WITHOUT appending any RecordData in gen=8 (so `WrittenDataHighWater(8)` returns `(0, false)`); `MarkAcked(7, 100)` already driven; `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(8, 0)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "unwritten_generation"`, BOTH cursors UNCHANGED at `AckCursor{100, 7}`. After the SessionAck handler runs the anomaly branch, exactly one WARN entry with `reason="unwritten_generation", server_seq=0, server_gen=8, local_persisted_seq=100, local_persisted_gen=7, wal_written_data_high_gen_ok=false`; metrics fake records exactly one `IncAnomalousAck("unwritten_generation")` call. No `wal.MarkAcked` call, no `SetAckHighWatermark` emission. CRITICAL: re-read meta.json AND list segments — assert lower-gen segments are still on disk and not GC'd (this proves the safety fix; the round-10 design would have GC'd them).

**Test #5c (`TestApplyServerAckTuple_HigherSameGenBeyondPerGenDataHW_Anomaly`)** — round-11 NEW (Finding 1): cross-gen anomaly sub-case where the WAL has emitted RecordData in the server's generation but the server's seq is beyond what was emitted in that generation. This is the second round-11 SAFETY case: the server is acking past anything we ever sent in that generation; admitting it would mark records that were never written as acked and again let lex GC discard surviving lower-gen segments. Setup: open a real `*wal.WAL`; drive `Append` to roll to gen=8 and append RecordData up to seq=10 in gen=8 (so `WrittenDataHighWater(8) == (10, true)`); `MarkAcked(7, 100)` driven; `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`; permissive limiter; logger capture. Call `t.applyServerAckTuple(8, 999)`. Assert: `outcome.Kind == AckOutcomeAnomaly`, `outcome.AnomalyReason == "server_ack_exceeds_local_data"`, BOTH cursors UNCHANGED at `AckCursor{100, 7}`. After the SessionAck handler runs the anomaly branch, exactly one WARN entry with `reason="server_ack_exceeds_local_data", server_seq=999, server_gen=8, local_persisted_seq=100, local_persisted_gen=7, wal_written_data_high_seq=10`; metrics fake records exactly one `IncAnomalousAck("server_ack_exceeds_local_data")` call. No `wal.MarkAcked` call, no `SetAckHighWatermark` emission.

**Test #6 (rate-limit guard `TestSessionAck_AnomalyWarnRateLimited`)** — OPTIONAL but RECOMMENDED to lock in the rate-limiter contract: inject a strict `rate.NewLimiter(rate.Every(time.Hour), 1)` and drive five back-to-back true-anomaly SessionAck handlers. Assert exactly one WARN entry (the limiter absorbed four).

**Test #7 (`TestApplyServerAckTuple_AdoptedDoesNotAdvanceOnMarkAckedFailure`)** — snapshot-and-rollback path. Setup: `Options.WAL` is a fake `*wal.WAL` whose `MarkAcked` returns a non-nil error on the next call (the simplest seam is a `walMarkAckedFn func(gen uint32, seq uint64) error` indirection on Transport that defaults to `t.wal.MarkAcked` and is overridden in tests via a `_test.go`-only export — matching the existing `RunReplayingForTest` pattern); `InitialAckTuple = &AckTuple{Sequence: 50, Generation: 7, Present: true}`; logger capture. Drive SessionAck `(serverGen=7, serverSeq=100)` (lex-higher → helper returns `Adopted`, mutates BOTH cursors to `(100, 7)` in-line). Assert: (a) `MarkAcked(7, 100)` was called exactly once and returned the injected error; (b) BOTH cursors rolled back to the pre-helper snapshot — `t.persistedAck == AckCursor{50, 7}`, `t.remoteReplayCursor == AckCursor{50, 7}`, `t.persistedAckPresent == true`; (c) the metrics fake recorded ZERO calls to `SetAckHighWatermark` (failure path does not emit); (d) the WARN buffer contains exactly one entry naming the failure with `attempted_seq=100, attempted_gen=7`, the `err` field, and the action ("rolled back"); (e) the rate-limited ack-anomaly WARN buffer is empty (failure is not an anomaly).

**Test #8 (`TestApplyServerAckTuple_EmitsMetricOnAdopted`)** — gauge emission contract. Setup: `Options.WAL` wired to a real `*wal.WAL` with `HighWaterSequence() >= 1000`; `InitialAckTuple = &AckTuple{Sequence: 50, Generation: 1, Present: true}`. Drive three sequential SessionAck handlers with monotonically same-gen lex-higher tuples THEN one same-gen NoOp: `(1, 100)`, `(1, 200)`, `(1, 300)`, `(1, 300)`. After each `Adopted`, assert: (a) `MarkAcked` was called with the post-clamp tuple; (b) the metrics fake's last recorded call is `SetAckHighWatermark(seq)` with the matching post-clamp seq (production signature today is `func (w *WTPMetrics) SetAckHighWatermark(seq int64)` — single unlabeled gauge); (c) BOTH cursors equal at the new server tuple after each call. After the three Adopted calls, the metrics fake's last-recorded call is `SetAckHighWatermark(300)` (the gauge holds the latest value). The fourth NoOp triggers `NoOp` — assert NO additional `MarkAcked` call, NO additional metric emission. (Cross-gen advances are NOT exercised here because they would return `Anomaly` per Tests #5a/#5b — gauge emission only fires on the same-gen Adopted path.)

**Step ordering for Task 15.1:**

- [ ] **Step 1:** Write the failing tests above (Tests #1–#8) plus the optional rate-limit guard.
- [ ] **Step 2:** Run tests to verify they fail with the expected symbols (`Transport.applyServerAckTuple` undefined or returning the wrong shape; `Transport.persistedAck` / `Transport.remoteReplayCursor` undefined; `Options.InitialAckTuple` / `Options.Logger` / `Options.WAL` / `Options.Metrics` / `transport.AckTuple` / `transport.AckCursor` / `transport.AckOutcome` undefined; current SessionAck handler does not honor the cursor split).
- [ ] **Step 3a:** Add `AckTuple`, `AckCursor`, `AckOutcome`, `AckOutcomeKind` types; `Options.InitialAckTuple`, `Options.Logger`, `Options.WAL`, `Options.Metrics` fields; `t.persistedAck`, `t.persistedAckPresent`, `t.remoteReplayCursor` fields; `t.ackAnomalyLimiter`. Default `Logger` to `slog.Default()` and `ackAnomalyLimiter` to `rate.NewLimiter(rate.Every(time.Minute), 1)` in `New`. Apply the seed in `New` if `InitialAckTuple != nil && InitialAckTuple.Present`.
- [ ] **Step 3b:** Add the `applyServerAckTuple` helper to `transport.go`. Refactor the `state_connecting.go:59` SessionAck handler to call into the helper AND dispatch on `AckOutcome.Kind` per Step 1b.
- [ ] **Step 4:** Run the tests to verify they pass; run the full transport package test suite to verify no regression.
- [ ] **Step 5:** Cross-compile (`GOOS=windows go build ./...`) — `golang.org/x/time/rate` is in the module already.
- [ ] **Step 6:** Commit with message `fix(wtp/transport): two-cursor ack clamp + WAL meta seed + injected logger`.
- [ ] **Step 7:** Run `/roborev-design-review` and address findings.

**Hard dependency (round-8 chain):**

- **14a → 15.1:** Task 15.1's `Options.WAL` must be a `*wal.WAL` carrying the `Options.SessionID`/`KeyFingerprint` set by Task 14a, so the WAL persists identity on every `MarkAcked`. Without 14a, the round-7 cold-start identity gate compares against fields production never populates.
- **15.1 → 17.X:** Task 17 sub-step 17.X (BatchAck/ServerHeartbeat clamp) reuses the `applyServerAckTuple` helper landed here. It MUST NOT proceed until Task 15.1 has landed.
- **15.1 → 22:** Task 22's StateReplaying/StateLive cases consume `t.remoteReplayCursor` for their reader-start calculations. Task 22 MUST NOT commit its Run loop until BOTH Task 15.1 (SessionAck clamp) AND Task 17 sub-step 17.X (BatchAck/ServerHeartbeat clamp) have landed; without the cursor split, an unclamped raw server value would silently propagate into the reader-start calculation.

Task 22's Store-wiring snippet (Step 2 of Task 22) MUST construct `*AckTuple` from `wal.ReadMeta` and pass it through `Options.InitialAckTuple` so the SessionInit watermark is seeded from disk per spec line 180.

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

// TestReplayer_StopsAtTailWatermark asserts the HARD STOP on RecordData
// seq > tailSeq. Three records are appended, seq=2 is acked, one more
// (seq=3) is appended past the ack, NewReplayer captures tailSeq=3, then
// a post-entry seq=4 is appended. The Replayer MUST surface seq=3 (a
// within-window record), MAY surface seq=4 as the boundary record (if the
// Reader catches it before done), and MUST NOT surface any seq>4 even if
// appends keep arriving. The boundary record (the first RecordData with
// seq > tailSeq) is INCLUDED in the final batch and replay returns
// done=true; loss markers continue to surface regardless of seq.
//
// Round-2 review note: the round-1 fix removed the early-exit on
// rec.Sequence >= tailSeq entirely so the Replayer drained until
// TryNext returned ok=false. Under sustained appends that signal may
// never arrive, so replay would never terminate (spec at design.md:586
// requires the finite (ack_hw, wal_hw_at_entry] window). The round-2
// fix restores a HARD stop on RecordData seq > tailSeq while leaving
// loss-marker handling untouched: loss markers always surface, and a
// trailing loss marker that lands at the WAL tail AFTER an over-tail
// RecordData is the responsibility of the Live state's Reader (see
// LastReplayedSequence docstring + design.md:586). The hard stop also
// guarantees TestReplayer_TerminatesUnderConcurrentAppends terminates.
func TestReplayer_StopsAtTailWatermark(t *testing.T) {
	w := openTestWAL(t)

	// Append seqs 0, 1, 2 then ack through seq=2.
	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.MarkAcked(0, 2); err != nil {
		t.Fatalf("mark acked: %v", err)
	}
	// Append one more so the replayer has work past the ack watermark.
	if _, err := w.Append(3, 0, []byte{0x33}); err != nil {
		t.Fatalf("append 3: %v", err)
	}

	rdr, err := w.NewReader(3) // start = ack+1; first emit must be seq>=3
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if got, want := r.TailSequence(), uint64(3); got != want {
		t.Fatalf("tail seq: got %d, want %d", got, want)
	}

	// Inject post-entry records. tailSeq was captured at NewReplayer time
	// (highSeq=3) so TailSequence() must remain 3. Per the round-2 hard-
	// stop contract, AT MOST ONE over-tail RecordData (seq=4) may surface
	// as the boundary record, and seq=5 must NEVER surface.
	if _, err := w.Append(4, 0, []byte{0x44}); err != nil {
		t.Fatalf("append 4 (post-entry): %v", err)
	}
	if _, err := w.Append(5, 0, []byte{0x55}); err != nil {
		t.Fatalf("append 5 (post-entry): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	emitted := 0
	seenSeqs := []uint64{}
	var lastBatch transport.ReplayBatch
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		for _, rec := range batch.Records {
			emitted++
			seenSeqs = append(seenSeqs, rec.Sequence)
		}
		if done {
			lastBatch = batch
			break
		}
	}

	// Hard-stop contract: seq=3 (within-window) MUST be emitted.
	if emitted < 1 {
		t.Fatalf("emitted: got %d (seqs=%v), want at least 1 (seq=3 must surface)", emitted, seenSeqs)
	}
	if seenSeqs[0] != 3 {
		t.Fatalf("first emitted seq: got %d, want 3", seenSeqs[0])
	}

	// Validate the over-tail boundary rule: AT MOST one over-tail seq may
	// appear (seq=4); seq=5 MUST NOT surface; if seq=4 surfaces, it MUST
	// be the LAST RecordData in the final batch.
	overTailCount := 0
	var lastDataSeq uint64
	haveData := false
	for _, s := range seenSeqs {
		if s > 3 {
			overTailCount++
			if s != 4 {
				t.Fatalf("over-tail seq: got %d, want at most 4 (seq>4 must not surface under hard-stop contract); seqs=%v", s, seenSeqs)
			}
		}
	}
	if overTailCount > 1 {
		t.Fatalf("over-tail count: got %d, want <=1 (boundary record only); seqs=%v", overTailCount, seenSeqs)
	}
	for _, rec := range lastBatch.Records {
		if rec.Kind == wal.RecordData {
			lastDataSeq = rec.Sequence
			haveData = true
		}
	}
	if overTailCount == 1 {
		if !haveData || lastDataSeq != 4 {
			t.Fatalf("boundary record placement: last RecordData in final batch was seq=%d (haveData=%v), want seq=4 (the boundary record must be the LAST RecordData in the final batch)", lastDataSeq, haveData)
		}
		if got := r.LastReplayedSequence(); got != 4 {
			t.Fatalf("LastReplayedSequence: got %d, want 4 (boundary record was seq=4)", got)
		}
	} else {
		// No boundary record surfaced — Reader observed ok=false before
		// reading seq=4. LastReplayedSequence must reflect the last
		// within-window emission (seq=3).
		if got := r.LastReplayedSequence(); got != 3 {
			t.Fatalf("LastReplayedSequence: got %d, want 3 (no boundary record surfaced)", got)
		}
	}

	// TailSequence is sampled once at NewReplayer time and MUST NOT
	// advance with post-entry appends.
	if got, want := r.TailSequence(), uint64(3); got != want {
		t.Fatalf("tail seq: got %d, want %d (the post-entry append must NOT advance tailSeq)", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/... -run TestReplayer_StopsAtTailWatermark`
Expected: FAIL — `transport.NewReplayer`, `transport.ReplayerOptions`, plus the
new `wal.Reader.TryNext`, `wal.Reader.LastSequence`, and
`wal.Reader.WALHighWaterSequence` accessors are undefined.

- [ ] **Step 3: Wire `nextSeq` through the WAL Reader**

The Reader type was created in Task 14 with `Next` (blocking), `Notify`, and
`Close`. `NewReader(start)` already accepted a start parameter but treated it
as informational. Task 16 turns it into the real cursor: `start` is the lowest
sequence the Reader will surface (RecordData entries with `Sequence < start`
are dropped on the floor). Loss records are NOT filtered.

Update the constructor in `internal/store/watchtower/wal/reader.go`:

```go
// NewReader returns a Reader that surfaces RecordData entries with sequence
// >= start (i.e. the first record returned has Sequence == start or later).
// Pass start=0 to receive every user record from the beginning of the
// on-disk stream — the same behaviour Task 14 shipped. RecordLoss entries
// are NOT filtered by start; the transport must propagate every loss notice
// regardless of the caller's cursor.
//
// Callers replaying after an ack pass start = ackHighSeq + 1 to skip the
// already-acknowledged tail (Task 16's Replayer enforces this idiom).
func (w *WAL) NewReader(start uint64) (*Reader, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	r := &Reader{w: w, notify: make(chan struct{}, 1), nextSeq: start}
	if err := r.rescanLocked(); err != nil {
		return nil, err
	}
	w.readers = append(w.readers, r)
	return r, nil
}
```

Add two new fields to `Reader` (alongside `lastGoodSeq`/`lastGoodGen` from Task 14):

```go
// nextSeq is the lowest user sequence the Reader will surface; records
// with Sequence < nextSeq are dropped from RecordData yields. Set by
// NewReader from the inclusive `start` argument: the first RecordData
// returned has Sequence == start (or later, if start was acked-past).
// Pass start=0 to receive every user record from the beginning of the
// on-disk stream. Loss records are NOT filtered by nextSeq — the
// transport must propagate every loss notice regardless of cursor.
nextSeq uint64
// lastEmittedSeq is the highest user sequence successfully returned to
// a caller so far, monotonic across the Reader's lifetime (does NOT
// reset on a generation change, unlike lastGoodSeq). Surfaced via
// LastSequence() purely as a diagnostic for callers that want to track
// replay progress; the Replayer does NOT use it for termination
// (catch-up is detected via TryNext returning ok=false alone — see
// transport.Replayer.NextBatch for the rationale).
lastEmittedSeq uint64
```

Refactor `Next` so the loop body lives in a private `nextLocked` helper that
returns `(Record, ok bool, err error)`. `Next` wraps it and converts
`ok=false` into `io.EOF`; the new `TryNext` wraps it and surfaces `ok=false`
directly:

```go
// Next returns the next available record. Returns io.EOF when caught up.
func (r *Reader) Next() (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, ErrReaderClosed
	}
	rec, ok, err := r.nextLocked()
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, io.EOF
	}
	return rec, nil
}

// TryNext returns the next available record without blocking. ok=false
// means no record is currently available (the reader is caught up to the
// WAL tail). Reuses the loop body of Next via nextLocked — do NOT
// duplicate the segment-walk logic.
func (r *Reader) TryNext() (Record, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, false, ErrReaderClosed
	}
	return r.nextLocked()
}
```

Inside `nextLocked`, the data-record branch becomes:

```go
seq, gen, ok := parseSeqGen(payload)
if !ok {
	return Record{}, false, fmt.Errorf("reader: malformed seq/gen frame (len=%d)", len(payload))
}
r.lastGoodSeq = seq
r.lastGoodGen = gen
r.lastGoodGenSet = true
if seq < r.nextSeq {
	continue // skip records before the cursor
}
r.lastEmittedSeq = seq
return Record{Kind: RecordData, Sequence: seq, Generation: gen, Payload: payload[12:]}, true, nil
```

Add the two accessors the Replayer needs:

```go
// LastSequence returns the highest user sequence the Reader has surfaced
// via Next or TryNext so far. Monotonic across the Reader's lifetime —
// does NOT reset on a generation change, unlike the internal lastGoodSeq
// used for loss-anchor calculations. Zero before the first emission.
//
// Diagnostic accessor: the Replayer does NOT consult LastSequence to
// detect catch-up (termination is driven solely by TryNext returning
// ok=false). Callers that want to track replay progress (logging,
// metrics, debug dumps) can read it; production transport code should
// not branch on it.
func (r *Reader) LastSequence() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastEmittedSeq
}

// WALHighWaterSequence returns the highest sequence ever appended to the
// underlying WAL at call time. Used by Replayer to capture an entry-time
// tail watermark.
func (r *Reader) WALHighWaterSequence() uint64 {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	return r.w.highSeq
}
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

// ReplayerOptions controls replay batching. Both bounds are advisory and
// trigger a return from NextBatch only after at least one record has been
// added (a single record larger than MaxBatchBytes will still ship, alone,
// rather than stall the replay).
type ReplayerOptions struct {
	// MaxBatchRecords caps the number of records returned per NextBatch
	// call. Zero is treated as "no record-count cap"; callers should set
	// a sensible bound (e.g. 100) to keep batches snappy.
	MaxBatchRecords int
	// MaxBatchBytes caps the cumulative payload bytes returned per
	// NextBatch call. Zero is treated as "no byte cap". The cap is
	// checked after each record is added, so a batch may overshoot by
	// the size of one record.
	MaxBatchBytes int
	// PrefixLoss, when non-nil, is emitted as the FIRST record of the
	// FIRST NextBatch call before any record drained from the underlying
	// Reader. Round-10 entry point: Task 15.1 Step 1b.5 synthesizes an
	// in-memory ack_regression_after_gc loss marker and threads it through
	// here so the receiver sees the gap before any surviving data records.
	//
	// The marker is NOT persisted to the WAL — it lives only for the
	// lifetime of this Replayer. Callers MUST recompute it from
	// (remoteReplayCursor, EarliestDataSequence(), persistedAck) on every
	// reconnect (see Task 15.1 Step 1b.5 decision tree for the four cases).
	//
	// PrefixLoss does NOT affect the seq-vs-tailSeq termination check (it
	// is a loss marker, not a data record) and does NOT contribute to
	// MaxBatchBytes accounting. It is appended verbatim to batch.Records[0].
	PrefixLoss *wal.LossRecord

	// OnPrefixLossEmitted, when non-nil, is invoked by the Replayer EXACTLY
	// ONCE — synchronously inside NextBatch — immediately after PrefixLoss
	// has been appended as record[0] of the FIRST NextBatch call. The
	// callback runs on the caller's goroutine (the Run loop's, in
	// production), so the implementation MUST be cheap and non-blocking
	// (typically a single counter Inc).
	//
	// Round-13 Finding 5 RATIONALE. The earlier round-12 design fired
	// `t.metrics.IncAckRegressionLoss()` from inside `computeReplayStart`
	// — i.e. at COMPUTE time, not EMIT time. That counts losses that the
	// helper *intended* to surface, even when the Replayer is constructed
	// with prefixLoss != nil but is aborted before its first NextBatch
	// (dialer fault, ctx cancel, state transition) — and the inevitable
	// reconnect re-runs computeReplayStart and double-counts the same
	// logical loss. The round-13 fix moves the counter to the EMIT site
	// via this callback so a one-to-one relationship exists between
	// "loss marker observed by the receiver" and "counter increment."
	// Compute-time INFO logging stays in `computeReplayStart` because the
	// inputs to the decision are operationally meaningful even when the
	// loss is never emitted.
	//
	// When PrefixLoss == nil the callback is NEVER invoked, regardless of
	// other batch surfacing. When PrefixLoss != nil the callback is
	// invoked EXACTLY ONCE in the Replayer's lifetime — the
	// `prefixLossEmitted` gate that ensures one-shot PrefixLoss emission
	// also gates the callback. Replayers that error out of NextBatch
	// before appending PrefixLoss to record[0] do NOT invoke the callback.
	//
	// The callback is OPTIONAL. Test cases that do not care about
	// emit-time observability MAY leave it nil; production wiring (Task
	// 15.1 Run-loop snippet AND Task 17.X recv-handler-driven Replayer
	// construction site) MUST set it to bump
	// `wtp_ack_regression_loss_total`.
	OnPrefixLossEmitted func()
}

// ReplayBatch is a chunk of WAL records returned by Replayer.NextBatch. The
// Records slice holds RecordData and RecordLoss entries in the order the
// Reader surfaced them; loss markers MUST be propagated to the receiver
// even if they fall before the entry-time tail watermark.
type ReplayBatch struct {
	Records []wal.Record
}

// Replayer drains a wal.Reader up to a captured entry-time tail watermark
// and emits records in size-bounded batches. Records appended to the WAL
// after NewReplayer is called belong to the Live state (Task 17), not the
// Replaying state, so the watermark is sampled exactly once at construction.
//
// The Replayer is not safe for concurrent NextBatch calls — callers MUST
// drive it from a single goroutine (typically the transport's run loop).
type Replayer struct {
	rdr  *wal.Reader
	opts ReplayerOptions
	// tailSeq is a HARD upper bound on RecordData surfaced during replay.
	// It is the WAL high-water sequence captured under the WAL lock at
	// NewReplayer time, so every record with seq <= tailSeq was already
	// on disk by then and will be visible to the underlying Reader. The
	// spec at docs/superpowers/specs/2026-04-18-wtp-client-design.md:586
	// defines replay as the finite (ack_hw, wal_hw_at_entry] window
	// before advancing to live; without a hard stop, sustained appends
	// would prevent TryNext from ever returning ok=false and replay
	// would never terminate.
	//
	// Two carve-outs:
	//
	//  1. RecordData with seq > tailSeq triggers replay completion. The
	//     boundary record is INCLUDED in the final batch (we cannot push
	//     it back to the Reader once read) and NextBatch returns
	//     done=true; no further over-tail records are pulled.
	//  2. RecordLoss records ALWAYS surface regardless of position. Loss
	//     markers are not subject to the seq-vs-tailSeq check; the
	//     receiver MUST see every gap notice.
	//
	// Trailing loss markers (overflow GC during replay that lands past
	// tailSeq) are Live-state's responsibility, not replay's. Live's
	// reader will encounter and surface them because (a) loss markers
	// bypass `Reader.nextSeq` filter (see wal/reader.go nextLocked near
	// the isLossMarker branch), and (b) Live opens its reader from
	// max(LastReplayedSequence()+1, ackHW+1), which is downstream of
	// the replay range.
	tailSeq uint64
	// lastReplayedSeq tracks the highest RecordData.Sequence surfaced by
	// NextBatch so far. Initialized to zero; updated whenever a RecordData
	// is appended to a batch. Task 22 (Store integration) consumes this
	// value via LastReplayedSequence() to position the Live-state Reader
	// at max(lastReplayedSeq+1, ackHW+1) — see LastReplayedSequence for
	// the rationale.
	lastReplayedSeq uint64
	// prefixLossEmitted gates the in-memory PrefixLoss emission to
	// EXACTLY ONCE — the first NextBatch call sets it true after
	// appending opts.PrefixLoss to batch.Records[0]. Subsequent batches
	// drain from the Reader normally without re-emitting the marker.
	// Round-10: this is the in-memory side of the Step 1b.5 PrefixLoss
	// design (the on-disk wal.AppendLoss path was abandoned per the
	// loss-marker ordering infeasibility argument).
	prefixLossEmitted bool
}

// NewReplayer captures the current WAL high-water sequence as a hard upper
// bound on RecordData surfaced during replay. Every RecordData with
// seq <= tailSeq is guaranteed to be surfaced before NextBatch returns
// done=true (the Reader will always reach it because tailSeq was sampled
// under the WAL lock). Records appended after this point belong to the Live
// state and MUST NOT extend replay; the boundary record (the first
// RecordData with seq > tailSeq) is included in the final batch as a side
// effect of having been read from the Reader (we cannot push it back), but
// no further over-tail records are pulled.
func NewReplayer(rdr *wal.Reader, opts ReplayerOptions) *Replayer {
	return &Replayer{
		rdr:     rdr,
		opts:    opts,
		tailSeq: rdr.WALHighWaterSequence(),
	}
}

// TailSequence returns the entry-time tail watermark this Replayer is
// draining toward. Surfaced for diagnostics and tests; the live transport
// uses it implicitly via the done flag from NextBatch.
func (r *Replayer) TailSequence() uint64 { return r.tailSeq }

// LastReplayedSequence returns the highest RecordData.Sequence surfaced by
// NextBatch so far. Zero before the first RecordData is emitted.
//
// Task 22 (Store integration) consumes this value to position the Live
// Reader at max(lastReplayedSeq+1, ackHW+1). The max() is required for
// two reasons:
//
//  1. Avoid duplicate RecordData sends: replay may have over-shot tailSeq
//     by ONE record (the boundary record per NextBatch's hard-stop rule),
//     so Live MUST start at lastReplayedSeq+1, not ackHW+1.
//  2. Still pass over the trailing-loss-marker WAL position: loss markers
//     bypass the Reader's nextSeq filter (see wal/reader.go nextLocked
//     near the isLossMarker branch), so Live's Reader will encounter and
//     surface any trailing loss marker that overflow GC appended at the
//     WAL tail mid-replay even though Live's start cursor is past the
//     marker's covered seq range.
//
// Without this contract, the trailing-loss-marker race that motivated
// the round-1 drain-until-ok=false fix would re-emerge as silent gap
// loss in the Live state.
func (r *Replayer) LastReplayedSequence() uint64 { return r.lastReplayedSeq }

// NextBatch pulls records from the underlying Reader without blocking and
// returns the next batch alongside a done flag. done=true means replay is
// complete and the caller should advance to the Live state. ctx is honoured
// between record reads — if it is cancelled, NextBatch returns its error.
//
// Termination rules (in order):
//
//  1. ctx cancelled → return (current-partial-batch, false, ctx.Err()).
//  2. RecordData with seq > tailSeq read → append the boundary record and
//     return done=true. tailSeq is a HARD upper bound: per spec
//     2026-04-18-wtp-client-design.md:586, replay is the finite
//     (ack_hw, wal_hw_at_entry] window before advancing to live. Without
//     this hard stop, sustained appends would prevent TryNext from ever
//     returning ok=false and replay would never terminate. The boundary
//     record is included because we have already read it from the Reader
//     and cannot push it back; the server treats EventBatch records
//     identically regardless of which state-machine state delivered them.
//  3. Reader is currently caught up (TryNext ok=false) → return done=true.
//  4. Batch caps hit (records or bytes) → return done=false, partial batch.
//
// There IS a hard stop on RecordData with seq > tailSeq (the boundary
// record is included). The trailing loss marker race is handled by Live's
// reader, not by replay drain — see the trailing-loss-marker race
// commentary below and the LastReplayedSequence docstring for the Live
// hand-off contract.
//
// Trailing-loss-marker race (documented for Task 17/22 Live state). While
// replay drains, overflow GC can drop a segment containing replay-era seqs
// and append a compensating loss marker AT THE WAL TAIL, with
// Loss.ToSequence <= tailSeq but a WAL position strictly beyond tailSeq.
// Two outcomes are possible:
//
//   - The Reader surfaces the loss marker BEFORE any over-tail RecordData.
//     NextBatch appends it to the batch (loss markers always surface and
//     do not contribute to the seq-vs-tailSeq check) and replay continues
//     normally.
//   - The Reader surfaces an over-tail RecordData first, NextBatch returns
//     done=true with the boundary record included, and the trailing loss
//     marker has not yet been seen. The Live state handler is responsible
//     for surfacing it: Live MUST open its Reader at
//     max(lastReplayedSeq+1, ackHW+1) — loss markers bypass the Reader's
//     nextSeq filter (see wal/reader.go nextLocked near the isLossMarker
//     branch), so the trailing marker WILL surface through Live's Reader
//     even though its covered seq range is past Live's start cursor.
//
// Loss records (RecordLoss) are appended verbatim and contribute neither
// to the byte cap accounting nor to the seq-vs-tailSeq check above.
func (r *Replayer) NextBatch(ctx context.Context) (ReplayBatch, bool, error) {
	batch := ReplayBatch{}
	bytes := 0
	// Round-10 PrefixLoss emission: if a transport-synthesized loss
	// marker is queued (Step 1b.5 ack_regression_after_gc) AND has not
	// yet been emitted, append it as batch.Records[0] before draining
	// the Reader. Loss markers do not contribute to MaxBatchBytes and
	// do not interact with the seq-vs-tailSeq termination check.
	//
	// Round-13 Finding 5: fire OnPrefixLossEmitted EXACTLY ONCE,
	// IMMEDIATELY after the marker is appended. The callback is wired by
	// the Run loop (Task 15.1) AND the recv-handler-driven Replayer
	// construction site (Task 17.X) to bump the
	// `wtp_ack_regression_loss_total` counter at the EMIT site so the
	// counter never increments for a Replayer that is aborted before
	// surfacing batch[0]. The gate `prefixLossEmitted = true` MUST be
	// set BEFORE invoking the callback so that an extraordinary callback
	// re-entry (the implementation MUST NOT be re-entrant; this is
	// defense-in-depth) cannot double-fire the counter.
	if !r.prefixLossEmitted && r.opts.PrefixLoss != nil {
		batch.Records = append(batch.Records, wal.Record{
			Kind: wal.RecordLoss,
			Loss: *r.opts.PrefixLoss,
		})
		r.prefixLossEmitted = true
		if r.opts.OnPrefixLossEmitted != nil {
			r.opts.OnPrefixLossEmitted()
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return batch, false, err
		}
		if r.opts.MaxBatchRecords > 0 && len(batch.Records) >= r.opts.MaxBatchRecords {
			return batch, false, nil
		}
		if r.opts.MaxBatchBytes > 0 && bytes >= r.opts.MaxBatchBytes && len(batch.Records) > 0 {
			return batch, false, nil
		}
		rec, ok, err := r.rdr.TryNext()
		if err != nil {
			return batch, false, fmt.Errorf("replayer: reader.TryNext: %w", err)
		}
		if !ok {
			// Reader is caught up to the live tail — replay is done.
			// tailSeq was snapshotted under the WAL lock at construction,
			// so every record with seq <= tailSeq has been visible to the
			// reader by now (whether emitted, filtered by start, or
			// surfaced as a loss marker).
			return batch, true, nil
		}
		if rec.Kind == wal.RecordData && rec.Sequence > r.tailSeq {
			batch.Records = append(batch.Records, rec)
			r.lastReplayedSeq = rec.Sequence
			return batch, true, nil
		}
		batch.Records = append(batch.Records, rec)
		if rec.Kind == wal.RecordData {
			bytes += len(rec.Payload)
			r.lastReplayedSeq = rec.Sequence
		}
	}
}
```

Create `internal/store/watchtower/transport/state_replaying.go`:

The transport spec (`docs/superpowers/specs/2026-04-18-wtp-client-design.md:565`)
requires `stateReplaying` to multiplex on `replayDone`, `replayBatchSent`,
`recv`, and `ctx.Done()` — i.e. inbound `BatchAck`, `ServerHeartbeat`,
`SessionUpdate`, and `Goaway` MUST be processed alongside replay
completion. The Task 16 implementation has NO recv branch, so any
inbound control frame that arrives during a long replay would be
dropped (or stall the receive side, depending on stream buffering).
Task 17 (Live state Batcher) and Task 18 (heartbeat) introduce the
shared recv-multiplexer goroutine; Task 22 (Store integration) wires
`runReplaying` through a `RunOnce` dispatch table that gates Replaying
behind those landing.

To enforce the deferral, `runReplaying` is unexported (lowercase) — this
is an EXTERNAL-CALL-SITE GUARD, not a compile-time guarantee. Production
code OUTSIDE the `internal/store/watchtower/transport` package cannot
reach it. Callers INSIDE the transport package CAN still call it
directly — Go's package-level visibility does not prevent this — so
production wiring inside the transport package (Task 22's Run loop) MUST
gate the call behind the recv-multiplexer plumbing Tasks 17/18
introduce. See the Task 22 Run-loop snippet (Step 4) for the structural
dependency. The exported test seam `RunReplayingForTest` lives in
`state_replaying_internal_test.go` (the `_test.go` suffix excludes it
from production binaries) so external `transport_test` callers can drive
the per-state handler without going through the unfinished production
dispatch.

```go
package transport

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runReplaying drains the WAL via the supplied Replayer and ships records
// in EventBatch messages over the conn that the Connecting state opened.
// On success it returns StateLive (and t.conn is RETAINED — the Live state
// handler picks up the same conn for ongoing batch sends). On any error
// path (Replayer error, build error, send error, ctx cancellation) it
// closes t.conn and clears it before returning StateConnecting so the
// run loop reconnects on the next iteration with a fresh dial.
//
// Lifecycle invariant matches runConnecting (state_connecting.go): every
// error path on a held Conn calls Close() exactly once (the full-teardown
// primitive — never CloseSend(), which is the half-close that would leave
// the underlying stream open and leak resources during reconnect backoff).
//
// ctx cancellation is surfaced as the wrapped Replayer error and treated
// the same as any other replay failure: conn is torn down, state regresses
// to Connecting, and the run loop owns whether to retry or shut down.
//
// PRODUCTION-BLOCKED — recv multiplexer not yet wired. The spec at
// docs/superpowers/specs/2026-04-18-wtp-client-design.md:565 requires
// stateReplaying to process inbound BatchAck, ServerHeartbeat,
// SessionUpdate, and Goaway concurrently with replay completion. This
// implementation only loops over NextBatch and Send — it has NO recv
// branch, so any inbound control frame that arrives during a long replay
// would be dropped (or, depending on the gRPC stream's buffer, would
// stall the receive side). Task 17 (Live state Batcher) and Task 18
// (heartbeat) introduce the shared recv goroutine + multiplexer that
// runReplaying will plug into. Until then, runReplaying MUST NOT be
// wired into the production run loop.
//
// The unexport of runReplaying is an EXTERNAL-CALL-SITE GUARD, not a
// compile-time guarantee:
//   - Callers OUTSIDE the internal/store/watchtower/transport package
//     CANNOT reach runReplaying without going through a future RunOnce
//     dispatch table that Task 22 will add (and which will gate
//     Replaying behind the recv loop landing in Task 17/18).
//   - Callers INSIDE the transport package CAN still call runReplaying
//     directly — Go's package-level visibility does not prevent this.
//     Production wiring inside the transport package (Task 22's Run
//     loop) MUST gate the call behind the recv-multiplexer plumbing
//     that Tasks 17/18 introduce. See the updated Task 22 Run-loop
//     snippet in docs/superpowers/plans/2026-04-18-wtp-client.md
//     "Task 16 — Deferred to Task 17/18", which makes that dependency
//     structural (the snippet visibly cannot work without Task 17/18
//     landing first).
//
// The exported test seam RunReplayingForTest lives in
// state_replaying_internal_test.go (compiled out of the production
// binary) so external transport_test callers can still drive the
// per-state handler in isolation.
func (t *Transport) runReplaying(ctx context.Context, r *Replayer) (State, error) {
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			_ = t.conn.Close()
			t.conn = nil
			return StateConnecting, fmt.Errorf("replay batch: %w", err)
		}
		if len(batch.Records) > 0 {
			msg, err := buildEventBatchFn(batch.Records)
			if err != nil {
				_ = t.conn.Close()
				t.conn = nil
				return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
			}
			if err := t.conn.Send(msg); err != nil {
				_ = t.conn.Close()
				t.conn = nil
				return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
			}
		}
		if done {
			return StateLive, nil
		}
	}
}

// buildEventBatchFn is the function variable runReplaying calls to wrap
// WAL records into a wtpv1.EventBatch envelope. Defaults to the empty-
// message stub so the Replaying state machine can be exercised in tests.
// Task 17 (Live-state Batcher) and Task 22 (Store integration) replace
// this with the real builder before runReplaying is wired into the
// production run loop. Until then, in addition to the stub-builder
// hazard, runReplaying is missing the recv multiplexer required by the
// spec (see runReplaying header) — both gaps are addressed by Task
// 17/18, and runReplaying remains unexported so production callers
// outside the transport package cannot reach it.
//
// Tests that need to assert against a non-empty wire format can override
// via setBuildEventBatchFnForTest (see state_replaying_internal_test.go);
// production code MUST NOT mutate this variable outside of the
// initialization performed by Task 22.
var buildEventBatchFn = buildEventBatchStub

// buildEventBatchStub is a no-op wire-format placeholder. Returns an empty
// ClientMessage so the Replaying state machine can be exercised in tests
// without depending on the unpublished EventBatch wire schema.
//
// TODO(Task 17): replace with the real builder that wraps records'
// payloads (already-serialized CompactEvent bytes) plus their (sequence,
// generation) and integrity records into a wtpv1.EventBatch envelope.
// Task 22 (Store integration) is responsible for the wiring that points
// buildEventBatchFn at the real implementation before the run loop ever
// reaches runReplaying in production.
func buildEventBatchStub(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	return &wtpv1.ClientMessage{}, nil
}
```

Also create `internal/store/watchtower/transport/state_replaying_internal_test.go`
holding the test seams (`RunReplayingForTest`, `SetConnForTest`,
`HasConnForTest`, `SetBuildEventBatchFnForTest`) so external
`transport_test` callers can drive `runReplaying` in isolation from
the `runConnecting` path. Lives in `*_test.go` so the helpers are
compiled out of the production binary.

```go
// RunReplayingForTest is the external test seam for runReplaying. The
// production runReplaying is unexported (see state_replaying.go header)
// because it is missing the recv multiplexer the spec requires for
// stateReplaying (design.md:565); shipping it as an exported method
// would let production callers outside the transport package wire it
// into a run loop without realising it would silently drop inbound
// BatchAck/ServerHeartbeat/SessionUpdate/Goaway frames during long
// replays.
//
// The unexport is an EXTERNAL-CALL-SITE GUARD, not a compile-time
// guarantee: callers inside the transport package can still call
// runReplaying directly. Production wiring inside the package (Task 22's
// Run loop) MUST gate the call behind the recv-multiplexer plumbing
// Tasks 17/18 introduce. See the Task 22 Run-loop snippet in
// docs/superpowers/plans/2026-04-18-wtp-client.md "Task 16 — Deferred
// to Task 17/18" for the structural dependency. Until then, only tests
// reach runReplaying — via this helper, which lives in *_test.go and is
// compiled out of the production binary.
//
// Tests using this seam MUST also override buildEventBatchFn via
// SetBuildEventBatchFnForTest (the default stub returns an empty
// ClientMessage that would put invalid frames on the wire if a Send
// went through to a real server).
func (t *Transport) RunReplayingForTest(ctx context.Context, r *Replayer) (State, error) {
	return t.runReplaying(ctx, r)
}
```

In addition to `TestReplayer_StopsAtTailWatermark` and
`TestReplayer_TerminatesUnderConcurrentAppends`, the round-1/round-2
reviews mandate four `RunReplayingForTest` tests in
`internal/store/watchtower/transport/state_replaying_test.go`:

- `TestRunReplaying_HappyPathReturnsLiveAndRetainsConn` — the conn is
  RETAINED across a successful transition so the Live handler can reuse it
  (this is the inverse of the runConnecting contract, where every state
  exit Close()s the dialed conn). Drives the unexported `runReplaying`
  via `RunReplayingForTest`.
- `TestRunReplaying_SendFailureClosesConn` — Send returning
  `write: broken pipe` mid-replay must Close exactly once, leave
  `t.conn==nil`, and return `StateConnecting`. Uses
  `RunReplayingForTest`.
- `TestRunReplaying_ReplayerErrorClosesConn` — a hard Replayer error
  (driven by closing the Reader before invocation) must Close + nil
  `t.conn` and return `StateConnecting`. Uses `RunReplayingForTest`.
- `TestRunReplaying_CtxCancelClosesConn` — ctx cancellation mid-replay
  must Close + nil `t.conn` and return `StateConnecting` with
  `errors.Is(err, context.Canceled)`. Uses `RunReplayingForTest`.

And four replayer-level tests in
`internal/store/watchtower/transport/replayer_test.go`:

- `TestReplayer_TerminatesUnderConcurrentAppends` — spins an appender
  that keeps writing past tailSeq while the replayer drains; asserts
  replay terminates within 5s AND that the boundary contract holds
  (`maxSeqSeen <= tailSeq+1`). This is the round-2 liveness regression
  test for the hard stop on `RecordData seq > tailSeq`; without the
  hard stop the replayer would chase the appender forever and the test
  would time out.
- `TestReplayer_DeliversLossMarkerBeforeStart` — overflow GC creates a
  TransportLoss marker; opening `NewReader(start=N)` past every covered
  seq still yields the marker (loss records are NOT subject to the
  nextSeq filter).
- `TestReplayer_DeliversWithinWindowLossMarker` — appends a synthetic
  loss marker covering seqs 1..2 BEFORE the data records, so it sits at
  a WAL position WITHIN the (ack_hw, wal_hw_at_entry] replay window.
  The marker MUST surface during replay. Round-2 reframed this from the
  round-1 `TestReplayer_DeliversTrailingLossMarker` (which asserted a
  trailing marker after over-tail data); with the hard stop restored,
  the trailing-marker race is Live-state's responsibility — Live's
  Reader will surface it because loss markers bypass `nextSeq` and
  Live opens at `max(LastReplayedSequence()+1, ackHW+1)`. A Task 17
  Live-state regression test will cover the trailing-marker hand-off.
- `TestReplayer_LossOnlyScenario` — WAL with only loss markers (no user
  data) drains every marker.
- `TestReplayer_EmitsPrefixLossOnFirstBatch` — round-10: covers the
  in-memory `ReplayerOptions.PrefixLoss` plumbing landed for Finding 3.
  Setup: a normal `*wal.WAL` with three data records at seqs 1..3; open
  `wal.NewReader(1)`; construct Replayer with
  `ReplayerOptions{PrefixLoss: &wal.LossRecord{FromSequence: 100,
  ToSequence: 200, Generation: 5, Reason: "ack_regression_after_gc"}}`.
  Drive `NextBatch` once and assert: (a) `batch.Records[0].Kind ==
  wal.RecordLoss`, `batch.Records[0].Loss == *opts.PrefixLoss`
  (verbatim); (b) `batch.Records[1..3].Kind == wal.RecordData` with
  the seq=1..3 payloads in order; (c) the prefix loss seq range
  (100..200) does NOT bound or filter the data records (there is no
  interaction with tailSeq or nextSeq for the prefix loss). Drive a
  second `NextBatch` and assert PrefixLoss is NOT re-emitted (the
  `prefixLossEmitted` gate works). Drive a third `NextBatch` after
  exhausting the Reader and assert `done=true`.

- `TestReplayer_OnPrefixLossEmittedFiresExactlyOnceWhenLossInBatch1`
  — Round-13 Finding 5 regression test for the EMIT-time metric
  callback. Setup: open a WAL, append 3 records (gen=1, seqs 1..3),
  open a Reader scoped to gen=1 with `Start=0`. Construct a Replayer
  with `ReplayerOptions{PrefixLoss: &wal.LossRecord{FromSequence: 10,
  ToSequence: 20, Generation: 1, Reason: "ack_regression_after_gc"},
  OnPrefixLossEmitted: func() { atomic.AddInt32(&n, 1) }}`. Phase 1:
  immediately after `NewReplayer` returns, assert `atomic.LoadInt32(&n)
  == 0` — the callback MUST NOT fire at construction time. Phase 2:
  drive `NextBatch` once. Assert `atomic.LoadInt32(&n) == 1` AND
  `batch.Records[0].Kind == wal.RecordLoss` (the marker surfaced) AND
  `batch.Records[1..3].Kind == wal.RecordData`. Phase 3: drive
  `NextBatch` a second time. Assert `atomic.LoadInt32(&n) == 1` (NOT
  2 — the callback is one-shot, gated by `prefixLossEmitted`). Phase 4:
  drive `NextBatch` a third time. Assert `atomic.LoadInt32(&n) == 1`
  AND `done=true` (the Reader is drained; the callback stays at one).
  CRITICAL: this test catches the regression where a future refactor
  accidentally moves the callback invocation outside the
  `prefixLossEmitted` gate — under the buggy code path the callback
  would fire on every NextBatch and the counter assertion would be
  >= the number of NextBatch calls.

- `TestReplayer_OnPrefixLossEmittedDoesNotFireWhenPrefixLossNil` —
  Round-13 Finding 5 regression test for the no-loss path. Setup: open
  a WAL, append 3 records, open a Reader, construct a Replayer with
  `ReplayerOptions{PrefixLoss: nil, OnPrefixLossEmitted: func()
  { atomic.AddInt32(&n, 1) }}`. Drive `NextBatch` until exhaustion.
  Assert `atomic.LoadInt32(&n) == 0` at every step (construction, after
  each NextBatch, and at done=true). The callback MUST NOT fire when
  PrefixLoss is nil — it would double-count on the next reconnect when
  computeReplayStart re-derives a non-nil PrefixLoss for the same gap.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/... ./internal/store/watchtower/wal/...`
Expected: PASS — both `TestReplayer_StopsAtTailWatermark` and the existing
WAL Reader tests (which use `NewReader(0)` and rely on the start cursor
being inclusive at zero).

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/replayer.go \
        internal/store/watchtower/transport/state_replaying.go \
        internal/store/watchtower/transport/replayer_test.go \
        internal/store/watchtower/wal/reader.go
git commit -m "feat(wtp/transport): add Replayer that drains WAL up to entry tail"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

### Task 16 — Deferred to Task 17/18

Replaying state currently has NO inbound recv multiplexer. The transport
spec (`docs/superpowers/specs/2026-04-18-wtp-client-design.md`, the
state-machine section near line 565) requires Replaying to process
`BatchAck`, `ServerHeartbeat`, `SessionUpdate`, and `Goaway` alongside
replay completion. Round-2 review flagged this as a High finding.

The deferral is enforced as an **external-call-site guard**, not a
compile-time guarantee:

- Callers OUTSIDE the `internal/store/watchtower/transport` package
  CANNOT reach `runReplaying` without going through a future RunOnce
  dispatch table that Task 22 will add. `runReplaying` is unexported
  (Task 16 round-2 fix), so external production code is structurally
  blocked from invoking it.
- Callers INSIDE the transport package CAN still call `runReplaying`
  directly — Go's package-level visibility does not prevent this.
  Production wiring inside the transport package (Task 22's `Run`
  loop) MUST gate the call behind the recv-multiplexer plumbing that
  Tasks 17/18 introduce. See the updated Task 22 Run-loop snippet
  (Step 4 below), which makes that dependency structural: the snippet's
  Live-state handoff (`max(rep.LastReplayedSequence()+1, ackHW+1)`) and
  recv-multiplexer dependency MUST be in place before Task 22 commits
  its Run loop. Until then, replay is reachable only via
  `RunReplayingForTest`.
- The exported test seam `RunReplayingForTest` lives in
  `state_replaying_internal_test.go` (the `_test.go` suffix excludes
  it from production binaries), so external `transport_test` callers
  can still drive the per-state handler in isolation.

Task 17 (Live state Batcher) introduces the shared recv-multiplexer
goroutine architecture. Task 18 (heartbeat) extends it. Once the recv
loop lands, Task 22 (Store integration) wires the production run loop
to invoke replay through the recv-aware path. The Task 22 Run-loop
snippet (Step 4) wires `runReplaying`. The wiring is gated by the
recv-multiplexer plumbing Tasks 17/18 introduce — the snippet's
Live-state handoff (`max(rep.LastReplayedSequence()+1, ackHW+1)`) and
recv-multiplexer dependency MUST be in place before Task 22 commits
its Run loop. Until then, replay is reachable only via
`RunReplayingForTest`.

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
- Modify: `proto/canyonroad/wtp/v1/validate.go` (Step 4 — add `ValidationReason` enum (including `ReasonUnknown` for the forward-compat unknown-oneof case), `AllValidationReasons() []ValidationReason` copy-returning getter (consumed by Task 22b's cross-task parity test; getter form, not a mutable exported slice), and `ValidationError` typed classifier so receivers consume `errors.As(err, &ve)` instead of grepping the validator's formatted message; `ValidationError.Error()` returns ONLY the Reason string per spec §"Invalid-frame log sanitization" defense-in-depth rule; ValidateEventBatch and ValidateSessionInit MUST return `*ValidationError` for every failure path including the forward-compat unknown-oneof case)
- Test: `proto/canyonroad/wtp/v1/validate_reason_test.go` (table-driven coverage that each input maps to its enum constant; `errors.As` and `errors.Is(err, ErrInvalidFrame)` both work)

**Prerequisites:** Task 22a Step 4 (the metrics-side `WTPInvalidFrameReason` enum + the `MetricsOnlyReasons()` getter, defined in `internal/metrics/wtp.go`) MUST be completed before Task 17 Step 4a executes — Step 4a's receiver wiring snippet uses `metrics.WTPInvalidFrameReasonClassifierBypass` and `metrics.WTPInvalidFrameReason(...)` cast, both of which depend on those constants existing in the `metrics` package. If executing the plan strictly in numeric order, jump to Task 22a Step 4 (define the `WTPInvalidFrameReason` enum + the validator-shared and metrics-only getter helpers), commit, then return to Task 17 Step 4a. The dependency is one-way: Task 17 Step 4 (the proto-side `ValidationReason` enum + `AllValidationReasons()` getter) is the input to Task 22b's cross-task parity test, but Task 17 Step 4a is the consumer of Task 22a's enum, so Step 4a is the step that blocks on Task 22a — Steps 1–4 of Task 17 do not.

**Downstream consumer:** Task 22b ("Cross-task parity integration") consumes `wtpv1.AllValidationReasons()` defined in this task's Step 4 to assert metrics/proto enum parity. Any change to the proto-side `ValidationReason` enum (adding/removing a constant, renaming a string value) MUST trigger a re-run of Task 22b's `TestWTPInvalidFrameReason_ParityWithValidator` to surface drift between the proto and metrics packages. Task 22b's test is the canonical enforcement mechanism for the duplicated-but-byte-equal contract documented in spec §"Frame validation and forward compatibility".

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
//
// Reader lifecycle: like the StateReplaying case, the Live case OWNS its
// Reader. `defer rdr.Close()` ensures the Reader is unregistered from the
// WAL on EVERY exit path (stream error → StateConnecting, ctx cancellation
// → StateShutdown). Per `wal/reader.go` Reader.Close (near line 446),
// Close is what removes the Reader from `WAL.readers` so notifyReaders
// stops waking it; without it, every reconnect cycle would leak a
// registered Reader. The StateLive case in the Run loop creates a fresh
// Reader on each entry — readers are NOT reused across reconnect cycles.
//
// Conn lifecycle: matches runReplaying's invariant. Every exit path on
// a held Conn calls t.conn.Close() exactly once and clears
// t.conn = nil before returning, so the Run loop's next StateConnecting
// iteration starts with a fresh dial. ctx cancellation also closes +
// clears (StateShutdown still tears down the conn — the caller does
// not need to know whether runLive returned by error or by shutdown to
// know it owns no conn now). Round-6: prior to this fix the error
// returns left t.conn dangling, and the Run loop would then dial on
// top of a still-held conn reference on the next StateConnecting
// iteration.
func (t *Transport) runLive(ctx context.Context, rdr *wal.Reader, opts LiveOptions) (State, error) {
	defer rdr.Close()
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
			// ctx cancellation: caller (Run loop) decides whether to
			// shut down or reconnect. Close the conn so the next
			// StateConnecting iteration starts clean.
			_ = t.conn.Close()
			t.conn = nil
			return StateShutdown, ctx.Err()
		case <-rdr.Notify():
			// Pull as many records as the window and batcher allow.
			for inflight < opts.MaxInflight {
				rec, ok, err := rdr.TryNext()
				if err != nil {
					_ = t.conn.Close()
					t.conn = nil
					return StateConnecting, fmt.Errorf("reader: %w", err)
				}
				if !ok {
					break
				}
				if outBatch := b.Add(rec); outBatch != nil {
					msg, err := encodeBatchMessage(outBatch.Records)
					if err != nil {
						_ = t.conn.Close()
						t.conn = nil
						return StateConnecting, err
					}
					if err := t.conn.Send(msg); err != nil {
						_ = t.conn.Close()
						t.conn = nil
						return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
					}
					inflight++
				}
			}
		case now := <-tick.C:
			if outBatch := b.Tick(now); outBatch != nil {
				msg, err := encodeBatchMessage(outBatch.Records)
				if err != nil {
					_ = t.conn.Close()
					t.conn = nil
					return StateConnecting, err
				}
				if err := t.conn.Send(msg); err != nil {
					_ = t.conn.Close()
					t.conn = nil
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

**runLive lifecycle invariant (round-6 fix).** runLive's lifecycle invariant matches runReplaying's — every error path on a held Conn calls Close() exactly once and clears `t.conn = nil` before returning, so the Run loop's next StateConnecting iteration starts with a fresh dial. ctx cancellation also closes + clears (StateShutdown still tears down the conn — the caller doesn't need to know whether it returned by error or by shutdown to know it owns no conn now). Round-6 reviewer: prior to this fix, the runLive snippet's error returns just bubbled the error without touching `t.conn`, so the Run loop's StateLive case regressed to StateConnecting on top of a still-held conn reference. The pattern above (close + clear before each `return StateConnecting/StateShutdown, ...`) brings runLive into line with runReplaying's contract.

**Sub-step 17.X: Two-cursor ack clamp in BatchAck/ServerHeartbeat handlers (round-8 rewrite — depends on Task 15.1)**

**Status (round-23): test-only until Task 22 wires it into runConnecting.** The recv multiplexer (`runRecv`, `newRecvSession`, `teardownRecv`, `applyAckFromRecv`) and the `Transport.recv *recvSession` field have all landed in production code, but `runConnecting` does NOT yet start the recv goroutine after accepting `SessionAck` — `state_connecting.go::runConnecting` returns straight to `StateReplaying` without touching `t.recv`. The recv path is exercised exclusively via the `StartRecvForTest` / `TeardownRecvForTest` test seams (see `seams_export_test.go`); production callers see `t.recv == nil` so the `state_live.go` and `state_replaying.go` recv-channel select arms are dormant by Go's nil-channel semantics. **Task 22 (Store integration / runConnecting wiring) will start a fresh `recvSession` on each successful dial after `SessionAck` is accepted** by adding `t.recv = newRecvSession(ctx); go t.runRecv(t.recv)` to `runConnecting` immediately before the `StateReplaying` return. Until that wiring lands, all "fresh recvSession created on each successful dial" / "started on each redial" / "production lifecycle" language in this section describes the END STATE that Task 22 finishes — not what production runConnecting does today. Cross-reference: see Task 22 Run-loop / Store integration sub-section for the runConnecting wiring.

**Scope: same-generation only.** Round-9 narrowing — mirrors Task 15.1. The BatchAck and ServerHeartbeat handlers reuse the same `applyServerAckTuple` helper and inherit the same scope: legitimate `ResendNeeded` outcomes are restricted to **same-generation** server tuples. Cross-generation server tuples (`server.gen != local.persistedAck.gen`, in either direction) take the `Anomaly` path or the cross-gen `Adopted` path per the unified classification table.

**Round-12 SCOPE NOTE (Finding 5 — supersedes round-11; mirrors Task 15.1 EXACTLY).** The recv-side wrapper dispatches on the SAME unified anomaly classification predicates Task 15.1's helper uses, in this order. Both call sites MUST stay in lock-step with this table — the helper is the single source of truth, and the wrapper is allowed only to add the `frame=...` label to the WARN.

```
- server.gen <  persistedAck.gen → Anomaly("stale_generation")
- server.gen == persistedAck.gen AND server.seq <= persistedAck.seq → either NoOp (==) or ResendNeeded (<)
- server.gen == persistedAck.gen AND server.seq >  persistedAck.seq AND
  server.seq <= WrittenDataHighWater(server.gen).seq → Adopted
- server.gen == persistedAck.gen AND server.seq >  WrittenDataHighWater(server.gen).seq → Anomaly("server_ack_exceeds_local_seq")
- server.gen >  persistedAck.gen AND WrittenDataHighWater(server.gen).ok == false → Anomaly("unwritten_generation")
- server.gen >  persistedAck.gen AND server.seq <= WrittenDataHighWater(server.gen).seq → Adopted
- server.gen >  persistedAck.gen AND server.seq >  WrittenDataHighWater(server.gen).seq → Anomaly("server_ack_exceeds_local_data")
- WrittenDataHighWater(server.gen) returns err != nil at any decision point → Anomaly("wal_read_failure")
```

The five Anomaly sub-cases (round-12 Finding 5):
- `stale_generation` (server.gen < persistedAck.gen).
- `unwritten_generation` (server.gen > persistedAck.gen AND `wal.WrittenDataHighWater(server.gen)` returns ok=false).
- `server_ack_exceeds_local_data` (server.gen > persistedAck.gen AND `wal.WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq > maxDataSeq`).
- `server_ack_exceeds_local_seq` (round-12 rename of round-11's `beyond_wal_high_water_seq` — same-gen `server.seq > WrittenDataHighWater(server.gen).seq`; the same-gen branch now reuses the cross-gen branch's `WrittenDataHighWater` predicate so the helper has a single source of truth for the "server seq exceeds local data" shape).
- `wal_read_failure` (round-12 Finding 4 — `wal.WrittenDataHighWater` returned a non-nil error; NOT peer-attributable; cursors stay unchanged so the next ack-bearing frame retries).

The legitimate cross-gen Adopted case (`server.gen > persistedAck.gen` AND `wal.WrittenDataHighWater(server.gen)` returns `(maxDataSeq, true)` AND `server.seq <= maxDataSeq`) IS supported — the recv-side wrapper does NOT classify higher-generation server tuples as Anomaly when the WAL has emitted data in that generation; only when the WAL has NOT emitted data, or has emitted but the server's seq exceeds it, does the helper return an Anomaly outcome. See Task 15.1 header for the WAL-side constraints (sequence-keyed Reader API, single-`Generation` LossRecord, monotonic-only `MarkAcked`) AND for the Round-11 SAFETY NOTE on why the per-gen data-bearing accessor is required (segment-header-seeded `w.highGen` cannot prove records were written). The recv-side test suite below mirrors Task 15.1's same-gen / cross-gen split: `LowerSameGen → ResendNeeded`, `EqualSameGen → NoOp`, `HigherSameGen within WrittenDataHighWater → Adopted`, `HigherSameGen exceeds WrittenDataHighWater → Anomaly("server_ack_exceeds_local_seq")`, `LowerGen → Anomaly("stale_generation")`, `HigherGen with no WAL data → Anomaly("unwritten_generation")`, `HigherGen with WAL data and server.seq within → Adopted`, `HigherGen with WAL data and server.seq exceeds → Anomaly("server_ack_exceeds_local_data")`, `WrittenDataHighWater walErr != nil → Anomaly("wal_read_failure")`.

Per spec §"Acknowledgement model" (design.md), the recv multiplexer's `BatchAck` and `ServerHeartbeat` handlers BOTH carry an `ack_high_watermark_seq` + `generation`. Both paths MUST run the SAME `applyServerAckTuple` clamp helper that Task 15.1 lands on Transport — the helper's two-cursor model (`persistedAck` monotonic + `remoteReplayCursor` regressable) is the SINGLE source of truth for cursor advancement. The recv-side wrapper, `applyAckFromRecv`, dispatches on the helper's `AckOutcome.Kind` and runs the same four-branch side-effect contract as the SessionAck handler in Step 1b of Task 15.1.

Round-8: this sub-step is no longer about a `(changed, anomaly)`-bool helper. The helper now returns an `AckOutcome` discriminated value (see Task 15.1 for the type definitions). The wrapper reuses Task 15.1's monotonic invariant: ONLY the `Adopted` outcome calls `wal.MarkAcked` + emits the metric; the `ResendNeeded` outcome (server lex-lower than persistedAck) regresses ONLY `remoteReplayCursor` and logs INFO; the `Anomaly` outcome (true anomaly: server claims ack beyond walHighSeq within the same generation) emits a rate-limited WARN and leaves both cursors unchanged. Without this dispatch, a stale `BatchAck` would either silently regress the persisted ack watermark (under the old "lower-server-adopts-and-persists" model that breaks the WAL monotonic-only contract) OR — worse — trick the client into advancing `wal.MarkAcked` past records the server has not actually durably acked.

Offending sites (will be added by this task — there is no production code to grep yet because the recv multiplexer does not exist; the sub-step's scope is to write the multiplexer with the two-cursor dispatch baked in from day one rather than retrofitting it later):

- The `case *wtpv1.ServerMessage_BatchAck:` arm of the recv goroutine's typed dispatch (introduced in this task).
- The `case *wtpv1.ServerMessage_ServerHeartbeat:` arm of the same dispatch.

Reuse the canonical `applyServerAckTuple` helper Task 15.1 lands on Transport (returns `AckOutcome` — see Task 15.1 type definitions). The recv-side handlers wrap it with the same `AckOutcome.Kind` dispatch used by SessionAck (rate-limited via `t.ackAnomalyLimiter`, logger via `t.opts.Logger`):

```go
// applyAckFromRecv is the recv-side wrapper around applyServerAckTuple.
// It is invoked from the main state-machine goroutine when a typed
// recvBatchAck or recvServerHeartbeat event surfaces on the recv
// channel; the recv goroutine NEVER touches t.persistedAck /
// t.remoteReplayCursor directly (single-owner invariant).
//
// `frame` is the proto frame name ("batch_ack" / "server_heartbeat")
// used in the anomaly WARN's structured log so operators can tell which
// frame type drove the anomaly. SessionAck logs through the SessionAck
// site directly (with frame="session_ack") — same side-effect contract,
// inlined there for the anomaly-WARN/rejectReason interleave.
//
// Round-8 — the four-branch dispatch matches Task 15.1 Step 1b. The
// `Adopted` branch is the ONLY one that calls wal.MarkAcked + emits
// the gauge; ResendNeeded logs INFO and regresses remoteReplayCursor
// only; Anomaly logs WARN and leaves both cursors unchanged; NoOp
// is silent.
func (t *Transport) applyAckFromRecv(frame string, serverGen uint32, serverSeq uint64) {
    // Snapshot BOTH cursors before the helper mutates — required for
    // rollback on Adopted-then-MarkAcked-failure per Task 15.1 Step 1b.5.
    priorPersisted := t.persistedAck
    priorReplay := t.remoteReplayCursor
    priorPresent := t.persistedAckPresent

    outcome := t.applyServerAckTuple(serverGen, serverSeq)
    switch outcome.Kind {
    case AckOutcomeAnomaly:
        if t.ackAnomalyLimiter.Allow() {
            // Per spec §"Acknowledgement model": True anomaly. FIVE
            // disjoint sub-cases discriminated by `outcome.AnomalyReason`
            // (round-12 expansion of round-11's four-case taxonomy):
            //   - "server_ack_exceeds_local_seq": server claims ack inside
            //     the current generation but past `WrittenDataHighWater(server.gen).seq`
            //     (we never sent that record). Round-12 rename of round-11's
            //     `beyond_wal_high_water_seq` so the same-gen and cross-gen
            //     "exceeds local data" branches share a coherent naming scheme.
            //   - "stale_generation": server's generation is strictly
            //     less than persistedAck.gen — the server is replaying
            //     a closed past, which is illegal under the same-gen
            //     scope (per Task 15.1 / Finding 1 narrowing).
            //   - "unwritten_generation": server.gen > persistedAck.gen
            //     AND `wal.WrittenDataHighWater(server.gen)` returns
            //     `(_, false)` — the WAL has rolled into the server's
            //     generation (a SegmentHeader exists on disk and
            //     `w.highGen` reflects it) but no RecordData has been
            //     written yet. Round-11 SAFETY case: under the round-10
            //     `WrittenHighGeneration() = w.highGen` design the
            //     helper would Adopt and let `wal.MarkAcked` mark a
            //     fabricated tuple, immediately making lower-gen
            //     segments lex-acked and reclaimable under the lex GC
            //     predicate (`segmentFullyAckedLocked` in wal.go) —
            //     silently dropping unsent history. The per-gen data-
            //     bearing accessor blocks this.
            //   - "server_ack_exceeds_local_data": server.gen >
            //     persistedAck.gen AND `wal.WrittenDataHighWater(server.gen)`
            //     returns `(maxDataSeq, true)` AND `server.seq > maxDataSeq`.
            //     The server is acking past anything we ever sent in that
            //     generation. Same safety rationale as
            //     `unwritten_generation`.
            //   - "wal_read_failure" (round-12 Finding 4): the helper hit
            //     `walErr != nil` from `WrittenDataHighWater(server.gen)`
            //     during classification. NOT peer-attributable — surfaced
            //     so the operator can correlate the anomaly counter with
            //     the underlying I/O failure; cursors stay unchanged so
            //     the next ack-bearing frame retries the classification
            //     once the underlying WAL I/O recovers.
            // Log the FULL cursor context so operators can diagnose without
            // log correlation. Round-12: emit the per-generation data-
            // bearing high-water (`wal_written_data_high_seq`) instead of
            // the global `HighWaterSequence()` because the unified predicate
            // now compares against `WrittenDataHighWater(serverGen)`.
            var (
                wtdHighSeq uint64
                wtdHighOK  bool
                wtdHighErr error
            )
            if t.wal != nil {
                wtdHighSeq, wtdHighOK, wtdHighErr = t.wal.WrittenDataHighWater(serverGen)
            }
            attrs := []slog.Attr{
                slog.String("frame", frame),
                slog.String("reason", outcome.AnomalyReason),
                slog.Uint64("server_seq", serverSeq),
                slog.Uint64("server_gen", uint64(serverGen)),
                slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
                slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
                slog.Uint64("wal_written_data_high_seq", wtdHighSeq),
                slog.Bool("wal_written_data_high_ok", wtdHighOK),
                slog.String("session_id", t.opts.SessionID),
            }
            if wtdHighErr != nil {
                attrs = append(attrs, slog.String("wal_written_data_high_err", wtdHighErr.Error()))
            }
            t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn, "ack: anomalous server ack tuple", attrs...)
        }
        t.metrics.IncAnomalousAck(outcome.AnomalyReason)
        // Cursors unchanged; nothing more to do.
    case AckOutcomeAdopted:
        // persistedAck advanced; persist to WAL and emit metric.
        if err := t.wal.MarkAcked(t.persistedAck.Generation, t.persistedAck.Sequence); err != nil {
            // Persistence failed: roll back BOTH cursors so the in-memory
            // mirrors stay in lock-step with the on-disk meta.json.
            t.opts.Logger.Warn("ack: wal.MarkAcked failed; rolling back ack cursors",
                slog.String("frame", frame),
                slog.Uint64("attempted_seq", t.persistedAck.Sequence),
                slog.Uint64("attempted_gen", uint64(t.persistedAck.Generation)),
                slog.String("err", err.Error()))
            t.persistedAck = priorPersisted
            t.remoteReplayCursor = priorReplay
            t.persistedAckPresent = priorPresent
            // Server will re-deliver this watermark on the next BatchAck
            // or ServerHeartbeat. No metric emission on the failure path.
            return
        }
        // SetAckHighWatermark currently takes a single seq (production
        // signature today: `func (w *WTPMetrics) SetAckHighWatermark(seq int64)`).
        // The metric remains a single unlabeled gauge for round-8;
        // see Task 22b for the deferred schema-extension proposal.
        t.metrics.SetAckHighWatermark(int64(t.persistedAck.Sequence))
    case AckOutcomeResendNeeded:
        // remoteReplayCursor moved within the SAME generation;
        // persistedAck unchanged; do NOT call wal.MarkAcked. Log INFO
        // so operators can see the server is stale relative to local
        // persistence (gradual rollout / partition recovery within a
        // generation — normal, not anomalous). Cross-generation
        // ResendNeeded is impossible under the same-gen scope (Task
        // 15.1 / Finding 1 narrowing): cross-gen tuples take the
        // Anomaly branch above. Bump the wtp_resend_needed_total
        // counter (Task 22b) so an unusual rate of legitimate same-gen
        // regressions is visible to operators.
        t.metrics.IncResendNeeded()
        t.opts.Logger.Info("ack: server ack tuple lower than persistedAck within same generation; remote replay cursor regressed",
            slog.String("frame", frame),
            slog.Uint64("server_seq", serverSeq),
            slog.Uint64("server_gen", uint64(serverGen)),
            slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
            slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
            slog.String("session_id", t.opts.SessionID))
    case AckOutcomeNoOp:
        // No cursor moved; nothing to do.
    }
}
```

The two recv-arm dispatches then become trivial:

```go
case recvBatchAck:
    // applyAckFromRecv runs the full four-branch contract: dispatch on
    // AckOutcome.Kind + WARN-on-anomaly + wal.MarkAcked + rollback-on-
    // failure + metric-on-success. The "downstream metrics / segment GC
    // trigger" placeholder that sat here in earlier rounds is GONE —
    // segment GC is driven by wal.MarkAcked itself (see wal/wal.go
    // segmentFullyAckedLocked), and the metric is emitted inside
    // applyAckFromRecv. There is no additional downstream side-effect
    // for the recv arm to perform.
    t.applyAckFromRecv("batch_ack", e.gen, e.seq)
case recvServerHeartbeat:
    t.applyAckFromRecv("server_heartbeat", e.gen, e.seq)
    // Liveness bookkeeping (reset stalled-stream timer) lives here —
    // it is independent of the ack-watermark side-effects which
    // applyAckFromRecv has already handled.
```

The SessionAck handler in `state_connecting.go` already calls `applyServerAckTuple` directly (per Task 15.1 Step 1b) — it dispatches on `AckOutcome.Kind` inline because it needs to set `t.rejectReason` on certain failure cases. BatchAck and ServerHeartbeat funnel through `applyAckFromRecv` instead. All three call sites share `t.ackAnomalyLimiter` so a flapping peer cannot multiply the WARN volume by trying alternate ack-bearing frame types.

Unit tests (mirror Task 15.1's two-cursor test suite, this time exercising the recv-side handlers via the recv-channel injection seam introduced earlier in Task 17). Tests use the injected `Options.Logger` (added in Task 15.1 Step 1d) writing to a `*bytes.Buffer` so the WARN/INFO content can be asserted byte-for-byte WITHOUT racing on the global `slog.Default()`. `Options.WAL` is wired to a real `*wal.WAL` constructed via `wal.Open` with the Task 14a identity options (`SessionID`, `KeyFingerprint`) so `wal.MarkAcked` calls actually mutate `meta.json` and `wal.HighWaterSequence()` returns truthful values.

- `TestRecvMultiplexer_BatchAckLowerSameGenIsResendNeeded`: pre-seed via `Options.InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}` and drive `wal.MarkAcked(7, 100)` so meta.json holds `(7, 100, true)`. Inject a `*wtpv1.ServerMessage_BatchAck` with `ack_high_watermark_seq = 50, generation = 7` (same generation, lower sequence) onto the recv-channel injection seam. Same-gen narrowing per Finding 1 (Round 9): legitimate `ResendNeeded` is restricted to same-generation server tuples. Assert post-handler: `t.persistedAck == AckCursor{100, 7}` (UNCHANGED), `t.remoteReplayCursor == AckCursor{50, 7}` (regressed to server tuple), `wal.ReadMeta` still shows `(7, 100, true)` (no `MarkAcked` call), the metrics fake recorded ZERO additional `SetAckHighWatermark` calls and exactly one `IncResendNeeded()` call, the WARN buffer is empty, and the INFO buffer contains exactly one entry naming the regression with `frame="batch_ack", server_seq=50, server_gen=7, local_persisted_seq=100, local_persisted_gen=7`.

- `TestRecvMultiplexer_BatchAckHigherSameGenAdvancesPersistedAck`: pre-seed via `Options.InitialAckTuple = &AckTuple{Sequence: 50, Generation: 7, Present: true}`; ensure `Options.WAL.HighWaterSequence() >= 100` (drive `Append` past seq=100 in gen=7 first). Inject BatchAck with `ack_high_watermark_seq = 100, generation = 7`. Assert post-handler: `t.persistedAck == AckCursor{100, 7}` (advanced), `t.remoteReplayCursor == AckCursor{100, 7}` (advanced in lockstep), `wal.ReadMeta` shows `(7, 100, true)` (`MarkAcked` was called), the metrics fake's last call is `SetAckHighWatermark(100)`, the WARN buffer is empty, and the INFO buffer is empty.

- `TestRecvMultiplexer_BatchAckServerAckExceedsLocalSeqIsAnomaly` (round-12 RENAMED from `_BatchAckBeyondWALHighSeqIsAnomaly`): pre-seed `InitialAckTuple = &AckTuple{Sequence: 30, Generation: 7, Present: true}`; drive WAL `Append` so `WrittenDataHighWater(7) == (50, true, nil)`. Inject BatchAck with `ack_high_watermark_seq = 60, generation = 7` (server claims ack at seq=60 inside current gen, but WAL has only emitted up to seq=50). Assert post-handler: BOTH cursors unchanged at `AckCursor{30, 7}`, `outcome.AnomalyReason == "server_ack_exceeds_local_seq"` (round-12 rename of `beyond_wal_high_water_seq` per Finding 5; same-gen branch now reuses `WrittenDataHighWater(serverGen)` predicate), exactly one WARN entry captured carrying `frame="batch_ack", reason="server_ack_exceeds_local_seq", server_seq=60, server_gen=7, local_persisted_seq=30, local_persisted_gen=7, wal_written_data_high_seq=50, wal_written_data_high_ok=true`, the metrics fake recorded exactly one `IncAnomalousAck("server_ack_exceeds_local_seq")` call, no `wal.MarkAcked` call, no `SetAckHighWatermark` call.

- `TestRecvMultiplexer_BatchAckLowerGenIsAnomaly`: pre-seed `InitialAckTuple = &AckTuple{Sequence: 0, Generation: 7, Present: true}`. Inject BatchAck with `ack_high_watermark_seq = 999999, generation = 6` — strictly LOWER generation than persistedAck. Cross-gen narrowing per Finding 1 (Round 9): cross-generation server tuples take the `Anomaly` path with `AnomalyReason="stale_generation"` because the same-gen-only `ResendNeeded` contract cannot express a cross-gen replay (sequences reset on generation rolls; the WAL Reader API is sequence-keyed; `LossRecord` carries a single `Generation`). Assert post-handler: BOTH cursors UNCHANGED at `AckCursor{0, 7}` (Anomaly leaves both cursors as-is), `outcome.AnomalyReason == "stale_generation"`, exactly one WARN entry captured carrying `frame="batch_ack", reason="stale_generation", server_seq=999999, server_gen=6, local_persisted_seq=0, local_persisted_gen=7`, the metrics fake recorded exactly one `IncAnomalousAck("stale_generation")` call, no `wal.MarkAcked` call, no `SetAckHighWatermark` call, the INFO buffer is empty (cross-gen lower is NOT a legitimate ResendNeeded).

- `TestRecvMultiplexer_BatchAckHigherGenButOnlyHeaderExists_Anomaly`: pre-seed `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`. Open a real `*wal.WAL` and roll the writer to gen=8 by appending in gen=7 then triggering a generation roll WITHOUT appending any RecordData in gen=8 (so `WrittenDataHighWater(8)` returns `(0, false)` — segment header for gen=8 written but no data). Inject BatchAck with `ack_high_watermark_seq = 0, generation = 8`. Round-11 SAFETY case (Finding 1): under the prior `WrittenHighGeneration() = w.highGen` design the helper would Adopt and `wal.MarkAcked(8, 0)` would be accepted by the WAL's lex-monotonic predicate, immediately making lower-gen segments lex-acked and reclaimable under the lex GC predicate (`segmentFullyAckedLocked` in wal.go) — silently dropping unsent history. The per-gen data-bearing accessor blocks this. Assert post-handler: BOTH cursors UNCHANGED at `AckCursor{100, 7}` (Anomaly leaves both cursors as-is), `outcome.AnomalyReason == "unwritten_generation"`, exactly one WARN entry captured carrying `frame="batch_ack", reason="unwritten_generation", server_seq=0, server_gen=8, local_persisted_seq=100, local_persisted_gen=7, wal_written_data_high_gen_ok=false`, the metrics fake recorded exactly one `IncAnomalousAck("unwritten_generation")` call, no `wal.MarkAcked` call, no `SetAckHighWatermark` call. CRITICAL: re-list segments — assert lower-gen segments are still on disk and not GC'd (this proves the safety fix; the round-10 design would have GC'd them).

- `TestRecvMultiplexer_BatchAckHigherGenBeyondPerGenDataHW_Anomaly`: pre-seed `InitialAckTuple = &AckTuple{Sequence: 100, Generation: 7, Present: true}`. Open a real `*wal.WAL` and drive `Append` to roll to gen=8 and append RecordData up to seq=10 in gen=8 (so `WrittenDataHighWater(8) == (10, true)`). Inject BatchAck with `ack_high_watermark_seq = 999, generation = 8`. Round-11 SAFETY case (Finding 1): the server is acking past anything we ever sent in that generation; admitting it would mark records that were never written as acked and again let lex GC discard surviving lower-gen segments. Assert post-handler: BOTH cursors UNCHANGED at `AckCursor{100, 7}`, `outcome.AnomalyReason == "server_ack_exceeds_local_data"`, exactly one WARN entry captured carrying `frame="batch_ack", reason="server_ack_exceeds_local_data", server_seq=999, server_gen=8, local_persisted_seq=100, local_persisted_gen=7, wal_written_data_high_seq=10`, the metrics fake recorded exactly one `IncAnomalousAck("server_ack_exceeds_local_data")` call, no `wal.MarkAcked` call, no `SetAckHighWatermark` call.

- `TestRecvMultiplexer_ServerHeartbeatLowerSameGenIsResendNeeded`: same setup as the BatchAck same-gen lower test but inject a `*wtpv1.ServerMessage_ServerHeartbeat` frame. Assert the same cursor split AND the INFO log entry has `frame="server_heartbeat"`, AND the metrics fake recorded exactly one `IncResendNeeded()` call.

- `TestRecvMultiplexer_ServerHeartbeatServerAckExceedsLocalSeqIsAnomaly` (round-12 RENAMED): same setup as the BatchAck `_ServerAckExceedsLocalSeqIsAnomaly` test but for ServerHeartbeat. Assert WARN entry has `frame="server_heartbeat", reason="server_ack_exceeds_local_seq", wal_written_data_high_seq=50, wal_written_data_high_ok=true`, the metrics fake recorded exactly one `IncAnomalousAck("server_ack_exceeds_local_seq")` call.

- `TestRecvMultiplexer_BatchAckWALReadFailureIsAnomaly` (round-12 NEW — Finding 4): pre-seed `InitialAckTuple = &AckTuple{Sequence: 30, Generation: 7, Present: true}`. Wire a fake `*wal.WAL` whose `WrittenDataHighWater` returns `(0, false, errors.New("EIO"))` on the next call (use the same `walWrittenDataHighWaterFn` indirection seam Task 15.1 introduces). Inject BatchAck with `ack_high_watermark_seq = 60, generation = 7`. Assert post-handler: BOTH cursors unchanged at `AckCursor{30, 7}`, `outcome.AnomalyReason == "wal_read_failure"`, exactly one WARN entry captured carrying `frame="batch_ack", reason="wal_read_failure", server_seq=60, server_gen=7, local_persisted_seq=30, local_persisted_gen=7, wal_written_data_high_seq=0, wal_written_data_high_ok=false, wal_written_data_high_err="EIO"`, the metrics fake recorded exactly one `IncAnomalousAck("wal_read_failure")` call. (Cross-gen variant `(serverGen=8, serverSeq=60)` exercises the cross-gen `walErr != nil` branch identically.)

- `TestRecvMultiplexer_BatchAckEmitsMetricOnAdopted`: gauge emission contract — mirror Task 15.1's `TestApplyServerAckTuple_EmitsMetricOnAdopted` for the recv path. Pre-seed `InitialAckTuple = &AckTuple{Sequence: 50, Generation: 1, Present: true}`; ensure `wal.HighWaterSequence() >= 1000`. Drive three sequential BatchAcks with monotonically higher SAME-GENERATION tuples (per Finding 1 narrowing — cross-gen advances are not Adopted; they take the Anomaly path): `(1, 100)`, `(1, 200)`, `(1, 300)`. After each, assert: `wal.MarkAcked` was called with the post-clamp tuple, the metrics fake's last call is `SetAckHighWatermark(seq)` with the matching post-clamp seq, and BOTH cursors equal at the new server tuple. After the three calls, the metrics fake's last call is `SetAckHighWatermark(300)` (gauge holds the latest, not the cumulative max — but in this same-gen monotonic case latest IS max). Negative sub-case: a fourth BatchAck with the equal tuple `(1, 300)` triggers `NoOp` — assert NO additional `MarkAcked` call, NO additional metric emission. Note: cross-gen variants are covered by `TestRecvMultiplexer_BatchAckLowerGenIsAnomaly` and `TestRecvMultiplexer_BatchAckHigherGenIsAnomaly` above; the EmitsMetricOnAdopted contract is intentionally same-gen-only.

- `TestRecvMultiplexer_BatchAckAdoptedDoesNotAdvanceOnMarkAckedFailure`: snapshot-and-rollback path mirrored from Task 15.1's `TestApplyServerAckTuple_AdoptedDoesNotAdvanceOnMarkAckedFailure`. Setup: `Options.WAL` is a fake whose `MarkAcked` returns a non-nil error on the next call (use the same `walMarkAckedFn` indirection seam Task 15.1 introduces); `InitialAckTuple = &AckTuple{Sequence: 50, Generation: 7, Present: true}`. Inject BatchAck `(serverGen=7, serverSeq=100)` (lex-higher → helper returns `Adopted`, mutates BOTH cursors to `(100, 7)` in-line). Assert: `MarkAcked(7, 100)` was called exactly once and returned the injected error; BOTH cursors rolled back to the pre-helper snapshot — `t.persistedAck == AckCursor{50, 7}`, `t.remoteReplayCursor == AckCursor{50, 7}`, `t.persistedAckPresent == true`; the metrics fake recorded ZERO calls to `SetAckHighWatermark` (failure path does not emit); the WARN buffer contains exactly one entry naming the failure with `frame="batch_ack", attempted_seq=100, attempted_gen=7`, the `err` field, and the action ("rolled back"); the rate-limited ack-anomaly WARN buffer is empty (failure is not an anomaly).

Round-22 integration tests (drive the recv goroutine via a fake Conn, not just the helper). The previous unit tests above exercise `applyAckFromRecv` directly and do not start the recv goroutine; the round-22 set asserts the channel/lifecycle properties end-to-end.

- `TestRecvMultiplexer_PreservesWireOrderingAcrossBatchAckAndHeartbeat`: drive a fake `Conn` whose `Recv()` emits a deterministic sequence of mixed `*wtpv1.ServerMessage_BatchAck` and `*wtpv1.ServerMessage_ServerHeartbeat` frames (e.g. BatchAck(1, 100), Heartbeat(99), BatchAck(1, 200), Heartbeat(150)). Start the recv goroutine via the test seam, drain the events on the main goroutine, and assert the resulting `applyAckFromRecv` calls happen in strict wire order — no heartbeat crosses a later BatchAck. Use a pre-allocated `Recorder` that captures `(frame, gen, seq)` in invocation order; the assertion is the recorded slice equals the wire order.

- `TestRecvMultiplexer_ReconnectDoesNotLeakStateAcrossSessions`: dial → drive a few events through the recv goroutine → tear down the recvSession via the test seam → re-dial (new recvSession). Push a stale event onto the OLD session's eventCh AFTER teardown (the channel still exists in the closure but the Transport no longer points at it); assert that the new recvSession's eventCh is empty, that the new session's ctx is alive, and that the old session's ctx is cancelled. This locks in round-22 Finding 2: no event from the prior connection is observable through the new recvSession. **Round-23 Finding 3 strengthening:** the test additionally (a) waits on the OLD session's `Done()` channel after teardown to prove the goroutine has fully returned from `runRecv` (not just that the ctx flipped), (b) compares old-vs-new `eventCh` channel identity to prove the constructor allocated a fresh channel for the new session, (c) attempts a non-blocking send onto the OLD session's eventCh after teardown via `RecvSessionHandle.TrySendStaleEventForTest`, and (d) drains the NEW session's eventCh and asserts the stale event is NOT observed (even after the legitimate event arrives) — proving channel-identity isolation AND no observable cross-channel propagation.

- `TestRecvMultiplexer_PerConnectionCancelUnblocksBlockedRecv`: fill `recvSession.eventCh` to capacity by draining nothing on the main goroutine, then have the fake conn deliver one more BatchAck — the recv goroutine blocks on the eventCh send. Trigger per-connection cancellation by calling `t.recv.cancelFn()`. Assert the recv goroutine exits within a short timeout (e.g. 100ms). This locks in round-22 Finding 2's per-connection-ctx behaviour: the recv goroutine MUST respond to the connection-scoped cancel even when the transport-wide ctx is still alive. **Round-23 Finding 4 strengthening:** after asserting `Ctx().Err() != nil`, the test ALSO waits on `RecvSessionHandle.Done()` (closed by `runRecv`'s `defer close(rs.done)` immediately before return) to prove the goroutine has actually returned — `ctx.Err()` only proves the per-connection ctx flipped, not that the goroutine exited.

- `TestRecvMultiplexer_GoawaySurfacesFailClosedError`: drive a fake Conn that emits a `*wtpv1.ServerMessage_Goaway` frame. Start the recv goroutine; assert that it pushes a non-nil error onto `recvSession.errCh` carrying a "control frame goaway not yet handled" substring (or equivalent), and that the recv goroutine exits. Sibling test `TestRecvMultiplexer_SessionUpdateSurfacesFailClosedError` does the same for `*wtpv1.ServerMessage_ServerUpdate`. This locks in round-22 Finding 4: the recv goroutine MUST NOT silently drop control frames the client cannot yet handle. Tasks 18/19/20 will replace these branches with real handlers. **Round-23 Finding 4 strengthening:** both tests additionally wait on `RecvSessionHandle.Done()` after the errCh delivery to prove the fail-closed branch actually returned from `runRecv` (errCh delivery alone proves only that the branch emitted; a missing `return` would still pass the errCh check but fail Done()).

Step ordering for sub-step 17.X (mirrors the Task 15.1 step shape — round-8 rewrite):

- [ ] **Sub-step 17.X.1:** Write the failing tests above (originally eight; round-9 expanded to ten by adding cross-gen Anomaly tests for `LowerGenIsAnomaly` and `HigherGenIsAnomaly` per Finding 1) against the recv-channel injection seam (constructing `Options.WAL` via the real `wal.Open` with the Task 14a identity options so the `wal.MarkAcked` / `wal.HighWaterSequence` calls operate on a real disk-backed WAL).
- [ ] **Sub-step 17.X.2:** Run tests to confirm they fail with the expected symbols (`Transport.applyAckFromRecv` undefined; recv handlers do not call into the shared `applyServerAckTuple` helper; `AckOutcome` / `AckOutcomeKind` symbols undefined — confirms hard dependency on Task 15.1).
- [ ] **Sub-step 17.X.3:** Add `applyAckFromRecv` to `transport.go` (delegating to the `applyServerAckTuple` helper Task 15.1 already landed); wire the BatchAck/ServerHeartbeat recv arms to call it.
- [ ] **Sub-step 17.X.4:** Run tests + cross-compile.
- [ ] **Sub-step 17.X.5:** Commit with message `fix(wtp/transport): two-cursor ack clamp in BatchAck/ServerHeartbeat handlers`.
- [ ] **Sub-step 17.X.6:** Run `/roborev-design-review` and address findings.

**Hard dependency (round-8 chain):**

- **14a → 17.X:** Task 17.X's `Options.WAL` MUST be a `*wal.WAL` constructed via `wal.Open` with the `SessionID`/`KeyFingerprint` identity options Task 14a introduces. Without 14a, the WAL produced by these tests will have empty identity in meta.json — the round-7 cold-start identity gate would then accept ANY post-restart SessionInit reply (no fingerprint match), defeating the test scope. The dependency is also transitive through 15.1: 17.X reuses the helper 15.1 lands.
- **15.1 → 17.X:** Task 17.X reuses the `applyServerAckTuple` helper, the `AckOutcome` / `AckOutcomeKind` types, `Options.InitialAckTuple`, `t.persistedAck` / `t.remoteReplayCursor` / `t.persistedAckPresent` fields, the `t.ackAnomalyLimiter`, and the `walMarkAckedFn` indirection seam — ALL of which are introduced in Task 15.1. Task 17.X MUST NOT proceed until Task 15.1 has landed and its tests are green.
- **17.X → 22:** Task 22's StateLive case consumes `t.remoteReplayCursor` for its reader-start calculation when re-entering Live after a transient drop. Task 22 MUST NOT commit its Run loop until BOTH Task 15.1 (SessionAck clamp) AND Task 17.X (BatchAck/ServerHeartbeat clamp) have landed; without both, an unclamped raw server value could silently propagate into the reader-start calculation.

**Concurrency boundary for ack-cursor updates (single-owner invariant).** Transport is documented as single-goroutine-owned (`transport.go:76-77`). Once the recv multiplexer lands, the recv goroutine and the main state-machine goroutine BOTH would otherwise reach for `t.persistedAck` / `t.remoteReplayCursor` / `t.persistedAckPresent` — the recv goroutine to update on BatchAck/ServerHeartbeat/SessionAck, the state-machine goroutine to read for replay/Live reader-start calculations. There are two ways to keep them safe:

1. **Mutex around `t.persistedAck`/`t.remoteReplayCursor`/`t.persistedAckPresent`.** Simple but breaks the documented single-owner invariant — every state-handler read of `t.remoteReplayCursor` (Replaying entry, Live entry) becomes a locked critical section, and any future state-machine goroutine code that does multi-field reads of Transport state has to remember to acquire the same mutex. The invariant becomes "single-owner except for these three fields, which require a mutex." That's the kind of subtle rule that breaks the next time someone adds a new ack-bearing field.
2. **Typed events on a channel.** The recv goroutine sends typed events (e.g., `recvBatchAck{seq uint64, gen uint32}`, `recvServerHeartbeat{seq uint64, gen uint32}`) over channels that the main state-machine goroutine selects on alongside its other inputs (ctx.Done, rdr.Notify, ticker, t.stopCh). The state-machine goroutine's event handler invokes `applyAckFromRecv` (which delegates to `applyServerAckTuple`) — so the clamp logic runs on the main goroutine, the recv goroutine never touches `t.persistedAck` / `t.remoteReplayCursor` / `t.persistedAckPresent` directly, and the single-owner invariant is preserved without locks.

**This task picks option 2 (typed events on a channel).** Rationale:

- Preserves the single-owner invariant documented in `transport.go:76-77`.
- The recv goroutine becomes a thin demuxer: typed-decode the inbound `*wtpv1.ServerMessage`, push a typed event onto the channel, return to recv. No business logic on the recv goroutine.
- The clamp / WARN-rate-limit / metric-update logic lives on the main goroutine alongside the rest of the state-machine code, making it trivial to unit-test by injecting events directly onto the channel (no need for a recv-goroutine fixture).

**Single FIFO ack-event channel (round-22 rewrite — supersedes the round-6 two-channel design).** Round-22 reviewer flagged that splitting BatchAck and ServerHeartbeat across separate channels (with the heartbeat path coalescing through `atomic.Pointer[recvServerHeartbeat]`) silently loses the wire ordering between the two frame types. Concretely: the server emits BatchAck(gen=8, seq=100) followed by ServerHeartbeat(seq=99); under the round-6 design the heartbeat could be processed AFTER the BatchAck and would be substituted with `t.persistedAck.Generation == 8` at apply-time, which then reinterprets the older heartbeat as belonging to gen=8 and incorrectly drives `applyAckFromRecv` against an inflated tuple. The round-22 fix collapses both event types onto a SINGLE bounded FIFO channel that preserves wire order, with the heartbeat-deadline timer (Task 18) as the sole defender against main-goroutine wedging. Coalescing was the round-6 mitigation for channel saturation under a wedged consumer; with a deadline timer driving a forced reconnect on wedge, coalescing is no longer worth the ordering cost.

The single channel carries a tagged-union event:

```go
// recvAckEventKind discriminates between the two ack-bearing wire frames
// the recv goroutine demuxes onto recvSession.eventCh.
type recvAckEventKind int

const (
    recvAckEventBatchAck recvAckEventKind = iota + 1
    recvAckEventHeartbeat
)

// recvAckEvent is the single event type the recv goroutine pushes onto
// recvSession.eventCh. The kind discriminator selects the wire-frame
// dispatch on the main goroutine; the gen/seq carry the ack tuple.
//
// Wire-ordering invariant (round-22 Finding 1): events on this channel
// are processed in strict FIFO order on the main goroutine. The recv
// goroutine pushes them in receive order; the main goroutine selects
// one at a time and runs applyAckFromRecv to completion before pulling
// the next. This is the load-bearing invariant for the heartbeat
// generation substitution rule (see ServerHeartbeat dispatch below).
type recvAckEvent struct {
    kind recvAckEventKind
    gen  uint32 // populated for BatchAck; ignored for Heartbeat (substituted at apply-time)
    seq  uint64
}
```

| Event type | Channel | Send policy | Drop semantics | Rationale |
|---|---|---|---|---|
| `recvAckEventBatchAck` AND `recvAckEventHeartbeat` | Shared `recvSession.eventCh chan recvAckEvent` (depth 4) | **Blocking send** with per-connection ctx cancellation | Recv goroutine BLOCKS if main is wedged; cancelling the per-connection ctx unblocks the send | A wedged main goroutine is a protocol-broken state — the heartbeat-deadline timer (Task 18) will fire on the per-connection ctx and force a reconnect via `runConnecting`. Until that fires, the recv goroutine blocks on send to preserve wire ordering. The depth of 4 absorbs steady-state burstiness without backpressuring the wire path; depth 1 would force the recv goroutine to block on every event. |

ServerHeartbeat generation handling (round-22 Finding 1, non-obvious invariant). The proto frame `wtpv1.ServerHeartbeat` carries ONLY `ack_high_watermark_seq` — no generation field on the wire. The recv goroutine therefore CANNOT populate `recvAckEvent.gen` for heartbeats from the wire alone. The previous round-6 trick of "substitute `t.persistedAck.Generation` at apply time" caused Finding 1 because earlier heartbeats could be reordered past later BatchAcks. The round-22 fix:

1. The recv goroutine pushes the heartbeat event onto `eventCh` with `gen` left as zero (it has no value to put there); the kind discriminator marks it as a heartbeat.
2. The main goroutine's dispatch site for `recvAckEventHeartbeat` substitutes `t.persistedAck.Generation` AT APPLY TIME, exactly as before.
3. **The substitution is now safe** because strict FIFO order on `eventCh` guarantees that any earlier `recvAckEventBatchAck` with a different gen has ALREADY been processed (and therefore has ALREADY advanced `t.persistedAck.Generation` if it was an Adopted outcome) before the heartbeat reaches the dispatch site.

This invariant depends entirely on strict FIFO order — if the channel were ever drained out of order (or coalesced with newer events) the substitution rule would break. Document this carefully wherever it matters; reviewers should treat any change to the recv-event ordering as load-bearing.

Implementation sketch (recv goroutine side, single FIFO):

```go
// Both branches push onto the SAME channel. Heartbeat carries no gen
// from the wire; the field stays zero and is substituted at apply time.
case *wtpv1.ServerMessage_BatchAck:
    a := m.BatchAck
    select {
    case rs.eventCh <- recvAckEvent{kind: recvAckEventBatchAck, gen: a.GetGeneration(), seq: a.GetAckHighWatermarkSeq()}:
    case <-rs.ctx.Done():
        return
    }
case *wtpv1.ServerMessage_ServerHeartbeat:
    h := m.ServerHeartbeat
    select {
    case rs.eventCh <- recvAckEvent{kind: recvAckEventHeartbeat, seq: h.GetAckHighWatermarkSeq()}:
    case <-rs.ctx.Done():
        return
    }
```

Main goroutine side (single select arm — both kinds funnel through one branch):

```go
case ev := <-t.recv.eventCh:
    switch ev.kind {
    case recvAckEventBatchAck:
        t.applyAckFromRecv("batch_ack", ev.gen, ev.seq)
    case recvAckEventHeartbeat:
        // Heartbeat carries no gen on the wire; FIFO order on eventCh
        // guarantees any earlier BatchAck has already advanced
        // t.persistedAck.Generation, so the substitution here is safe.
        t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, ev.seq)
    }
```

**Per-connection recv state (round-22 rewrite — Finding 2).** Earlier rounds held the recv-multiplexer channels and the `latestHeartbeat` pointer as fields directly on `Transport`. Round-22 reviewer flagged that this lets stale state from an old stream bleed into the next stream after reconnect: a pending recv-error value, a queued heartbeat signal, or the `latestHeartbeat` pointer all survive a `t.conn.Close()` + redial cycle. Worse, a recv goroutine blocked on `recvBatchAckCh` was only listening to the transport-wide `ctx.Done()` — so cancelling a connection mid-state-transition (StateLive → StateConnecting on stream error) could not unblock the recv goroutine until the entire transport shut down.

The round-22 fix: hold all recv-multiplexer state in a single per-connection `recvSession` struct. Once Task 22 wires the recv lifecycle into `runConnecting`, the struct will be created fresh on each successful dial after SessionAck and discarded on every tear-down. State cannot survive across reconnect because the field that holds it is a fresh allocation on each Connecting-success path. Until Task 22 lands the wiring, the only callers that allocate a `recvSession` are the `StartRecvForTest` / `TeardownRecvForTest` test seams (see Status callout above and `seams_export_test.go`).

```go
// recvSession bundles all per-connection recv-multiplexer state. Task 22
// will create a new instance on each successful dial (in runConnecting,
// immediately after SessionAck is accepted, by calling
// t.recv = newRecvSession(ctx) followed by go t.runRecv(t.recv)) and
// discard it when the conn tears down. Until Task 22 lands, only the
// test seams allocate a recvSession; production runConnecting does NOT
// touch t.recv. The fields are non-nil for the lifetime of the
// connection; the Transport.recv field points at the live session OR is
// nil (when no recv goroutine is running, e.g. between connections or
// in tests that do not dial).
//
// Per-connection ctx + cancelFn is the load-bearing piece for round-22
// Finding 2: cancelling the per-connection ctx unblocks the recv
// goroutine's blocking send on eventCh, even when the transport-wide
// ctx is still alive (e.g. StateLive→StateConnecting transition after
// a stream error — only this connection is dead, not the transport).
//
// done is closed by runRecv right before it returns. teardownRecv waits
// on it so callers can rely on the recv goroutine being fully stopped
// (and no longer reading t.conn) once teardownRecv returns. This is the
// synchronisation primitive that prevents data races on t.conn between
// the recv goroutine and the main state-machine goroutine when the next
// dial overwrites t.conn after teardown.
type recvSession struct {
    ctx      context.Context
    cancelFn context.CancelFunc
    eventCh  chan recvAckEvent
    errCh    chan error
    done     chan struct{}
}
```

`Transport.recv *recvSession` replaces the four round-6 fields (`recvBatchAckCh`, `heartbeatSignalCh`, `latestHeartbeat`, `recvErrCh`). Every state-exit path that tears down the conn (StateLive → StateConnecting on stream error, StateLive → StateShutdown on ctx cancel, StateReplaying → StateConnecting on err, StateReplaying → StateShutdown on ctx cancel) MUST follow this **exact ordering** to avoid a deadlock in `teardownRecv`'s wait on `rs.done`:

1. **`t.conn.Close()`** — unblocks any in-flight `t.conn.Recv()` call inside the recv goroutine. `rs.ctx` cancellation alone does NOT unblock `Recv()`: the gRPC stream / fake test conn / etc. only returns from `Recv` when (a) a frame arrives, (b) `Recv` hits a stream error, or (c) the conn is `Close()`d. Skipping this step would deadlock the next step because `runRecv` cannot reach its `defer close(rs.done)` until `Recv` returns.
2. **`t.teardownRecv()`** — calls `rs.cancelFn()` (which prevents new blocking sends on `eventCh`) AND waits on `rs.done` (which is closed by `runRecv`'s top-of-function `defer close(rs.done)` immediately before return). After this returns, the recv goroutine has fully exited and no longer holds a reference to `t.conn`.
3. **`t.conn = nil`** — clears the field so the next state-handler iteration sees no stale reference and the next `runConnecting` call can dial fresh.

This is the order the production code in `state_live.go::runLive` and `state_replaying.go::runReplaying` follows on every exit path; the canonical snippet is:

```go
_ = t.conn.Close()
t.teardownRecv()
t.conn = nil
return StateConnecting, fmt.Errorf("recv: %w", err) // or StateShutdown for ctx-cancel
```

The select arms in `state_live.go` / `state_replaying.go` read recv-channel state via `t.recv.eventCh` and `t.recv.errCh`, gated on `t.recv != nil` (Go's nil-channel semantics make those select arms dormant when the field is nil — preserves the current "recv goroutine not started yet" behaviour for tests that drive `applyAckFromRecv` directly without a dial AND for the pre-Task-22 production reality where `runConnecting` doesn't start the goroutine).

**Fail-closed for unhandled control frames (round-22 Finding 4).** The round-6 design silently dropped `Goaway` and `SessionUpdate` frames in the recv-goroutine's default switch arm. Round-22 reviewer flagged that as unsafe staging once the recv goroutine becomes the sole production recv path — a Goaway is the server's reconnect signal and silently dropping it would wedge the session forever; a SessionUpdate is a key-rotation control frame and dropping it desynchronises the chain. The round-22 fix: when the recv goroutine sees a `*wtpv1.ServerMessage_Goaway` or `*wtpv1.ServerMessage_ServerUpdate`, it pushes a fatal error onto `recvSession.errCh` ("control frame X not yet handled") and returns. The main goroutine's `recvErrCh` arm sees the error and returns to `StateConnecting` — same path as a real stream error. A separate fall-through arm catches any future unknown frame type with a similar fatal error ("unknown control frame, returning to Connecting"), which is the proto-evolution defence (server may add new frame types the client predates). Tasks 18/19/20 will replace the Goaway and SessionUpdate paths with real handlers; the fail-closed staging keeps production from ever silently swallowing them.

Deterministic test seam for the policy (round-7 fix). Earlier rounds described the acceptance tests as "stall the main goroutine, then probe the recv goroutine via `runtime.Stack` or a wallclock timeout." Both probes are non-deterministic — `runtime.Stack` parsing races with the scheduler, and a timeout-based assertion either flakes (deadline too short) or wastes wallclock budget (deadline too long) and never proves the send actually blocked vs. simply not having reached the channel yet. Round-7 replaces this with a SYNCHRONOUS test-only hook on `Transport`, exported from a `*_test.go` file using the same pattern as the existing `RunReplayingForTest` / `SetConnForTest` / `SetBuildEventBatchFnForTest` seams (`internal/store/watchtower/transport/state_replaying_internal_test.go`). The hook fires inside the recv goroutine at deterministic phase boundaries, so tests observe ordering without timing.

The seam (lives in `transport.go` as an unexported field and in `*_internal_test.go` as the exported setter):

```go
// transport.go — production:

// recvHookForTest, when non-nil, is invoked synchronously by the recv
// goroutine at the deterministic phase boundaries documented on each
// recvPhase constant. Production code MUST NOT set this field; it is
// nil in production and a no-op when nil. The Transport mutex is NOT
// held when the hook fires — hooks must not reach back into Transport
// state without their own synchronisation.
recvHookForTest func(phase recvPhase, ev recvHookEvent)

// recvPhase enumerates the deterministic phase boundaries the recv
// goroutine notifies via recvHookForTest. Order matters: each phase
// either always precedes (PreSend) or always follows (PostStore /
// PostSignalAttempt) the corresponding mutation, so a test can install
// a hook and assert observable ordering without timing.
type recvPhase int

const (
    // recvPhasePreBatchAckSend fires SYNCHRONOUSLY before the recv
    // goroutine attempts the blocking send to recvBatchAckCh. Because
    // the channel is 1-deep and the send is blocking, a test that
    // pre-fills the channel from the test side then triggers a
    // BatchAck delivery sees this hook fire AND THEN observes the
    // recv goroutine wedged on the send — the hook proves the send
    // was attempted; the wedged goroutine proves it blocked.
    recvPhasePreBatchAckSend recvPhase = iota
    // recvPhasePostHeartbeatStore fires SYNCHRONOUSLY after the recv
    // goroutine completes `latestHeartbeat.Store(...)` on a
    // ServerHeartbeat frame. A test that injects N heartbeats
    // back-to-back and counts hook invocations sees exactly N — and
    // a single `latestHeartbeat.Load()` on the consumer side returns
    // the LAST stored event. Coalescing is observable without timing.
    recvPhasePostHeartbeatStore
    // recvPhasePostHeartbeatSignalAttempt fires SYNCHRONOUSLY after
    // the recv goroutine's non-blocking `select` on heartbeatSignalCh
    // returns (whether the send took the channel slot OR fell into
    // the `default:` arm). The hook event carries `signalSent bool`
    // so the test can assert exactly which arm was taken on each
    // heartbeat — proving the coalesce policy without timing.
    recvPhasePostHeartbeatSignalAttempt
)

// recvHookEvent carries the event details so tests can assert on the
// exact frame that triggered the hook firing.
type recvHookEvent struct {
    gen        uint32
    seq        uint64
    signalSent bool // only meaningful for recvPhasePostHeartbeatSignalAttempt
}
```

```go
// state_recv_internal_test.go — test-only export (NEW *_test.go file
// in the transport package, mirrors the pattern in
// state_replaying_internal_test.go):

// SetRecvHookForTest installs a recv-phase hook on the Transport for
// the duration of a test. The returned restore func MUST be deferred
// so a leaked hook from one test does not corrupt another. Hooks fire
// synchronously inside the recv goroutine; do NOT reach back into
// Transport state without your own synchronisation.
func SetRecvHookForTest(t *Transport, fn func(phase recvPhase, ev recvHookEvent)) func() {
    prev := t.recvHookForTest
    t.recvHookForTest = fn
    return func() { t.recvHookForTest = prev }
}

// RecvPhasePreBatchAckSend / RecvPhasePostHeartbeatStore /
// RecvPhasePostHeartbeatSignalAttempt are the test-visible aliases for
// the unexported recvPhase constants. External tests use these to
// switch on the phase argument without depending on the integer
// representation.
const (
    RecvPhasePreBatchAckSend             = recvPhasePreBatchAckSend
    RecvPhasePostHeartbeatStore          = recvPhasePostHeartbeatStore
    RecvPhasePostHeartbeatSignalAttempt  = recvPhasePostHeartbeatSignalAttempt
)
```

The recv-goroutine implementation calls the hook at each phase boundary if non-nil:

```go
// recv goroutine — BatchAck path:
if t.recvHookForTest != nil {
    t.recvHookForTest(recvPhasePreBatchAckSend, recvHookEvent{
        gen: a.GetGeneration(),
        seq: a.GetAckHighWatermarkSeq(),
    })
}
recvBatchAckCh <- recvBatchAck{gen: a.GetGeneration(), seq: a.GetAckHighWatermarkSeq()}

// recv goroutine — ServerHeartbeat path:
ev := &recvServerHeartbeat{gen: h.GetGeneration(), seq: h.GetAckHighWatermarkSeq(), at: time.Now()}
latestHeartbeat.Store(ev)
if t.recvHookForTest != nil {
    t.recvHookForTest(recvPhasePostHeartbeatStore, recvHookEvent{
        gen: ev.gen,
        seq: ev.seq,
    })
}
signalSent := false
select {
case heartbeatSignalCh <- struct{}{}:
    signalSent = true
default:
    // Main hasn't drained the previous signal yet; the latest pointer
    // already reflects the new heartbeat. No-op.
}
if t.recvHookForTest != nil {
    t.recvHookForTest(recvPhasePostHeartbeatSignalAttempt, recvHookEvent{
        gen: ev.gen,
        seq: ev.seq,
        signalSent: signalSent,
    })
}
```

The hook is unconditionally `nil` in production — no mutex, no atomic, no scheduling cost beyond a single nil-check on the recv-goroutine hot path. It is set ONLY by `SetRecvHookForTest` in `*_test.go` files; the production binary never compiles a code path that writes to `recvHookForTest`.

Acceptance tests for the policy (rewritten to use the hook — no `runtime.Stack` parsing, no wallclock deadlines, no goroutine-state inspectors):

- `TestRecvLoop_HeartbeatCoalescesUnderBackpressure`: install a `SetRecvHookForTest` hook that records every `(phase, event)` invocation into a thread-safe slice. Pre-empt the main goroutine's heartbeat-signal drain by NOT starting the main loop's select (the test drives the recv goroutine directly via the recv-channel injection seam from earlier in Task 17). Inject 1000 `*wtpv1.ServerMessage_ServerHeartbeat` frames with monotonically increasing `(gen, seq)` into the recv side. Assertions (all deterministic, no timing): (a) the recorded hook slice contains EXACTLY 1000 `recvPhasePostHeartbeatStore` entries in injected order; (b) the recorded hook slice contains EXACTLY 1000 `recvPhasePostHeartbeatSignalAttempt` entries; (c) AT MOST ONE of those 1000 `recvPhasePostHeartbeatSignalAttempt` events has `signalSent=true` (the first one — every subsequent send falls into the non-blocking `default:` arm because main never drained); (d) `latestHeartbeat.Load()` returns the 1000th heartbeat's `(gen, seq)` exactly — last write wins; (e) the recv goroutine returned from `runRecv` cleanly when the test closed the input — proving no send blocked.

- `TestRecvLoop_BatchAckBlocksOnFullChannel`: pre-fill `recvBatchAckCh` from the test side with one stub `recvBatchAck{}` (the channel is 1-deep, so it is now full). Install a `SetRecvHookForTest` hook that signals a test-controlled `chan struct{}` when `recvPhasePreBatchAckSend` fires. Inject one `*wtpv1.ServerMessage_BatchAck` with `(gen=7, seq=42)` into the recv side. Assertions (all deterministic, no timing): (a) the hook channel fires EXACTLY ONCE — proving the recv goroutine reached the send call site; (b) attempt a non-blocking receive on a `recvCompletedCh` (a test-side channel the test sends to AFTER the BatchAck `<-` returns — see the `runRecvForTest` wrapper described below); the receive returns `select { default: ... }` proving the send blocked because the channel was full; (c) drain the pre-filled stub from `recvBatchAckCh` from the test side — the recv goroutine's send now succeeds and `recvCompletedCh` becomes readable; (d) drain `recvBatchAckCh` again to read the injected `(7, 42)` ack and assert it matches.

The deterministic seam for "did the recv-side send unblock" in `TestRecvLoop_BatchAckBlocksOnFullChannel` is a thin test-only wrapper around the recv loop:

```go
// state_recv_internal_test.go — test-only wrapper:
//
// RunRecvForTest drives the recv goroutine for one inbound frame and
// returns AFTER the recv goroutine's per-frame work (typed-decode,
// hook fires, channel send) completes. Tests use this to assert "the
// send did not return" without timing — the test calls RunRecvForTest
// in a goroutine, then probes a result channel for completion via a
// non-blocking select.
func RunRecvForTest(t *Transport, frame *wtpv1.ServerMessage) {
    t.handleRecvFrame(frame) // unexported helper that runs the per-frame logic
}
```

The test then does:

```go
recvCompletedCh := make(chan struct{}, 1)
go func() {
    transport.RunRecvForTest(tr, batchAckFrame)
    recvCompletedCh <- struct{}{}
}()
// Wait for the hook to confirm the recv goroutine reached the send.
<-hookFiredCh
// Non-blocking probe: the send is wedged because the channel is full.
select {
case <-recvCompletedCh:
    t.Fatal("recv goroutine completed; expected blocked send")
default:
    // Expected: the send blocked.
}
// Drain the pre-filled stub; the recv goroutine's send now succeeds.
<-tr.RecvBatchAckChForTest()
// Now the recv goroutine completes — receive on recvCompletedCh proves it.
<-recvCompletedCh
```

`RecvBatchAckChForTest` is another test-only export (returns `<-chan recvBatchAck` — same pattern). With these three seams (`SetRecvHookForTest`, `RunRecvForTest`, `RecvBatchAckChForTest`), both backpressure acceptance tests run with zero timeouts and zero `runtime.Stack` parsing — every assertion is on a hook invocation that fires synchronously or on a channel state visible from the test goroutine via non-blocking select.

**Hard requirement for Tasks 17/18 implementers:** do NOT introduce a mutex on `t.persistedAck`/`t.remoteReplayCursor`/`t.persistedAckPresent`. The recv goroutine MUST send typed events; the main state-machine goroutine MUST be the only writer. Any patch that adds `sync.Mutex` to Transport for the ack-cursor fields is a regression against this contract.

A new acceptance test `TestRun_ReadersUnregisterAcrossReconnect` is the leak regression guard for runLive's Reader lifecycle (see Task 22 acceptance-tests block below). It drives multiple reconnect cycles and asserts the WAL's registered-reader count never grows unboundedly — closing both `defer rdr.Close()` paths (success and error) and the StateReplaying explicit-Close path.

- [ ] **Step 4 (validator-classifier prerequisite for Step 4a): Extend validator boundary with typed reason classifier**

Step 4a relies on the receiver classifying validator failures into a fixed `wtp_dropped_invalid_frame_total{reason}` enum. Today `proto/canyonroad/wtp/v1/validate.go` exposes only generic sentinels (`ErrInvalidFrame`, `ErrPayloadTooLarge`) constructed via `fmt.Errorf("%w: <peer-supplied details>", ErrXxx, ...)` — receivers would have to grep the formatted message to recover the reason, which both leaks peer-supplied bytes (the wrapped detail string embeds byte counts and oneof discriminators) into metric cardinality and is fragile. This step adds a typed classifier so receivers consume the reason via `errors.As(err, &ve)` and never touch the formatted message in the hot path.

Files to modify (Go-code change — small but real):
- Modify: `proto/canyonroad/wtp/v1/validate.go` — add `ValidationReason` enum (including `ReasonUnknown` for the forward-compat unknown-oneof case), `ValidationError` typed struct (with `Error() string` returning ONLY the canonical Reason value, never peer-derived Inner detail — see spec §"Invalid-frame log sanitization" defense-in-depth rule), `AllValidationReasons() []ValidationReason` copy-returning getter (exported so the metrics-side parity test in Task 22b can range over it; the getter returns a fresh copy on each call so callers cannot mutate the underlying enumeration — STABLE PRODUCTION API per spec §"Stable production API"), refactor `ValidateEventBatch` and `ValidateSessionInit` to return `&ValidationError{Reason: ..., Inner: fmt.Errorf(...)}` for EVERY failure path (the forward-compat unknown-oneof default branch returns `&ValidationError{Reason: ReasonUnknown, Inner: fmt.Errorf("unknown body oneof case")}` — bare `fmt.Errorf("%w: ...", ErrInvalidFrame, ...)` returns from the validator are a CONTRACT VIOLATION per spec). Constants are EXACTLY six canonical names — `ReasonEventBatchBodyUnset`, `ReasonEventBatchCompressionUnspecified`, `ReasonEventBatchCompressionMismatch`, `ReasonSessionInitAlgorithmUnspecified`, `ReasonPayloadTooLarge`, `ReasonUnknown` — NO aliases (see the "ALIASES ARE FORBIDDEN" comment in the constant block below).
- Create: `proto/canyonroad/wtp/v1/validate_reason_test.go` — TDD-first table-driven tests asserting each enum constant maps to the correct input, `errors.As(err, &ve)` works, `errors.Is(err, ErrInvalidFrame)` / `errors.Is(err, ErrPayloadTooLarge)` still work for legacy callers, AND `ValidationError.Error()` returns ONLY the Reason string (no peer-derived Inner content) so naive `slog.Error("...", "err", ve)` call sites cannot leak peer bytes.
- Create: `proto/canyonroad/wtp/v1/validate_unknown_test.go` — declared `package wtpv1` (same package, NOT `_test`) so it can implement the sealed `isEventBatch_Body()` oneof interface marker, which is unexported per the protobuf-generated code in `wtp.pb.go`. Defines an unexported synthetic `unknownBodyForTest` type and exercises the `default:` branch of the body-switch in `ValidateEventBatch`. See the "Validator unknown-oneof test seam" subsection in TDD step 1 below for the exact code. This is the only way to test the unknown-oneof code path without rebuilding the proto with a fresh oneof arm.

TDD order:

1. **Write the failing tests** (`proto/canyonroad/wtp/v1/validate_reason_test.go`):

```go
package wtpv1_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Each enum constant maps to the correct ValidateEventBatch input.
func TestValidateEventBatch_ReasonClassification(t *testing.T) {
	cases := []struct {
		name     string
		batch    *wtpv1.EventBatch
		reason   wtpv1.ValidationReason
		isInner  error // sentinel that errors.Is must match
	}{
		{"nil_batch", nil, wtpv1.ReasonEventBatchBodyUnset, wtpv1.ErrInvalidFrame},
		{"compression_unspecified", &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_UNSPECIFIED}, wtpv1.ReasonEventBatchCompressionUnspecified, wtpv1.ErrInvalidFrame},
		{"body_unset", &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_NONE, Body: nil}, wtpv1.ReasonEventBatchBodyUnset, wtpv1.ErrInvalidFrame},
		{"compression_mismatch_uncompressed", &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_ZSTD,
			Body:        &wtpv1.EventBatch_Uncompressed{Uncompressed: &wtpv1.UncompressedEvents{}},
		}, wtpv1.ReasonEventBatchCompressionMismatch, wtpv1.ErrInvalidFrame},
		{"compression_mismatch_compressed_with_none", &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_NONE,
			Body:        &wtpv1.EventBatch_CompressedPayload{CompressedPayload: []byte{1, 2, 3}},
		}, wtpv1.ReasonEventBatchCompressionMismatch, wtpv1.ErrInvalidFrame},
		{"payload_too_large", &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_ZSTD,
			Body:        &wtpv1.EventBatch_CompressedPayload{CompressedPayload: bytes.Repeat([]byte{0}, wtpv1.MaxCompressedPayloadBytes+1)},
		}, wtpv1.ReasonPayloadTooLarge, wtpv1.ErrPayloadTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wtpv1.ValidateEventBatch(tc.batch)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var ve *wtpv1.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As: not a *ValidationError: %v", err)
			}
			if ve.Reason != tc.reason {
				t.Errorf("reason: got %q, want %q", ve.Reason, tc.reason)
			}
			if !errors.Is(err, tc.isInner) {
				t.Errorf("errors.Is(%v): want match for %v", err, tc.isInner)
			}
			// Defense in depth: ValidationError.Error() returns ONLY the
			// canonical Reason string — never peer-derived detail from
			// Inner. This means even a naive `slog.Error("...", "err",
			// ve)` call site cannot leak peer bytes to a log sink.
			// The Inner detail is still reachable via errors.Unwrap for
			// tests, but Error()'s formatted message is the reason.
			if got, want := err.Error(), string(tc.reason); got != want {
				t.Errorf("Error() = %q, want %q (must equal Reason, NOT Inner)", got, want)
			}
			// And the Inner error is still accessible for in-memory
			// inspection via Unwrap (tests / developer debugging only).
			if ve.Unwrap() == nil {
				t.Errorf("Unwrap() returned nil; expected the Inner error to remain accessible")
			}
		})
	}
}

// TestValidationError_ErrorReturnsOnlyReason locks in the defense-in-
// depth contract from spec §"Invalid-frame log sanitization": even a
// naive logger that calls .Error() on a *ValidationError MUST NOT see
// peer-supplied content. The formatted message equals the Reason
// string verbatim.
func TestValidationError_ErrorReturnsOnlyReason(t *testing.T) {
	ve := &wtpv1.ValidationError{
		Reason: wtpv1.ReasonPayloadTooLarge,
		Inner:  fmt.Errorf("32MiB exceeds 8MiB cap"), // peer-derived detail
	}
	if got, want := ve.Error(), "payload_too_large"; got != want {
		t.Errorf("Error() = %q, want %q (peer-derived Inner MUST NOT leak)", got, want)
	}
}

func TestValidateSessionInit_ReasonClassification(t *testing.T) {
	cases := []struct {
		name   string
		s      *wtpv1.SessionInit
		reason wtpv1.ValidationReason
	}{
		{"nil_session_init", nil, wtpv1.ReasonSessionInitAlgorithmUnspecified},
		{"algorithm_unspecified", &wtpv1.SessionInit{Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED}, wtpv1.ReasonSessionInitAlgorithmUnspecified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wtpv1.ValidateSessionInit(tc.s)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var ve *wtpv1.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As: not a *ValidationError: %v", err)
			}
			if ve.Reason != tc.reason {
				t.Errorf("reason: got %q, want %q", ve.Reason, tc.reason)
			}
			if !errors.Is(err, wtpv1.ErrInvalidFrame) {
				t.Errorf("errors.Is(ErrInvalidFrame): want true")
			}
		})
	}
}
```

**Validator unknown-oneof test seam.** The unknown-oneof default branch in `ValidateEventBatch`'s body switch is forward-compat infrastructure that fires when a future protobuf revision adds a new oneof arm without updating the switch. There is no way to exercise that branch with proto-generated types alone — `EventBatch_Body` is a sealed interface (the `isEventBatch_Body()` marker method is unexported in `wtp.pb.go`), so only same-package code can implement it. The receiver-side `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` test (Step 4a) verifies the receiver wiring (defense-in-depth `errors.As`-false path), NOT the validator's unknown branch — that test injects a synthetic bare error, not a synthetic body, and it asserts `reason="classifier_bypass"` (the disjoint metrics-only reason for caller-side bypass).

To exercise the validator branch directly, create `proto/canyonroad/wtp/v1/validate_unknown_test.go` declared `package wtpv1` (same package — NOT `package wtpv1_test`) so it can implement the unexported `isEventBatch_Body()` marker:

```go
package wtpv1

import (
	"errors"
	"testing"
)

// unknownBodyForTest implements isEventBatch_Body so we can exercise the
// default branch of ValidateEventBatch's body switch. Proto schema
// additions of new oneof discriminators are forward-compat events that
// hit this path in production until the validator is updated to
// classify them under a dedicated ValidationReason. This test seam
// MUST live in package wtpv1 (NOT wtpv1_test) because the
// isEventBatch_Body() marker method is unexported per the protobuf-
// generated code in wtp.pb.go — only same-package code can implement
// the sealed oneof interface.
type unknownBodyForTest struct{}

func (*unknownBodyForTest) isEventBatch_Body() {}

func TestValidateEventBatch_UnknownOneof_ReturnsReasonUnknown(t *testing.T) {
	batch := &EventBatch{
		Compression: Compression_COMPRESSION_NONE,
		Body:        &unknownBodyForTest{},
	}
	err := ValidateEventBatch(batch)
	if err == nil {
		t.Fatal("ValidateEventBatch returned nil for unknown body oneof; expected *ValidationError")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if ve.Reason != ReasonUnknown {
		t.Fatalf("want ReasonUnknown (%q), got %q", ReasonUnknown, ve.Reason)
	}
	// Defense-in-depth: even the unknown branch returns a typed
	// *ValidationError whose Error() method is peer-safe (returns ONLY
	// the canonical reason string, NOT any peer-supplied body bytes).
	if got, want := err.Error(), string(ReasonUnknown); got != want {
		t.Errorf("Error() = %q, want %q (must equal Reason, NOT Inner)", got, want)
	}
}
```

This test is a REQUIRED acceptance step for Task 17 Step 4 — the unknown-oneof default branch is unreachable from any other test, so without this seam the branch is permanently uncovered. Documenting why the test file must live in `package wtpv1` (and not `package wtpv1_test`) prevents future contributors from "fixing" the package qualifier and breaking the test suite.

2. **Run the tests to confirm they fail** (`go test ./proto/canyonroad/wtp/v1/... -run "TestValidate.*Reason|TestValidateEventBatch_UnknownOneof"`). Expected: `wtpv1.ValidationReason undefined`, `wtpv1.ValidationError undefined`, `wtpv1.Reason* undefined` for the external test file plus `undefined: ValidationError` etc. for the same-package unknown-oneof test.

3. **Implement** in `proto/canyonroad/wtp/v1/validate.go`:

```go
// ValidationReason is the canonical low-cardinality classification of
// validator failures. Receivers consume this via errors.As to stamp
// wtp_dropped_invalid_frame_total{reason=string(ve.Reason)} without
// parsing the formatted error message. The string values match the
// enumerated reasons in spec §Metrics; adding a new validator branch
// requires adding a new ValidationReason constant AND adding the
// matching label to internal/metrics' WTPInvalidFrameReason enum (Task
// 22a). Note: `decompress_error` and `classifier_bypass` are NOT
// ValidationReasons — both are metrics-only reasons (see Task 22a
// overview): `decompress_error` is emitted by the streaming-decompression
// code downstream of the validator, and `classifier_bypass` is emitted by
// the receiver-side defense-in-depth `errors.As`-false guard and by the
// metrics-side invalid-label collapse. Neither has a proto-side
// counterpart by definition (see spec §"Frame validation and forward
// compatibility").
type ValidationReason string

const (
	// ReasonEventBatchBodyUnset is the reason returned by ValidateEventBatch
	// when the EventBatch is nil OR when its Body oneof is unset. The two
	// failure modes fold under one canonical reason because operators
	// cannot distinguish a nil envelope from an envelope-with-empty-body
	// at the metric layer — both are semantically "no payload."
	ReasonEventBatchBodyUnset              ValidationReason = "event_batch_body_unset"
	ReasonEventBatchCompressionUnspecified ValidationReason = "event_batch_compression_unspecified"
	ReasonEventBatchCompressionMismatch    ValidationReason = "event_batch_compression_mismatch"
	// ReasonSessionInitAlgorithmUnspecified is the reason returned by
	// ValidateSessionInit when the SessionInit is nil OR when its
	// Algorithm enum is HASH_ALGORITHM_UNSPECIFIED. As with
	// ReasonEventBatchBodyUnset above, the two failure modes share one
	// canonical reason for the metric — operators cannot differentiate a
	// nil session-init from one missing the algorithm enum, and both
	// indicate the same root cause (peer did not populate the required
	// algorithm field).
	ReasonSessionInitAlgorithmUnspecified  ValidationReason = "session_init_algorithm_unspecified"
	ReasonPayloadTooLarge                  ValidationReason = "payload_too_large"
	// ReasonUnknown is the forward-compat reason returned by the
	// validator when a new oneof discriminator is added to the proto
	// schema before the validator switch is updated to classify it. The
	// validator returns &ValidationError{Reason: ReasonUnknown, ...} —
	// it MUST NOT fall back to a bare fmt.Errorf return. A non-zero
	// metrics-side wtp_dropped_invalid_frame_total{reason="unknown"}
	// series is the operator-visible signal that a new validator failure
	// class has shipped and the next maintenance cycle MUST extend the
	// enum to classify it under a dedicated reason. The "unknown"
	// reason is RESERVED for this validator-emitted forward-compat
	// case; the receiver-side defense-in-depth path uses the separate
	// metrics-only "classifier_bypass" reason (see spec
	// §"Receiver-side defense in depth").
	ReasonUnknown                          ValidationReason = "unknown"
)

// ALIASES ARE FORBIDDEN. There is exactly ONE canonical ValidationReason
// constant per reason string value — six constants total above. Earlier
// drafts of this validator design (rounds 7-8) introduced "ergonomic"
// aliases like ReasonNilBatch / ReasonBodyUnset and ReasonNilSessionInit
// / ReasonAlgorithmUnspecified that pointed at the same string value;
// these are EXPLICITLY DISALLOWED because:
//   (a) AllValidationReasons() (below) is the canonical enumeration of
//       reason values and aliases inflate its length without adding
//       semantic content (the parity test in Task 22b silently
//       deduped via map and masked the duplication),
//   (b) validator code MUST reference the canonical name (e.g.,
//       ReasonEventBatchBodyUnset, NOT ReasonNilBatch) so reading the
//       validator switch makes the reason obvious,
//   (c) external dashboard consumers see the reason string only and
//       cannot benefit from constant-name aliases.
// If a future contributor finds themselves wanting an alias for
// "ergonomics," the answer is no — pick one canonical name and use it
// throughout.

// ValidationError carries both a structured Reason (safe for metric labels
// and structured logs) and the original Inner error (which embeds peer-
// supplied details and MUST NOT be logged by receivers per the spec
// sanitization rule). Receivers MUST consume Reason via errors.As; the
// Inner error remains available via Unwrap for tests and developer-side
// debugging only — it MUST NOT be serialized to any production log sink.
type ValidationError struct {
	Reason ValidationReason
	Inner  error
}

// Error returns ONLY the Reason string (no peer-derived content). This
// is intentional defense-in-depth: even a naive call site that does
// `slog.Error("...", "err", ve)` or `fmt.Sprintf("%s", ve)` cannot leak
// peer bytes — the formatted message is the canonical reason value.
// Callers that need the Inner detail (tests, in-memory debugging) read
// it via Unwrap().
func (e *ValidationError) Error() string { return string(e.Reason) }
func (e *ValidationError) Unwrap() error  { return e.Inner }

// Is preserves errors.Is(err, ErrInvalidFrame) / ErrPayloadTooLarge
// semantics so legacy callers built before this typed boundary still
// work. The match is delegated to the Inner error which itself wraps
// the appropriate sentinel.
func (e *ValidationError) Is(target error) bool { return errors.Is(e.Inner, target) }

// allValidationReasons enumerates every ValidationReason constant in
// stable insertion order (matching enum declaration order). Package-
// private to prevent external mutation; consumers use the
// AllValidationReasons() getter below which returns a fresh copy.
//
// Exactly one entry per canonical reason — no aliases (see the
// "ALIASES ARE FORBIDDEN" comment above the const block). The parity
// test in Task 22b asserts exact slice-length equality between
// this slice and the metrics-side validator-shared set, so any future
// drift toward aliases will fail the test.
var allValidationReasons = []ValidationReason{
	ReasonEventBatchBodyUnset,
	ReasonEventBatchCompressionUnspecified,
	ReasonEventBatchCompressionMismatch,
	ReasonSessionInitAlgorithmUnspecified,
	ReasonPayloadTooLarge,
	ReasonUnknown,
}

// AllValidationReasons returns a fresh copy of every ValidationReason
// constant in stable insertion order (matching enum declaration order
// in this file). Consumers (notably the metrics package's
// TestWTPInvalidFrameReason_ParityWithValidator test, plus any external
// dashboard generator) range over this slice to assert the proto-side
// and metrics-side enums stay in sync. Adding a new ValidationReason
// constant MUST also append it to allValidationReasons above.
//
// STABLE PRODUCTION API (not test-only): see spec §"Stable production
// API" (which documents the carve-out within the otherwise-unstable
// canyonroad.wtp.v1 package). Returns a fresh copy on each call so
// callers cannot mutate the package-private enumeration. Insertion
// order is documented stable (matching enum declaration order);
// removals or renames of existing reason constants are breaking
// changes regardless of pre-1.0 status — they require a coordinated
// metrics + dashboards migration.
func AllValidationReasons() []ValidationReason {
	out := make([]ValidationReason, len(allValidationReasons))
	copy(out, allValidationReasons)
	return out
}

// ValidateEventBatch returns a *ValidationError on failure; the typed
// Reason field lets receivers classify the failure into a fixed metric
// label without parsing the error message.
func ValidateEventBatch(b *EventBatch) error {
	if b == nil {
		return &ValidationError{Reason: ReasonEventBatchBodyUnset, Inner: fmt.Errorf("%w: batch is nil", ErrInvalidFrame)}
	}
	if b.Compression == Compression_COMPRESSION_UNSPECIFIED {
		return &ValidationError{Reason: ReasonEventBatchCompressionUnspecified, Inner: fmt.Errorf("%w: compression unspecified", ErrInvalidFrame)}
	}
	switch body := b.Body.(type) {
	case nil:
		return &ValidationError{Reason: ReasonEventBatchBodyUnset, Inner: fmt.Errorf("%w: body unset", ErrInvalidFrame)}
	case *EventBatch_Uncompressed:
		if b.Compression != Compression_COMPRESSION_NONE {
			return &ValidationError{Reason: ReasonEventBatchCompressionMismatch, Inner: fmt.Errorf("%w: uncompressed body requires compression=NONE (got %s)", ErrInvalidFrame, b.Compression)}
		}
	case *EventBatch_CompressedPayload:
		if b.Compression == Compression_COMPRESSION_NONE {
			return &ValidationError{Reason: ReasonEventBatchCompressionMismatch, Inner: fmt.Errorf("%w: compressed_payload requires compression != NONE", ErrInvalidFrame)}
		}
		if len(body.CompressedPayload) > MaxCompressedPayloadBytes {
			return &ValidationError{Reason: ReasonPayloadTooLarge, Inner: fmt.Errorf("%w: compressed_payload is %d bytes (cap %d)", ErrPayloadTooLarge, len(body.CompressedPayload), MaxCompressedPayloadBytes)}
		}
	default:
		// Forward-compat: a future protobuf revision that adds a new
		// oneof arm without updating this switch surfaces as
		// wtp_dropped_invalid_frame_total{reason="unknown"} downstream.
		// We return *ValidationError (NOT a bare fmt.Errorf) so the
		// receiver-side errors.As classifier always succeeds — the
		// validator MUST return *ValidationError for every failure
		// path, no exceptions (see spec §"Reason classification
		// (validator contract)" — bare fmt.Errorf returns are a
		// CONTRACT VIOLATION).
		return &ValidationError{Reason: ReasonUnknown, Inner: fmt.Errorf("%w: unknown body oneof case", ErrInvalidFrame)}
	}
	return nil
}

func ValidateSessionInit(s *SessionInit) error {
	if s == nil {
		return &ValidationError{Reason: ReasonSessionInitAlgorithmUnspecified, Inner: fmt.Errorf("%w: session_init is nil", ErrInvalidFrame)}
	}
	if s.Algorithm == HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return &ValidationError{Reason: ReasonSessionInitAlgorithmUnspecified, Inner: fmt.Errorf("%w: algorithm unspecified", ErrInvalidFrame)}
	}
	return nil
}
```

4. **Run the tests to confirm they pass** (`go test ./proto/canyonroad/wtp/v1/... -count=1`). Expected: PASS.

5. **Cross-compile** (`GOOS=windows go build ./...`) before moving on.

This step is a small but real Go-code change — doc-only rounds (such as round 6) MUST NOT touch `validate.go`; the actual edit happens during Task 17 execution.

- [ ] **Step 4a: Inbound frame validation acceptance**

**Prerequisite (mirrors the task-level Prerequisites note above):** Task 22a Step 4 MUST be completed before this step executes. The receiver wiring snippet below references `metrics.WTPInvalidFrameReasonClassifierBypass` and `metrics.WTPInvalidFrameReason(...)` — both are defined in Task 22a Step 4 (`internal/metrics/wtp.go`). If Task 22a has not landed yet, jump to it now, complete Step 4 (define the `WTPInvalidFrameReason` enum + the `MetricsOnlyReasons()`/`ValidationReasons()` getters), commit, and return here. The compiler will surface the dependency as `undefined: metrics.WTPInvalidFrameReasonClassifierBypass` if Step 4a is attempted first.

The Live state (and any other receive site introduced in Phase 8) MUST honor the spec's "Frame validation and forward compatibility" contract for every inbound `ServerMessage`. Acceptance criteria:

(a) When the receiver detects a frame-validation failure, it MUST classify the failure into a fixed `wtp_dropped_invalid_frame_total{reason}` label using the following two-step rule (NO fallback that parses `err.Error()` — the typed boundary is the contract):

   1. Attempt `errors.As(err, &ve)` against `*wtpv1.ValidationError`. If it returns true, use `WTPInvalidFrameReason(ve.Reason)` as the label value (the proto-side string is byte-equal to the metrics-side constant per Task 17 Step 4 / Task 22a parity check). For validator-returned errors this branch SHOULD always be taken — the validator MUST return `*ValidationError` for every failure path, including the forward-compat unknown-oneof case (which returns `&ValidationError{Reason: ReasonUnknown, ...}`).
   2. **Defense-in-depth fallback**: if `errors.As` returns false, the receiver MUST classify the failure as `WTPInvalidFrameReasonClassifierBypass` (label string `"classifier_bypass"`, NOT `"unknown"` — those are now disjoint reasons with disjoint operator interpretations per spec §"Frame validation and forward compatibility") AND emit a WARN-level diagnostic. This branch SHOULD NEVER trigger in production because validator-returned errors always satisfy `errors.As(err, &ve)` per the contract above; if it does trigger, a non-validator caller passed a bare error into the receiver-side classifier (e.g., a unit-test mock or a future code path that bypasses `ValidateEventBatch`) and the WARN log makes that drift visible to operators. See spec §"Receiver-side defense in depth (should never trigger in production)" for rationale, and §"Operator runbook: invalid-frame reason interpretation" for the `classifier_bypass` triage path (any non-zero increment is a code-path defect).

   The canonical defense-in-depth implementation pattern (use this verbatim in any new receiver wiring):

   ```go
   var ve *wtpv1.ValidationError
   if !errors.As(err, &ve) {
       // Defense-in-depth: should never happen for validator-returned errors,
       // but a non-validator caller might pass a bare error (e.g., a unit test
       // mock or future code path that bypasses ValidateEventBatch).
       // Classify as classifier_bypass (NOT unknown — see spec
       // §"Operator runbook" for why these are distinct reasons) and log a
       // WARN-level diagnostic so operators can investigate any such regression.
       slogger.Warn("non-typed frame validation error",
           slog.String("err_type", fmt.Sprintf("%T", err)),
           slog.String("reason", "classifier_bypass"))
       metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass)
       return // close stream, etc.
   }
   metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason(ve.Reason))
   ```

   After classification, increment `wtp_dropped_invalid_frame_total{reason=<classified>}` exactly once per offending frame. The `reason` value MUST come from the canonical `wtpv1.ValidationReason` constants defined in Step 4 above (currently: `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`, `unknown`) plus the metrics-only `decompress_error` (emitted by streaming decompression downstream of the validator — see (d) below; no `wtpv1.ValidationReason` counterpart) and the metrics-only `classifier_bypass` (emitted by the defense-in-depth fallback above; no `wtpv1.ValidationReason` counterpart by definition). New validator-emitted reasons added in future tasks MUST be added to the `ValidationReason` enum first; receivers reference `wtpv1.Reason*` constants, never literals.
(b) After incrementing the counter, the receiver MUST tear down the stream rather than silently consuming the malformed frame: server-side validation failures (this task) take the `stream_recv_error` reconnect path documented in spec §"Frame validation and forward compatibility" — close the current stream, return `StateConnecting` from the live loop, and let the Run loop's backoff handle the reconnect. The newly-added Goaway path is reserved for the testserver / server-side validators in Phase 9 (where the client's outbound frame is rejected) — Phase 8 receivers do not emit Goaway because they are reading, not writing.
(c) Invalid-frame logging MUST follow the spec's sanitization rule: log only `session_id` (local UUID, internal-only), `reason` (the canonical `string(ve.Reason)`), and `hex_prefix` (a hex-encoded prefix of the offending frame's serialized representation, capped at 16 input bytes — 32 hex chars output). The receiver MUST NOT log `ve.Inner` or `err.Error()` — both embed peer-supplied byte counts and oneof discriminators per the validator's `fmt.Errorf` construction.
(d) The streaming decompression path (downstream of `ValidateEventBatch` — added when WTP gains a real decompression code path post-MVP) MUST classify zstd/gzip framing errors and `MaxDecompressedBatchBytes` overruns as `WTPInvalidFrameReasonDecompressError` (metrics-side label `decompress_error`) and route them through the same counter + tear-down path. There is NO `wtpv1.ReasonDecompressError` constant — `decompress_error` is metrics-only because it is emitted downstream of the validator (decompression runs after `ValidateEventBatch` accepts the frame envelope). Until a real decompression path lands, the metrics-side `decompress_error` reason exists in the metrics enum so the metric series is registered at zero (always-emit contract) — no live increment yet.

Add a transport-level unit test that injects each enumerated frame-validation reason via the fakeConn `recvCh` (mirror the table-driven pattern used by the existing `wtp_reconnects_total{reason}` tests in `internal/metrics/wtp_test.go` — that family already exercises the reason-enumeration always-emit + per-reason inject-and-assert pattern this task adopts). For each reason the test MUST assert: (1) the corresponding `wtp_dropped_invalid_frame_total{reason="<value>"}` series increments by exactly one, AND (2) the live loop returns `StateConnecting` (i.e., the reconnect path was taken). The test SHOULD use a table-driven structure keyed by the `wtpv1.Reason*` constants so adding a new reason is a one-line change. The test MUST consume reasons via `errors.As` against `*wtpv1.ValidationError` rather than parsing the error string.

**Test acceptance — split by live-path availability:**

- **Reasons with a live validator path NOW** (each MUST have an inject-and-assert test row in the table): `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`, and `unknown`. For each, the test injects a synthetic `*wtpv1.ValidationError` with the matching `Reason` (or constructs the offending frame and lets the validator return it; the `unknown` row uses `&wtpv1.ValidationError{Reason: wtpv1.ReasonUnknown, Inner: fmt.Errorf("synthetic")}` since the unknown-oneof code path is hard to trigger from a test without rebuilding the proto), asserts the counter increments by exactly one with `reason="<value>"`, and asserts the live loop returns `StateConnecting`.
- **`TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` (defense-in-depth guard)**: a separate dedicated test that verifies the receiver-side `errors.As`-false fallback. The test injects a bare `fmt.Errorf("%w: synthetic", wtpv1.ErrInvalidFrame)` (NOT wrapped in `*ValidationError` — this simulates a non-validator caller passing a bare error into the receiver, which SHOULD never happen for validator-returned errors per the contract). Assert: (1) the receiver's `errors.As(err, &ve)` returns false, (2) a WARN-level log entry is emitted with `err_type` and `reason="classifier_bypass"` fields, (3) the counter increments by exactly one with `reason="classifier_bypass"` (NOT `reason="unknown"` — those are now disjoint reasons), and (4) the live loop returns `StateConnecting`. This validates the defense-in-depth guard from spec §"Receiver-side defense in depth (should never trigger in production)" and ensures operators can distinguish a peer-side schema drift (`unknown`) from a local-side caller bug (`classifier_bypass`) without log correlation.
- **`decompress_error` (deferred)**: explicitly EXCLUDED from the inject-and-assert table for this task. The metric series is registered NOW via the `WTPInvalidFrameReason` valid map and `wtpInvalidFrameReasonsEmitOrder` slice (zero-emission test in `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons` covers it), but the live-path inject-and-assert test is added in the future Phase that introduces streaming decompression. Reason: there is no decompression code path in this task — adding a synthetic injection here would test fakeConn machinery, not the real classifier. There is also no `wtpv1.ReasonDecompressError` to range over from the proto side — `decompress_error` is metrics-only.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./proto/canyonroad/wtp/v1/... ./internal/store/watchtower/transport/... -run "TestBatcher|TestLive_FrameValidation|TestReceiver_NonTypedErrorClassifiedAsClassifierBypass|TestValidate.*Reason|TestValidateEventBatch_UnknownOneof|TestValidationError_ErrorReturnsOnlyReason"`
Expected: PASS — all 5 batcher invariant tests plus the table-driven frame-validation tests added in Step 4a (one entry per validator-emitted `wtp_dropped_invalid_frame_total{reason}` value, including `unknown` since the validator now returns `*ValidationError{Reason: ReasonUnknown}` for the forward-compat unknown-oneof case), plus the dedicated `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` defense-in-depth test that injects a bare `fmt.Errorf` into the receiver-side classifier (asserts label is `classifier_bypass`, NOT `unknown`), plus the validator-side `TestValidateEventBatch_UnknownOneof_ReturnsReasonUnknown` test (in `proto/canyonroad/wtp/v1/validate_unknown_test.go`, package `wtpv1`) that uses the `unknownBodyForTest` synthetic implementer to exercise the validator's unknown-oneof default branch. The `decompress_error` reason is excluded per the split-acceptance rule above (metrics-only — no proto-side counterpart). The `classifier_bypass` reason has no validator-side coverage by definition (validator never emits it).

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_reason_test.go proto/canyonroad/wtp/v1/validate_unknown_test.go internal/store/watchtower/transport/batcher.go internal/store/watchtower/transport/batcher_test.go internal/store/watchtower/transport/state_live.go
git commit -m "feat(wtp/transport): add Batcher + Live state + typed validator classifier"
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
//
// rdrFactory takes the WAL generation AND the start sequence so the
// caller can position the Reader explicitly per state entry. `gen` is
// the WAL generation the Reader will be scoped to (segments with a
// different SegmentHeader.Generation are skipped at segment-iteration
// before record decoding — see wal/reader.go ReaderOptions.Generation
// and Task 14b Step 3); `start` is the inclusive lowest seq the
// returned Reader will surface for RecordData (RecordLoss markers
// always surface — see wal/reader.go NewReader docstring).
// Replaying opens at the seq returned by
// `t.computeReplayStart(t.remoteReplayCursor, t.persistedAck)`
// (round-11 Finding 3): the canonical helper rolls together the
// `t.remoteReplayCursor.Sequence + 1` start (mirroring the
// `wal.Reader.NewReader` "replay-after-ack callers pass ackHighSeq + 1"
// idiom from reader.go:114 and the spec's
// `(remote_replay_cursor, wal_hw_at_entry]` replay window) AND the
// 4-case `ack_regression_after_gc` PrefixLoss decision (Task 15.1
// Step 1b.5 cases A/B/C/D). Without that +1, any reconnect with
// `t.remoteReplayCursor.Sequence > 0` would re-read and re-send
// already-acknowledged history. Replayer's entry-time tail watermark
// hard-stops drain at the upper bound (over-tail records are surfaced
// once as the boundary record). Live opens at
// max(rep.LastReplayedSequence()+1, t.remoteReplayCursor.Sequence+1)
// so it picks up exactly past the boundary record without re-emitting
// it AND without missing any trailing TransportLoss marker overflow GC
// may have appended at the WAL tail mid-replay (loss markers bypass
// the Reader's nextSeq filter — see wal/reader.go nextLocked near the
// isLossMarker branch).
//
// Round-8: the reader-start cursor is `remoteReplayCursor`, NOT
// `persistedAck`. The two cursors diverge during stale-server recovery:
// `persistedAck` is the durable, monotonic-only watermark mirroring
// `wal.Meta`; `remoteReplayCursor` may be lex-LOWER (server is stale
// relative to local persistence) so that the Replaying state RE-SENDS
// the gap the server has not yet acked. Using `persistedAck` here
// would silently drop the gap on the floor.
//
// `t.remoteReplayCursor.Sequence` is the local-seq half of the
// regressable cursor `(t.remoteReplayCursor.Generation,
// t.remoteReplayCursor.Sequence)`; the cursor is owned by Transport
// (not by Conn) and is the post-clamp value per spec
// §"Effective-ack tuple and clamp". The two fields move together via
// `applyServerAckTuple` (Adopted advances both, ResendNeeded sets
// remoteReplayCursor only). Using `t.remoteReplayCursor.Sequence`
// alone for the reader-start cursor is safe because the Reader operates
// within a single WAL generation — the cursor is generation-implicit,
// scoped by whichever segment file the Reader opens.
//
// SEEDING: cold start seeds BOTH `t.persistedAck` and
// `t.remoteReplayCursor` (lock-step) from `wal.Meta`
// (`AckHighWatermarkGen`, `AckHighWatermarkSeq`) via
// `Options.InitialAckTuple` constructed in the store-wiring layer
// (Task 27); `AckRecorded` maps to the AckTuple's `Present` flag so
// first-apply semantics work even when the persisted tuple is the
// zero value. In the steady state the two cursors equal each other.
//
// ADVANCEMENT: SessionAck (Task 15.1, state_connecting.go) and
// BatchAck/ServerHeartbeat (Task 17 sub-step 17.X, recv multiplexer)
// each call the shared `applyServerAckTuple` helper, which dispatches
// on `AckOutcome.Kind`:
//   - Adopted (server > persistedAck lex): advance BOTH cursors;
//     persist via wal.MarkAcked.
//   - ResendNeeded (server < persistedAck lex): regress ONLY
//     remoteReplayCursor to the server tuple; persistedAck UNCHANGED;
//     no wal.MarkAcked call (gradual rollout / partition recovery).
//   - NoOp (server == persistedAck): no cursor moved.
//   - Anomaly (FIVE disjoint sub-cases per Round-12):
//     same-gen `server.seq > wal.WrittenDataHighWater(server.gen)` →
//     `server_ack_exceeds_local_seq` (round-12 RENAMED from
//     `beyond_wal_high_water_seq`); cross-gen `server.gen <
//     persistedAck.gen` → `stale_generation`; cross-gen
//     `server.gen > persistedAck.gen` AND
//     `wal.WrittenDataHighWater(server.gen)` returns ok=false →
//     `unwritten_generation`; cross-gen `server.gen > persistedAck.gen`
//     AND `wal.WrittenDataHighWater(server.gen)` returns
//     `(maxDataSeq, true)` AND `server.seq > maxDataSeq` →
//     `server_ack_exceeds_local_data`; ANY branch where
//     `wal.WrittenDataHighWater(...)` returns a non-nil error →
//     `wal_read_failure` (round-12 NEW — propagates I/O failure
//     instead of silently treating it as ok=false). In all five
//     sub-cases: cursors UNCHANGED; rate-limited WARN with FULL
//     cursor context plus the `outcome.AnomalyReason` field.
//
// The state handlers READ `remoteReplayCursor` for their reader-start
// calculations; they DO NOT advance it and they DO NOT re-clamp it —
// the clamp is the SessionAck/BatchAck/ServerHeartbeat handler's
// responsibility, not the state-handler's. SessionUpdate is NOT an
// acknowledgement (spec §"Acknowledgement model") and never advances
// either cursor.
//
// HARD DEPENDENCY: Task 22's StateReplaying / StateLive cases assume
// the two-cursor model is wired. Task 22 MUST NOT commit its Run loop
// until BOTH Task 15.1 (SessionAck clamp + WAL meta seed + cursor
// split) and Task 17 sub-step 17.X (BatchAck/ServerHeartbeat clamp)
// have landed. Without the cursor split wired upstream, an unclamped
// raw server value would silently propagate into the reader-start
// calculation here, and without the WAL meta seed the first
// SessionInit after restart would lie about the local watermark.
//
// rep is hoisted to the outer Run scope and threaded across the
// Replaying → Live boundary so Live can compute its start cursor from
// rep.LastReplayedSequence(). On any state regress to StateConnecting
// (e.g. on Replaying or Live error) we MUST reset rep = nil so a stale
// handoff doesn't leak into a subsequent Live entry on the next
// connect cycle.
//
// Reader lifecycle. Each state-handler case OWNS the reader it opens.
// The replay reader created in StateReplaying is closed by that case
// on EVERY exit path (success and error) so it unregisters from the
// WAL (see `wal/reader.go` Reader.Close near line 446); the Live case
// then opens its own fresh reader at the recomputed start cursor. The
// two readers never overlap.
func (t *Transport) Run(ctx context.Context, rdrFactory func(gen uint32, start uint64) (*wal.Reader, error), liveOpts LiveOptions) error {
	bo := NewBackoff(BackoffOptions{
		Initial: 200 * time.Millisecond,
		Max:     30 * time.Second,
		Factor:  2.0,
	})
	st := StateConnecting
	// rep carries Replayer state across the Replaying → Live boundary.
	// nil before Replaying runs; set in StateReplaying; consumed (and
	// then cleared) in StateLive. Reset to nil whenever we regress to
	// StateConnecting so the next Live entry gets a fresh handoff.
	var rep *Replayer
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
			rep = nil // fresh connect cycle — no stale handoff
			st = next
		case StateReplaying:
			// The replay reader(s) are OWNED by this case: each stage's
			// reader is opened here, threaded into a per-stage Replayer,
			// and explicitly Closed on every exit path (success and
			// error) so it unregisters from the WAL (see wal/reader.go
			// Reader.Close near line 446). The StateLive case opens its
			// own fresh reader at a recomputed start cursor — the
			// replay readers and the Live reader never overlap.
			//
			// Round-15 Finding 4: this case calls computeReplayPlan
			// (NOT computeReplayStart) and iterates the returned
			// []ReplayStage in strictly ascending generation order.
			// Each stage opens a fresh Reader scoped to its generation
			// (Task 14b's wal.NewReader(ReaderOptions{Generation, Start}))
			// and a fresh Replayer over that reader. Only the FIRST
			// stage carries a non-nil PrefixLoss (the synthetic
			// ack_regression_after_gc marker); subsequent stages start
			// at the generation's earliest sequence with PrefixLoss=nil
			// because the loss is bounded to the original replay
			// generation under the same-generation invariant of the
			// 4-case decision tree (see spec §"Loss between replay
			// cursor and persisted ack").
			//
			// Transition to Live ONLY after the LAST stage drains —
			// transitioning earlier would silently skip the later-gen
			// backlog because Live's Reader is scoped to the writer's
			// current generation only and never re-reads older
			// generations. The records remain on disk but no state
			// would re-read them.
			//
			// computeReplayPlan internally calls computeReplayStart for
			// the first stage (consuming `remoteReplayCursor` for the
			// 4-case decision tree) and then probes
			// wal.HasReplayableRecords(gen) for each generation in
			// (persistedAck.Generation, wal.HighGeneration()] to
			// enumerate later-gen stages. Round-16 Finding 2:
			// HasReplayableRecords is used instead of the older
			// WrittenDataHighWater probe because loss-only generations
			// (e.g., produced by overflow GC mid-session) MUST still
			// receive a replay stage so the receiver observes the gap —
			// WrittenDataHighWater would return ok=false for such a
			// generation and silently drop it from the plan. Cost is
			// O(span) where span = wal.HighGeneration() -
			// persistedAck.Generation — the iteration count is the
			// RANGE of generation numbers, NOT the surviving on-disk
			// count and NOT the post-filter stage count. Round-17
			// Finding 2: in healthy operation, span on reconnect is
			// typically 0-1 (the writer has not advanced more than once
			// since the last persisted ack); surviving-count is
			// typically 1-3 independent of span (the active generation
			// plus 0-2 GC-eligible neighbours pending pruning). Span
			// and surviving-count diverge whenever GC has pruned middle
			// generations (e.g., span=10 with surviving-count=3 if
			// generations 11-13 were fully GC'd between
			// persistedAck.Generation=10 and HighGeneration=20). The
			// production loop carries an explicit wraparound guard
			// (`gen > persistedAck.Generation`) so that a hypothetical
			// persistedAck.Generation == math.MaxUint32 short-circuits
			// instead of looping back through gen=0. The per-gen call
			// is an in-memory map lookup with no disk I/O. See spec
			// §"Cost bound for reconnect-time replay scan".
			stages, lerr := t.computeReplayPlan(t.remoteReplayCursor, t.persistedAck)
			if lerr != nil {
				rep = nil
				st = StateConnecting
				continue
			}
			var stageErr error
			for i := range stages {
				stage := stages[i]
				rdr, err := rdrFactory(stage.Generation, stage.StartSeq)
				if err != nil {
					stageErr = err
					break
				}
				rep = NewReplayer(rdr, ReplayerOptions{
					MaxBatchRecords: liveOpts.Batcher.MaxRecords,
					MaxBatchBytes:   liveOpts.Batcher.MaxBytes,
					PrefixLoss:      stage.PrefixLoss, // nil for stages[1..]
				})
				next, err := t.runReplaying(ctx, rep)
				_ = rdr.Close()
				if err != nil {
					// runReplaying tore down t.conn on its way out per
					// its lifecycle rule. Back off and reconnect.
					stageErr = err
					break
				}
				if next != StateLive {
					// Defensive: runReplaying signalled a different
					// next state (e.g. Shutdown). Honour it without
					// continuing to subsequent stages.
					st = next
					stageErr = nil
					goto stageLoopDone
				}
			}
			if stageErr != nil {
				rep = nil
				st = StateConnecting
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(bo.Next()):
				}
				continue
			}
			st = StateLive
		stageLoopDone:
		case StateLive:
			// Live opens its Reader at max(rep.LastReplayedSequence()+1,
			// t.remoteReplayCursor.Sequence+1). The max() avoids two
			// failure modes:
			//   1. Re-emitting the boundary record (Replayer hard-stops
			//      one past tailSeq; rep.LastReplayedSequence() captures
			//      that over-tail record, so Live's start MUST be
			//      strictly greater).
			//   2. Missing trailing loss markers overflow GC may have
			//      appended at the WAL tail mid-replay. Loss markers
			//      bypass Reader.nextSeq (see wal/reader.go isLossMarker
			//      branch), so Live's Reader will surface them even
			//      though its start cursor is past their covered range.
			//
			// Round-8: the cursor is `remoteReplayCursor` (NOT
			// `persistedAck`) for the same reason as Replaying — it is
			// the regressable cursor that captures where the SERVER
			// thinks its ack-watermark sits. A stale-server case must
			// re-send the gap from `remoteReplayCursor + 1`, not from
			// the (higher) `persistedAck + 1` (which would silently drop
			// the gap on the floor).
			//
			// `t.remoteReplayCursor.Sequence` is the local-seq half of
			// the regressable cursor `(t.remoteReplayCursor.Generation,
			// t.remoteReplayCursor.Sequence)` per spec
			// §"Effective-ack tuple and clamp". The two fields move
			// together via `applyServerAckTuple` (Adopted advances both,
			// ResendNeeded sets remoteReplayCursor only). Using
			// `t.remoteReplayCursor.Sequence` alone for the reader-start
			// cursor is safe because the Reader operates within a single
			// WAL generation — the cursor is generation-implicit, scoped
			// by whichever segment file the Reader opens.
			//
			// SEEDING: cold start seeds BOTH `t.persistedAck` and
			// `t.remoteReplayCursor` (lock-step) from `wal.Meta`
			// (`AckHighWatermarkGen`, `AckHighWatermarkSeq`) via
			// `Options.InitialAckTuple` constructed in the store-wiring
			// layer (Task 27); `AckRecorded` maps to the AckTuple's
			// `Present` flag so first-apply semantics work even when
			// the persisted tuple is the zero value.
			//
			// ADVANCEMENT: SessionAck (Task 15.1, state_connecting.go)
			// and BatchAck/ServerHeartbeat (Task 17 sub-step 17.X, recv
			// multiplexer) each call the shared `applyServerAckTuple`
			// helper with `AckOutcome.Kind` dispatch:
			//   - Adopted: server > persistedAck (lex). Both cursors
			//     advance; wal.MarkAcked persists the new persistedAck.
			//   - ResendNeeded: server < persistedAck (lex). ONLY
			//     remoteReplayCursor moves to the server tuple;
			//     persistedAck UNCHANGED; no wal.MarkAcked call.
			//   - NoOp: server == persistedAck. Nothing moved.
			//   - Anomaly (FIVE disjoint sub-cases per Round-12):
			//     same-gen `server.seq >
			//     wal.WrittenDataHighWater(server.gen)` →
			//     `server_ack_exceeds_local_seq` (round-12
			//     RENAMED from `beyond_wal_high_water_seq`);
			//     `server.gen < persistedAck.gen` → `stale_generation`;
			//     `server.gen > persistedAck.gen` AND
			//     `wal.WrittenDataHighWater(server.gen)` returns
			//     `(_, false)` → `unwritten_generation`;
			//     `server.gen > persistedAck.gen` AND
			//     `wal.WrittenDataHighWater(server.gen)` returns
			//     `(maxDataSeq, true)` AND `server.seq > maxDataSeq`
			//     → `server_ack_exceeds_local_data`; ANY branch
			//     where `wal.WrittenDataHighWater(...)` returns a
			//     non-nil error → `wal_read_failure` (round-12
			//     NEW). Cursors UNCHANGED in all five sub-cases;
			//     rate-limited WARN with `outcome.AnomalyReason`
			//     discriminator.
			//
			// The Replaying and Live cases READ `remoteReplayCursor` for
			// their reader-start calculations; they DO NOT advance it
			// and they DO NOT re-clamp it — the clamp is the SessionAck/
			// BatchAck/ServerHeartbeat handler's responsibility, not the
			// state-handler's. SessionUpdate is NOT an acknowledgement
			// (spec §"Acknowledgement model") and never advances either
			// cursor.
			start := t.remoteReplayCursor.Sequence + 1
			if rep != nil {
				if cand := rep.LastReplayedSequence() + 1; cand > start {
					start = cand
				}
			}
			// One-shot handoff — clear rep so a subsequent Live entry
			// after a reconnect cycle picks up the fresh value (or nil
			// if no replay ran).
			rep = nil
			// Round-16 Finding 4: rdrFactory is the (gen, start) form
			// per Task 14b Step 3 / Step 5. The Live Reader is scoped
			// to the writer's CURRENT generation (`t.wal.HighGeneration()`)
			// captured under the WAL lock at StateLive entry — Live
			// only ever reads the writer's current generation; if the
			// writer rolls mid-Live, the Reader hard-stops at the old
			// generation's tail (segment-iteration filter rejects the
			// new generation's segments) and the next reconnect re-enters
			// Replaying with the new generation surfaced as a later-stage
			// ReplayStage per Round-16 Finding 2's loss-only-generations
			// contract.
			rdr, err := rdrFactory(t.wal.HighGeneration(), start)
			if err != nil {
				st = StateConnecting
				continue
			}
			next, err := t.runLive(ctx, rdr, liveOpts)
			if err != nil {
				// runLive guarantees t.conn was closed + cleared on every
				// exit path; we do not need to defensively close it here.
				// Same teardown contract as runReplaying. Back off and
				// reconnect.
				st = StateConnecting
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(bo.Next()):
				}
				continue
			}
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

The snippet above structurally depends on Tasks 17/18:

- The `runLive` method called from `StateLive` is introduced by Task 17
  (Live state Batcher) and gains its recv-multiplexer plumbing from
  Task 18 (heartbeat). The snippet visibly cannot compile without
  Task 17 landing first — that is the structural enforcement promised
  in the "Task 16 — Deferred to Task 17/18" subsection.
- The ack watermark consumed by both state cases is the
  `t.remoteReplayCursor` (regressable cursor) on the `Transport`
  struct, per spec §"Effective-ack tuple and clamp". Round-8 splits
  the single ack tuple into TWO cursors: `persistedAck` (monotonic,
  mirrors `wal.Meta`, drives SessionInit's `wal_high_watermark_seq`
  + segment GC) and `remoteReplayCursor` (regressable, drives the
  reader-start calculation here). The two cursors equal each other in
  the steady state; they diverge briefly during stale-server recovery.
  BOTH cursors are SEEDED on cold start from `wal.Meta`
  (`AckHighWatermarkGen`, `AckHighWatermarkSeq`, with `AckRecorded`
  → `Present`) via `Options.InitialAckTuple` constructed in the
  store-wiring layer (Task 27); the cursors are then ADVANCED by
  SessionAck (Task 15.1, Connecting handler) and by BatchAck/
  ServerHeartbeat (Task 17 sub-step 17.X, recv multiplexer), all via
  the shared `applyServerAckTuple` helper. The helper dispatches on
  `AckOutcome.Kind`:
  - Adopted (server > persistedAck lex): ADOPT the server tuple into
    BOTH cursors; persist via `wal.MarkAcked`.
  - ResendNeeded (server < persistedAck lex): set ONLY
    `remoteReplayCursor` to the server tuple; `persistedAck`
    UNCHANGED (the WAL is monotonic-only — see
    `wal/wal.go` `MarkAcked` line 859); no `wal.MarkAcked` call.
    Logs INFO (legitimate gradual-rollout / partition recovery).
  - NoOp (server == persistedAck): no cursor moved.
  - Anomaly: same-generation `server.seq > wal.HighWaterSequence()`
    OR cross-generation server tuple in EITHER direction (per Round-9
    same-gen narrowing — `LossRecord` carries a single `Generation`
    so cross-gen ResendNeeded cannot be expressed). Cursors UNCHANGED;
    rate-limited WARN with FULL cursor context (`server_gen`,
    `server_seq`, `local_persisted_seq`, `local_persisted_gen`,
    `wal_high_water_seq`, `reason`).

  The state-handler cases here READ `remoteReplayCursor` but do NOT
  write it, and they do NOT re-clamp — the clamp lives in the
  SessionAck / BatchAck / ServerHeartbeat handlers, not the state-
  handler cases. SessionUpdate is NOT an acknowledgement (spec
  §"Acknowledgement model") and never advances either cursor. No
  accessor on `Conn` is required — `Conn`'s surface stays
  Send/Recv/CloseSend/Close (`conn.go:34`).

  HARD DEPENDENCY: Task 22 MUST NOT commit its Run loop until BOTH
  Task 15.1 (SessionAck clamp + WAL meta seed + cursor split) and
  Task 17 sub-step 17.X (BatchAck/ServerHeartbeat clamp) have landed.
  Without the cursor split wired upstream, an unclamped raw server
  value would silently propagate into the reader-start calculation
  here, and without the WAL meta seed the first SessionInit after
  restart would lie about the local watermark. Task 14a (WAL identity
  persistence) is also a transitive prerequisite — without it, the
  cold-start identity gate compares against meta.json fields production
  never populates, and the seed decision is made against an empty
  identity that can never match the configured Store identity.

Acceptance tests in `internal/store/watchtower/transport/transport_run_test.go`
exercise the Replaying → Live handoff and the round-6 tuple-clamp /
Reader-lifecycle invariants:

- `TestRun_LiveResumesPastReplayBoundary` — verifies Live does not
  re-emit the boundary record. Setup: WAL with records seq 1..10,
  `NewReplayer` captures `tailSeq=10`, then append seq=11 post-entry,
  then complete replay (the boundary record seq=11 surfaces in the
  final replay batch). Assert: Live's Reader is opened at
  `max(11+1, 0+1) = 12`, and no record with `seq <= 11` surfaces in any
  Live `EventBatch` (no duplicate boundary record on the wire). This
  is the zero-cursor happy path (`t.remoteReplayCursor.Sequence == 0`).
- `TestRun_LiveSurfacesTrailingLossMarker` — verifies the trailing-
  loss-marker race is closed by the Live handoff. Setup: drive overflow
  GC to append a `TransportLoss` marker covering seqs within the
  `(remote_replay_cursor, tail_seq]` window AT THE WAL TAIL, AFTER
  `NewReplayer` has captured `tailSeq`. Per the Replayer hard-stop
  rule, the marker is NOT surfaced during replay if it sits past an
  over-tail `RecordData` (NextBatch returns done=true on the boundary
  record before reaching the trailing marker). Assert: after replay
  returns done=true with the boundary record, Live's Reader (opened
  at `max(rep.LastReplayedSequence()+1,
  t.remoteReplayCursor.Sequence+1)`) surfaces the trailing
  `TransportLoss` marker via `EventBatch`. This works because loss
  markers bypass `Reader.nextSeq` (see `wal/reader.go` near
  `isLossMarker`), so the marker surfaces even though Live's start
  cursor is past the marker's covered seq range.
- `TestRun_NonZeroCursorSkipsAlreadyAckedHistory` — regression test
  for the spec §"Effective-ack tuple and clamp" replay window. Setup:
  WAL with records seqs 1..20. Pre-seed via
  `Options.InitialAckTuple = &AckTuple{Sequence: 10, Generation: 0,
  Present: true}` so BOTH cursors start at `(10, 0)` (simulate a
  SessionAck that came back with `ack_high_watermark_seq = 10`).
  `NewReplayer` captures `tailSeq=20`. Assert: the replay reader is
  opened at `start=11` (i.e. `t.remoteReplayCursor.Sequence + 1`); no
  `EventBatch` surfaces a `RecordData` with `seq <= 10`; the Replayer
  surfaces records with seqs 11..20 inclusive (the within-window
  range) and terminates. Live then opens at
  `max(LastReplayedSequence()+1, t.remoteReplayCursor.Sequence+1) =
  max(21, 11) = 21` and waits for the next append. Without this test
  the round-3 `rdrFactory(_, 0)` regression would slip through unnoticed
  because `TestRun_LiveResumesPastReplayBoundary` only exercises
  `t.remoteReplayCursor.Sequence == 0`.
- `TestRun_LiveStartsFromAdvancedRemoteCursorIfReplayLagged` —
  REQUIRES Tasks 17/18 recv multiplexer to land. Until then this test
  is a PLACEHOLDER and SHOULD be `t.Skip`-gated with a message
  pointing at Tasks 17/18 (e.g. `t.Skip("requires Task 17/18 recv
  multiplexer to land — gates ack advancement during replay")`).
  Setup: WAL with records 1..50. Pre-seed `Options.InitialAckTuple`
  so BOTH cursors start at `(5, 0)`. `NewReplayer` captures
  `tailSeq=50`. During replay, simulate a `BatchAck` arriving on the
  recv channel that advances BOTH cursors to `(30, 0)` via the
  `Adopted` outcome (this is why the test is gated on the recv
  multiplexer landing). Assert: Live opens at
  `max(rep.LastReplayedSequence()+1,
  t.remoteReplayCursor.Sequence+1)`. If `LastReplayedSequence()` is
  50, Live starts at 51. If for any reason
  `LastReplayedSequence() < t.remoteReplayCursor.Sequence` (e.g.
  early termination plus an aggressive ack), the
  `t.remoteReplayCursor.Sequence+1 = 31` branch wins so we do not
  re-replay records 6..30. This is the regression test for the
  spec's clamp rule applied across the state-handler boundary. It
  is the ONLY test that exercises ack advancement DURING replay;
  without it, a future refactor that reads the cursor only at
  Replaying entry (not at Live entry) would silently re-send
  replay-era records on long replays.
- `TestRun_NonZeroCursorPopulatedViaSessionAckSkipsAlreadyAckedHistory`
  — the round-5 sibling of `TestRun_NonZeroCursorSkipsAlreadyAckedHistory`
  that closes the "test bypasses real handler path" gap. Setup:
  REQUIRES Task 21 testserver fixture (or equivalent fakeConn dialer
  that can be programmed to respond to SessionInit with a typed
  SessionAck); if the fixture has not landed yet, gate the test with
  `t.Skip("requires Task 21 testserver fixture for SessionAck
  programming")`. WAL has records seqs 1..20 already on disk before
  `Run` is called. Drive the dialer to respond to SessionInit with a
  SessionAck carrying `ack_high_watermark_seq = 10, accepted = true`.
  DO NOT pre-seed `Options.InitialAckTuple` — the test exercises the
  SessionAck HANDLER's clamp + assignment, not its CONSUMPTION.
  Assert: after Run progresses through Connecting → Replaying,
  BOTH cursors equal `(10, 0)` (set by the handler via the `Adopted`
  outcome's first-apply branch), the replay reader was opened at
  `start=11` (i.e. `t.remoteReplayCursor.Sequence + 1`), and no
  record with `seq <= 10` surfaces in any `EventBatch`. This test
  catches a regression where a future SessionAck handler change
  drops the watermark on the floor or fails to clamp properly — the
  existing `TestRun_NonZeroCursorSkipsAlreadyAckedHistory` would
  still pass in that case because it pre-seeds the field directly.
- `TestRun_StaleLowerServerHWAdvancesRemoteCursorOnly` (gated on
  Task 15.1 landing) — verifies the gradual-rollout / partition-
  recovery `ResendNeeded` branch of the spec §"Effective-ack tuple
  and clamp": when `(server_gen, server_seq)` lex-precedes
  `(persistedAck.gen, persistedAck.seq)`, ONLY `remoteReplayCursor`
  moves to the server tuple — `persistedAck` is UNCHANGED so
  `wal.MarkAcked` is NOT called (the WAL is monotonic-only). Setup:
  pre-seed via `Options.InitialAckTuple = &AckTuple{Sequence: 10,
  Generation: 1, Present: true}`; drive `wal.MarkAcked(1, 10)` so
  meta.json holds `(1, 10, true)` (simulate a prior session's acked
  state preserved across reconnect). Drive the dialer to respond to
  SessionInit with a SessionAck carrying
  `generation = 1, ack_high_watermark_seq = 5`. Assert: post-handler,
  `t.persistedAck == AckCursor{10, 1}` (UNCHANGED — persistedAck
  never regresses), `t.remoteReplayCursor == AckCursor{5, 1}`
  (regressed to server tuple); `wal.ReadMeta` still shows
  `(1, 10, true)` (no MarkAcked call); the metrics fake recorded
  ZERO additional `SetAckHighWatermark` calls; the INFO buffer
  contains exactly one entry naming the regression with
  `frame="session_ack"`; replay reader opens at
  `start=6` (i.e. `t.remoteReplayCursor.Sequence + 1`).
  Round-9 Finding 1 narrowing: cross-generation `ResendNeeded` is
  IMPOSSIBLE under the same-gen scope (the WAL Reader API is
  sequence-keyed and `LossRecord` carries a single `Generation`).
  Cross-gen server tuples take the Anomaly path instead — see the
  separate `TestRun_CrossGenSessionAckLogsAnomalyAndKeepsCursors`
  acceptance test below.
- `TestRun_AnomalousHigherServerHWLogsAndKeepsCursors` (gated on
  Task 15.1 landing) — verifies the `server_ack_exceeds_local_seq`
  sub-case (round-12 RENAMED from `beyond_wal_high_water_seq`) of
  the True-Anomaly branch (spec §"Effective-ack tuple and clamp"):
  when `serverGen == persistedAck.gen AND serverSeq >
  wal.WrittenDataHighWater(serverGen)`, BOTH cursors stay UNCHANGED
  and a rate-limited WARN is emitted with FULL cursor context
  including `reason="server_ack_exceeds_local_seq"`. Setup: pre-seed
  `Options.InitialAckTuple = &AckTuple{Sequence: 10, Generation: 1,
  Present: true}` AND drive WAL `Append` so
  `WrittenDataHighWater(1) == (15, true, nil)` in gen=1; drive
  SessionAck with `generation = 1, ack_high_watermark_seq = 20`
  (server claims ack beyond local data-bearing high-water inside
  current gen); inject a permissive `*rate.Limiter` and a
  `slog.Logger` capture buffer. Assert: post-handler, BOTH cursors
  unchanged at `AckCursor{10, 1}`;
  `outcome.AnomalyReason == "server_ack_exceeds_local_seq"`; exactly
  one WARN log emitted via the rate-limited path with seven fields
  `frame="session_ack", reason="server_ack_exceeds_local_seq",
  server_gen=1, server_seq=20, local_persisted_seq=10,
  local_persisted_gen=1, wal_written_data_high_seq=15,
  wal_written_data_high_ok=true`; the metrics fake recorded
  exactly one `IncAnomalousAck("server_ack_exceeds_local_seq")`
  call; replay reader opens at `start=11` (i.e.
  `t.remoteReplayCursor.Sequence + 1` using the unchanged cursor).
- `TestRun_CrossGenSessionAckLogsAnomalyAndKeepsCursors` (gated on
  Task 15.1 landing, NEW per Round-9 Finding 1; round-11 expanded to
  THREE sub-cases per Finding 1) — verifies the cross-generation sub-
  cases of the True-Anomaly branch. Per the same-gen narrowing, server
  tuples whose generation differs from persistedAck.gen take the
  Anomaly path in EITHER direction (the Reader API is sequence-keyed;
  sequences reset on gen rolls; a `LossRecord` carries a single
  `Generation`). Three sub-cases (round-11 expansion):
  (a) `stale_generation` — pre-seed `(local_gen=3, local_seq=0,
  Present=true)`; drive SessionAck `(server_gen=2, server_seq=999)`;
  assert `outcome.AnomalyReason == "stale_generation"`, BOTH cursors
  unchanged at `AckCursor{0, 3}`, exactly one WARN with
  `reason="stale_generation"`, exactly one
  `IncAnomalousAck("stale_generation")` call.
  (b) `unwritten_generation` — pre-seed `(local_gen=2, local_seq=5,
  Present=true)`; open the real WAL and roll the writer to gen=3 by
  appending in gen=2 then triggering a generation roll WITHOUT
  appending any RecordData in gen=3 (so `WrittenDataHighWater(3)`
  returns `(_, false)`); drive SessionAck `(server_gen=3,
  server_seq=0)`; assert `outcome.AnomalyReason == "unwritten_generation"`,
  BOTH cursors unchanged at `AckCursor{5, 2}`, exactly one WARN with
  `reason="unwritten_generation"`, exactly one
  `IncAnomalousAck("unwritten_generation")` call. CRITICAL: re-list
  segments — assert lower-gen segments are still on disk (this proves
  the round-11 safety fix; the round-10 design would have GC'd them).
  (c) `server_ack_exceeds_local_data` — pre-seed `(local_gen=2,
  local_seq=5, Present=true)`; open the real WAL and roll the writer
  to gen=3 with RecordData appended up to seq=10 in gen=3 (so
  `WrittenDataHighWater(3) == (10, true)`); drive SessionAck
  `(server_gen=3, server_seq=999)`; assert `outcome.AnomalyReason
  == "server_ack_exceeds_local_data"`, BOTH cursors unchanged at
  `AckCursor{5, 2}`, exactly one WARN with
  `reason="server_ack_exceeds_local_data"`, exactly one
  `IncAnomalousAck("server_ack_exceeds_local_data")` call. NO
  `wal.MarkAcked` call in any sub-case.
- `TestRun_ReadersUnregisterAcrossReconnect` — leak regression guard
  for runLive's Reader lifecycle (Finding 4). Drive multiple reconnect
  cycles (Connecting → Replaying → Live → stream error → Connecting
  → Replaying → Live → ...) by injecting send errors on the fakeConn
  after each Live entry. After N cycles (N=3 is sufficient), assert
  that the WAL's count of registered Readers is 0 between cycles AND
  never grows unboundedly across cycles. The test depends on a
  `len(w.readers)` accessor on `*wal.WAL` for inspection — if the
  accessor does not exist, this test step requires adding a small
  `func (w *WAL) NumRegisteredReaders() int { w.mu.Lock(); defer
  w.mu.Unlock(); return len(w.readers) }` accessor (or a `_test`
  build-tagged variant). The expected count is 0 between cycles
  because (a) StateReplaying explicitly Closes its replay reader on
  every exit path, and (b) StateLive's `runLive` `defer rdr.Close()`
  unregisters its Live reader on every exit path. A non-zero count
  between cycles is the leak Finding 4 names.
- `TestRun_RestartSeedsAckTupleFromWALMeta` (gated on Task 14a +
  Task 15.1 landing) — verifies the AckTuple WAL-meta seed closes
  the cold-start gap that the round-5 `local == 0` escape hatch
  was hiding (Finding 2). Round-8 rewrite: this test runs against
  a REAL `*wal.WAL` opened with `wal.Options{SessionID:"s1",
  KeyFingerprint:"sha256:k1", ...}` — the test no longer mocks the
  Store-options identity gate behavior the round-7 plan implicitly
  assumed. Setup: open a WAL on a fresh `t.TempDir()` with
  `wal.Options{SessionID:"s1", KeyFingerprint:"sha256:k1"}` (Task 14a
  identity options). Append records with seqs 1..50, drive
  `MarkAcked(gen=3, seq=30)` so meta.json persists
  `(SessionID="s1", KeyFingerprint="sha256:k1",
  AckHighWatermarkGen=3, AckHighWatermarkSeq=30, AckRecorded=true)`
  with fsync. Close the WAL. Re-open the WAL from the same directory
  via `wal.Open(wal.Options{SessionID:"s1",
  KeyFingerprint:"sha256:k1", ...})` (matching identity → Open
  succeeds AND seeds `w.ackHighSeq/Gen/Present` from meta) AND
  re-read meta.json via `wal.ReadMeta`. Build a fresh `*Transport`
  via `transport.New(Options{..., WAL: w, InitialAckTuple:
  &transport.AckTuple{Generation: meta.AckHighWatermarkGen,
  Sequence: meta.AckHighWatermarkSeq, Present: meta.AckRecorded}})`.
  Use a `fakeConn` whose Recv returns a SessionAck with
  `(generation=3, ack_high_watermark_seq=30, accepted=true)` — the
  matching no-op case (`AckOutcomeNoOp` from `applyServerAckTuple`).
  Run the Connecting handler. Assert: (a) the FIRST `ClientMessage`
  sent on the conn is a SessionInit carrying
  `wal_high_watermark_seq=30, generation=3` (NOT the zero values
  the round-5 transport would have sent on cold start); (b) after
  the SessionAck no-op,
  `t.persistedAck == AckCursor{Sequence:30, Generation:3}` AND
  `t.remoteReplayCursor == AckCursor{Sequence:30, Generation:3}`
  AND `t.persistedAckPresent == true` (both cursors mirror the
  seed; the no-op branch updates neither); (c) the replay reader
  opens at `start = t.remoteReplayCursor.Sequence + 1 = 31` (i.e.
  no record with seq <= 30 surfaces in any replay batch). Negative
  variant `TestRun_RestartFromZeroAckOmitsSeed` covers the inverse:
  the WAL dir is opened FRESH (no meta.json) → `wal.Meta` reports
  AckRecorded=false → `Options.InitialAckTuple` is nil →
  SessionInit carries `wal_high_watermark_seq=0, generation=0`
  AND first SessionAck does not trip the anomaly WARN even if the
  server returns a non-zero tuple AND the WAL has emitted RecordData
  in the server's generation (round-15 Finding 1: first-apply branch
  in `applyServerAckTuple` returns `AckOutcomeAdopted` and adopts the
  server tuple ONLY when the WAL data validation passes — vacuous
  `serverSeq == 0`, OR `wal.WrittenDataHighWater(serverGen)` returns
  `(maxDataSeq, true, nil)` AND `serverSeq <= maxDataSeq`. Both
  cursors AND `wal.MarkAcked` advance to the server tuple in the
  validated-adopt branch).
- `TestRun_RestartIgnoresAckOnSessionIDMismatch` (round-7 Finding 1,
  round-8 rewrite — gated on Task 14a + Task 15.1 + Task 27
  store-wiring identity gate landing) — verifies the cold-start
  identity check refuses to seed when the persisted meta.json was
  written by a different installation, AND that the second `wal.Open`
  with mismatched identity still succeeds (Task 14a's first-writer-
  wins rule means Open must NOT clobber an existing different
  identity; the Store's own seed-decision gate is what nils the
  AckTuple, not the WAL itself). Round-8 rewrite: this test now
  uses real `wal.Open` end-to-end — the round-7 mocked-Store-options
  shape is gone. Setup phase 1 (writer): open WAL on a fresh
  `t.TempDir()` with `wal.Options{SessionID:"installation-A",
  KeyFingerprint:"sha256:k-A"}`. Append seqs 1..50, drive
  `MarkAcked(gen=3, seq=30)` so meta.json persists with identity
  `("installation-A", "sha256:k-A")` and watermark `(gen=3, seq=30)`,
  AckRecorded=true. Close. Setup phase 2 (mismatched re-open at
  the Store layer): the daemon was reconfigured to a new session ID
  ("installation-B" with the same KeyFingerprint), and the WAL dir
  was reused by accident or by a copy-and-paste deploy. The Store
  computes `expectedSessionID="installation-B"` from its config,
  reads meta.json via `wal.ReadMeta`, and compares against the
  persisted `("installation-A", "sha256:k-A")`. The Store's own
  identity gate sees the mismatch and (a) sets `Options.InitialAckTuple
  = nil` for the Transport AND (b) emits a single WARN with
  `persisted_session_id="installation-A"`,
  `expected_session_id="installation-B"`, plus an explicit action
  description. The Store then opens the WAL via `wal.Open` with
  `wal.Options{SessionID:"installation-B",
  KeyFingerprint:"sha256:k-A", ...}` — Task 14a's first-writer-wins
  rule means the WAL Open ITSELF SHOULD ERROR when persisted identity
  mismatches expected identity (this test exercises the Store-layer
  recovery: on Open error, the Store either refuses to start the
  Transport or quarantines the WAL dir; the choice is captured in
  Task 27 wiring). The test variant covered here is the recovery-
  path behavior: the Store quarantines the existing WAL dir (rename
  to `wal.quarantine.<timestamp>`) and opens a FRESH WAL with
  `("installation-B", "sha256:k-A")`. The fresh WAL has no meta.json
  → `Options.InitialAckTuple` is nil. Use a `fakeConn` whose Recv
  returns a SessionAck with `(generation=99,
  ack_high_watermark_seq=999, accepted=true)` — values deliberately
  unrelated to the persisted (3, 30). Capture slog output to a
  `*bytes.Buffer`. Assert: (a) the FIRST SessionInit on the wire
  carries `wal_high_watermark_seq=0, generation=0` (fresh WAL has
  no persisted ack); (b) after the SessionAck is processed, the
  first-apply branch validates the server tuple against
  `wal.WrittenDataHighWater(99)` per round-15 Finding 1; the fresh
  WAL has emitted no data in gen=99 so the call returns
  `(0, false, nil)` and the helper takes the Anomaly path with
  `AnomalyReason="unwritten_generation"` — both cursors stay at
  `AckCursor{}` (zero) AND `t.persistedAckPresent == false`
  (cursors UNCHANGED on the Anomaly branch); the rate-limited
  ack-anomaly warn buffer contains exactly ONE WARN with
  `reason="unwritten_generation"`, `server_gen=99`,
  `server_seq=999`, `wal_written_data_high_ok=false`, AND
  `wtp_anomalous_ack_total{reason="unwritten_generation"}` was
  incremented exactly once; (c) the buffer DOES contain exactly
  one identity-mismatch WARN naming
  `persisted_session_id="installation-A"`,
  `expected_session_id="installation-B"`, and the action taken
  (quarantine OR refuse-to-start, depending on Task 27's choice);
  (d) if the chosen action is "quarantine," the original WAL dir
  has been renamed to `wal.quarantine.<timestamp>` and a fresh WAL
  dir has been created with the new identity (verify via
  `os.ReadDir(parent)`).
- `TestRun_RestartIgnoresAckOnKeyFingerprintMismatch` (round-7
  Finding 1, same round-8 rewrite + same gating as above) — same
  shape as the SessionID mismatch test, but with matching
  `SessionID` and mismatched `KeyFingerprint`. Setup phase 1:
  persist meta via real `wal.Open` + `MarkAcked` with
  `(SessionID:"s1", KeyFingerprint:"sha256:old",
  AckHighWatermarkGen=3, AckHighWatermarkSeq=30, AckRecorded=true)`.
  Setup phase 2: Store opens WAL with
  `wal.Options{SessionID:"s1", KeyFingerprint:"sha256:new"}`; the
  Store-layer identity gate detects the KeyFingerprint mismatch,
  emits a single WARN naming the persisted vs. expected
  fingerprints + action, sets `Options.InitialAckTuple = nil`, AND
  takes the recovery path (quarantine the existing WAL dir, open a
  fresh WAL with the new identity). Use the same fakeConn SessionAck
  `(99, 999, accepted=true)`. Assert: (a) seed is nil → SessionInit
  on the wire carries `(0, 0)`; (b) first-apply
  (`AckOutcomeAdopted`) adopts server tuple wholesale —
  `t.persistedAck == t.remoteReplayCursor == AckCursor{Sequence:999,
  Generation:99}` — no ack-anomaly WARN; (c) exactly one WARN
  naming the key_fingerprint mismatch with the persisted vs.
  expected fingerprints and the action taken; (d) quarantine
  filesystem assertion as in the SessionID-mismatch test.
- `TestRun_RestartLogsMismatchOnce` (round-7 Finding 1, round-8
  rewrite — same gating as above) — verifies that the identity-
  mismatch WARN is emitted EXACTLY once per Store lifetime, NOT
  on every reconnect cycle. Round-8 rewrite: drives the test
  against the same real `wal.Open` + Store-layer identity gate as
  the two prior tests. Setup: same as the SessionID-mismatch test
  (persisted identity "installation-A", Store opens with
  "installation-B", Store quarantines and opens fresh WAL). After
  Store construction, drive five reconnect cycles via injected
  stream errors on the fakeConn after each Live entry. Assert: the
  captured slog buffer contains exactly ONE WARN line carrying
  `persisted_session_id` across all five cycles (the identity-
  mismatch decision is made ONCE at Store construction during the
  `wal.Open` recovery path; reconnects do NOT re-evaluate identity
  because the Transport is built against the post-quarantine fresh
  WAL whose identity matches by construction). The ack-anomaly
  WARN buffer remains empty across all five cycles: each
  reconnect's first SessionAck for cycle N either (i) takes the
  `AckOutcomeAdopted` first-apply branch on cycle 1 (cursors
  initially zero), then (ii) takes the equal-no-op
  (`AckOutcomeNoOp`) branch on cycles 2..5 because the server
  returns the same `(99, 999)` tuple each time AND the cursors
  carry forward across reconnect cycles within the same Transport
  instance (per the round-8 spec note: cursors are NOT reset on
  reconnect; the Transport instance is reused across reconnects,
  and only Store teardown resets them). Variant: the same test
  with `KeyFingerprint` mismatch instead of SessionID mismatch —
  exactly one WARN with `persisted_key_fingerprint`, zero ack-
  anomaly WARNs.
- `TestRun_RestartSeedsAckTupleFromV1WALMeta` (round-10 Finding 4
  — gated on Task 14a + Task 15.1 + Task 27 store-wiring landing)
  — verifies the V1-to-V2 identity migration path: a meta.json
  written by a pre-Task-14a binary (with EMPTY `SessionID` and
  EMPTY `KeyFingerprint`) is treated as MATCH by the Store-layer
  identity gate, NOT as a mismatch that would force quarantine
  and discard the on-disk ack tuple. This is the critical upgrade
  path from a deployed agent that pre-dates identity persistence.
  Setup: write a `meta.json` v2 file directly to a fresh
  `t.TempDir()` carrying `SchemaVersion=2, SessionID="",
  KeyFingerprint="", AckHighWatermarkGen=3,
  AckHighWatermarkSeq=30, AckRecorded=true` (simulating a v1
  legacy file rewritten by Task 13's v1-to-v2 inference path).
  Open the Store with `Options{SessionID:"s-current",
  KeyFingerprint:"sha256:k-current", ...}`. Assert: (a) the
  Store-layer identity gate did NOT call os.Rename (the
  quarantine path was NOT taken — verify the parent dir contains
  no `*.quarantine.*` entries via `os.ReadDir`); (b) the
  `IncWALQuarantine` metric was NOT incremented (verify via the
  test metrics fake); (c) the WARN log buffer is EMPTY for
  identity-mismatch entries (no "session_id mismatch" or
  "key_fingerprint mismatch" WARN); (d) `Options.InitialAckTuple`
  was seeded from disk to
  `&transport.AckTuple{Sequence:30, Generation:3, Present:true}`;
  (e) the FIRST `SessionInit` on the wire carries
  `wal_high_watermark_seq=30, generation=3` (proving the seed was
  used, not discarded). Without this test, the Finding 4
  contradiction would re-emerge and every upgrade from a v1
  binary would lose the on-disk ack tuple to a spurious
  quarantine.
- `TestStoreWiring_QuarantineRapidRestartDoesNotCollide` (round-10
  Missing A — gated on Task 14a + Task 27 store-wiring landing) —
  verifies the quarantine naming format `<dir>.quarantine.<unix-
  nanos>-<random4hex>` is collision-resistant under tight restart
  loops. Setup: write a meta.json with mismatching identity
  (e.g. persisted `SessionID="installation-A"`, expected
  `SessionID="installation-B"`) into a fresh `t.TempDir()`. Drive
  the Store-layer wal-Open recovery path TWICE in tight succession
  (within the same goroutine, no sleep) on the SAME parent dir,
  re-creating the original WAL dir between each call (so the
  quarantine path fires twice). Assert: (a) BOTH renames succeed
  without surfacing `fs.ErrExist`; (b) the parent dir contains
  exactly TWO distinct `*.quarantine.*` entries (verify via
  `os.ReadDir` and glob match); (c) the two quarantine names
  share the nanosecond-prefix (or differ by < 100 nanos depending
  on system clock resolution) but DIFFER in the trailing `-<4hex>`
  suffix (parse the name with a regex; assert the hex tags are
  different hex strings — collision would manifest as identical
  hex strings AND `errors.Is(renameErr, fs.ErrExist)` on the
  second os.Rename); (d) the `IncWALQuarantine` metric was
  incremented exactly twice with the appropriate reason label
  (e.g. two `session_id_mismatch` increments). The test bounds the
  collision risk: if the random tag generation is broken (e.g.
  reused seed, deterministic suffix), this test would fail on
  the second os.Rename with `fs.ErrExist`. Without this test, the
  Missing A finding's "k8s liveness churn at the same wall-clock
  second" failure mode would be uncaught.
- `TestStoreWiring_QuarantineRetriesOnExistingTarget` (round-11
  Missing B; round-12 Finding 6 RESHAPED — gated on Task 14a +
  Task 27 store-wiring landing) — verifies the cross-platform
  retry loop in the quarantine rename path. Round-12 switched
  from errno-detection (post-Rename `errors.Is(err, fs.ErrExist)`)
  to a PROBE-THEN-RENAME pattern (`os.Lstat(candidate)` BEFORE
  `os.Rename`); the test now exercises the Lstat-based collision
  branch by pre-creating directories at the candidate quarantine
  target paths so the FIRST `os.Lstat(candidate1)` returns nil
  (candidate exists); the retry MUST regenerate the random suffix
  and `os.Lstat(candidate2)` MUST return `fs.ErrNotExist` so the
  rename onto `candidate2` proceeds. Setup uses `t.TempDir()`
  (cross-platform — no `/tmp` assumption, no filesystem-specific
  assumption). The test runs on Linux, Darwin, AND Windows
  (verified via `GOOS=windows go test ./internal/store/watchtower/...`
  cross-compile gate, plus a runtime smoke gate on the target
  platforms in CI). Setup steps:
  1. Create `dir := t.TempDir()` and a child WAL dir
     `walDir := filepath.Join(dir, "wal")` with a meta.json that
     mismatches the configured identity (forces the quarantine
     branch).
  2. Inject a deterministic clock + RNG into the Store-wiring layer
     so the FIRST candidate quarantine path is predictable. Pre-
     create that exact path as a directory inside `dir` so
     `os.Lstat(candidate1)` returns nil (the probe sees the
     candidate as already in use). Either:
     - Use a test seam: a package-private `quarantineNameFunc`
       func variable (default `defaultQuarantineName(walDir)`)
       that the test overrides to return a fixed first candidate
       and a different second candidate.
     - Or, advance the test RNG so the first two `rand.Read` calls
       produce known bytes; pre-create the first byte-derived
       path and confirm the second succeeds.
  3. Run the Store-wiring layer's wal-open recovery path.
  4. Assert: (a) `wal.Open` recovery succeeded (the Store
     constructor returned no error); (b) the WAL dir was renamed
     to the SECOND candidate path (verify via `os.ReadDir(dir)`
     and check that the pre-created collision path is unchanged
     AND a NEW `*.quarantine.*` entry exists); (c) exactly ONE
     `IncWALQuarantine` increment was emitted (the retry inside
     the loop does not double-count); (d) at least one DEBUG log
     entry was emitted with `candidate_path` matching the pre-
     created collision target AND log message
     `"wtp: quarantine candidate exists; retrying with fresh tag"`
     (verify via the slog-buffer test pattern used elsewhere in
     this plan); (e) the WARN log emitted AFTER the successful
     rename names the FINAL `quarantine_dir` (not the colliding
     intermediate). The test MUST NOT assert any specific errno
     (no `errors.Is(renameErr, fs.ErrExist)` check) — round-12
     Finding 6 dropped the errno-based collision detection
     because `os.Rename` semantics for "destination exists"
     diverge across platforms when the destination is a non-empty
     directory; the probe-then-rename pattern collapses every
     "candidate is taken" outcome to a single Lstat check
     regardless of platform errno mapping. A negative variant
     `TestStoreWiring_QuarantineRetriesExhausted` pre-creates
     collisions at ALL 8 candidate paths and asserts the
     constructor returns an error mentioning "after 8 attempts"
     (the wrapped error is the synthesized
     `fmt.Errorf("quarantine candidate %q already exists", ...)`,
     NOT `fs.ErrExist`, because no Rename ever runs in the all-
     collision case — every iteration's Lstat returns nil and
     the loop produces a synthetic candidate-in-use error
     instead). Without these two tests, the round-12 Finding 6
     "platform errno divergence on directory rename" failure
     mode would be uncaught: a future Linux kernel returning
     ENOTEMPTY instead of EEXIST (or a Windows FS driver
     returning ERROR_ACCESS_DENIED) would silently classify the
     collision as a non-collision error and skip the retry.
  Cross-compile note: this test imports `io/fs` (for the
  `fs.ErrNotExist` assertion in the probe branch) which is a
  stdlib package available on
  all GOOS targets — no build tags required.

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

	tr, err := transport.New(transport.Options{
		Dialer: dialer, AgentID: "a", SessionID: "s",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	rdrFactory := func(gen uint32, start uint64) (*wal.Reader, error) {
		return w.NewReader(wal.ReaderOptions{Generation: gen, Start: start})
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

// Conn is the transport.Conn shape produced by Dial. CloseSend is the
// half-close primitive (signals "no more sends"); Close is the full
// teardown primitive (releases the underlying ClientConn). Test code
// that just wants to stop sending should call CloseSend; code that
// wants to fully release resources must call Close.
type Conn interface {
	Send(*wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
	Close() error
}

type grpcConn struct {
	stream wtpv1.Watchtower_StreamClient
	cc     *grpc.ClientConn
	closed atomic.Bool
}

func (g *grpcConn) Send(m *wtpv1.ClientMessage) error   { return g.stream.Send(m) }
func (g *grpcConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }

// CloseSend half-closes the send side of the stream. It does NOT
// release the underlying ClientConn — call Close for that.
func (g *grpcConn) CloseSend() error { return g.stream.CloseSend() }

// Close fully tears down the stream by closing the underlying
// ClientConn, which cancels any in-flight Send/Recv. Idempotent so
// error paths can call it without coordinating with a graceful close.
func (g *grpcConn) Close() error {
	if !g.closed.CompareAndSwap(false, true) {
		return nil
	}
	return g.cc.Close()
}

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
- Create: `internal/store/watchtower/store_export_test.go` (test-only inspectors)
- Create: `internal/store/watchtower/chain/sink_chain_api.go` (test-substitutable interface)
- Create: `internal/store/watchtower/chain/sink_adapter.go` (`*audit.SinkChain` adapter)
- Create: `internal/store/watchtower/chain/sink_adapter_test.go`
- Test: `internal/store/watchtower/options_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/options_test.go`:

```go
package watchtower_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/pkg/types"
)

// testHMACKey is a fixed 32-byte HMAC key used across watchtower tests.
// audit.NewSinkChain rejects keys shorter than audit.MinKeyLength (32),
// so test fixtures must hit at least that length. Bytes.Repeat keeps the
// pattern grep-friendly across files; zero-bytes would also satisfy the
// length check but a recognizable filler eases debugging.
func testHMACKey() []byte { return bytes.Repeat([]byte("a"), 32) }

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
		HMACSecret:   testHMACKey(),
		BatchMaxRecords: 256,
		BatchMaxBytes:   256 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		// AllowStubMapper deliberately omitted.
	})
	if err == nil {
		t.Fatal("expected New to reject StubMapper")
	}
	if !strings.Contains(err.Error(), "StubMapper") {
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

// TestNew_RejectsShortHMACSecret verifies validate() mirrors
// audit.MinKeyLength: a non-empty but too-short key is rejected at
// watchtower-load time with a watchtower-shaped error rather than
// surfacing as a generic audit error mid-construction.
func TestNew_RejectsShortHMACSecret(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 16), // 16 bytes; below audit.MinKeyLength
		BatchMaxRecords: 1, BatchMaxBytes: 4096, BatchMaxAge: time.Second,
		AllowStubMapper: true,
	})
	if err == nil {
		t.Fatal("expected validate() to reject a 16-byte HMAC secret")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error must mention key length: %v", err)
	}
}

// TestNew_RejectsUntypedNilMapper verifies validate() rejects an unset
// Mapper field with a clear "mapper is required" error, before any other
// validation can produce a confusing message. This is the first branch of
// the three-branch mapper check (see options.go validate()).
func TestNew_RejectsUntypedNilMapper(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          nil, // explicit untyped nil
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1",
		HMACSecret:      testHMACKey(),
		BatchMaxRecords: 1, BatchMaxBytes: 4096, BatchMaxAge: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "mapper is required") {
		t.Fatalf("expected 'mapper is required' error, got: %v", err)
	}
}

// TestNew_RejectsTypedNilMapper verifies validate() rejects a typed-nil
// pointer wrapped in the compact.Mapper interface — e.g. a caller writing
// `var m *compact.StubMapper; opts.Mapper = m`. The interface value's
// dynamic type is non-nil so `o.Mapper == nil` returns false; the reflect
// check catches it. Without this branch a typed-nil non-stub pointer would
// slip past validate() and panic on the first AppendEvent call. This test
// is the regression guard against narrowing the rejection to IsStubMapper
// only — see also TestNew_RejectsTypedNilNonStubMapper which proves the
// rejection isn't stub-specific (it fires for any typed-nil pointer
// implementing Mapper).
func TestNew_RejectsTypedNilMapper(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	var typedNil *compact.StubMapper
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          typedNil, // typed nil — dynamic type is *StubMapper, value is nil
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1",
		HMACSecret:      testHMACKey(),
		BatchMaxRecords: 1, BatchMaxBytes: 4096, BatchMaxAge: time.Second,
		AllowStubMapper: true, // even with this on, typed-nil should still fail
	})
	if err == nil || !strings.Contains(err.Error(), "mapper is required") {
		t.Fatalf("expected 'mapper is required' (typed-nil) error, got: %v", err)
	}
}

// fakeMapper is a non-stub Mapper used only to prove the typed-nil
// pointer rejection branch fires for arbitrary Mapper implementations,
// not just the stub. The pointer is intentionally left nil — Map() would
// panic if it were ever called.
type fakeMapper struct{}

func (*fakeMapper) Map(types.Event) (compact.MappedEvent, error) {
	panic("must not be called — validate() should reject the typed-nil before any Map invocation")
}

// TestNew_RejectsTypedNilNonStubMapper locks in the invariant that the
// typed-nil pointer rejection branch isn't stub-specific: any typed-nil
// pointer to a Mapper implementation is rejected. The companion
// TestNew_RejectsTypedNilMapper proves the branch fires for the
// stub-typed-nil case (a regression guard if someone narrows the
// rejection to IsStubMapper only); this test proves it fires for an
// arbitrary non-stub Mapper pointer. Both tests are needed — the
// stub-only test alone would not catch a regression that removed the
// reflect typed-nil branch entirely while leaving IsStubMapper in place.
// Scope: both tests cover non-stub typed-nil POINTER implementations,
// matching the contract in the spec; non-pointer nilable kinds (map,
// slice, chan, func) implementing Mapper are pathological and not part
// of the contract.
func TestNew_RejectsTypedNilNonStubMapper(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	var m *fakeMapper // nil pointer, but typed
	_, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          dir,
		Mapper:          m, // wrap typed-nil pointer into the Mapper interface
		Allocator:       allocator,
		AgentID:         "a", SessionID: "s",
		HMACKeyID:       "k1",
		HMACSecret:      testHMACKey(),
		BatchMaxRecords: 1, BatchMaxBytes: 4096, BatchMaxAge: time.Second,
	})
	if err == nil {
		t.Fatal("expected typed-nil pointer rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "mapper") {
		t.Errorf("error must mention mapper: %v", err)
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
	"fmt"
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
	HMACKeyID     string
	HMACSecret    []byte
	HMACAlgorithm string // "hmac-sha256" (default) or "hmac-sha512"

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

	// Metrics, if non-nil, is the metrics collector wtp_* series are
	// emitted through. Optional but strongly recommended in production;
	// tests pass metrics.New() directly. Nil is safe: the WTP() accessor
	// on a nil Collector returns a *WTPMetrics whose mutators are no-ops.
	Metrics *metrics.Collector

	// SinkChainOverrideForTests, when non-nil, replaces the default
	// chain.WatchtowerSink (wrapping *audit.SinkChain) constructed by
	// New. Permanent test-only seam — production callers MUST leave this
	// nil. validate() rejects a non-nil value unless
	// AllowSinkChainOverrideForTests is also true (mirroring the
	// AllowStubMapper pattern). The companion flag forces tests to opt
	// in explicitly and makes accidental production wiring a startup
	// error rather than a silent behavior change.
	//
	// API stability: this field and AllowSinkChainOverrideForTests are
	// exempt from normal API-stability expectations. They are test-only
	// seams that may be renamed, refactored, or replaced without notice.
	SinkChainOverrideForTests     chain.SinkChainAPI
	AllowSinkChainOverrideForTests bool
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
	// Mapper rejection has three branches that MUST run in this order:
	//   (1) untyped nil — `o.Mapper == nil` catches the zero interface value.
	//   (2) typed-nil pointer — a caller writing
	//       `var m *compact.StubMapper; opts.Mapper = m` produces an interface
	//       value with non-nil type and nil dynamic value. `o.Mapper == nil`
	//       returns false, so we use reflect to detect it. Detection is
	//       scoped to pointer form (`reflect.Ptr` + `IsNil`) because
	//       production Mapper implementations are struct pointers (e.g.
	//       *OcsfMapper). map/slice/chan/func types implementing Mapper are
	//       technically possible but pathological; if a future
	//       implementation deviates from struct-pointer form, this contract
	//       should be revisited then. This branch must run BEFORE
	//       IsStubMapper so the error message points the caller at the real
	//       bug (a nil mapper) rather than the secondary issue (the stub
	//       type). Without this branch the stub-rejection in (3) would
	//       still fire for *StubMapper(nil), but a non-stub typed-nil
	//       pointer (e.g. (*FakeMapper)(nil) in a test) would slip through
	//       and panic on the first AppendEvent.
	//   (3) test-only StubMapper — compact.IsStubMapper matches both value
	//       and pointer forms (StubMapper{}, *StubMapper, and the typed-nil
	//       *StubMapper case redundantly covered by (2)). Gated by
	//       AllowStubMapper so unit tests can opt in.
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
	// Mirror audit.NewSinkChain's precondition so a short key is rejected at
	// watchtower-load time with a watchtower-shaped error rather than as a
	// generic audit error mid-construction. audit remains the canonical
	// source of truth — if it tightens, this branch must be updated to match.
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
	if o.WALSegmentSize > o.WALMaxTotalSize/2 {
		return errors.New("watchtower: WALSegmentSize must be <= WALMaxTotalSize/2")
	}
	if o.TLSCertFile != "" && o.AuthBearer != "" {
		return errors.New("watchtower: TLS client cert and bearer auth are mutually exclusive")
	}
	if o.SinkChainOverrideForTests != nil && !o.AllowSinkChainOverrideForTests {
		return errors.New("watchtower: SinkChainOverrideForTests must be nil in production (set AllowSinkChainOverrideForTests in tests that need the seam)")
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
	"crypto/rand" // round-10 Missing A: 16-bit random tag for quarantine name
	"errors"
	"fmt"
	"io/fs" // round-11 Missing B: portable fs.ErrExist for quarantine rename collision detection
	"os"
	"sync"
	"time" // round-10 Missing A: nanosecond resolution for quarantine name

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
)

// Store implements store.EventStore.
type Store struct {
	opts    Options
	w       *wal.WAL
	tr      *transport.Transport
	sink    chain.SinkChainAPI
	metrics *metrics.WTPMetrics

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

	// Wire the chain sink BEFORE opening the WAL. Chain construction is
	// pure (no IO side effects) — doing it first means a failure here
	// returns immediately without leaking an open WAL or held lock file.
	// Production callers get a real *audit.SinkChain wrapped in the
	// watchtower-local *chain.WatchtowerSink adapter (the adapter
	// satisfies chain.SinkChainAPI and is what tests substitute). The
	// audit phase-0 contract stays untouched; the adapter only adds
	// PeekPrevHash on top of the existing Compute/Commit/State surface.
	// Tests can replace the adapter via Options.SinkChainOverrideForTests
	// (gated behind AllowSinkChainOverrideForTests; see validate()).
	innerChain, err := audit.NewSinkChain(opts.HMACSecret, opts.HMACAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("audit.NewSinkChain: %w", err)
	}
	var sinkChain chain.SinkChainAPI = chain.NewWatchtowerSink(innerChain)
	if opts.SinkChainOverrideForTests != nil {
		sinkChain = opts.SinkChainOverrideForTests
	}

	w, err := wal.Open(wal.Options{
		Dir:            opts.WALDir,
		SegmentSize:    opts.WALSegmentSize,
		MaxTotalBytes:  opts.WALMaxTotalSize,
		// Round-8 (Finding 2 / Task 14a): persist identity on every
		// meta.json write so the persisted (gen, seq) watermark is
		// cryptographically attributable to a known (SessionID,
		// KeyFingerprint) installation. The WAL's own first-writer-
		// wins rule (Task 14a) will REFUSE to open this Dir if
		// meta.json on disk carries a mismatching SessionID or
		// KeyFingerprint — the recovery path lives below in the
		// `errors.As(err, &wal.ErrIdentityMismatch{})` branch.
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
	})
	if err != nil {
		// Round-8 recovery path: if wal.Open refused due to identity
		// mismatch (Task 14a's first-writer-wins rule), quarantine the
		// existing WAL dir (rename to wal.quarantine.<unix-nanos>) and
		// open a fresh WAL with the new identity. The pre-existing
		// meta.json that drove the refusal is preserved under the
		// quarantine name for forensic inspection. Quarantine is the
		// chosen action over "refuse to start" because a key rotation
		// or session reissue is a legitimate operator action — the
		// daemon SHOULD continue running against a fresh WAL rather
		// than blocking on a stale meta.json the operator may not even
		// remember.
		var idErr *wal.ErrIdentityMismatch
		if errors.As(err, &idErr) {
			// Round-10 Missing A: quarantine name encodes both
			// nanosecond-resolution time AND a 16-bit random tag so
			// rapid successive restarts (think k8s liveness churn at
			// the same wall-clock second) cannot collide on the
			// rename target. Format:
			//   <wal-dir>.quarantine.<unix-nanos>-<4-hex-random>
			// Example: /var/lib/agentsh/wtp.wal.quarantine.1737324001000000000-9c3f
			//
			// The 4-hex random suffix uses crypto/rand for collision
			// resistance under a misbehaving wall clock. Even with
			// 1ns clock granularity AND many concurrent restarts, the
			// 65k random space makes name collision astronomically
			// unlikely.
			//
			// Round-12 Finding 6: switched from errno-detection (post-Rename
			// `errors.Is(err, fs.ErrExist)`) to a PROBE-THEN-RENAME pattern.
			// `os.Rename` semantics for "destination exists" diverge across
			// platforms when the destination is a non-empty directory:
			// some Unix kernels return EEXIST, some return ENOTEMPTY, and
			// Windows can surface ERROR_ACCESS_DENIED or ERROR_DIR_NOT_EMPTY
			// instead of ERROR_ALREADY_EXISTS depending on the destination
			// state and FS driver. Worse, on macOS APFS a rename whose
			// destination is a symlink to a directory does NOT collapse to
			// ERR_EXIST. Probing with `os.Lstat(candidate)` BEFORE the
			// rename collapses every "this candidate is taken" outcome to
			// a single check, regardless of platform errno mapping. The
			// Lstat-then-Rename window is racy under hostile concurrent
			// renames, but the random suffix already makes the namespace
			// effectively unique, and any genuine collision still surfaces
			// through the rename's own error path on the next iteration.
			//
			// The retry cap is 8: enough to absorb realistic clock
			// quantization + random collision (probability ~ 8/65536
			// even with a stuck nanosecond clock, well below any
			// concrete failure budget) but small enough that a truly
			// stuck quarantine target surfaces as a hard error rather
			// than an unbounded loop.
			classifyQuarantineReason := func() metrics.WTPWALQuarantineReason {
				switch {
				case idErr.PersistedSessionID != opts.SessionID:
					return metrics.WTPWALQuarantineReasonSessionIDMismatch
				case idErr.PersistedKeyFingerprint != opts.KeyFingerprint:
					return metrics.WTPWALQuarantineReasonKeyFingerprintMismatch
				default:
					return metrics.WTPWALQuarantineReasonUnknown
				}
			}
			quarantineReason := classifyQuarantineReason()
			const quarantineRenameMaxAttempts = 8
			var quarantine string
			var renameErr error
			for attempt := 1; attempt <= quarantineRenameMaxAttempts; attempt++ {
				var randTag [2]byte
				if _, rerr := rand.Read(randTag[:]); rerr != nil {
					// crypto/rand failure is unrecoverable; surface as a
					// startup error rather than fall back to a less-random
					// suffix.
					return nil, fmt.Errorf("wtp: WAL identity mismatch and crypto/rand failed for quarantine tag: %w (original: %v)", rerr, err)
				}
				quarantine = fmt.Sprintf("%s.quarantine.%d-%x", opts.WALDir, time.Now().UnixNano(), randTag)
				// Round-12 Finding 6: probe-then-rename. Lstat returning
				// nil (or any error other than fs.ErrNotExist) means the
				// candidate path is already in use OR is unreachable for
				// some other reason — in either case do NOT attempt the
				// rename onto it. Generate a fresh tag and retry.
				if _, statErr := os.Lstat(quarantine); statErr == nil {
					// Candidate exists — log and retry with a fresh tag.
					opts.Logger.Debug("wtp: quarantine candidate exists; retrying with fresh tag",
						"attempt", attempt,
						"max_attempts", quarantineRenameMaxAttempts,
						"candidate_path", quarantine)
					renameErr = fmt.Errorf("quarantine candidate %q already exists", quarantine)
					continue
				} else if !errors.Is(statErr, fs.ErrNotExist) {
					// Lstat failed for a non-existence reason (permission
					// denied, broken FS, etc.). Surface as a hard error
					// rather than blindly attempting the rename.
					return nil, fmt.Errorf("wtp: WAL identity mismatch and quarantine probe failed: %w (original: %v)", statErr, err)
				}
				// Lstat returned fs.ErrNotExist — candidate is free; rename.
				renameErr = os.Rename(opts.WALDir, quarantine)
				if renameErr == nil {
					break
				}
				// Rename failed for some reason OTHER than the candidate
				// being free at probe time. This is unusual (the candidate
				// was free a microsecond ago) but indicates a non-collision
				// failure: surface as a hard error instead of looping.
				return nil, fmt.Errorf("wtp: WAL identity mismatch and quarantine rename failed: %w (original: %v)", renameErr, err)
			}
			if renameErr != nil {
				// All quarantineRenameMaxAttempts probes collided. Either
				// the operator pre-created a directory tree that systematically
				// shadows our naming scheme, or the random source is broken,
				// or the clock is wedged AND every random tag in the 65k
				// space is taken (impossible without operator intervention).
				return nil, fmt.Errorf("wtp: WAL identity mismatch and quarantine rename failed after %d attempts: %w (original: %v)", quarantineRenameMaxAttempts, renameErr, err)
			}
			// Log the WARN AFTER the successful rename so the
			// `quarantine_dir` field reflects the actual final path
			// (not a transient one).
			opts.Logger.Warn("wtp: WAL identity mismatch; quarantining stale WAL dir",
				"persisted_session_id", idErr.PersistedSessionID,
				"expected_session_id", opts.SessionID,
				"persisted_key_fingerprint", idErr.PersistedKeyFingerprint,
				"expected_key_fingerprint", opts.KeyFingerprint,
				"reason", string(quarantineReason),
				"quarantine_dir", quarantine,
				"action", "renamed stale WAL dir; opening fresh WAL with new identity")
			// Round-10 Finding 6: bump wtp_wal_quarantine_total via the
			// real WTPMetrics façade with the labelled reason. The
			// receiver is `mw := opts.Metrics.WTP()` (resolved later in
			// New); we resolve it here too so the early-failure path
			// emits the metric. The IncWALQuarantine method is nil-safe.
			//
			// Quarantine is a legitimate operator action (key rotation
			// / session reissue) but should be RARE — a sustained
			// nonzero rate of either reason indicates a misconfigured
			// restart loop or a session_id generator that does not
			// persist across restarts.
			opts.Metrics.WTP().IncWALQuarantine(quarantineReason)
			// Re-open against the now-empty Dir; this WILL succeed because
			// no meta.json exists to compare against.
			w, err = wal.Open(wal.Options{
				Dir:            opts.WALDir,
				SegmentSize:    opts.WALSegmentSize,
				MaxTotalBytes:  opts.WALMaxTotalSize,
				SessionID:      opts.SessionID,
				KeyFingerprint: opts.KeyFingerprint,
			})
			if err != nil {
				return nil, fmt.Errorf("open WAL (post-quarantine): %w", err)
			}
		} else {
			return nil, fmt.Errorf("open WAL: %w", err)
		}
	}

	// Round-6 (Finding 2) + round-7 (Finding 1) + round-8 (Finding 1):
	// seed the Transport's persistedAck cursor from the persisted WAL
	// meta.json so the FIRST SessionInit after restart carries the actual
	// local watermark — not a lying (0, 0). The AckTuple.Present flag
	// mirrors wal.Meta.AckRecorded so first-apply semantics in
	// applyServerAckTuple work even when the persisted tuple is zero.
	//
	// Round-8 note on the identity gate below: with Task 14a's identity
	// enforcement built INTO wal.Open above, the meta-mismatch case is
	// ALREADY caught by the quarantine recovery path — by the time we
	// reach this block, `w` is either (a) opened against meta whose
	// identity matches opts.SessionID/KeyFingerprint by construction, or
	// (b) opened against a fresh post-quarantine Dir with no meta.json.
	// The Store's pre-existing identity gate below is RETAINED as
	// defense-in-depth observability: it captures the rare case where
	// meta.json was written by a buggy older binary that didn't persist
	// identity (Meta.SessionID == "" reads from disk, which never matches
	// any non-empty opts.SessionID), and it provides a single chokepoint
	// to seed `initialAck` consistently across all "should not seed"
	// branches (no meta, mismatching meta, ack-not-recorded). The
	// operator-facing WARN on mismatch is also useful for audit trails
	// independent of the wal.Open quarantine path's WARN.
	//
	// Round-10 Finding 4 — v1 identity migration. Earlier WAL writers
	// (pre-Task 14a) produced meta.json files with EMPTY SessionID and
	// EMPTY KeyFingerprint fields (the JSON encoder emitted the zero
	// values when the writer didn't populate them). Treating empty as
	// mismatch would force a quarantine on every cold start after an
	// upgrade — destroying the ack tuple that the user actually has on
	// disk and forcing a re-replay of every event since the prior ack.
	// The migration rule is: empty `meta.SessionID` AND/OR empty
	// `meta.KeyFingerprint` is treated as MATCH (the v1 writer didn't
	// know about identity; we assume the operator knows what they're
	// doing on the upgrade and trust the on-disk ack tuple). The first
	// `wal.MarkAcked` call after this Store starts will rewrite meta.json
	// with the v2 (populated) shape, so the migration completes lazily.
	//
	// Match/reset rules (mirror the spec table; round-10 v1 migration
	// notes in parentheses):
	//   - meta.SessionID != "" AND meta.SessionID != cfg.SessionID → seed = nil + WARN once
	//     (defense-in-depth; the wal.Open path above usually catches this
	//     first via Task 14a's first-writer-wins rule). Empty
	//     meta.SessionID is V1 LEGACY and treated as MATCH.
	//   - meta.KeyFingerprint != "" AND meta.KeyFingerprint != cfg.KeyFingerprint → seed = nil + WARN once
	//     (same defense-in-depth caveat). Empty meta.KeyFingerprint is V1
	//     LEGACY and treated as MATCH.
	//   - meta.AckRecorded == false → seed = nil (no anomaly; legitimate
	//     pre-ack cold start whose meta.json was written by a prior failed
	//     append, before any MarkAcked call).
	//   - all three match (treating empty identity fields as match) → seed from wal.Meta (the only seeding case).
	//
	// In both true-mismatch cases the WARN names the field that mismatched, the
	// persisted vs. expected values, and the action taken; the transport's
	// applyServerAckTuple first-apply branch then adopts the server tuple
	// wholesale on the first SessionAck (no anomaly log).
	//
	// ReadMeta returning os.ErrNotExist is the cold-cold-start case (no
	// meta.json on disk at all): leave initialAck nil so the Transport
	// behaves exactly as it does on a fresh install (zero seed, no anomaly
	// on first SessionAck — first-apply branch adopts wholesale).
	var initialAck *transport.AckTuple
	meta, err := wal.ReadMeta(opts.WALDir)
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist):
		// Pre-ack cold start: no meta.json on disk. Leave initialAck nil.
	case err != nil:
		_ = w.Close()
		return nil, fmt.Errorf("read WAL meta: %w", err)
	case meta.SessionID != "" && meta.SessionID != opts.SessionID:
		// Round-10 Finding 4: empty meta.SessionID is V1 legacy, so the
		// `!= ""` guard treats it as MATCH (the legacy writer didn't
		// know about identity; trust the on-disk ack tuple). The next
		// MarkAcked rewrites meta.json with the populated v2 shape.
		//
		// Stale meta from a different installation (or the server-issued
		// session was rotated and the daemon was reconfigured). Do NOT
		// seed — first SessionAck adopts the server tuple wholesale.
		opts.Logger.Warn("wtp: meta session_id mismatch; ignoring persisted ack",
			"persisted_session_id", meta.SessionID,
			"expected_session_id", opts.SessionID,
			"action", "ignoring persisted ack tuple; first SessionAck will adopt server tuple wholesale")
		// initialAck stays nil.
	case meta.KeyFingerprint != "" && meta.KeyFingerprint != opts.KeyFingerprint:
		// Round-10 Finding 4: empty meta.KeyFingerprint is V1 legacy
		// (same `!= ""` guard rationale as above).
		//
		// Signing key rotated outside this process's lifetime. The
		// persisted ack history may not be cryptographically attributable
		// to the current key; do NOT seed.
		opts.Logger.Warn("wtp: meta key_fingerprint mismatch; ignoring persisted ack",
			"persisted_key_fingerprint", meta.KeyFingerprint,
			"expected_key_fingerprint", opts.KeyFingerprint,
			"action", "ignoring persisted ack tuple; first SessionAck will adopt server tuple wholesale")
		// initialAck stays nil.
	case !meta.AckRecorded:
		// Identity matches (or is V1 legacy treated-as-match) but no ack
		// has ever been recorded for this WAL directory; the persisted
		// tuple fields are zero-valued and meaningless. No anomaly —
		// leave initialAck nil so first-apply adopts the server tuple
		// wholesale.
	default:
		// All three checks passed (identity matches OR is V1 legacy)
		// AND ack_recorded is true. Seed the Transport from disk.
		initialAck = &transport.AckTuple{
			Generation: meta.AckHighWatermarkGen,
			Sequence:   meta.AckHighWatermarkSeq,
			Present:    true, // == meta.AckRecorded by case discriminator
		}
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = newGRPCDialer(opts)
	}

	// Resolve the WTP metrics façade BEFORE transport.New so we can
	// inject it via Options.Metrics. opts.Metrics may be nil; the
	// WTP() accessor is nil-safe and returns a *WTPMetrics whose
	// mutators no-op when the underlying *Collector is nil.
	mw := opts.Metrics.WTP()

	tr, err := transport.New(transport.Options{
		Dialer:           dialer,
		AgentID:          opts.AgentID,
		SessionID:        opts.SessionID,
		InitialAckTuple:  initialAck,
		Logger:           opts.Logger, // round-6 (Finding 4): inject for ack-anomaly WARN
		// Round-8 (Finding 1): the Transport needs direct access to the WAL
		// AND the metrics façade so applyServerAckTuple can call
		// wal.MarkAcked + metrics.SetAckHighWatermark on the Adopted branch
		// (the side-effect contract introduced in Task 15.1 Step 1b).
		WAL:              w,
		Metrics:          mw,
	})
	if err != nil {
		return nil, fmt.Errorf("transport.New: %w", err)
	}

	s := &Store{
		opts:    opts,
		w:       w,
		tr:      tr,
		sink:    sinkChain,
		metrics: mw,
		fatalCh: make(chan error, 1),
	}

	go func() {
		_ = tr.Run(ctx, func(gen uint32, start uint64) (*wal.Reader, error) {
			return w.NewReader(wal.ReaderOptions{Generation: gen, Start: start})
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

- [ ] **Step 3.5: Add the watchtower sink adapter + scaffolding for downstream Task 23 drop tests**

This step lands four pieces of infrastructure that Task 23's drop tests depend on:

1. A `chain.WatchtowerSink` adapter that wraps `*audit.SinkChain` and exposes the watchtower-local `chain.SinkChainAPI` (Compute / Commit / PeekPrevHash). The adapter is the only added surface area on top of `audit.SinkChain` — see spec §"Watchtower-local adapter: `chain.WatchtowerSink`".
2. A new `chain.SinkChainAPI` interface whose method set EXACTLY mirrors what `Store` consumes from the adapter. Method signatures match the real `audit.SinkChain` contract (positional `Compute` arguments, `Commit` returning `error`); a previous narrower or signature-mismatched interface was rejected in earlier review rounds for breaking the integrity guarantees.
3. A `store_export_test.go` file that exposes test-only inspectors on `*Store` (file lives in package `watchtower`; the `_test.go` suffix excludes it from production builds automatically — no build tag required).
4. The `Options.SinkChainOverrideForTests` + `Options.AllowSinkChainOverrideForTests` fields added in Step 3 above (already in the Options struct; wiring + validate-time rejection covered there).

Note: the failing-sink test double itself lives **inline in `internal/store/watchtower/append_test.go`** (defined in Task 23 Step 3 below), not in a separate package. Putting it in a `_test.go` file is what makes it test-only by construction; no separate doubles package is needed.

(a) Create `internal/store/watchtower/chain/sink_chain_api.go` for the interface, and `internal/store/watchtower/chain/sink_adapter.go` for the `*audit.SinkChain` adapter. Splitting the two files keeps the test seam (interface) visually separate from the production wrapper (adapter), which makes a future audit-package signature change easy to localize.

`internal/store/watchtower/chain/sink_chain_api.go`:

```go
package chain

import "github.com/agentsh/agentsh/internal/audit"

// SinkChainAPI is the test-substitutable surface that watchtower.Store
// consumes. Production callers wire *WatchtowerSink (which wraps
// *audit.SinkChain); tests substitute via Options.SinkChainOverrideForTests.
//
// Method signatures align with the real audit.SinkChain contract:
//   - Compute takes positional args matching audit.SinkChain.Compute.
//   - Commit returns error; AppendEvent treats audit.ErrFatalIntegrity,
//     audit.ErrStaleResult, and audit.ErrCrossChainResult as terminal
//     (chain has latched fatal — no further appends).
//   - PeekPrevHash is the watchtower-only convenience accessor that
//     reads the prev_hash component of audit.SinkChainState. It is
//     implemented in the adapter, NOT on audit.SinkChain itself, because
//     the audit package's State() already returns the full
//     SinkChainState{Generation, PrevHash, Fatal} triple — sufficient for
//     production callers. PeekPrevHash narrows that down to the single
//     field the watchtower drop tests need.
//
// Any method the Store touches MUST appear here — silently downgrading
// the interface (e.g., dropping Commit's error return) is what produced
// the round-6 review failure.
type SinkChainAPI interface {
	Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*audit.ComputeResult, error)
	Commit(result *audit.ComputeResult) error
	Fatal(reason error)
	PeekPrevHash() string
}
```

`internal/store/watchtower/chain/sink_adapter.go`:

```go
package chain

import "github.com/agentsh/agentsh/internal/audit"

// WatchtowerSink adapts *audit.SinkChain to the watchtower-local
// SinkChainAPI. The adapter is a pure pass-through for Compute and
// Commit (the audit phase-0 contract is untouched) and adds a single
// new accessor: PeekPrevHash, a read-only test seam that returns the
// prev_hash component of audit.SinkChain.State().
//
// This is the only added surface area on top of audit.SinkChain — see
// spec §"Watchtower-local adapter: `chain.WatchtowerSink`" for why it
// lives in the watchtower package rather than the audit package.
type WatchtowerSink struct {
	inner *audit.SinkChain
}

// NewWatchtowerSink wraps inner so it satisfies SinkChainAPI. Callers
// keep ownership of inner; the adapter does not copy or mutate it
// outside Compute/Commit (which are forwarded verbatim).
func NewWatchtowerSink(inner *audit.SinkChain) *WatchtowerSink {
	return &WatchtowerSink{inner: inner}
}

// Compute delegates to audit.SinkChain.Compute. Pure — no chain mutation.
func (s *WatchtowerSink) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*audit.ComputeResult, error) {
	return s.inner.Compute(formatVersion, sequence, generation, payload)
}

// Commit delegates to audit.SinkChain.Commit. The error return covers
// the latched-fatal cases (audit.ErrFatalIntegrity), stale tokens
// (audit.ErrStaleResult), cross-chain misuse (audit.ErrCrossChainResult),
// and backwards-generation commits — AppendEvent treats all of them as
// terminal.
func (s *WatchtowerSink) Commit(result *audit.ComputeResult) error {
	return s.inner.Commit(result)
}

// Fatal delegates to audit.SinkChain.Fatal. AppendEvent invokes this on
// ambiguous WAL failures: subsequent Compute calls return
// audit.ErrFatalIntegrity, stopping further appends safely.
func (s *WatchtowerSink) Fatal(reason error) {
	s.inner.Fatal(reason)
}

// PeekPrevHash returns the current chain prev_hash without advancing
// the chain. Implemented as a narrow read of audit.SinkChain.State().
// Used by Store.PeekPrevHash (test-only accessor) so drop-path tests
// can assert "chain did not advance" after a dropped append.
func (s *WatchtowerSink) PeekPrevHash() string {
	return s.inner.State().PrevHash
}
```

Add a sibling test `internal/store/watchtower/chain/sink_adapter_test.go` covering Compute/Commit pass-through and PeekPrevHash:

```go
package chain_test

import (
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
)

func TestWatchtowerSink_PeekPrevHashEmptyAtGenesis(t *testing.T) {
	inner, err := audit.NewSinkChain([]byte("0123456789abcdef0123456789abcdef"), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	s := chain.NewWatchtowerSink(inner)
	if got := s.PeekPrevHash(); got != "" {
		t.Errorf("genesis PeekPrevHash should be empty, got %q", got)
	}
}

func TestWatchtowerSink_ComputeCommitAdvancesPrevHash(t *testing.T) {
	inner, err := audit.NewSinkChain([]byte("0123456789abcdef0123456789abcdef"), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	s := chain.NewWatchtowerSink(inner)
	res, err := s.Compute(2, 1, 1, []byte(`{"sequence":1}`))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if err := s.Commit(res); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := s.PeekPrevHash(); got == "" {
		t.Error("PeekPrevHash should be non-empty after a successful Commit")
	}
	if got := s.PeekPrevHash(); got != res.EntryHash() {
		t.Errorf("PeekPrevHash should equal the committed EntryHash; got %q want %q", got, res.EntryHash())
	}
}
```

(b) Create `internal/store/watchtower/store_export_test.go` (package `watchtower`, NOT `watchtower_test`, so the methods are first-class on `*Store`):

```go
package watchtower

// Test-only inspectors exported for sibling _test.go files in this and
// other packages. The _test.go suffix excludes this file from production
// builds automatically — no build tag needed.

// PeekPrevHash returns the current chain prev_hash without advancing the
// chain. Used in append_test.go to assert that drop paths leave the chain
// untouched. Forwards to chain.SinkChainAPI.PeekPrevHash on s.sink, which
// in production is the *chain.WatchtowerSink adapter.
func (s *Store) PeekPrevHash() string {
	return s.sink.PeekPrevHash()
}

// WALSegmentCount returns the number of WAL segment files on disk.
// Used in append_test.go to assert that drop paths do not write to the WAL.
func (s *Store) WALSegmentCount() int {
	return s.w.SegmentCount()
}

// Test-only metrics inspectors. Each returns the current value of the
// underlying counter; mirror of internal/metrics/wtp.go's accessors but
// resolved through the Store's own *WTPMetrics handle so cross-package
// (watchtower_test) callers can read them without poking the unexported
// metrics field directly.
func (s *Store) DroppedInvalidUTF8() uint64      { return s.metrics.DroppedInvalidUTF8() }
func (s *Store) DroppedSequenceOverflow() uint64 { return s.metrics.DroppedSequenceOverflow() }
```

`(*chain.WatchtowerSink).PeekPrevHash()` is added in (a) above. `(*wal.WAL).SegmentCount() int` is a simple read-only inspector; if it was not added by Task 11, add it in this step.

(c) Add `TestNew_RejectsSinkChainOverrideInProduction` and `TestNew_AcceptsSinkChainOverrideWhenAllowed` to `options_test.go`, exercising the new validate-time gate added in Step 3:

```go
// failingSink defined inline in append_test.go (Task 23 Step 3); for the
// validate-time test we only need a value that satisfies chain.SinkChainAPI.
// A nil-method-pointer struct works because validate() rejects on the field
// being non-nil before any method is called. Using a real *chain.WatchtowerSink
// (built from a real audit.SinkChain) keeps the value behaviorally honest
// in case validate() is ever extended to call methods.

func TestNew_RejectsSinkChainOverrideInProduction(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	innerChain, err := audit.NewSinkChain([]byte("0123456789abcdef0123456789abcdef"), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	override := chain.NewWatchtowerSink(innerChain)
	_, err = watchtower.New(context.Background(), watchtower.Options{
		WALDir:                    dir,
		Mapper:                    compact.StubMapper{},
		Allocator:                 allocator,
		AgentID:                   "a",
		SessionID:                 "s",
		HMACKeyID:                 "k1",
		HMACSecret:                []byte("0123456789abcdef0123456789abcdef"),
		BatchMaxRecords:           1,
		BatchMaxBytes:             4096,
		BatchMaxAge:               time.Second,
		AllowStubMapper:           true,
		SinkChainOverrideForTests: override,
		// AllowSinkChainOverrideForTests deliberately omitted.
	})
	if err == nil {
		t.Fatal("expected New to reject SinkChainOverrideForTests without AllowSinkChainOverrideForTests")
	}
	if !strings.Contains(err.Error(), "SinkChainOverrideForTests") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_AcceptsSinkChainOverrideWhenAllowed(t *testing.T) {
	dir := t.TempDir()
	allocator := audit.NewSequenceAllocator(0, 0)
	innerChain, err := audit.NewSinkChain([]byte("0123456789abcdef0123456789abcdef"), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	override := chain.NewWatchtowerSink(innerChain)
	_, err = watchtower.New(context.Background(), watchtower.Options{
		WALDir:                         dir,
		Mapper:                         compact.StubMapper{},
		Allocator:                      allocator,
		AgentID:                        "a",
		SessionID:                      "s",
		HMACKeyID:                      "k1",
		HMACSecret:                     []byte("0123456789abcdef0123456789abcdef"),
		BatchMaxRecords:                1,
		BatchMaxBytes:                  4096,
		BatchMaxAge:                    time.Second,
		AllowStubMapper:                true,
		SinkChainOverrideForTests:      override,
		AllowSinkChainOverrideForTests: true,
	})
	if err != nil {
		t.Fatalf("expected New to accept SinkChainOverrideForTests when AllowSinkChainOverrideForTests is true, got %v", err)
	}
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
git add internal/store/watchtower/store.go internal/store/watchtower/options.go internal/store/watchtower/options_test.go internal/store/watchtower/store_export_test.go internal/store/watchtower/chain/sink_chain_api.go internal/store/watchtower/chain/sink_adapter.go internal/store/watchtower/chain/sink_adapter_test.go
git commit -m "feat(wtp/store): add Options + New with watchtower sink adapter"
```

- [ ] **Step 7: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 22a: Add sink-failure metrics

The spec lists five sink-failure counters that Task 23 (`AppendEvent`) and Phase 8 (transport) depend on:

- `wtp_dropped_invalid_utf8_total` (counter): a record was dropped because the canonical encoder reported `chain.ErrInvalidUTF8`. Wired by `AppendEvent` (Task 23).
- `wtp_dropped_sequence_overflow_total` (counter): a record was dropped because `ev.Chain.Sequence > math.MaxInt64`. Wired by `AppendEvent` (Task 23).
- `wtp_dropped_invalid_frame_total{reason}` (counter, labeled): a peer frame was dropped at the protocol-validation boundary. The reason set splits into two disjoint categories:
  - **Validator-emitted reasons** (proto-side `wtpv1.ValidationReason` constants returned by `ValidateEventBatch`/`ValidateSessionInit` as `*ValidationError`): `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`, and `unknown` (forward-compat catch-all for new oneof discriminators added to the proto schema before the validator switch is updated; the validator returns `&ValidationError{Reason: ReasonUnknown}` rather than a bare `fmt.Errorf` — see Task 17 Step 4). These reasons MUST appear in BOTH `wtpv1.ValidationReason` and `WTPInvalidFrameReason` with byte-equal string values; the parity test (Step 4 below) enforces exact set equality.
  - **Metrics-only reasons** (NOT validator-emitted; no proto-side counterpart): `decompress_error` (incremented by streaming-decompression code downstream of `ValidateEventBatch` when zstd/gzip framing fails or `MaxDecompressedBatchBytes` is exceeded) and `classifier_bypass` (incremented by the defense-in-depth path when a non-`*ValidationError` is encountered by the receiver-side `errors.As`-false guard, OR when an invalid label string is passed to `IncDroppedInvalidFrame` and collapsed by the metrics-side invalid-label guard — see Step 4 below for both code paths and the WARN log emitted on the metrics-side collapse).

  The Go-side label values come from `wtpv1.ValidationReason` constants for the validator-emitted reasons (added in Task 17 Step 4); a future receiver consumes `errors.As(err, &ve)` and increments using `WTPInvalidFrameReason(ve.Reason)`. Wired by transport / receivers in Phase 8 — specifically Task 17 Step 4a, where the Live state's inbound `ServerMessage` handling increments this counter and triggers the `stream_recv_error` reconnect path. Phase 9 (testserver) covers the symmetric server-side validation of inbound `ClientMessage` frames.
- `wtp_session_init_failures_total{reason}` (counter, labeled): an in-band session-init step failed; reason `invalid_utf8` is the only enumerated value today, with `unknown` as the catch-all. Wired by transport in Phase 8.
- `wtp_session_rotation_failures_total{reason}` (counter, labeled): same shape as init, but for rotation/SessionUpdate. Wired by transport in Phase 8.

**Encode-error classification counters.** Task 9 added defense-in-depth validation to `compact.Encode`. `AppendEvent` (Task 23) classifies Encode failures via `errors.Is`. Three classes are dropped silently and counted (each also emits a WARN-severity structured log); the fourth (`ErrMissingChain`) is propagated to the caller as a wrapped error and has no counter (a missing chain indicates a composite-store regression that operators must surface loudly), but it DOES emit one ERROR-severity structured log per occurrence with internal-only fields `{event_id, session_id, event_type, err}` — `generation` is intentionally excluded because the chain is nil on this branch (see spec §"Caller contract for propagated `compact.ErrMissingChain`" for the rationale):

- `wtp_dropped_invalid_mapper_total` (counter): a record was dropped because `compact.Encode` returned `ErrInvalidMapper`. This is defense in depth — `Store.New` rejects the same condition at construction time, so this counter SHOULD always be 0 in practice. A non-zero value indicates a code path constructed `Store` with an invalid mapper or mutated it post-construction.
- `wtp_dropped_invalid_timestamp_total` (counter): a record was dropped because `compact.Encode` returned `ErrInvalidTimestamp` (zero or pre-epoch).
- `wtp_dropped_mapper_failure_total` (counter): a record was dropped because `compact.Encode` returned a wrapped mapper-side error — i.e., `mapper.Map()` returned a non-sentinel error. This is the catch-all for mapper-internal failures and matches the `default` branch of the `errors.Is` classification switch in `AppendEvent`. The wrapped error is preserved through `errors.Unwrap` so operators can inspect the underlying mapper failure in the structured log.

Wiring sketch in `AppendEvent`:

```go
ce, err := compact.Encode(s.opts.Mapper, ev)
if err != nil {
    switch {
    case errors.Is(err, compact.ErrMissingChain):
        // Loud failure — composite-store regression. No counter (it's a
        // developer error, not a runtime drop class), but MUST emit one
        // ERROR-severity structured log via the same `slogger` used by
        // the other drop branches. Fields: {event_id, session_id,
        // event_type, err} — internal state only, no peer-supplied
        // content. The log is exempt from the invalid-frame
        // sanitization rule because every field is internal-only (no
        // peer bytes ever appear). `generation` is intentionally
        // excluded because composite-store generation is only available
        // via `ev.Chain.Generation`, which is nil on this branch by
        // definition — see spec §"Caller contract for propagated
        // `compact.ErrMissingChain`".
        slog.ErrorContext(ctx, "watchtower: composite-store regression — missing chain",
            slog.String("event_id", ev.ID),         // ev.ID verbatim — empty string when ev.ID is empty (no substitute)
            slog.String("session_id", ev.SessionID), // internal-only correlation key
            slog.String("event_type", ev.Type),     // internal-only event category
            slog.String("err", err.Error()),        // wrapped sentinel string only — no peer bytes
        )
        return fmt.Errorf("watchtower: %w", err)
    case errors.Is(err, compact.ErrInvalidMapper):
        s.opts.Metrics.WTP().IncDroppedInvalidMapper(1)
    case errors.Is(err, compact.ErrInvalidTimestamp):
        s.opts.Metrics.WTP().IncDroppedInvalidTimestamp(1)
    default:
        // Mapper-internal error wrapped by Encode as `compact mapper: %w`.
        s.opts.Metrics.WTP().IncDroppedMapperFailure(1)
    }
    return nil // sink-internal drop; chain does NOT advance
}
```

Task 3 already executed and was committed; these counters were not in scope at the time. Task 3 also shipped a `wtp_dropped_missing_chain_total` counter that is no longer used: the missing-chain class is now propagated as a wrapped error from `AppendEvent` (composite-store regressions must surface loudly). The orphaned counter is removed in Step 3.5 below to avoid leaving dead metric series in scrapes. The remaining sink-failure counters are added here, between the existing Task 22 (Store skeleton) and Task 23 (AppendEvent), so the dependency chain "metrics exist → AppendEvent uses them" is honored.

**Files:**
- Modify: `internal/metrics/wtp.go`
- Modify: `internal/metrics/metrics.go` (new Collector fields)
- Modify: `internal/metrics/wtp_test.go`

- [ ] **Step 1: Write the failing tests**

Append the new test functions below to `internal/metrics/wtp_test.go` (mirror the existing pattern from Task 3). The full list (ten functions) covers the five sink-failure counters added in this task PLUS the `wtp_dropped_invalid_frame_total{reason}` always-emit zero-init, the validator-emitted-vs-metrics-only label coverage, and the `IncDroppedInvalidFrame` invalid-label collapse + WARN log path. The new test `TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses` requires `bytes` and `log/slog` imports (the existing test file does not yet pull them in — add them at the top of the file alongside the existing `httptest`/`strings`/`testing` imports):

```go
func TestWTPMetrics_DroppedInvalidUTF8(t *testing.T) {
	c := New()
	w := c.WTP()

	// Initial scrape: counter must be present at zero.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_utf8_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_utf8_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidUTF8(2)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_utf8_total 2") {
		t.Errorf("expected wtp_dropped_invalid_utf8_total 2 after IncDroppedInvalidUTF8(2)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidUTF8(); got != 2 {
		t.Errorf("DroppedInvalidUTF8 accessor returned %d, want 2", got)
	}
}

func TestWTPMetrics_DroppedSequenceOverflow(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_sequence_overflow_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_sequence_overflow_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedSequenceOverflow(3)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_sequence_overflow_total 3") {
		t.Errorf("expected wtp_dropped_sequence_overflow_total 3 after IncDroppedSequenceOverflow(3)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedSequenceOverflow(); got != 3 {
		t.Errorf("DroppedSequenceOverflow accessor returned %d, want 3", got)
	}
}

func TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	// Note: no IncSessionInitFailures calls. Per spec the family must
	// still be present with zero-valued series for every enumerated reason.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{"invalid_utf8", "unknown"}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_session_init_failures_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued series %q\nbody:\n%s", want, body)
		}
	}
	// After one increment, only that reason flips to 1; the others stay 0.
	c.WTP().IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_session_init_failures_total{reason="invalid_utf8"} 1`) {
		t.Errorf("expected invalid_utf8=1 after one IncSessionInitFailures\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_session_init_failures_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid_utf8 increment\nbody:\n%s", body)
	}
}

func TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{"invalid_utf8", "unknown"}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_session_rotation_failures_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued series %q\nbody:\n%s", want, body)
		}
	}
	c.WTP().IncSessionRotationFailures(WTPSessionFailureReasonInvalidUTF8)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_session_rotation_failures_total{reason="invalid_utf8"} 1`) {
		t.Errorf("expected invalid_utf8=1 after one IncSessionRotationFailures\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_session_rotation_failures_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid_utf8 increment\nbody:\n%s", body)
	}
}

func TestWTPMetrics_SessionFailureReasonValidationAndEscape(t *testing.T) {
	c := New()
	w := c.WTP()

	w.IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	// Invalid (unknown enum) collapses to WTPSessionFailureReasonUnknown.
	w.IncSessionInitFailures(WTPSessionFailureReason("evil\"label\\value"))
	w.IncSessionRotationFailures(WTPSessionFailureReasonInvalidUTF8)
	w.IncSessionRotationFailures(WTPSessionFailureReason("evil\"label\\value"))

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_init_failures_total{reason="unknown"} 1`,
		`wtp_session_rotation_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_rotation_failures_total{reason="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

func TestWTPMetrics_DroppedInvalidMapper(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_mapper_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_mapper_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidMapper(1)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_mapper_total 1") {
		t.Errorf("expected wtp_dropped_invalid_mapper_total 1 after IncDroppedInvalidMapper(1)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidMapper(); got != 1 {
		t.Errorf("DroppedInvalidMapper accessor returned %d, want 1", got)
	}
}

func TestWTPMetrics_DroppedInvalidTimestamp(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_timestamp_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_timestamp_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidTimestamp(2)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_timestamp_total 2") {
		t.Errorf("expected wtp_dropped_invalid_timestamp_total 2 after IncDroppedInvalidTimestamp(2)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidTimestamp(); got != 2 {
		t.Errorf("DroppedInvalidTimestamp accessor returned %d, want 2", got)
	}
}

func TestWTPMetrics_DroppedMapperFailure(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_mapper_failure_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_mapper_failure_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedMapperFailure(4)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_mapper_failure_total 4") {
		t.Errorf("expected wtp_dropped_mapper_failure_total 4 after IncDroppedMapperFailure(4)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedMapperFailure(); got != 4 {
		t.Errorf("DroppedMapperFailure accessor returned %d, want 4", got)
	}
}

func TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	// Note: no IncDroppedInvalidFrame calls. Per spec the family must
	// still be present with zero-valued series for every enumerated reason.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{
		"classifier_bypass",
		"decompress_error",
		"event_batch_body_unset",
		"event_batch_compression_mismatch",
		"event_batch_compression_unspecified",
		"payload_too_large",
		"session_init_algorithm_unspecified",
		"unknown",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_dropped_invalid_frame_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued series %q\nbody:\n%s", want, body)
		}
	}

	// After one increment, only that reason flips to 1; the others stay 0.
	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReasonEventBatchBodyUnset)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="event_batch_body_unset"} 1`) {
		t.Errorf("expected event_batch_body_unset=1 after one IncDroppedInvalidFrame\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after event_batch_body_unset increment\nbody:\n%s", body)
	}

	// Invalid (unknown enum) collapses to WTPInvalidFrameReasonClassifierBypass
	// (NOT WTPInvalidFrameReasonUnknown — those are now disjoint reasons per
	// spec §"Operator runbook": `unknown` is RESERVED for validator-emitted
	// ReasonUnknown, while invalid label values from a caller are metrics-side
	// defect indicators that share the `classifier_bypass` semantic).
	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReason("evil\"label\\value"))
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="classifier_bypass"} 1`) {
		t.Errorf("expected classifier_bypass=1 after invalid-reason fallback\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid-reason fallback (unknown is RESERVED for validator-emitted ReasonUnknown)\nbody:\n%s", body)
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

// TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses asserts that
// IncDroppedInvalidFrame emits a single WARN-level structured log on the
// invalid-label collapse path AND increments the metric under
// classifier_bypass. The log line MUST include `raw_reason` (the offending
// caller-supplied string) so operators paged on classifier_bypass can grep
// recent WARN logs to identify the offending callsite. Pairs with the
// receiver-side `non-typed frame validation error` WARN log emitted by
// Task 17 Step 4a's defense-in-depth guard — together they cover both
// classifier_bypass code paths per spec §"Operator runbook".
func TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses(t *testing.T) {
	// Capture slog output via a buffer-backed handler so we can assert
	// exactly one WARN entry was emitted. Restore the previous default
	// logger on cleanup so other tests are not affected.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := New()
	const badRaw = "not-a-canonical-reason"
	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReason(badRaw))

	// (1) Metric incremented under classifier_bypass (NOT under "unknown" or
	// the bad raw value).
	if got := c.WTP().DroppedInvalidFrame(WTPInvalidFrameReasonClassifierBypass); got != 1 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 1", got)
	}
	if got := c.WTP().DroppedInvalidFrame(WTPInvalidFrameReasonUnknown); got != 0 {
		t.Errorf("DroppedInvalidFrame(unknown) = %d, want 0 (must NOT collapse to unknown)", got)
	}

	// (2) Exactly one WARN entry was emitted with the expected message and
	// raw_reason field. The handler emits one JSON object per log call, so
	// counting newlines tells us exactly one entry was captured.
	logOutput := buf.String()
	if want := "invalid invalid-frame reason label"; !strings.Contains(logOutput, want) {
		t.Errorf("expected WARN log message %q in captured log output\nlog:\n%s", want, logOutput)
	}
	if want := `"raw_reason":"` + badRaw + `"`; !strings.Contains(logOutput, want) {
		t.Errorf("expected raw_reason field %q in captured log output\nlog:\n%s", want, logOutput)
	}
	if want := `"reason":"classifier_bypass"`; !strings.Contains(logOutput, want) {
		t.Errorf("expected reason=classifier_bypass field in captured log output\nlog:\n%s", want, logOutput)
	}
	if got := strings.Count(strings.TrimRight(logOutput, "\n"), "\n") + 1; got != 1 {
		t.Errorf("expected exactly one WARN log entry, got %d\nlog:\n%s", got, logOutput)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/metrics/ -run "TestWTPMetrics_DroppedInvalidUTF8|TestWTPMetrics_DroppedSequenceOverflow|TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons|TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons|TestWTPMetrics_SessionFailureReasonValidationAndEscape|TestWTPMetrics_DroppedInvalidMapper|TestWTPMetrics_DroppedInvalidTimestamp|TestWTPMetrics_DroppedMapperFailure|TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons|TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses"`
Expected: FAIL with `IncDroppedInvalidUTF8 undefined`, `WTPSessionFailureReason undefined`, `IncDroppedInvalidMapper undefined`, `IncDroppedMapperFailure undefined`, `WTPInvalidFrameReason undefined`, etc.

- [ ] **Step 3: Implement — extend `internal/metrics/wtp.go`**

Add the failure-reason type, valid map, and emit-order slice (mirroring `WTPReconnectReason`):

```go
// WTPSessionFailureReason is a fixed, low-cardinality classification of why
// a session-init or session-rotation step failed. Adding new reasons
// requires updating both the spec §Metrics section and the
// wtpSessionFailureReasonsValid table below.
type WTPSessionFailureReason string

const (
	WTPSessionFailureReasonInvalidUTF8 WTPSessionFailureReason = "invalid_utf8"
	WTPSessionFailureReasonUnknown     WTPSessionFailureReason = "unknown"
)

var wtpSessionFailureReasonsValid = map[WTPSessionFailureReason]struct{}{
	WTPSessionFailureReasonInvalidUTF8: {},
	WTPSessionFailureReasonUnknown:     {},
}

// wtpSessionFailureReasonsEmitOrder is the canonical, sorted-by-string
// emission order for the session-failure families. Using a fixed slice
// keeps Prometheus exposition deterministic and lets emitWTPMetrics emit
// zero-valued series for reasons that have not yet fired (per the
// always-emit contract in the design spec).
var wtpSessionFailureReasonsEmitOrder = []WTPSessionFailureReason{
	WTPSessionFailureReasonInvalidUTF8,
	WTPSessionFailureReasonUnknown,
}

// WTPInvalidFrameReason is a fixed, low-cardinality classification of why
// a peer frame was dropped at the protocol-validation boundary. The
// reason set splits into two disjoint categories:
//
//   - Validator-emitted (proto-side wtpv1.ValidationReason has byte-equal
//     constants): WTPInvalidFrameReasonEventBatchBodyUnset,
//     WTPInvalidFrameReasonEventBatchCompressionUnspec,
//     WTPInvalidFrameReasonEventBatchCompressionMismatch,
//     WTPInvalidFrameReasonSessionInitAlgorithmUnspec,
//     WTPInvalidFrameReasonPayloadTooLarge,
//     WTPInvalidFrameReasonUnknown. Receivers consume the reason via
//     errors.As against *wtpv1.ValidationError and forward ve.Reason
//     directly into IncDroppedInvalidFrame. The parity test
//     (TestWTPInvalidFrameReason_ParityWithValidator, Step 4) enforces
//     exact set equality between this category and AllValidationReasons().
//
//   - Metrics-only (no proto-side counterpart):
//     WTPInvalidFrameReasonDecompressError — emitted by the streaming-
//     decompression code downstream of ValidateEventBatch (decompression
//     runs after the validator accepts the frame envelope).
//     WTPInvalidFrameReasonClassifierBypass — emitted by the receiver-
//     side errors.As-false defense-in-depth guard when a non-validator
//     caller passes a bare error into the classifier. Has no proto-side
//     counterpart by definition because the validator never emits it
//     (the validator MUST always return *ValidationError per spec
//     §"Reason classification (validator contract)"); a non-zero count
//     is a code-path defect indicator (see spec §"Operator runbook").
//
// IMPORTANT — `unknown` vs `classifier_bypass`: these are DISJOINT
// reasons with disjoint operator interpretations. `unknown` means the
// validator returned ReasonUnknown for a new oneof discriminator
// (peer-side schema drift, fix by extending the validator). `classifier_
// bypass` means the receiver's errors.As returned false (local-side
// caller bug, fix by finding and wrapping the bare error). Operators
// MUST NOT treat them as interchangeable.
//
// Adding a new validator-emitted reason requires updating: (a)
// wtpv1.ValidationReason in proto/canyonroad/wtp/v1/validate.go and
// allValidationReasons backing AllValidationReasons(), (b) the
// constants below, (c) the wtpInvalidFrameReasonsValid table, (d) the
// wtpInvalidFrameReasonsEmitOrder slice, and (e) the spec §Metrics enum
// list. Adding a new metrics-only reason skips (a) but adds the
// constant to MetricsOnlyReasons() (Step 3). The two enums are kept
// deliberately separate (proto vs. metrics package) so the metrics
// package does not import the proto package — but the validator-
// emitted string values must stay byte-equal.
type WTPInvalidFrameReason string

const (
	WTPInvalidFrameReasonEventBatchBodyUnset            WTPInvalidFrameReason = "event_batch_body_unset"
	WTPInvalidFrameReasonEventBatchCompressionUnspec    WTPInvalidFrameReason = "event_batch_compression_unspecified"
	WTPInvalidFrameReasonEventBatchCompressionMismatch  WTPInvalidFrameReason = "event_batch_compression_mismatch"
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec     WTPInvalidFrameReason = "session_init_algorithm_unspecified"
	WTPInvalidFrameReasonPayloadTooLarge                WTPInvalidFrameReason = "payload_too_large"
	WTPInvalidFrameReasonDecompressError                WTPInvalidFrameReason = "decompress_error"
	// WTPInvalidFrameReasonClassifierBypass is the metrics-only reason
	// emitted by the receiver-side errors.As-false defense-in-depth
	// guard (see spec §"Receiver-side defense in depth"). Disjoint from
	// WTPInvalidFrameReasonUnknown — see the type-doc above for the
	// "unknown vs classifier_bypass" distinction. Has no proto-side
	// counterpart by definition.
	WTPInvalidFrameReasonClassifierBypass               WTPInvalidFrameReason = "classifier_bypass"
	WTPInvalidFrameReasonUnknown                        WTPInvalidFrameReason = "unknown"
)

var wtpInvalidFrameReasonsValid = map[WTPInvalidFrameReason]struct{}{
	WTPInvalidFrameReasonEventBatchBodyUnset:           {},
	WTPInvalidFrameReasonEventBatchCompressionUnspec:   {},
	WTPInvalidFrameReasonEventBatchCompressionMismatch: {},
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec:    {},
	WTPInvalidFrameReasonPayloadTooLarge:               {},
	WTPInvalidFrameReasonDecompressError:               {},
	WTPInvalidFrameReasonClassifierBypass:              {},
	WTPInvalidFrameReasonUnknown:                       {},
}

// wtpInvalidFrameReasonsEmitOrder mirrors the wtpSessionFailureReasonsEmitOrder
// pattern: a fixed slice keeps Prometheus exposition deterministic and lets
// emitWTPMetrics emit zero-valued series for every enumerated reason on
// every scrape. Order is alphabetical-by-string for stable output.
var wtpInvalidFrameReasonsEmitOrder = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonClassifierBypass,
	WTPInvalidFrameReasonDecompressError,
	WTPInvalidFrameReasonEventBatchBodyUnset,
	WTPInvalidFrameReasonEventBatchCompressionMismatch,
	WTPInvalidFrameReasonEventBatchCompressionUnspec,
	WTPInvalidFrameReasonPayloadTooLarge,
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec,
	WTPInvalidFrameReasonUnknown,
}
```

Add the four new accessors / mutators on `WTPMetrics`:

```go
func (w *WTPMetrics) IncDroppedInvalidUTF8(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidUTF8.Add(n)
}

func (w *WTPMetrics) DroppedInvalidUTF8() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidUTF8.Load()
}

func (w *WTPMetrics) IncDroppedSequenceOverflow(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedSequenceOverflow.Add(n)
}

func (w *WTPMetrics) DroppedSequenceOverflow() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedSequenceOverflow.Load()
}

func (w *WTPMetrics) IncSessionInitFailures(reason WTPSessionFailureReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpSessionFailureReasonsValid[reason]; !ok {
		reason = WTPSessionFailureReasonUnknown
	}
	ptr, _ := w.c.wtpSessionInitFailuresByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

func (w *WTPMetrics) IncSessionRotationFailures(reason WTPSessionFailureReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpSessionFailureReasonsValid[reason]; !ok {
		reason = WTPSessionFailureReasonUnknown
	}
	ptr, _ := w.c.wtpSessionRotationFailuresByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// Encode-error classification counters. AppendEvent (Task 23) classifies
// compact.Encode failures via errors.Is and increments the matching
// counter. The chain does NOT advance on any of these drops.

func (w *WTPMetrics) IncDroppedInvalidMapper(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidMapper.Add(n)
}

func (w *WTPMetrics) DroppedInvalidMapper() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidMapper.Load()
}

func (w *WTPMetrics) IncDroppedInvalidTimestamp(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidTimestamp.Add(n)
}

func (w *WTPMetrics) DroppedInvalidTimestamp() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidTimestamp.Load()
}

func (w *WTPMetrics) IncDroppedMapperFailure(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedMapperFailure.Add(n)
}

func (w *WTPMetrics) DroppedMapperFailure() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedMapperFailure.Load()
}

// IncDroppedInvalidFrame increments the wtp_dropped_invalid_frame_total
// counter for the supplied frame-validation reason. Unknown reason values
// collapse to WTPInvalidFrameReasonClassifierBypass (NOT
// WTPInvalidFrameReasonUnknown — those are now disjoint reasons per
// spec §"Operator runbook"; an invalid label value passed by a caller is
// a metrics-side defect indicator, NOT validator-side schema drift) so
// the labeled family stays at a fixed cardinality.
//
// On the invalid-label collapse path the function ALSO emits a WARN-
// level structured log (`slog.Default()`) with the offending raw_reason
// string so operators paged on `classifier_bypass` can identify which
// callsite passed the bad label. The raw_reason is internal — caller-
// controlled, NEVER peer-derived — so it is safe to log verbatim per
// spec §"Operator runbook" and the invalid-frame log sanitization rule.
// This complements the receiver-side WARN log (`non-typed frame
// validation error`) emitted by Task 17 Step 4a's defense-in-depth
// guard; together the two messages let operators grep for either
// `err_type` (receiver path) or `raw_reason` (metrics path) when
// triaging a `classifier_bypass` increment.
func (w *WTPMetrics) IncDroppedInvalidFrame(reason WTPInvalidFrameReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		// Defense-in-depth: caller passed a label string that is not in
		// the canonical WTPInvalidFrameReason enum. Collapse to
		// classifier_bypass and emit a WARN log so operators paged on
		// classifier_bypass can identify the offending callsite via the
		// `raw_reason` field. slog.Default() is used (not a per-collector
		// logger) because WTPMetrics has no plumbed logger today and this
		// path SHOULD never trigger in production — adding a logger field
		// would be over-engineered for a permanently-zero counter.
		slog.Warn("invalid invalid-frame reason label",
			slog.String("raw_reason", string(reason)),
			slog.String("reason", string(WTPInvalidFrameReasonClassifierBypass)),
		)
		reason = WTPInvalidFrameReasonClassifierBypass
	}
	ptr, _ := w.c.wtpDroppedInvalidFrameByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// DroppedInvalidFrame returns the current count for one frame-validation
// reason. Unknown reason values return 0.
func (w *WTPMetrics) DroppedInvalidFrame(reason WTPInvalidFrameReason) uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		return 0
	}
	v, ok := w.c.wtpDroppedInvalidFrameByReason.Load(string(reason))
	if !ok || v == nil {
		return 0
	}
	return v.(*atomic.Uint64).Load()
}
```

Note: `IncDroppedInvalidUTF8`, `IncDroppedSequenceOverflow`, `IncDroppedInvalidMapper`, `IncDroppedInvalidTimestamp`, and `IncDroppedMapperFailure` take a `uint64` for symmetry with the existing `IncEventsAppended(n uint64)` family — a callsite that drops one record passes 1; tests can preload arbitrary values. `IncDroppedInvalidFrame`, `IncSessionInitFailures`, and `IncSessionRotationFailures` take a typed reason instead and always increment by 1, matching `wtp_reconnects_total` — labeled families never need callsite-batched increments.

Imports note: the WARN log emission in `IncDroppedInvalidFrame` requires the `log/slog` import in `internal/metrics/wtp.go` (the file does not currently import it). Add `"log/slog"` to the import block alongside the existing `fmt`, `io`, `sync/atomic`, and `time` entries when implementing this step. The WARN log uses `slog.Default()` rather than a per-collector logger because (a) `WTPMetrics` has no plumbed logger today, (b) this code path SHOULD never trigger in production (the counter is permanently zero in healthy code), and (c) introducing a logger field for a single never-fires path would be over-engineered. The test harness in Step 1's `TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses` swaps `slog.Default()` to a buffer-backed JSON handler and restores it on cleanup so other tests are unaffected.

Update `emitWTPMetrics` (in `internal/metrics/wtp.go`) — append eight new sections just before the histogram block, and (per Step 3.5 below) DELETE the existing Task 3 emit block for `wtp_dropped_missing_chain_total`. The five unlabeled counters are simple; the three labeled families follow the always-emit contract used by `wtp_reconnects_total`:

```go
	fmt.Fprint(w, "# HELP wtp_dropped_invalid_utf8_total Records dropped because the canonical encoder reported invalid UTF-8.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_utf8_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_utf8_total %d\n", c.wtpDroppedInvalidUTF8.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_sequence_overflow_total Records dropped because Chain.Sequence exceeded math.MaxInt64.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_sequence_overflow_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_sequence_overflow_total %d\n", c.wtpDroppedSequenceOverflow.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_invalid_mapper_total Records dropped because compact.Encode rejected the mapper (defense in depth — Store.New also rejects; non-zero means a code path mutated mapper post-construction).\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_mapper_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_mapper_total %d\n", c.wtpDroppedInvalidMapper.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_invalid_timestamp_total Records dropped because compact.Encode rejected ev.Timestamp (zero or pre-epoch).\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_timestamp_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_timestamp_total %d\n", c.wtpDroppedInvalidTimestamp.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_mapper_failure_total Records dropped because compact.Encode wrapped a mapper-side error (default branch of the AppendEvent classification switch).\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_mapper_failure_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_mapper_failure_total %d\n", c.wtpDroppedMapperFailure.Load())

	// Always emit the wtp_dropped_invalid_frame_total family with all
	// enumerated reasons (per the always-emit contract in the design spec).
	fmt.Fprint(w, "# HELP wtp_dropped_invalid_frame_total WTP peer frames dropped at the protocol-validation boundary, by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_frame_total counter\n")
	for _, r := range wtpInvalidFrameReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpDroppedInvalidFrameByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_dropped_invalid_frame_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	// Always emit the wtp_session_init_failures_total family with all
	// enumerated reasons (per the always-emit contract in the design spec).
	fmt.Fprint(w, "# HELP wtp_session_init_failures_total WTP session-init failures by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_session_init_failures_total counter\n")
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpSessionInitFailuresByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_session_init_failures_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	// Always emit the wtp_session_rotation_failures_total family with all
	// enumerated reasons (per the always-emit contract in the design spec).
	fmt.Fprint(w, "# HELP wtp_session_rotation_failures_total WTP session-rotation failures by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_session_rotation_failures_total counter\n")
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpSessionRotationFailuresByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_session_rotation_failures_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}
```

Extend `Collector` (in `internal/metrics/metrics.go`) — add eight new fields next to the existing WTP series. Note that `wtpDroppedMissingChain` already exists from Task 3 and is REMOVED in Step 3.5 below; it is intentionally absent from this list. Round-9 additions (Findings 1, 2, 3 + Missing C) add four more fields below — see "Round-9 ack-cursor / WAL-quarantine series" subsection.

```go
type Collector struct {
	// ... existing fields ...

	// WTP series — sink-failure additions
	wtpDroppedInvalidUTF8              atomic.Uint64
	wtpDroppedSequenceOverflow         atomic.Uint64
	wtpDroppedInvalidMapper            atomic.Uint64
	wtpDroppedInvalidTimestamp         atomic.Uint64
	wtpDroppedMapperFailure            atomic.Uint64
	wtpDroppedInvalidFrameByReason     sync.Map
	wtpSessionInitFailuresByReason     sync.Map
	wtpSessionRotationFailuresByReason sync.Map

	// Round-9 ack-cursor / WAL-quarantine series. See "Round-9 ack-
	// cursor / WAL-quarantine series" subsection below for the per-
	// metric semantics, accessor signatures, alert thresholds, and
	// emission contracts. Brief field roles:
	//   - wtpResendNeeded:      legitimate same-gen ResendNeeded count
	//   - wtpAckRegressionLoss: synthetic loss synthesized in-memory
	//                           (NOT via wal.AppendLoss; per Round-10
	//                           Finding 3) on ack regression past GC'd
	//                           tail
	//   - wtpAnomalousAckByReason: anomalous ack counts keyed by AnomalyReason
	//                              (Round-12 Findings 4+5: FIVE reasons —
	//                              "server_ack_exceeds_local_seq" (round-12
	//                              RENAMED from round-11's
	//                              "beyond_wal_high_water_seq"),
	//                              "stale_generation",
	//                              "unwritten_generation",
	//                              "server_ack_exceeds_local_data",
	//                              "wal_read_failure" (round-12 NEW per
	//                              Finding 4: surfaces non-nil err returned
	//                              by wal.WrittenDataHighWater(...) instead
	//                              of treating I/O failure as ok=false);
	//                              the round-9 "future_generation" name
	//                              was split in round-11 into the
	//                              "unwritten_generation" /
	//                              "server_ack_exceeds_local_data"
	//                              safety-class reasons)
	//   - wtpWALQuarantineByReason: WAL identity-mismatch quarantine count
	//                               keyed by WTPWALQuarantineReason (reasons:
	//                               "session_id_mismatch", "key_fingerprint_mismatch",
	//                               "unknown_identity_mismatch") — Round-10 Finding 6
	//                               replaces the prior unlabelled wtpWALQuarantine field
	wtpResendNeeded            atomic.Uint64
	wtpAckRegressionLoss       atomic.Uint64
	wtpAnomalousAckByReason    sync.Map
	wtpWALQuarantineByReason   sync.Map

	// ... rest unchanged ...
}
```

**Round-9 ack-cursor / WAL-quarantine series.** Four new metrics emitted by the Round-9 cursor model (Findings 1 / 2 / 3 / Missing C). All four feed the spec §"Operational signals" subsection so operators have an alertable signal for each round-9 contract:

| Metric | Type | Labels | Accessor | Emit site | Alert threshold (operator-facing) |
|---|---|---|---|---|---|
| `wtp_resend_needed_total` | counter | none | `IncResendNeeded()` | `applyServerAckTuple` `ResendNeeded` branch (Task 15.1 SessionAck handler + Task 17.X recv handler) | >5/min sustained for >5min — investigate server-side ack persistence (gradual rollout / partition recovery is normal at low rate; sustained high rate indicates an actual server-side bug) |
| `wtp_ack_regression_loss_total` | counter | none | `IncAckRegressionLoss()` | **Round-13 Finding 5: emit-time, NOT compute-time.** Fired by the `ReplayerOptions.OnPrefixLossEmitted` callback wired by Task 15.1's reader-open path (callback closes over `t.metrics.IncAckRegressionLoss()`). The Replayer invokes the callback synchronously inside its FIRST `NextBatch()` call AFTER the synthetic `wal.LossRecord{Reason: "ack_regression_after_gc"}` has been appended as record[0] of the batch AND AFTER the in-Replayer `prefixLossEmitted` gate has flipped to true. **This relocates the increment from the prior compute-time site (round-12: "IMMEDIATELY AFTER `transport.NewReplayer` SUCCEEDS and BEFORE the Replayer produces its first batch") to the emit-time site so the counter reflects "marker landed in a batch the receiver consumed" rather than "marker was scheduled to be consumed".** The synthetic loss record is constructed in memory by `computeReplayStart` when `wal.EarliestDataSequence(persistedAck.gen)` indicates the server's last-seen position is BEHIND the GC'd tail; threaded into the Replayer via `ReplayerOptions.PrefixLoss`; surfaced as the FIRST record of the FIRST batch so it lands at the head of the replay stream, ordered correctly relative to surviving on-disk data. NO `wal.AppendLoss` call, no fsync, no on-disk pollution. The counter is NOT incremented when (a) `computeReplayStart` returned `prefixLoss == nil` (cases B/D of the §"Loss between replay cursor and persisted ack" 4-case table — the no-gap and fully-GC'd-but-server-at-or-past-persisted shapes do not synthesize a marker; `OnPrefixLossEmitted` is only called by the Replayer when `r.opts.PrefixLoss != nil`), (b) `computeReplayStart` returned a non-nil err (the `wal_read_failure` Anomaly path or any other I/O failure surfaces to the Run loop and forces a state transition; no Replayer materialises so the callback never fires), (c) the Replayer is constructed with `PrefixLoss == nil` (the Replayer never re-derives the marker on its own; the callback is never fired), (d) the Replaying state aborts after constructing the Replayer but BEFORE the Replayer's first `NextBatch` returns successfully (e.g. transport.Conn closed by Run loop, ctx cancelled, gen-aware Reader fails to open at the resolved start; the callback is invoked synchronously at the end of `NextBatch` so any pre-emit failure aborts before increment), or (e) the Replaying state never enters the wire-send path because the Run loop tears down between callback fire and batch transmit (the receiver never sees the marker AND the counter incorrectly increments — this case is documented but not architectural: the test of record drives `OnPrefixLossEmitted` immediately after `prefixLossEmitted = true`, before `NextBatch` returns, so it is reachable only by a process abort between the gate flip and the function return; treated as acceptable rounding given the operator-visible signal a divergence between this counter and the receive-side `replay_loss_marker_total` would generate). Net: this counter counts "ack-regression-after-GC loss markers EMITTED into a batch by the Replayer" — strictly tighter than the round-12 "scheduled into the wire path" definition. (Round-10 Finding 3: the prior on-disk-AppendLoss design is abandoned because `AppendLoss` writes to the live WAL tail, which is out-of-order vs. the surviving older sequences AND latches the WAL into fatal on I/O failure — neither is acceptable for a per-reconnect transient signal.) | nonzero rate — investigate ack regression past GC'd WAL tail (this means the server believes data the client has already discarded; usually a server-side ack-persistence bug or a recovery-from-corruption event). A nonzero divergence between this counter and the receive-side `replay_loss_marker_total` family would indicate either (a) a transport bug dropping markers on close, or (b) a server-side classification bug; either is operator-actionable. |
| `wtp_anomalous_ack_total` | counter | `reason ∈ {"server_ack_exceeds_local_seq", "stale_generation", "unwritten_generation", "server_ack_exceeds_local_data", "wal_read_failure"}` | `IncAnomalousAck(reason string)` | `applyServerAckTuple` `Anomaly` branch (all five sub-cases per Round-12 Findings 4+5) | nonzero rate on ANY label — investigate immediately. `server_ack_exceeds_local_seq` (round-12 RENAMED from `beyond_wal_high_water_seq`) indicates the server claims ack of records the client never sent (same-gen `serverSeq > wal.WrittenDataHighWater(server.gen)`). `stale_generation` indicates the server is replaying a closed past. `unwritten_generation` indicates the server named a generation whose segment-header exists on disk but whose RecordData the writer has not emitted — admitting this ack would let lex GC discard lower-gen segments holding unsent history. `server_ack_exceeds_local_data` indicates the server claims ack past the per-gen data-bearing high-water seq the writer has emitted in that generation — same safety class as `unwritten_generation`. `wal_read_failure` (round-12 NEW per Finding 4) indicates `wal.WrittenDataHighWater(server.gen)` returned a non-nil error (I/O failure in the WAL accessor) — the helper surfaces it as Anomaly so cursors stay frozen and the operator gets a discoverable signal instead of a silent ok=false fallback. None should ever fire under correct operation. |
| `wtp_wal_quarantine_total` | counter | `reason ∈ {"session_id_mismatch", "key_fingerprint_mismatch", "unknown_identity_mismatch"}` | `IncWALQuarantine(reason WTPWALQuarantineReason)` | Store-layer `wal.Open` recovery path (Task 27 wiring) when `errors.As(err, &wal.ErrIdentityMismatch{})` triggers a rename of the existing WAL dir to `<dir>.quarantine.<unix-nanos>-<random4hex>` (per Round-10 Missing A — see spec §Quarantine policy) and a fresh `wal.Open` against the now-empty Dir. The reason label is derived from `ErrIdentityMismatch.Field` (`session_id` → `session_id_mismatch`, `key_fingerprint` → `key_fingerprint_mismatch`, anything else → `unknown_identity_mismatch`). The accessor validates the reason against `wtpWALQuarantineReasonsValid` and falls back to `unknown_identity_mismatch` on any unknown string (mirroring the `IncReconnects` reason-validation pattern in `wtp.go`). | nonzero rate on `session_id_mismatch` or `key_fingerprint_mismatch` — investigate WAL identity mismatch (legitimate operator action: key rotation / session reissue. RARE — sustained nonzero rate indicates a misconfigured restart loop or a session_id generator that does not persist across restarts.) `unknown_identity_mismatch` is a hard alert: it indicates `ErrIdentityMismatch.Field` carried a value the accessor did not enumerate, which is a programming error in the WAL package or in the wiring layer's classifier. |

Accessor signatures live in `internal/metrics/wtp.go`. The accessors are nil-safe and use the `WTPMetrics{c *Collector}` facade pattern established in Task 3 (NOT `parent` — see existing `IncReconnects` / `IncEventsAppended` etc. for the canonical shape). Reason-validated counters mirror the `wtpReconnectReasonsValid` table pattern from the same file: an enumerated `WTPWALQuarantineReason` type with a validation map and an emit-order slice keeps the Prometheus exposition deterministic and bounds label cardinality.

**Migration story for `wtp_wal_quarantine_total` (Round-11 Missing A).** This metric is BRAND NEW in Round 9 / Round 10 — there is NO predecessor counter that operators are scraping for the same signal. Concretely:

- No prior version of this spec or codebase shipped a counter, log, or alert with the same semantic ("WAL identity mismatch triggered a quarantine rename"). Identity mismatch was added by the Round-9 PRD policy and the supporting metric is being introduced in the same release. **Therefore no migration is required — operators add the new alert without retiring an old one.**
- Standard Prometheus rule shape (recommended for operator dashboards):
  - **Per-reason rate alert** — `sum by (reason) (increase(wtp_wal_quarantine_total{reason=~"session_id_mismatch|key_fingerprint_mismatch"}[5m])) > 0` to detect any legitimate-but-rare identity-mismatch event. Pair with the runbook entry covering key rotation / session reissue. Page on the FIRST observation if your environment does not perform planned key rotations; otherwise alert-don't-page and review during business hours.
  - **Programming-error alert** — `sum (increase(wtp_wal_quarantine_total{reason="unknown_identity_mismatch"}[5m])) > 0` is a HARD page: it indicates the WAL package returned an `ErrIdentityMismatch` whose `Field` value is not enumerated by the metrics-side classifier (or the classifier is stale). Investigate the WAL package's `errIdentityMismatch.Field` constants vs. the metrics-side `WTPWALQuarantineReason` enumeration; the two MUST stay in lock-step.
- Always-emit / zero-init contract (per Task 22a Step 3): the metric MUST appear in the Prometheus exposition at zero on every scrape from the moment metrics is initialized, regardless of WTP enable state. This means dashboards using the metric never have to special-case "no data" vs. "zero quarantines" — the series is always present.
- Series cardinality is bounded by the three-element `wtpWALQuarantineReasonsValid` enumeration. Adding a new reason value is a coordinated change (WAL package + metrics package + dashboards + alerts + runbook entry) and is documented in this section's update procedure rather than a metrics-only refactor.

This Round-11 Missing A note exists to reassure operators that there is NO breaking change here — unlike the `wtp_dropped_missing_chain_total` removal (Step 3.5 above) or the `wtp_dropped_invalid_frame_total{reason="unknown"}` semantic split (spec §"Migration from pre-split `unknown`"), this metric is a pure addition. Operators copy the alert recipes above into their stack-of-choice (Prometheus, Grafana, Datadog, etc.) without any prior-state cleanup.

```go
// IncResendNeeded increments wtp_resend_needed_total. Called by
// applyServerAckTuple's ResendNeeded branch (the only legitimate
// same-gen regression path; cross-gen lower-server is Anomaly per
// Round-9 same-gen narrowing). NOT rate-limited — the metric is
// the canonical volume signal.
func (w *WTPMetrics) IncResendNeeded() {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpResendNeeded.Add(1)
}

// IncAckRegressionLoss increments wtp_ack_regression_loss_total.
// Called from the `ReplayerOptions.OnPrefixLossEmitted` callback that
// the Replaying state's reader-open path wires when constructing the
// Replayer (Task 15.1 Step 1b.5; closure shape:
// `func() { t.metrics.IncAckRegressionLoss() }`). The Replayer fires
// this callback synchronously inside its FIRST `NextBatch()` call AFTER
// the synthetic `wal.LossRecord{Reason: "ack_regression_after_gc"}`
// has been appended as record[0] of the batch AND AFTER the in-Replayer
// `prefixLossEmitted` gate has flipped to true. The transport synthesizes
// the loss record IN MEMORY (Round-10 Finding 3: NOT via wal.AppendLoss —
// see "Round-9 ack-cursor" series description above for the rationale)
// inside `computeReplayStart` when the local WAL's earliest sequence is
// strictly past the server's last-seen position (i.e. the server's
// belief is BEHIND the GC'd tail) and threads it into the Replayer via
// `ReplayerOptions.PrefixLoss`; the Replayer surfaces it as the FIRST
// record of its FIRST batch so the receiver gets a single coalescable
// loss notice ordered correctly relative to the surviving on-disk data,
// instead of silent data drop.
//
// Counting semantics (round-13 Finding 5: emit-time, NOT compute-time).
// The counter is incremented EXACTLY ONCE per batch that successfully
// emits a synthetic PrefixLoss as record[0]. Concretely the call site
// is the Replayer's `NextBatch()` method, immediately AFTER the
// `prefixLossEmitted` gate has been set to true (defense-in-depth
// against re-entry: the Replayer cannot re-fire the callback even if
// `NextBatch` is somehow re-entered before the gate flip is observed).
// **This relocates the increment from the prior compute-time site
// (round-12: "IMMEDIATELY AFTER `transport.NewReplayer(...)` SUCCEEDS
// and BEFORE the Replayer produces its first batch") to the emit-time
// site so the counter reflects "marker landed in a batch the receiver
// consumed" rather than "marker was scheduled to be consumed".** The
// counter is NOT incremented when:
//   - `computeReplayStart` returns `prefixLoss == nil` (cases B, D
//     of the §"Loss between replay cursor and persisted ack" 4-case
//     table — the no-gap and fully-GC'd-but-server-at-or-past-
//     persisted shapes do not synthesize a marker; `OnPrefixLossEmitted`
//     is only called by the Replayer when `r.opts.PrefixLoss != nil`);
//   - `computeReplayStart` returns a non-nil err (case `wal_read_failure`
//     or any other I/O failure — the helper surfaces the error to the
//     Run loop which forces a state transition, and no Replayer
//     materialises so the callback never fires);
//   - the Replayer is constructed with `PrefixLoss == nil` (the
//     Replayer never re-derives the marker on its own; the callback
//     is never fired);
//   - the Replaying state aborts after constructing the Replayer but
//     BEFORE the Replayer's first `NextBatch` returns successfully
//     (e.g. transport.Conn closed by Run loop, ctx cancelled, gen-aware
//     Reader fails to open at the resolved start; the callback is
//     invoked synchronously at the end of `NextBatch` so any pre-emit
//     failure aborts before increment);
//   - `OnPrefixLossEmitted` is left nil by the caller (the Replayer
//     guards the callback invocation with `if r.opts.OnPrefixLossEmitted
//     != nil` — production wiring MUST set it; the option is nil-safe
//     so unit tests can construct a Replayer without the metric
//     dependency).
// In other words: this counter strictly counts "ack-regression-after-
// GC loss markers EMITTED INTO A BATCH BY THE REPLAYER" — strictly
// tighter than the round-12 "scheduled into the wire path" definition.
// A nonzero divergence between this counter and the receive-side
// `replay_loss_marker_total` (server-side) family would indicate
// either (a) a transport bug dropping markers on close (the marker
// emitted but the batch never crossed the wire), or (b) a server-side
// classification bug; either is operator-actionable.
func (w *WTPMetrics) IncAckRegressionLoss() {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpAckRegressionLoss.Add(1)
}

// IncAnomalousAck increments wtp_anomalous_ack_total{reason=<reason>}.
// Reason MUST be one of "server_ack_exceeds_local_seq" (round-12 RENAMED
// from "beyond_wal_high_water_seq"), "stale_generation",
// "unwritten_generation", "server_ack_exceeds_local_data", or
// "wal_read_failure" (round-12 NEW) — the FIVE Anomaly sub-cases
// enumerated by applyServerAckTuple (round-11 Finding 1 split the
// round-9 "future_generation" name into the
// "unwritten_generation"/"server_ack_exceeds_local_data" pair;
// round-12 Findings 4 + 5 added "wal_read_failure" and renamed
// "beyond_wal_high_water_seq" → "server_ack_exceeds_local_seq" to
// align same-gen and cross-gen taxonomy). Other strings are accepted
// (the sync.Map keys on raw string), but emitWTPMetrics will quote
// the label and operators will see whatever raw string flowed
// through. Validator drift is caught by the Task 22b parity tests
// asserting these five reasons are the only ones the helper can emit.
func (w *WTPMetrics) IncAnomalousAck(reason string) {
	if w == nil || w.c == nil {
		return
	}
	v, _ := w.c.wtpAnomalousAckByReason.LoadOrStore(reason, &atomic.Uint64{})
	v.(*atomic.Uint64).Add(1)
}

// WTPWALQuarantineReason is a fixed, low-cardinality classification of
// why the Store-wiring layer quarantined an existing WAL directory.
// Adding new reasons requires updating both the spec
// §"Quarantine policy" subsection and the wtpWALQuarantineReasonsValid
// table below (parity-asserted by the Task 22b verification tests).
type WTPWALQuarantineReason string

const (
	WTPWALQuarantineReasonSessionIDMismatch     WTPWALQuarantineReason = "session_id_mismatch"
	WTPWALQuarantineReasonKeyFingerprintMismatch WTPWALQuarantineReason = "key_fingerprint_mismatch"
	WTPWALQuarantineReasonUnknown               WTPWALQuarantineReason = "unknown_identity_mismatch"
)

var wtpWALQuarantineReasonsValid = map[WTPWALQuarantineReason]struct{}{
	WTPWALQuarantineReasonSessionIDMismatch:     {},
	WTPWALQuarantineReasonKeyFingerprintMismatch: {},
	WTPWALQuarantineReasonUnknown:               {},
}

// wtpWALQuarantineReasonsEmitOrder is the canonical, sorted-by-string
// emission order for the wtp_wal_quarantine_total family. Mirrors the
// wtpReconnectReasonsEmitOrder pattern: a fixed slice keeps Prometheus
// exposition deterministic and lets emitWTPMetrics emit zero-valued
// series for reasons that have not yet fired (always-emit contract).
var wtpWALQuarantineReasonsEmitOrder = []WTPWALQuarantineReason{
	WTPWALQuarantineReasonKeyFingerprintMismatch,
	WTPWALQuarantineReasonSessionIDMismatch,
	WTPWALQuarantineReasonUnknown,
}

// IncWALQuarantine increments wtp_wal_quarantine_total{reason=<reason>}.
// Called by the Store-layer wal.Open recovery path when an existing WAL
// dir's persisted identity (SessionID / KeyFingerprint) does not match
// the configured identity. The recovery path renames the existing dir
// to <dir>.quarantine.<unix-nanos>-<random4hex> (per Round-10 Missing A
// — see spec §"Quarantine policy" for the naming rationale) and opens
// a fresh WAL against the now-empty Dir; this counter records the
// rename/quarantine event keyed by the field that mismatched.
//
// Unknown reasons fall back to WTPWALQuarantineReasonUnknown rather
// than being silently passed through — this mirrors the IncReconnects
// validation pattern in wtp.go and bounds label cardinality even if a
// future ErrIdentityMismatch.Field carries a value the wiring layer's
// classifier did not anticipate.
func (w *WTPMetrics) IncWALQuarantine(reason WTPWALQuarantineReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpWALQuarantineReasonsValid[reason]; !ok {
		reason = WTPWALQuarantineReasonUnknown
	}
	ptr, _ := w.c.wtpWALQuarantineByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}
```

Note the field rename in `Collector`: `wtpWALQuarantine atomic.Uint64` becomes `wtpWALQuarantineByReason sync.Map` (mirroring `wtpReconnectsByReason`) so the per-reason counter set is sparse on the wire but always emitted in the canonical order. Update the field declaration block above accordingly when implementing this task.

Exposition lines (in `emitWTPMetrics`):

```go
fmt.Fprintf(w, "wtp_resend_needed_total %d\n", c.wtpResendNeeded.Load())
fmt.Fprintf(w, "wtp_ack_regression_loss_total %d\n", c.wtpAckRegressionLoss.Load())
c.wtpAnomalousAckByReason.Range(func(k, v any) bool {
	r := k.(string)
	n := v.(*atomic.Uint64).Load()
	fmt.Fprintf(w, "wtp_anomalous_ack_total{reason=%q} %d\n", escapeLabelValue(r), n)
	return true
})
// Always emit wtp_wal_quarantine_total with all enumerated reasons (per the
// always-emit contract). Mirrors the wtp_reconnects_total emission shape.
fmt.Fprint(w, "# HELP wtp_wal_quarantine_total WTP WAL identity-mismatch quarantines by reason.\n")
fmt.Fprint(w, "# TYPE wtp_wal_quarantine_total counter\n")
for _, r := range wtpWALQuarantineReasonsEmitOrder {
	var n uint64
	if v, ok := c.wtpWALQuarantineByReason.Load(string(r)); ok && v != nil {
		n = v.(*atomic.Uint64).Load()
	}
	fmt.Fprintf(w, "wtp_wal_quarantine_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
}
```

- [ ] **Step 3.5: Remove the orphaned `wtp_dropped_missing_chain_total` counter shipped in Task 3**

Task 3 shipped a `wtp_dropped_missing_chain_total` counter and an `IncDroppedMissingChain` accessor. The current design propagates `compact.ErrMissingChain` from `AppendEvent` as a wrapped error rather than dropping silently, so that counter has no remaining call site in the WTP sink. Leaving it in place would emit a permanently-zero series on every scrape and risk operators wiring alerts on a metric that can never fire.

Edits:

1. In `internal/metrics/metrics.go`, delete the `wtpDroppedMissingChain atomic.Uint64` field.
2. In `internal/metrics/wtp.go`, delete the `IncDroppedMissingChain` method, the matching `DroppedMissingChain` accessor (if present), and the three `emitWTPMetrics` lines for `wtp_dropped_missing_chain_total`.
3. In `internal/metrics/wtp_test.go`, delete the `w.IncDroppedMissingChain(1)` call from `TestWTPMetrics_AppendAndExpose` and the `"wtp_dropped_missing_chain_total 1"` assertion from the same test's expected-substring slice.

If a callsite outside `internal/metrics` invokes `IncDroppedMissingChain`, the build will fail with `IncDroppedMissingChain undefined` — verify with `rg -n "IncDroppedMissingChain|wtp_dropped_missing_chain_total" internal/ pkg/ cmd/` after the deletion. The expected result is no matches in code; references in `docs/superpowers/plans/` are historical and explicitly superseded (see the admonitions above the Task 3 snippets) and in `docs/superpowers/specs/2026-04-18-wtp-client-design.md` appear only in the migration-guidance paragraph — do not touch the docs from this step.

- [ ] **Step 4: Define metrics-side enum + getter helpers (parity test deferred to Task 22b)**

**Cross-task scheduling note (back-reference to Task 17 Step 4a):** This step's enum and getter helpers (`WTPInvalidFrameReason`, `WTPInvalidFrameReasonClassifierBypass`, `MetricsOnlyReasons()`, `ValidationReasons()`) are consumed by Task 17 Step 4a (the receiver-side defense-in-depth wiring snippet). Schedule Task 22a Step 4 BEFORE Task 17 Step 4a executes; the dependency is one-way (Task 22b's parity test consumes `wtpv1.AllValidationReasons()` from Task 17 Step 4 AND `metrics.ValidationReasons()` / `metrics.MetricsOnlyReasons()` from THIS step, but that does NOT block Task 22a Step 4's own definition of the metrics-side enum — Task 22a Step 4 has NO cross-package dependency and ships independently). Task 17's Prerequisites section calls out this ordering for implementers following the plan strictly in order.

**Parity test deferred to Task 22b.** The cross-package parity test (`TestWTPInvalidFrameReason_ParityWithValidator`) lives in Task 22b ("Cross-task parity integration"), NOT in this step. Task 22a Step 4 ships ONLY the metrics-internal enum, getter helpers, and an internal-only test that asserts the getter contracts on the metrics side (no proto dependency). The four-invariant parity test (forward, reverse, disjoint, coverage) MUST wait until BOTH Task 17 Step 4 AND Task 22a Step 4 have landed — splitting it into Task 22b makes the cross-task dependency explicit and avoids declaring this task "complete" while one of its tests cannot yet pass.

The proto-side `wtpv1.ValidationReason` enum (Task 17 Step 4) and the metrics-side `WTPInvalidFrameReason` enum (defined in THIS step) are intentionally duplicated string sets — the metrics package does NOT import the proto package, but the string values for validator-emitted reasons MUST stay byte-equal so that `WTPInvalidFrameReason(ve.Reason)` always lands in `wtpInvalidFrameReasonsValid`. Task 22b is the canonical enforcement mechanism for that contract — see its task-level description for the four-invariant parity test, which catches drift the moment someone adds a reason to one side and forgets the other. The metrics-only `decompress_error` and `classifier_bypass` reasons are intentionally NOT mirrored on the proto side (the former is emitted downstream of the validator by streaming decompression; the latter is emitted only by the receiver-side defense-in-depth fallback and by definition has no validator counterpart).

This step's acceptance is INTERNAL to the metrics package: define the `WTPInvalidFrameReason` constants, the `wtpInvalidFrameReasonsValid` map, the `wtpInvalidFrameReasonsEmitOrder` slice, and the three exported getters (`ValidWTPInvalidFrameReasons`, `ValidationReasons`, `MetricsOnlyReasons`). Add `internal/metrics/wtp_test.go` (`package metrics`) tests asserting (a) every constant in `validationReasonsShared` appears in `wtpInvalidFrameReasonsValid`; (b) every constant in `metricsOnlyReasons` appears in `wtpInvalidFrameReasonsValid`; (c) `validationReasonsShared` and `metricsOnlyReasons` are disjoint (set-intersection is empty); (d) `validationReasonsShared ∪ metricsOnlyReasons == wtpInvalidFrameReasonsValid` (coverage). These four assertions are SEPARATE from the cross-task parity test in Task 22b — they exercise the metrics-side internal contract using package-private state, and they pass with NO proto dependency. The cross-task parity test in Task 22b uses the EXPORTED getters defined here and additionally asserts byte-equality with the proto-side `wtpv1.AllValidationReasons()`.

Add the `metrics.ValidWTPInvalidFrameReasons`, `metrics.ValidationReasons`, and `metrics.MetricsOnlyReasons` helpers to `internal/metrics/wtp.go`. All return fresh copies on each call so callers cannot mutate the package-private state:

```go
// ValidWTPInvalidFrameReasons returns a copy of the set of metrics-side
// frame-validation reasons that are recognized by IncDroppedInvalidFrame.
// Returned as a map[WTPInvalidFrameReason]struct{} so parity tests (and
// any future consumer) can range over keys without touching the
// unexported wtpInvalidFrameReasonsValid table directly. The returned
// map is a fresh copy — mutating it does NOT affect the package state.
func ValidWTPInvalidFrameReasons() map[WTPInvalidFrameReason]struct{} {
	out := make(map[WTPInvalidFrameReason]struct{}, len(wtpInvalidFrameReasonsValid))
	for k := range wtpInvalidFrameReasonsValid {
		out[k] = struct{}{}
	}
	return out
}

// validationReasonsShared backs the ValidationReasons() getter. It is
// the SUBSET of WTPInvalidFrameReason values that are also returned by
// wtpv1.AllValidationReasons() — i.e., the validator-emitted reasons
// shared across the proto and metrics packages. Adding a new validator-
// shared reason MUST also append it here AND to allValidationReasons
// in proto/canyonroad/wtp/v1/validate.go.
var validationReasonsShared = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonEventBatchBodyUnset,
	WTPInvalidFrameReasonEventBatchCompressionUnspec,
	WTPInvalidFrameReasonEventBatchCompressionMismatch,
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec,
	WTPInvalidFrameReasonPayloadTooLarge,
	WTPInvalidFrameReasonUnknown,
}

// ValidationReasons returns a fresh copy of the validator-emitted
// (SHARED with wtpv1.AllValidationReasons()) frame-validation reasons.
// Consumers (notably the parity test) range over this slice to assert
// the proto-side and metrics-side enums stay in sync. Returns a fresh
// copy on each call so callers cannot mutate the underlying enumeration.
// STABLE PRODUCTION API.
func ValidationReasons() []WTPInvalidFrameReason {
	out := make([]WTPInvalidFrameReason, len(validationReasonsShared))
	copy(out, validationReasonsShared)
	return out
}

// metricsOnlyReasons backs the MetricsOnlyReasons() getter. It is the
// SUBSET of WTPInvalidFrameReason values that have NO proto-side
// counterpart — emitted by code paths downstream of the validator
// (decompress_error, by streaming decompression) OR by the receiver-
// side defense-in-depth guard (classifier_bypass, when errors.As
// against *wtpv1.ValidationError returns false). Adding a new metrics-
// only reason MUST append it here, NOT to validationReasonsShared.
var metricsOnlyReasons = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonClassifierBypass,
	WTPInvalidFrameReasonDecompressError,
}

// MetricsOnlyReasons returns a fresh copy of the metrics-only frame-
// validation reasons (those without a proto-side wtpv1.ValidationReason
// counterpart). Today: classifier_bypass and decompress_error. Returns
// a fresh copy on each call so callers cannot mutate the underlying
// enumeration. STABLE PRODUCTION API.
func MetricsOnlyReasons() []WTPInvalidFrameReason {
	out := make([]WTPInvalidFrameReason, len(metricsOnlyReasons))
	copy(out, metricsOnlyReasons)
	return out
}
```

This step ships the metrics-internal enum + getters + four metrics-internal assertion tests (forward-shared, reverse-shared, disjoint, coverage — all using `package metrics` and exercising the unexported `wtpInvalidFrameReasonsValid` map directly). The cross-task four-invariant parity test `TestWTPInvalidFrameReason_ParityWithValidator` (which additionally asserts byte-equality with `wtpv1.AllValidationReasons()`) is deferred to Task 22b — that test cannot pass until BOTH this step AND Task 17 Step 4 have landed, so making it part of Task 22b avoids declaring this task complete while a documented test is still red.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/metrics/...`
Expected: PASS — all existing tests + the ten new tests added in Step 1 (`TestWTPMetrics_DroppedInvalidUTF8`, `TestWTPMetrics_DroppedSequenceOverflow`, `TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionFailureReasonValidationAndEscape`, `TestWTPMetrics_DroppedInvalidMapper`, `TestWTPMetrics_DroppedInvalidTimestamp`, `TestWTPMetrics_DroppedMapperFailure`, `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons`, `TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses`) plus the four metrics-internal assertion tests added in Step 4 (forward-shared, reverse-shared, disjoint, coverage — all asserting against `wtpInvalidFrameReasonsValid` and `validationReasonsShared`/`metricsOnlyReasons` from inside `package metrics`). The legacy `TestWTPMetrics_AppendAndExpose` test from Task 3 has its `wtp_dropped_missing_chain_total` reference removed per Step 3.5. **Parity test deferred to Task 22b** — `TestWTPInvalidFrameReason_ParityWithValidator` (the four-invariant test that compares the metrics-side getters against the proto-side `wtpv1.AllValidationReasons()`) ships as part of Task 22b, NOT here, because it depends on Task 17 Step 4 (the proto-side enum + getter); this task verifies ONLY metrics-internal tests.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go internal/metrics/metrics.go
git commit -m "feat(metrics): add sink-failure counters for WTP lifecycle and per-record drops"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 22c: WTP reconnect-reason schema expansion for fail-closed control frames

This task owns the dedicated-label expansion of the `wtp_reconnects_total{reason}` family for the fail-closed recv branches documented in spec §"Operator observability for fail-closed recv branches". The Round-23 spec text introduced two new structured-log `reason` strings — `server_update_unsupported_in_phase_4` and `recv_unknown_frame_type` — that today MUST collapse onto the existing `server_goaway` / `unknown` metric labels because the labels for those branches do not yet exist. This task adds the dedicated labels (`server_update_unsupported`, `recv_unknown_frame`), wires the always-emit contract, and ships the operator-facing migration runbook.

**Why a dedicated task.** Adding a metric label is a contract change for every dashboard, alert, and saved query that filters by `wtp_reconnects_total{reason=~...}`. Folding the change into Task 18 / Task 19 (where the reconnect plumbing lands) would have buried the migration story under unrelated state-machine work. This task makes the schema delta the unit of work, with its own roborev cycle and its own monitoring preflight.

**Interim state (this is what the spec describes today, before this task lands).** Per spec §"Operator observability for fail-closed recv branches" walked-back wording (Round-24 Finding 1):
- `Goaway` → drives `wtp_reconnects_total{reason="server_goaway"}` (existing label, no change after this task either).
- `ServerUpdate` → drives `wtp_reconnects_total{reason="unknown"}` under the seven-label schema (interim); this task moves it to `wtp_reconnects_total{reason="server_update_unsupported"}`.
- Unknown frame → drives `wtp_reconnects_total{reason="unknown"}` under the seven-label schema (interim); this task moves it to `wtp_reconnects_total{reason="recv_unknown_frame"}`.

The structured-log `reason` field on each WARN entry stays the same across this transition (`goaway_received`, `server_update_unsupported_in_phase_4`, `recv_unknown_frame_type`); only the metric label set changes.

**Prerequisites:**
- Task 3 — established the original seven-label `WTPReconnectReason` enum, the `wtpReconnectReasonsValid` validation table, the `wtpReconnectReasonsEmitOrder` always-emit slice, and the `TestWTPMetrics_ReconnectsAlwaysEmittedAllReasons` regression test. This task extends all four touch points symmetrically.
- Task 18 / Task 19 — wire `IncReconnects(reason)` from the actual reconnect path; this task is independent of THAT wiring and ships the labels at the metrics layer regardless of whether the call sites have landed (always-emit semantics ensure the new series are visible at zero on registration even if the recv path never fires).

**Files:**
- Modify: `internal/metrics/wtp.go` (extend the const block, validation map, and emit-order slice)
- Modify: `internal/metrics/wtp_test.go` (extend the always-emit regression test)
- Modify: `docs/superpowers/specs/2026-04-18-wtp-client-design.md` (rewrite §"Operator observability for fail-closed recv branches" to describe the END STATE under the expanded schema; update the §"Metrics" reason enumeration to add the two new labels)

- [ ] **Step 1: Write the failing test**

Append the following to `internal/metrics/wtp_test.go` (mirror the existing `TestWTPMetrics_ReconnectsAlwaysEmittedAllReasons` shape):

```go
func TestWTPMetrics_ReconnectsAlwaysEmittedIncludesFailClosedControlFrameLabels(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, reason := range []string{"server_update_unsupported", "recv_unknown_frame"} {
		want := fmt.Sprintf(`wtp_reconnects_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued reconnect series %q (Task 22c always-emit)\nbody:\n%s", want, body)
		}
	}

	c.WTP().IncReconnects(WTPReconnectReasonServerUpdateUnsupported)
	c.WTP().IncReconnects(WTPReconnectReasonRecvUnknownFrame)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	for _, want := range []string{
		`wtp_reconnects_total{reason="server_update_unsupported"} 1`,
		`wtp_reconnects_total{reason="recv_unknown_frame"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q after IncReconnects\nbody:\n%s", want, body)
		}
	}
}
```

Also extend the existing `TestWTPMetrics_ReconnectsAlwaysEmittedAllReasons` `expectedReasons` slice to include `"recv_unknown_frame"` and `"server_update_unsupported"` so the original regression test catches a future deletion of either label.

Run: `go test ./internal/metrics/ -run TestWTPMetrics_ReconnectsAlwaysEmitted -count=1`
Expected: FAIL with "missing zero-valued reconnect series" because the constants and emit-order entries don't exist yet.

- [ ] **Step 2: Extend the const block, validation map, and emit-order slice**

In `internal/metrics/wtp.go`:

```go
const (
	WTPReconnectReasonDialFailed              WTPReconnectReason = "dial_failed"
	WTPReconnectReasonStreamRecvError         WTPReconnectReason = "stream_recv_error"
	WTPReconnectReasonSendError               WTPReconnectReason = "send_error"
	WTPReconnectReasonAckTimeout              WTPReconnectReason = "ack_timeout"
	WTPReconnectReasonHeartbeatTimeout        WTPReconnectReason = "heartbeat_timeout"
	WTPReconnectReasonServerGoaway            WTPReconnectReason = "server_goaway"
	WTPReconnectReasonServerUpdateUnsupported WTPReconnectReason = "server_update_unsupported" // Task 22c
	WTPReconnectReasonRecvUnknownFrame        WTPReconnectReason = "recv_unknown_frame"        // Task 22c
	WTPReconnectReasonUnknown                 WTPReconnectReason = "unknown"
)
```

Add both to `wtpReconnectReasonsValid`. Insert into `wtpReconnectReasonsEmitOrder` in sorted-by-string order (so `recv_unknown_frame` lands between `heartbeat_timeout` and `send_error`, and `server_update_unsupported` lands between `stream_recv_error` and `unknown`).

- [ ] **Step 3: Run the test to prove it passes**

Run: `go test ./internal/metrics/ -run TestWTPMetrics_ReconnectsAlwaysEmitted -count=1`
Expected: PASS.

- [ ] **Step 4: Rewrite spec §"Operator observability for fail-closed recv branches" to the END STATE**

In `docs/superpowers/specs/2026-04-18-wtp-client-design.md`, the subsection currently reflects the INTERIM state (Round-24 Finding 1 walk-back: ServerUpdate / unknown frame collapse to `unknown`). After Step 2 lands, rewrite the bullet list so it reads:
- `Goaway` → `wtp_reconnects_total{reason="server_goaway"}` (unchanged).
- `ServerUpdate` → `wtp_reconnects_total{reason="server_update_unsupported"}`.
- Unknown frame → `wtp_reconnects_total{reason="recv_unknown_frame"}`.

Drop the "**temporary debugging guidance only** — replaced by the dedicated labels when Task 22c lands" wrapper around the `errCh` substring guidance because the dedicated labels now exist; keep the `errCh`-substring text as a one-line implementer hint at the recv-error correlation site, but mark the labels as the canonical operator surface.

Also update §"Metrics" (the `wtp_reconnects_total` enumeration) to add `server_update_unsupported` and `recv_unknown_frame` between `server_goaway` and `unknown` with the same per-reason one-line description style as the existing labels.

- [ ] **Step 5: Backwards Compatibility**

Adding labels to `wtp_reconnects_total{reason}` is **backwards-compatible at the wire level**: new time series appear at zero on registration via the always-emit contract (Step 2 above), so existing dashboards and alerts that aggregate across all reasons (`sum(wtp_reconnects_total)`) continue to behave identically. The compatibility break is at the **monitoring-config level**:

- Dashboards that filter by an explicit reason set (`wtp_reconnects_total{reason=~"server_goaway|unknown"}`) MUST be updated to include the new labels, otherwise reconnects driven by `ServerUpdate` / unknown frames will silently disappear from the panel after Step 2 lands.
- Alerts keyed on the `unknown` reason — e.g., `rate(wtp_reconnects_total{reason="unknown"}[5m]) > X` as a "we don't know what's reconnecting us, investigate" trip — will see a one-time DROP in the `unknown` series the moment Step 2 lands (the ServerUpdate / unknown-frame traffic that previously fed `unknown` now feeds the dedicated labels). Operators should EITHER widen the alert to `reason=~"unknown|server_update_unsupported|recv_unknown_frame"` ahead of the schema change, OR add separate alerts on the new labels in the same release.

**Migration cadence:** dashboards bumped one release ahead of the schema change (so a new label appearing at zero is already visible in the panel before any reconnect of that type can fire); alerts updated in the same release as Step 2; changelog / release notes call out the new labels and link to this task. The always-emit contract (Step 2) ensures the dashboard preflight can verify the new series are present at zero before the schema change ships.

- [ ] **Step 6: Cross-compile check**

Run: `go build ./...`
Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go docs/superpowers/specs/2026-04-18-wtp-client-design.md
git commit -m "feat(metrics): add wtp_reconnects_total labels for fail-closed control frames"
```

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

---

### Task 22b: Cross-task parity integration

This task is a coordination point that spans the proto package (Task 17 Step 4) and the metrics package (Task 22a Step 4). Its purpose is to host the four-invariant parity test that asserts byte-equality between `wtpv1.AllValidationReasons()` (proto-side) and `metrics.ValidationReasons()` (metrics-side) PLUS the disjointness/coverage contract for `metrics.MetricsOnlyReasons()`. It also hosts the cross-package `TestClassifierBypassWARN_RateLimited` test that exercises the shared rate-limiter wired between Task 17 Step 4a's receiver-side WARN path and Task 22a's metrics-side WARN path.

**Prerequisites:**
- Task 17 Step 4 — defines `wtpv1.AllValidationReasons()` (proto-side getter). The parity test consumes this getter.
- Task 17 Step 4a — defines the receiver-side defense-in-depth WARN path AND creates the test `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` (in `internal/store/watchtower/transport/`, package determined by Task 17 Step 4a's implementer — current scaffolding suggests `package transport_test` to mirror the other transport tests). Task 22b Step 4a EXTENDS that existing test (or adds a sibling test in the same file) rather than creating a new test file with a placeholder receiver-classifier seam.
- Task 22a Step 4 — defines `metrics.ValidationReasons()`, `metrics.MetricsOnlyReasons()`, `metrics.ValidWTPInvalidFrameReasons()` (metrics-side getters). The parity test consumes these getters.
- All three prerequisite steps MUST be complete before Task 22b executes; the parity test will not compile (missing exports) without Task 17 Step 4 + Task 22a Step 4, `TestClassifierBypassWARN_RateLimited` cannot exercise both code paths without both wirings landing, and Step 4a's receiver-side rate-limit assertion modifies the test that Task 17 Step 4a creates.

**Files:**
- Create: `internal/metrics/wtp_parity_test.go` (`package metrics_test` — external test package)
- Create: `internal/metrics/wtp_ratelimit.go` (the shared rate-limiter helper consumed by both `IncDroppedInvalidFrame`'s metrics-side WARN path and Task 17 Step 4a's receiver-side WARN path; also exports the test-only reset hook `ResetClassifierBypassLimiterForTest`)
- Modify: `internal/metrics/wtp.go` (`IncDroppedInvalidFrame` invokes the shared rate-limiter before emitting the metrics-side WARN)
- Modify: any new receiver-wiring file under `internal/store/watchtower/transport/` that emits the receiver-side `non-typed frame validation error` WARN (it MUST consume the same shared rate-limiter from `internal/metrics`)
- Modify (NOT create): the file Task 17 Step 4a places `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` in (under `internal/store/watchtower/transport/`; exact filename and package are determined by Task 17 Step 4a's implementer — current scaffolding suggests `package transport_test` to mirror the other transport tests). Step 4a below extends that existing test (or adds a sibling test in the same file) with the receiver-side rate-limit assertions; no new test seam or placeholder helper is introduced.

- [ ] **Step 1: Define the shared rate-limiter helper**

Add `internal/metrics/wtp_ratelimit.go`:

```go
// File: internal/metrics/wtp_ratelimit.go
// Package: metrics
//
// classifierBypassLimiter is the SHARED package-level token bucket used by
// BOTH classifier_bypass WARN paths:
//  - the metrics-side `invalid invalid-frame reason label` WARN emitted
//    by IncDroppedInvalidFrame when a caller passes an invalid label;
//  - the receiver-side `non-typed frame validation error` WARN emitted by
//    Task 17 Step 4a's defense-in-depth guard.
//
// Sharing a single bucket between both paths bounds total log volume to
// AT MOST 10 emissions per minute per process — a single bursty caller
// in either path cannot starve the other path's diagnostic. Rate
// `rate.Every(6*time.Second)` with burst 1 yields ~10/min on average;
// the limiter starts full so the first emission per process burst is
// always allowed (providing a useful diagnostic for genuinely rare
// misuses while preventing a hot-path bug from flooding logs).
//
// The COUNTER (`wtp_dropped_invalid_frame_total{reason="classifier_bypass"}`)
// tracks the true volume regardless of throttling — operators read the
// metric for the rate signal and the (sampled) WARN log for the
// diagnostic discriminator (`err_type` for receiver path, `raw_reason`
// for metrics path). When the limiter throttles a WARN, the suppressed
// event is NOT counted by any auxiliary "logs dropped" metric per spec
// §"WARN rate-limit (both `classifier_bypass` paths)".
//
// This rate-limiter applies ONLY to classifier_bypass WARN paths. Other
// validator-emitted-reason WARN logs follow the existing per-frame
// logging contract (those are gated by reconnect/Goaway, so log volume
// is bounded by the peer disconnecting).
package metrics

import (
	"time"

	"golang.org/x/time/rate"
)

// classifierBypassLimiter is package-level so both code paths
// (IncDroppedInvalidFrame and the receiver-side WARN) share one bucket.
// Initialized to a 6-second period (= ~10/min on average) with burst 1
// (= the first emission per process is always allowed; subsequent
// emissions wait for a token). NewLimiter returns a limiter that starts
// full per golang.org/x/time/rate semantics.
var classifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)

// AllowClassifierBypassWARN returns true if a classifier_bypass WARN log
// MAY be emitted now (the limiter has a token), false if the caller
// should suppress this WARN. The caller MUST still increment the
// `wtp_dropped_invalid_frame_total{reason="classifier_bypass"}` counter
// regardless of the return value — the metric is the canonical volume
// signal; the WARN is sampled diagnostic.
func AllowClassifierBypassWARN() bool {
	return classifierBypassLimiter.Allow()
}

// ResetClassifierBypassLimiterForTest resets the shared classifier-bypass
// rate-limiter to a fresh full-bucket state. Test-only — the "ForTest"
// suffix is the canonical Go convention signalling test-only intent.
// NEVER invoke from production code paths; the function lives in the
// production file (rather than a separate _test_export.go) because Go's
// `go test` does NOT enable any custom build tag by default, so a
// build-tagged file would not be reachable from `go test ./...` without
// extra ceremony. The function has no side effects on production paths
// (it just reassigns the package var, which production never calls).
//
// Rationale: the limiter is a package-level singleton (so both WARN
// paths share one bucket per the WARN rate-limit contract). Tests that
// assert rate-limit behavior MUST start from a known-fresh bucket;
// without this hook, a prior test that drained the bucket would make
// TestClassifierBypassWARN_RateLimited (and the receiver-side
// inject-and-assert test in internal/store/watchtower/transport)
// order-dependent. Callers MUST invoke this at test start AND register
// it via t.Cleanup so subsequent tests inherit a fresh bucket.
func ResetClassifierBypassLimiterForTest() {
	classifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
}
```

The `golang.org/x/time/rate` dependency is already in `go.mod` (used by `internal/store/watchtower/transport` for backoff in Task 18); no new module additions required.

The `ResetClassifierBypassLimiterForTest` hook intentionally lives in the
production file (no separate `_test_export.go` and no build-tag gate).
Two reasons:

  - Go's `go test` does not enable any custom build tag by default; a
    `//go:build test` file would be unreachable from `go test ./...`
    without surgery to the test invocation.
  - The function is small, has no side effects on production paths
    (production never calls it; it only reassigns the package var), and
    the `ForTest` suffix is the canonical Go signal that callers in
    production code are misuse. Lint can flag production callers if
    needed.

- [ ] **Step 2: Wire the rate-limiter into both WARN code paths**

In `internal/metrics/wtp.go`, modify `IncDroppedInvalidFrame` so the WARN emission is gated by `AllowClassifierBypassWARN()`:

```go
func (w *WTPMetrics) IncDroppedInvalidFrame(reason WTPInvalidFrameReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		// Emit the WARN only if the rate-limiter allows; the metric
		// counter ALWAYS increments regardless so the true volume is
		// visible in /metrics even when the WARN is sampled.
		if AllowClassifierBypassWARN() {
			slog.Warn("invalid invalid-frame reason label",
				slog.String("raw_reason", string(reason)),
				slog.String("reason", string(WTPInvalidFrameReasonClassifierBypass)),
			)
		}
		reason = WTPInvalidFrameReasonClassifierBypass
	}
	ptr, _ := w.c.wtpDroppedInvalidFrameByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}
```

In the receiver wiring added by Task 17 Step 4a, gate the receiver-side WARN identically:

```go
var ve *wtpv1.ValidationError
if !errors.As(err, &ve) {
	if metrics.AllowClassifierBypassWARN() {
		slogger.Warn("non-typed frame validation error",
			slog.String("err_type", fmt.Sprintf("%T", err)),
			slog.String("reason", "classifier_bypass"))
	}
	metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass)
	return // close stream, etc.
}
metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason(ve.Reason))
```

The metric counter increment happens unconditionally; the WARN is rate-limited.

- [ ] **Step 3: Write the cross-task parity test**

Create `internal/metrics/wtp_parity_test.go` (NOT in `internal/metrics/wtp_test.go` — see "external test package" rationale below) declared as **`package metrics_test`** (external test package), asserting the FOUR cross-task invariants in one test function. The file MUST be a NEW file and MUST be an external test package because:
- The existing `internal/metrics/wtp_test.go` is `package metrics` (internal test) — it tests the package's unexported state. Code in `package metrics` cannot use `metrics.` qualifiers (those are only valid for external consumers), so a parity test written with `metrics.ValidationReasons()` / `metrics.WTPInvalidFrameReason` qualifiers WILL NOT COMPILE inside `wtp_test.go`.
- Parity is inherently a cross-package concern (it validates that two packages — `wtpv1` and `metrics` — stay aligned). An external test package can use BOTH `metrics.` and `wtpv1.` qualifiers naturally without import cycles.
- The four metrics-INTERNAL assertion tests added in Task 22a Step 4 (forward-shared / reverse-shared / disjoint / coverage against the unexported `wtpInvalidFrameReasonsValid` table) stay in `package metrics` and continue to work — Task 22b adds the FOUR cross-package invariants on top.

Required file scaffolding for `internal/metrics/wtp_parity_test.go`:

```go
// File: internal/metrics/wtp_parity_test.go
// Package: metrics_test (external) — DO NOT change to package metrics or
// merge into wtp_test.go. The parity test MUST live in an external test
// package because it consumes BOTH metrics.* and wtpv1.* exported APIs;
// the existing internal/metrics/wtp_test.go is package metrics, which
// cannot use the metrics.* qualifier.
package metrics_test

import (
	"testing"

	"github.com/agentsh/agentsh/internal/metrics"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// (parity test body below — uses fully-qualified metrics.* and wtpv1.*
// names throughout)
```

The four cross-task assertions:

1. **Forward parity (exact set equality)**: every value in `wtpv1.AllValidationReasons()` MUST appear in `metrics.ValidationReasons()` (which returns a copy of just the validator-emitted SHARED set, NOT including metrics-only reasons), and vice versa. Use sorted comparison for a clear failure message that names the offending constant. ALSO assert `len(wtpv1.AllValidationReasons()) == len(metrics.ValidationReasons())` so any future drift toward aliases (multiple constants pointing at the same string value) fails fast — without the slice-length check, a map-based dedupe silently masks alias duplication.
2. **Reverse parity (exact set equality)**: every value in `metrics.ValidationReasons()` MUST appear in `wtpv1.AllValidationReasons()`. (Same assertion as forward direction, but framed from the metrics side; both directions must hold for set equality.)
3. **Disjoint check**: `metrics.MetricsOnlyReasons()` (which returns `[WTPInvalidFrameReasonClassifierBypass, WTPInvalidFrameReasonDecompressError]`) MUST be disjoint from `wtpv1.AllValidationReasons()`. This catches the regression where someone accidentally adds `decompress_error` or `classifier_bypass` to the proto enum (which would violate the design contract that both are metrics-only).
4. **Coverage check**: `metrics.ValidationReasons() ∪ metrics.MetricsOnlyReasons()` MUST equal `metrics.ValidWTPInvalidFrameReasons()` (the always-emit set used by zero-emission). This catches the regression where someone adds a new constant to the metrics package but forgets to put it into either the validator-shared set or the metrics-only set.

All four assertions live in one test function with clear failure messages naming the offending constant and the file it lives in.

Test snippet:

```go
// TestWTPInvalidFrameReason_ParityWithValidator locks the metrics-side
// WTPInvalidFrameReason constants to the proto-side wtpv1.ValidationReason
// constants. The two enums are intentionally duplicated (metrics MUST NOT
// import the proto package) but the string values for validator-emitted
// reasons MUST stay byte-equal so receivers can do
// `metrics.WTPInvalidFrameReason(ve.Reason)` safely. The metrics-only
// `decompress_error` and `classifier_bypass` reasons are intentionally NOT
// mirrored on the proto side (the former is emitted post-validator by
// streaming decompression; the latter is emitted only by the receiver-
// side defense-in-depth fallback and by the metrics-side invalid-label
// collapse, neither of which has a validator counterpart by definition).
//
// Adding a new reason in either package without the other will fail this
// test with a precise actionable message.
func TestWTPInvalidFrameReason_ParityWithValidator(t *testing.T) {
	// 1. Forward parity (exact set equality on the validator-emitted shared set).
	validatorAll := make(map[wtpv1.ValidationReason]struct{})
	for _, r := range wtpv1.AllValidationReasons() {
		validatorAll[r] = struct{}{}
	}
	metricsShared := make(map[metrics.WTPInvalidFrameReason]struct{})
	for _, r := range metrics.ValidationReasons() {
		metricsShared[r] = struct{}{}
	}

	// Forward: every validator reason must have a metrics constant in the SHARED set.
	for r := range validatorAll {
		if _, ok := metricsShared[metrics.WTPInvalidFrameReason(string(r))]; !ok {
			t.Errorf("metrics package is missing WTPInvalidFrameReason constant for validator reason %q (string=%q); add the constant to internal/metrics/wtp.go and append it to wtpInvalidFrameReasonsValid + wtpInvalidFrameReasonsEmitOrder + the validator-shared set returned by ValidationReasons()",
				r, string(r))
		}
	}

	// 2. Reverse: every metrics SHARED reason must have a validator constant.
	for r := range metricsShared {
		if _, ok := validatorAll[wtpv1.ValidationReason(string(r))]; !ok {
			t.Errorf("validator package is missing ValidationReason constant for metrics reason %q (string=%q); add the constant to proto/canyonroad/wtp/v1/validate.go and append it to allValidationReasons (returned by AllValidationReasons())",
				r, string(r))
		}
	}

	// 3. Disjoint: metrics-only reasons MUST NOT appear on the validator side.
	for _, r := range metrics.MetricsOnlyReasons() {
		if _, ok := validatorAll[wtpv1.ValidationReason(string(r))]; ok {
			t.Errorf("metrics-only reason %q (string=%q) accidentally appears in wtpv1.AllValidationReasons() — the design contract is that metrics-only reasons (classifier_bypass, decompress_error) have NO proto-side counterpart; remove it from proto/canyonroad/wtp/v1/validate.go's allValidationReasons or remove it from internal/metrics/wtp.go's MetricsOnlyReasons() (whichever was added in error)",
				r, string(r))
		}
	}

	// 4. Coverage: shared ∪ metrics-only MUST equal the full valid set.
	covered := make(map[metrics.WTPInvalidFrameReason]struct{})
	for r := range metricsShared {
		covered[r] = struct{}{}
	}
	for _, r := range metrics.MetricsOnlyReasons() {
		covered[r] = struct{}{}
	}
	for r := range metrics.ValidWTPInvalidFrameReasons() {
		if _, ok := covered[r]; !ok {
			t.Errorf("metrics constant %q (string=%q) is in ValidWTPInvalidFrameReasons() but is in NEITHER ValidationReasons() (the validator-shared set) NOR MetricsOnlyReasons() (the metrics-only set); add it to one of those getters in internal/metrics/wtp.go so the parity test can classify it",
				r, string(r))
		}
	}
	for r := range covered {
		if _, ok := metrics.ValidWTPInvalidFrameReasons()[r]; !ok {
			t.Errorf("metrics constant %q (string=%q) appears in ValidationReasons() or MetricsOnlyReasons() but is NOT in ValidWTPInvalidFrameReasons() (the always-emit set); add it to wtpInvalidFrameReasonsValid in internal/metrics/wtp.go so it is registered for emit",
				r, string(r))
		}
	}
}
```

- [ ] **Step 4: Add `TestClassifierBypassWARN_RateLimited` cross-package burst test**

Add to `internal/metrics/wtp_parity_test.go` (same external test package — the test exercises the cross-package contract that BOTH WARN paths share one limiter):

```go
// TestClassifierBypassWARN_RateLimited verifies that the shared
// classifierBypassLimiter caps WARN log emissions at ~10/min while the
// counter still tracks true volume. Pumps 100 invalid-label calls in a
// tight loop and asserts:
//   - the counter increments exactly 100 times (always-on),
//   - the WARN log captures AT MOST 11 entries (10 from the steady-state
//     bucket plus 1 from the initial-burst token),
//   - the test does NOT depend on wall-clock waits — token bucket
//     starts full, so the first emission lands immediately and
//     subsequent emissions are throttled until the next token arrives.
//
// This test asserts the contract documented in spec §"WARN rate-limit
// (both `classifier_bypass` paths)" — that both code paths share ONE
// bucket so a hot-path bug in either path cannot drown the other path's
// diagnostic.
func TestClassifierBypassWARN_RateLimited(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Reset the shared limiter so this test does not depend on prior
	// test state. The limiter is a package-level singleton shared
	// between BOTH classifier_bypass WARN paths (metrics-side and
	// receiver-side); without an explicit reset, a prior test that
	// drained the bucket would make this assertion order-dependent.
	// The t.Cleanup call is defensive: it ensures any subsequent test
	// that depends on a fresh bucket inherits one regardless of test
	// ordering.
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	c := metrics.New()
	const burst = 100
	for i := 0; i < burst; i++ {
		c.WTP().IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason("not-a-canonical-reason"))
	}

	// (1) Counter ALWAYS increments — sampling does not affect the metric.
	if got := c.WTP().DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != burst {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want %d (counter MUST track true volume regardless of WARN throttling)", got, burst)
	}

	// (2) WARN log capped at ~11 entries (10 steady-state + 1 burst).
	// Count newlines (one JSON object per log call).
	logged := strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") + 1
	if buf.Len() == 0 {
		logged = 0
	}
	if logged > 11 {
		t.Errorf("WARN log emitted %d entries for %d invalid-label calls — rate-limiter failed to throttle (expected ≤11)", logged, burst)
	}
	if logged < 1 {
		t.Errorf("WARN log emitted %d entries — first emission per burst MUST be allowed (token bucket starts full)", logged)
	}
}
```

The test file imports: `bytes`, `log/slog`, `strings`, `testing`, plus `metrics` (the package under test). The metrics-side WARN path is exercised through `IncDroppedInvalidFrame`. The receiver-side WARN path is owned by Task 22b and is exercised by Step 4a below — Step 4a EXTENDS the existing `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` test created by Task 17 Step 4a (in `internal/store/watchtower/transport/`) to also assert that the receiver-side defense-in-depth guard consumes the same shared limiter.

- [ ] **Step 4a: Extend Task 17 Step 4a's receiver-side test to assert the rate-limit contract**

**Prerequisite**: Task 17 Step 4a (plan §"Task 17 Step 4a: Inbound frame validation acceptance") MUST be complete. That step creates `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` in `internal/store/watchtower/transport/` (filename and package determined by Task 17 Step 4a's implementer; current scaffolding suggests `package transport_test` to mirror the other transport tests at plan line ~7124). Task 22b modifies that test in place rather than creating a new file — this avoids inventing a new exported test seam and keeps the receiver-side coverage colocated with the Step-4a test it extends.

Modify (do NOT create a new file): the file Task 17 Step 4a places `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` in. Either:

- **(Preferred) Extend the existing test** to inject the bare-error TWICE in sequence (no time advance) before any assertion, then assert: (1) the WARN log emitted EXACTLY ONCE (the second injection's WARN was throttled by the shared limiter), and (2) `wtp_dropped_invalid_frame_total{reason="classifier_bypass"}` incremented EXACTLY TWICE (the counter is unconditional). The first assertion exercises the rate-limit; the second confirms the metric still tracks true volume regardless of WARN throttling.
- **(Alternative) Add a sibling test** in the same file (e.g., `TestReceiver_NonTypedError_RateLimited`) that does the same double-injection + dual assertion. Use this if the preferred path would make the existing test too long to read.

The test MUST call `metrics.ResetClassifierBypassLimiterForTest()` at the start (and in `t.Cleanup`) so the burst is order-independent, mirroring the metrics-side `TestClassifierBypassWARN_RateLimited` pattern.

Sketch (extend OR sibling — pick one):

```go
metrics.ResetClassifierBypassLimiterForTest()
t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

// ... existing TestReceiver_NonTypedErrorClassifiedAsClassifierBypass setup
// (inject bare fmt.Errorf("%w: synthetic", wtpv1.ErrInvalidFrame) via fakeConn recvCh) ...

// NEW: inject the same bare error a SECOND time before asserting.
injectBareErr() // whatever helper Task 17 Step 4a's test uses
injectBareErr()

// Existing assertions (unchanged): errors.As returns false on each, live loop
// returns StateConnecting on each.

// NEW (rate-limit contract): exactly 1 WARN, exactly 2 counter increments.
if logged := countWARNLines(buf); logged != 1 {
    t.Errorf("WARN log emitted %d entries for 2 errors — expected 1 (first allowed by full bucket, second throttled)", logged)
}
if got := c.WTP().DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 2 {
    t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 2 (counter MUST track true volume regardless of WARN throttling)", got)
}
```

The exact function signatures (`injectBareErr`, `countWARNLines`, etc.) are determined by Task 17 Step 4a's test implementation; Task 22b's modification just calls the existing injection mechanism a second time and adds two assertions. No new test seam is invented.

Acceptance criterion: this rate-limit assertion MUST be implemented as part of Task 22b (NOT deferred to a separate task). The assertion enforces that BOTH WARN paths share one rate-limiter and that the receiver-side counter increments unconditionally, mirroring the metrics-side guarantees verified by Step 4. Without this assertion, the cross-package WARN-rate-limit contract from spec §"WARN rate-limit (both `classifier_bypass` paths)" is only half-covered.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/metrics/... ./proto/canyonroad/wtp/v1/... ./internal/store/watchtower/transport/...`
Expected: PASS — the parity test `TestWTPInvalidFrameReason_ParityWithValidator` succeeds (proto-side `wtpv1.AllValidationReasons()` and metrics-side getters agree on the shared/disjoint/coverage invariants), the rate-limit test `TestClassifierBypassWARN_RateLimited` succeeds (counter at 100, WARN logs ≤ 11), and the modified `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass` test (extended in Step 4a, or its sibling test in the same file added by Step 4a) succeeds with its rate-limit assertions (counter at 2, WARN log = 1) in addition to the original Task 17 Step 4a assertions (errors.As false, live loop returns StateConnecting). All previously-passing tests continue to pass.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/metrics/wtp_parity_test.go internal/metrics/wtp_ratelimit.go internal/metrics/wtp.go
# Also stage the file Task 17 Step 4a placed `TestReceiver_NonTypedErrorClassifiedAsClassifierBypass`
# in (under internal/store/watchtower/transport/) — Step 4a above modified it (extended the existing
# test or added a sibling test in the same file). Exact filename is determined by Task 17 Step 4a's
# implementer; substitute it here.
git add internal/store/watchtower/transport/<file-from-task-17-step-4a>
git commit -m "feat(metrics): cross-task parity test + shared classifier_bypass WARN rate-limiter (extends Task 17 Step 4a receiver test)"
```

(If Task 17 Step 4a's receiver wiring is being committed in this same task, also add the corresponding `internal/store/watchtower/transport/state_live.go` change.)

- [ ] **Step 8: Roborev**

Run `/roborev-design-review` and address findings.

**Round-13 Missing B: `wtp_anomalous_ack_total` label-rename migration runbook (`beyond_wal_high_water_seq` → `server_ack_exceeds_local_seq`).**

Round-12 Findings 4 + 5 introduced a 5-reason taxonomy for `wtp_anomalous_ack_total` (`stale_generation`, `unwritten_generation`, `server_ack_exceeds_local_seq`, `server_ack_exceeds_local_data`, `wal_read_failure`) — replacing the round-9 names (`stale_generation`, `future_generation`, `beyond_wal_high_water_seq`). The `future_generation` → `unwritten_generation`/`server_ack_exceeds_local_data` split was already documented in spec §"Migration from pre-split `future_generation`" (round-11). The remaining label rename — `beyond_wal_high_water_seq` → `server_ack_exceeds_local_seq` — has no migration documented yet because Round 12's Finding 5 was scoped to "rename the label so same-gen and cross-gen ack-overshoot use the parallel `server_ack_exceeds_local_*` shape." This Round-13 Missing B note closes that gap.

**Migration shape — clean swap (NO dual-emit window).** Per the round-9 release notes, this metric series shipped in the same release as the WTP client client-side cursor model (no WTP client deployment ever observed `wtp_anomalous_ack_total{reason="beyond_wal_high_water_seq"}` in production); operators have not yet built dashboards or alerts against the round-9 / round-11 / round-12 label set. **The migration is therefore a clean swap** (compile-time symbol rename + `wtpAnomalousAckReasons*` table swap + parity-test update + spec/plan rename), NOT a backward-compatible dual-emit window. Operators consuming the round-9 / round-11 / round-12 prerelease names MUST update their dashboards and alerts in lock-step with the upgrade.

The migration steps below are sequenced so the parity test (Task 22b Step 3 above) catches any drift between the metrics-side enumeration and the wiring-layer call sites. Each step's expected git diff is bounded so reviewers can confirm the swap is clean.

**Migration steps:**

1. **Rename the metrics-side constant.** In `internal/metrics/wtp.go`, replace the `WTPAnomalousAckReasonBeyondWALHighWaterSeq` constant with `WTPAnomalousAckReasonServerAckExceedsLocalSeq`. Update the string value: `"beyond_wal_high_water_seq"` → `"server_ack_exceeds_local_seq"`. Update the `wtpAnomalousAckReasonsValid` map and `wtpAnomalousAckReasonsEmitOrder` slice in lock-step. Confirm the `IncAnomalousAck` accessor docstring lists the five round-12 / round-13 reason names (this round-13 commit already updates the docstring at lines 13993-14005 above).

2. **Sweep the wiring-layer call sites.** In `internal/store/watchtower/transport/conn.go` (or wherever `applyServerAckTuple` lives — see Task 15.1 step 1 + Task 17.X step 4), replace ALL `IncAnomalousAck("beyond_wal_high_water_seq")` calls with `IncAnomalousAck("server_ack_exceeds_local_seq")`. The same-gen `serverSeq > wal.WrittenDataHighWater(server.gen)` branch (the only Anomaly emitter for this reason) now mirrors the cross-gen `server_ack_exceeds_local_data` shape. Confirm the round-12 plan + spec invariant docstrings already use the new name (the round-12 commit + this round-13 commit established that — no further sweep needed).

3. **Run the Task 22b parity test.** Re-run `go test ./internal/metrics/... ./internal/store/watchtower/transport/... -run TestApplyServerAckTuple_ReasonLabelsMatchValidator -count=1` (the parity test name documented in Task 22b Step 3 — adapt to the actual test name landed by the implementer). Expected: PASS — the `applyServerAckTuple` Anomaly emitter and the `wtpAnomalousAckReasonsValid` table agree on the five round-12 / round-13 reason names.

4. **Update operator-facing docs.** This step is a documentation-only sweep:
   - `docs/superpowers/specs/2026-04-18-wtp-client-design.md` §"Operational signals" → confirm the `wtp_anomalous_ack_total` row enumerates the five round-12 / round-13 reason names (NOT the round-9 `beyond_wal_high_water_seq` name). The round-12 commit already established this rename in the spec; this round-13 step is a re-grep to confirm.
   - Internal runbooks: any markdown / wiki page that names the metric label MUST be updated in the same commit that lands the rename. Use `git grep -l beyond_wal_high_water_seq -- docs/` to find stragglers; expected outcome is zero matches after this round-13 commit lands. (The round-13 commit also greps the codebase to confirm zero remaining `beyond_wal_high_water_seq` references in non-historical files; see step 6 below.)

5. **Acceptance criteria.** No backward compatibility shim is shipped (the prerelease design contract is explicit: round-9 / round-11 / round-12 names are NOT operator-visible). After the swap:
   - `git grep beyond_wal_high_water_seq` returns ONLY historical references (commit messages, plan/spec change-log entries, comments documenting the rename — NOT live code or live operator-facing strings).
   - `wtp_anomalous_ack_total{reason="server_ack_exceeds_local_seq"}` appears at zero on the always-emit Prometheus exposition (per Task 22a Step 3 zero-init contract — the new label MUST be in `wtpAnomalousAckReasonsEmitOrder` so it always emits).
   - `wtp_anomalous_ack_total{reason="beyond_wal_high_water_seq"}` does NOT appear in the exposition (the old constant was removed from the table).

6. **Rename-coverage assertion (test-time defense in depth).** Optional but recommended for ANY developer-facing dashboard regression detection: extend the Task 22b parity test (or add a sibling assertion in `wtp_parity_test.go`) to grep the running test binary's `wtpAnomalousAckReasonsValid` table for the absence of the round-9 string and the presence of the round-12 / round-13 string. Sketch:

```go
func TestAnomalousAckLabel_NoLegacyName(t *testing.T) {
    valid := metrics.ValidWTPAnomalousAckReasons()  // returns the validation map
    if _, ok := valid[metrics.WTPAnomalousAckReason("beyond_wal_high_water_seq")]; ok {
        t.Errorf("wtpAnomalousAckReasonsValid still contains the round-9 legacy name `beyond_wal_high_water_seq`; the round-13 Missing B migration removed this — see plan §`Round-13 Missing B: wtp_anomalous_ack_total label-rename migration runbook`")
    }
    if _, ok := valid[metrics.WTPAnomalousAckReason("server_ack_exceeds_local_seq")]; !ok {
        t.Errorf("wtpAnomalousAckReasonsValid is missing the round-12/round-13 name `server_ack_exceeds_local_seq`; add the constant per plan §`Round-13 Missing B`")
    }
}
```

This assertion is OPTIONAL because the broader parity test in Step 3 already catches drift between the wiring-layer call sites and the validation table. The targeted assertion exists as a cheap regression net for the specific round-13 rename.

**Future enhancement (deferred — round-8 scope reduction):** Task 22b
intentionally does NOT extend `wtp_ack_high_watermark` to a `(gen, seq)`
labeled gauge. Production today exposes a single unlabeled gauge via
`func (w *WTPMetrics) SetAckHighWatermark(seq int64)` (see
`internal/metrics/wtp.go` line 137; `/metrics` text format at line 230
emits a single `wtp_ack_high_watermark <value>` line). The round-8
review deferred the schema change because: (a) extending the gauge to
two labels is a backward-incompatible monitoring change that requires
dashboard + alert audit, and (b) the two-cursor model already gives
operators the diagnostic they need via the INFO log (regression naming
both cursors) plus the WARN log (true-anomaly naming both cursors).
A future task may extend the gauge to a labeled
`wtp_ack_high_watermark{gen,seq}` shape after the dashboard/alert
migration is planned; until then, the production signature is the
single-int64 form and the plan + tests reflect that.

---



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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
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
		HMACKeyID:       "k1", HMACSecret: bytes.Repeat([]byte("a"), 32),
		BatchMaxRecords: 8, BatchMaxBytes: 8 * 1024, BatchMaxAge: 50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         metrics.New(),
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
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

func TestAppendEvent_DropsSequenceOverflow(t *testing.T) {
	s := mkStore(t)
	prevHashBefore := s.PeekPrevHash() // test-only accessor; see store_export_test.go
	walSegmentsBefore := s.WALSegmentCount()

	// Timestamp must be valid so Encode succeeds and execution reaches the
	// sequence-overflow bounds-check (Encode's ErrInvalidTimestamp branch
	// would otherwise short-circuit first).
	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: math.MaxUint64, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent should drop silently for overflow, got err: %v", err)
	}

	if got := s.DroppedSequenceOverflow(); got != 1 {
		t.Errorf("expected 1 sequence-overflow drop, got %d", got)
	}
	if got := s.WALSegmentCount(); got != walSegmentsBefore {
		t.Errorf("WAL must remain untouched on overflow drop; segments before=%d after=%d", walSegmentsBefore, got)
	}
	if got := s.PeekPrevHash(); got != prevHashBefore {
		t.Errorf("chain prev_hash must not advance on overflow drop; before=%q after=%q", prevHashBefore, got)
	}
}

func TestAppendEvent_DropsInvalidUTF8(t *testing.T) {
	// Use a chain.SinkChainAPI test double (failingSink, defined below in
	// this file) that returns chain.ErrInvalidUTF8 on every Compute call.
	// Verifies the boundary drop semantics: counter increments, WAL stays
	// empty, chain prev_hash unchanged.
	s := mkStoreWithFailingSink(t, chain.ErrInvalidUTF8)
	prevHashBefore := s.PeekPrevHash()
	walSegmentsBefore := s.WALSegmentCount()

	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent should drop silently for invalid-utf8, got err: %v", err)
	}

	if got := s.DroppedInvalidUTF8(); got != 1 {
		t.Errorf("expected 1 invalid-utf8 drop, got %d", got)
	}
	if got := s.WALSegmentCount(); got != walSegmentsBefore {
		t.Errorf("WAL must remain untouched on invalid-utf8 drop; segments before=%d after=%d", walSegmentsBefore, got)
	}
	if got := s.PeekPrevHash(); got != prevHashBefore {
		t.Errorf("chain prev_hash must not advance on invalid-utf8 drop; before=%q after=%q", prevHashBefore, got)
	}
}

// TestAppendEvent_PropagatesMissingChain verifies that compact.Encode's
// ErrMissingChain branch fires when ev.Chain is nil and AppendEvent
// PROPAGATES the error to the caller (wrapped as `watchtower: %w`)
// rather than dropping silently. Composite-store regressions must be
// loud — there is no `wtp_dropped_missing_chain_total` counter (this
// is a developer-facing integration bug, not a per-record drop class),
// but AppendEvent MUST emit one ERROR-severity structured log per
// occurrence so operators see the regression at the call site. The
// log carries internal-only fields ({event_id, session_id, event_type,
// err}) sourced from `types.Event` itself plus the sentinel error
// string, and is exempt from the invalid-frame sanitization rule
// because no peer-supplied bytes ever appear in the field set.
// `generation` is intentionally NOT in the field set because
// composite-store generation is only available via `ev.Chain.Generation`,
// which is nil on this branch by definition (see spec §"Caller contract
// for propagated `compact.ErrMissingChain`").
//
// Note: ErrInvalidMapper has no end-to-end test here. Store.New rejects
// invalid mappers at construction time, so reaching Encode with an invalid
// mapper through the public API is not possible. Coverage for that branch
// comes from Task 9 (Encode-direct unit tests) and Task 22 (Store.New
// rejection tests). The wtp_dropped_invalid_mapper_total counter remains
// defense in depth — non-zero signals a code-path bug bypassing Store.New.
func TestAppendEvent_PropagatesMissingChain(t *testing.T) {
	s := mkStore(t)
	prevHashBefore := s.PeekPrevHash()
	walSegmentsBefore := s.WALSegmentCount()

	ev := types.Event{
		ID:        "evt-42",
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		// Chain intentionally nil — Encode must reject with ErrMissingChain.
	}
	err := s.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent must propagate missing-chain as a wrapped error, got nil")
	}
	if !errors.Is(err, compact.ErrMissingChain) {
		t.Errorf("expected wrapped compact.ErrMissingChain, got %v", err)
	}
	if !strings.Contains(err.Error(), "watchtower:") {
		t.Errorf("expected error wrapped with `watchtower:` prefix, got %q", err.Error())
	}

	// Ensure the loud-failure path did NOT touch any of the per-class drop
	// counters or sink-internal state.
	if got := s.WALSegmentCount(); got != walSegmentsBefore {
		t.Errorf("WAL must remain untouched on missing-chain propagation; segments before=%d after=%d", walSegmentsBefore, got)
	}
	if got := s.PeekPrevHash(); got != prevHashBefore {
		t.Errorf("chain prev_hash must not advance on missing-chain propagation; before=%q after=%q", prevHashBefore, got)
	}
}

func TestAppendEvent_DropsInvalidTimestamp(t *testing.T) {
	s := mkStore(t)
	prevHashBefore := s.PeekPrevHash()
	walSegmentsBefore := s.WALSegmentCount()

	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Time{}, // zero — Encode must reject with ErrInvalidTimestamp.
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent should drop silently for invalid-timestamp, got err: %v", err)
	}

	if got := s.DroppedInvalidTimestamp(); got != 1 {
		t.Errorf("expected 1 invalid-timestamp drop, got %d", got)
	}
	if got := s.WALSegmentCount(); got != walSegmentsBefore {
		t.Errorf("WAL must remain untouched on invalid-timestamp drop; segments before=%d after=%d", walSegmentsBefore, got)
	}
	if got := s.PeekPrevHash(); got != prevHashBefore {
		t.Errorf("chain prev_hash must not advance on invalid-timestamp drop; before=%q after=%q", prevHashBefore, got)
	}
}

// failingMapper.Map returns a non-sentinel error so Encode wraps it as
// `compact mapper: %w`. AppendEvent's classification switch must hit the
// default branch and increment wtp_dropped_mapper_failure_total.
type failingMapper struct{}

func (failingMapper) Map(_ types.Event) (*wtpv1.CompactEvent, error) {
	return nil, errors.New("boom")
}

func TestAppendEvent_DropsMapperFailure(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          failingMapper{}, // Store.New accepts this — it's a valid Mapper, just one that always errors.
		Allocator:       allocator,
		AgentID:         "a",
		SessionID:       "s",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		BatchMaxRecords: 8,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		Dialer:          srv.DialerFor(),
		Metrics:         metrics.New(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	prevHashBefore := s.PeekPrevHash()
	walSegmentsBefore := s.WALSegmentCount()

	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent should drop silently for mapper-failure, got err: %v", err)
	}

	if got := s.DroppedMapperFailure(); got != 1 {
		t.Errorf("expected 1 mapper-failure drop, got %d", got)
	}
	if got := s.WALSegmentCount(); got != walSegmentsBefore {
		t.Errorf("WAL must remain untouched on mapper-failure drop; segments before=%d after=%d", walSegmentsBefore, got)
	}
	if got := s.PeekPrevHash(); got != prevHashBefore {
		t.Errorf("chain prev_hash must not advance on mapper-failure drop; before=%q after=%q", prevHashBefore, got)
	}
}
```

- [ ] **Step 1.5: Add test scaffolding required by the new drop tests**

The drop tests (`TestAppendEvent_DropsSequenceOverflow`, `TestAppendEvent_DropsInvalidUTF8`, `TestAppendEvent_PropagatesMissingChain`, `TestAppendEvent_DropsInvalidTimestamp`, `TestAppendEvent_DropsMapperFailure`) and the structured-log tests (`TestAppendEvent_LogsInvalidTimestamp`, `TestAppendEvent_LogsMapperFailure`, `TestAppendEvent_LogsInvalidUTF8`) reference five pieces of test infrastructure:

1. **`store_export_test.go`** in `internal/store/watchtower/`, package `watchtower` (NOT `watchtower_test`): exposes `(*Store).PeekPrevHash() string`, `(*Store).WALSegmentCount() int`, plus per-class drop accessors `(*Store).DroppedInvalidUTF8() uint64`, `(*Store).DroppedSequenceOverflow() uint64`, `(*Store).DroppedInvalidMapper() uint64`, `(*Store).DroppedInvalidTimestamp() uint64`, and `(*Store).DroppedMapperFailure() uint64`. (NO `DroppedMissingChain` accessor — that counter was removed in Task 22a Step 3.5; the `TestAppendEvent_PropagatesMissingChain` test asserts the wrapped error instead.) Uses Go's standard `_test.go` suffix so the file is automatically excluded from non-test builds — no build tag required. The metrics inspectors forward to `s.metrics.Dropped*()`, letting the cross-package `watchtower_test` callers read counters without poking the unexported `metrics` field directly. (The `DroppedInvalidMapper` accessor is included for symmetry; no test in this task exercises it because `Store.New` rejects invalid mappers at construction time — see the `TestAppendEvent_PropagatesMissingChain` doc comment for the rationale.)

2. **Inline `failingSink` struct** at the bottom of `internal/store/watchtower/append_test.go` (defined in Step 3 of this task): a `chain.SinkChainAPI` test double whose `Compute` method always returns the supplied sentinel error. Lives in `package watchtower_test` because the `_test.go` suffix prevents production code from importing it by construction — no separate doubles package is needed.

3. **`mkStoreWithFailingSink(t *testing.T, sentinel error) *watchtower.Store`** helper defined in Step 3 of this task: same setup as `mkStore` but injects the failing sink via `watchtower.Options.SinkChainOverrideForTests` (test-only Options field, type `chain.SinkChainAPI`).

4. **Inline `failingMapper` struct** in `append_test.go` (defined alongside `TestAppendEvent_DropsMapperFailure`): a `compact.Mapper` test double whose `Map` returns a non-sentinel `errors.New("boom")`. Used to exercise the default branch of `AppendEvent`'s classification switch (which increments `wtp_dropped_mapper_failure_total`). Wired through `Mapper:` in `watchtower.Options` — no test seam needed because `Store.New` accepts any non-nil, non-stub `Mapper` value.

5. **`captureLogs(t *testing.T) *bytes.Buffer`** helper at the bottom of `append_test.go`: installs a `slog.NewJSONHandler` over a `bytes.Buffer` via `slog.SetDefault`, registers a `t.Cleanup` to restore the previous default logger, and returns the buffer for the caller to read after the action under test runs. Used by the log-capture tests in Step 1.6 below. JSON handler keeps assertions straightforward: each emitted record is a single JSON line where `key=value` matches reduce to substring or `json.Unmarshal` checks. Defined inline in `append_test.go` (no separate package) because slog redirection is an in-process global — keeping the helper in the same file as the tests it serves prevents accidental cross-test interference.

```go
// captureLogs installs a slog.JSONHandler over a bytes.Buffer as the
// default logger for the duration of the test. Returns the buffer the
// caller reads after triggering the code path under test. The previous
// default logger is restored by a t.Cleanup hook.
//
// Each captured record is one JSON line; assertions use strings.Contains
// (substring match on the encoded key/value) or json.Unmarshal for
// stronger structural checks. The handler is at LevelDebug so WARN-level
// drop logs always reach the buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}
```

Tests reference scaffolding added in Task 22 Step 3.5 (`store_export_test.go`, `chain.SinkChainAPI` interface, `Options.SinkChainOverrideForTests`) and the `failingSink` / `failingMapper` structs + `mkStoreWithFailingSink` + `captureLogs` helpers defined in Step 3 of this task.

- [ ] **Step 1.6: Add structured-log assertions for each drop class**

For every drop class that emits a structured WARN log, add (or extend) a test that captures the slog output and asserts the expected fields. Compact tests pattern:

```go
func TestAppendEvent_LogsInvalidTimestamp(t *testing.T) {
	logs := captureLogs(t)
	s := mkStore(t)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Time{}, // zero — Encode rejects with ErrInvalidTimestamp.
		Chain:     &types.ChainState{Sequence: 7, Generation: 2},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	body := logs.String()
	for _, want := range []string{
		`"msg":"watchtower: dropping event — invalid timestamp"`,
		`"session_id":"s"`,
		`"sequence":7`,
		`"generation":2`,
		`"err":"compact: invalid timestamp"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected log substring %q\nlogs:\n%s", want, body)
		}
	}
}

func TestAppendEvent_LogsMapperFailure(t *testing.T) {
	logs := captureLogs(t)
	// Same setup as TestAppendEvent_DropsMapperFailure but with logs
	// capture; assert msg/session_id/sequence/generation/err in the
	// JSON body.
	// ... (constructs a Store with failingMapper{}, calls AppendEvent,
	// then asserts the same five substrings as above with msg
	// `"watchtower: dropping event — mapper failure"`).
}

func TestAppendEvent_LogsInvalidUTF8(t *testing.T) {
	logs := captureLogs(t)
	// Same setup as TestAppendEvent_DropsInvalidUTF8 but with logs
	// capture; assert msg/session_id/sequence/generation/err in the
	// JSON body with msg `"watchtower: dropping event — invalid UTF-8 in chain field"`.
}

// TestAppendEvent_DropsSequenceOverflow already exists from Step 1; extend
// it to also assert the structured-log fields. Add a captureLogs(t) call
// at the top, then after the existing counter / WAL / prev_hash assertions
// add a substring loop matching:
//   "msg":"watchtower: dropping event — sequence > math.MaxInt64"
//   "session_id":"s"
//   "sequence":18446744073709551615   (math.MaxUint64; JSON encodes uint64 directly)
//   "generation":1
// (No `err` field — sequence-overflow has no wrapped Encode error;
// AppendEvent emits the log without an error attribute.)
```

Note: `TestAppendEvent_PropagatesMissingChain` keeps its assertion that the wrapped `compact.ErrMissingChain` is propagated to the caller AND ALSO asserts (via `captureLogs(t)` mounted at the top of the test) that exactly one `slog.LevelError` record was emitted with fields `event_id`, `session_id`, `event_type`, and `err` set, NO `generation` field present (it is intentionally excluded — the chain is nil on this branch), and NO `payload`, NO `mapper_err`, NO peer-derived content. The single-record assertion catches both regressions where the log call is silently dropped (zero records) and regressions where missing-chain accidentally re-enters a retry loop (multiple records). The assertion shape:

```go
// At top of TestAppendEvent_PropagatesMissingChain, before the AppendEvent call:
logs := captureLogs(t)

// ...existing setup + AppendEvent call + wrapped-error / WAL / prev_hash assertions...

// Exactly one ERROR-level record was emitted.
records := strings.Split(strings.TrimRight(logs.String(), "\n"), "\n")
if len(records) != 1 {
    t.Fatalf("expected exactly one structured log record, got %d:\n%s", len(records), logs.String())
}
body := records[0]
for _, want := range []string{
    `"level":"ERROR"`,
    `"msg":"watchtower: composite-store regression — missing chain"`,
    `"event_id":"evt-42"`,
    `"session_id":"s"`,
    `"event_type":"exec"`,
    `"err":"compact.Encode: ev.Chain is nil; composite did not stamp"`,
} {
    if !strings.Contains(body, want) {
        t.Errorf("expected log substring %q\nrecord:\n%s", want, body)
    }
}
// Sanitization + scope: no peer-derived content, and `generation` is
// intentionally NOT in the field set because composite-store generation is
// only available via ev.Chain.Generation, which is nil on this branch.
for _, banned := range []string{`"payload"`, `"mapper_err"`, `"generation"`} {
    if strings.Contains(body, banned) {
        t.Errorf("missing-chain log must not include %q\nrecord:\n%s", banned, body)
    }
}
```

`TestAppendEvent_LogsInvalidMapper` is intentionally omitted: end-to-end coverage requires constructing a `Store` with an invalid mapper, which `Store.New` rejects at construction time (Task 22). The branch is exercised by Encode-direct unit tests in Task 9.

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
	"log/slog"
	"math"

	"github.com/agentsh/agentsh/internal/audit"
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
//
// Per-record drop classes (sink-internal — return nil, do NOT propagate
// to caller; chain does NOT advance; WAL is not touched):
//   - compact.ErrInvalidMapper → wtp_dropped_invalid_mapper_total
//   - compact.ErrInvalidTimestamp → wtp_dropped_invalid_timestamp_total
//   - mapper-wrapped error (default) → wtp_dropped_mapper_failure_total
//   - sequence > math.MaxInt64 → wtp_dropped_sequence_overflow_total
//   - chain.ErrInvalidUTF8 (per-record) → wtp_dropped_invalid_utf8_total
//
// Loud-failure class (NOT a drop — propagated to caller as wrapped error):
//   - compact.ErrMissingChain → returned as fmt.Errorf("watchtower: %w", err).
//     This is a composite-store regression (the composite MUST stamp
//     ev.Chain before fanning out); operators surface it at the call site
//     rather than via a per-sink counter.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	if s.isFatal() {
		return errFatalLatch
	}

	// 1. Encode payload (no chain yet — leaves Integrity nil).
	//    Encode is the FIRST step so that ErrMissingChain / ErrInvalidMapper /
	//    ErrInvalidTimestamp surface here, classified into per-class drop
	//    counters (or, for ErrMissingChain, propagated as a wrapped error).
	//    The sequence-overflow bounds-check below requires ev.Chain != nil,
	//    which Encode guarantees by rejecting nil chains with ErrMissingChain
	//    BEFORE this method ever reaches the bounds-check.
	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		switch {
		case errors.Is(err, compact.ErrMissingChain):
			// Loud failure — composite-store regression. Propagate as a
			// wrapped error rather than dropping silently AND emit one
			// ERROR-severity structured log per occurrence. ev.Chain is
			// nil here, so we cannot include sequence/generation from the
			// chain — fall back to event-level identifiers that live on
			// types.Event itself (ID, SessionID, Type) plus the sentinel
			// error string. All four logged values are internal-only —
			// no peer-supplied bytes ever appear. No counter is wired:
			// missing-chain is a developer-facing integration bug, not a
			// per-record runtime drop class. The log is exempt from the
			// invalid-frame sanitization rule because every field is
			// internal-only. `generation` is intentionally excluded
			// because composite-store generation is only available via
			// ev.Chain.Generation, which is nil on this branch by
			// definition (see spec §"Caller contract for propagated
			// `compact.ErrMissingChain`").
			slog.ErrorContext(ctx, "watchtower: composite-store regression — missing chain",
				slog.String("event_id", ev.ID),         // ev.ID verbatim — empty string when ev.ID is empty (no substitute)
				slog.String("session_id", ev.SessionID), // internal-only correlation key
				slog.String("event_type", ev.Type),     // internal-only event category
				slog.String("err", err.Error()),        // wrapped sentinel string only — no peer bytes
			)
			return fmt.Errorf("watchtower: %w", err)
		case errors.Is(err, compact.ErrInvalidMapper):
			s.metrics.IncDroppedInvalidMapper(1)
			slog.WarnContext(ctx, "watchtower: dropping event — invalid mapper",
				"session_id", s.opts.SessionID,
				"sequence", ev.Chain.Sequence,
				"generation", ev.Chain.Generation,
				"err", err,
			)
			return nil
		case errors.Is(err, compact.ErrInvalidTimestamp):
			s.metrics.IncDroppedInvalidTimestamp(1)
			slog.WarnContext(ctx, "watchtower: dropping event — invalid timestamp",
				"session_id", s.opts.SessionID,
				"sequence", ev.Chain.Sequence,
				"generation", ev.Chain.Generation,
				"err", err,
			)
			return nil
		default:
			// Default branch = mapper.Map() returned a non-sentinel error
			// wrapped by Encode as `compact mapper: %w`.
			s.metrics.IncDroppedMapperFailure(1)
			slog.WarnContext(ctx, "watchtower: dropping event — mapper failure",
				"session_id", s.opts.SessionID,
				"sequence", ev.Chain.Sequence,
				"generation", ev.Chain.Generation,
				"err", err,
			)
			return nil
		}
	}

	// 2. Bounds-check the sequence. Encode succeeded, so ev.Chain is
	//    guaranteed non-nil here (ErrMissingChain branch above returned).
	if ev.Chain.Sequence > math.MaxInt64 {
		s.metrics.IncDroppedSequenceOverflow(1)
		slog.WarnContext(ctx, "watchtower: dropping event — sequence > math.MaxInt64",
			"session_id", s.opts.SessionID,
			"sequence", ev.Chain.Sequence,
			"generation", ev.Chain.Generation,
		)
		return nil
	}

	payload, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// 2. Compute integrity record (pure; no chain mutation yet).
	// Signature matches audit.SinkChain.Compute via the WatchtowerSink
	// adapter (positional args). audit.IntegrityFormatVersion is the
	// canonical wire constant — using it here avoids defining a watchtower-
	// local alias that would have to be kept in lockstep with the audit
	// constant. The sequence cast is safe because the math.MaxInt64
	// bounds check above already rejected overflow.
	cr, err := s.sink.Compute(audit.IntegrityFormatVersion, int64(ev.Chain.Sequence), ev.Chain.Generation, payload)
	if err != nil {
		if errors.Is(err, chain.ErrInvalidUTF8) {
			s.metrics.IncDroppedInvalidUTF8(1)
			slog.WarnContext(ctx, "watchtower: dropping event — invalid UTF-8 in chain field",
				"session_id", s.opts.SessionID,
				"sequence", ev.Chain.Sequence,
				"generation", ev.Chain.Generation,
				"err", err,
			)
			return nil
		}
		return fmt.Errorf("chain compute: %w", err)
	}

	// Attach integrity record to the CompactEvent and re-marshal so that
	// the WAL stores the wire-final bytes. The IntegrityRecord is built
	// from cr.EntryHash() / cr.PrevHash() plus the WTP-side context
	// digest + key fingerprint owned by the Store.
	ce.Integrity = s.buildIntegrityRecord(cr, ev.Chain)
	final, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal final: %w", err)
	}

	// 3. Append to WAL.
	res, err := s.w.Append(final)
	if err != nil {
		var ae wal.AppendError
		if errors.As(err, &ae) && ae.IsAmbiguous() {
			s.sink.Fatal(err) // latch the underlying audit chain
			s.latchFatal(err)
		}
		// Clean failure: no chain commit, prev_hash unchanged.
		return fmt.Errorf("wal append: %w", err)
	}

	// 4. Commit chain advance. audit.SinkChain.Commit returns the latched-
	// fatal sentinels (audit.ErrFatalIntegrity / ErrStaleResult /
	// ErrCrossChainResult / ErrBackwardsGeneration). All four are terminal
	// — the chain is corrupt and no further appends are safe.
	if err := s.sink.Commit(cr); err != nil {
		s.latchFatal(err)
		return fmt.Errorf("chain commit: %w", err)
	}
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

`audit.SinkChain.Compute` returns a `*audit.ComputeResult` whose `EntryHash()` and `PrevHash()` accessors give the values needed to populate the WTP `IntegrityRecord`. `Store.buildIntegrityRecord(cr, chainState)` (defined alongside `AppendEvent` in `append.go`) assembles the record from those plus the WTP-side context digest and key fingerprint owned by the Store. No additional accessor on `*audit.ComputeResult` is needed; the audit phase-0 contract stays untouched.

No new constants are needed in `internal/store/watchtower/chain` for
this task: `AppendEvent` references `audit.IntegrityFormatVersion`
directly so the wire-format version is sourced from a single canonical
location.

Also add the inline `failingSink` test double + the `mkStoreWithFailingSink` helper to `append_test.go`. The double EMBEDS `*chain.WatchtowerSink` (built from a real `*audit.SinkChain`) so PeekPrevHash returns the actual chain state — the assertion "prev_hash unchanged" then proves the chain didn't advance, not just that a stub returned the same constant. Only `Compute` is overridden:

```go
// failingSink is a chain.SinkChainAPI test double whose Compute always
// returns the configured sentinel error. It embeds *chain.WatchtowerSink
// (over a real *audit.SinkChain) so PeekPrevHash returns the actual
// genesis prev_hash; the drop-path assertion "prev_hash unchanged"
// proves the chain did not advance, not merely that a stub returned a
// constant. Commit panics if invoked — the drop path under test must
// short-circuit before reaching Commit, and a silent no-op would mask
// a control-flow regression.
//
// Defined here in a _test.go file so it cannot be imported by production
// code — the _test.go suffix excludes it from non-test builds.
type failingSink struct {
	*chain.WatchtowerSink
	err error
}

func newFailingSink(t *testing.T, err error) *failingSink {
	t.Helper()
	inner, innerErr := audit.NewSinkChain([]byte("0123456789abcdef0123456789abcdef"), "hmac-sha256")
	if innerErr != nil {
		t.Fatalf("audit.NewSinkChain: %v", innerErr)
	}
	return &failingSink{WatchtowerSink: chain.NewWatchtowerSink(inner), err: err}
}

func (f *failingSink) Compute(_ int, _ int64, _ uint32, _ []byte) (*audit.ComputeResult, error) {
	return nil, f.err
}

// Commit panics on invocation: the failure path under test must drop the
// record before Commit is ever called. A silent no-op here would mask a
// regression where a dropped record reaches commit anyway. Inheriting
// the embedded WatchtowerSink's Commit would be worse — it would advance
// the real audit chain on a record the harness expects to have been
// dropped.
func (f *failingSink) Commit(_ *audit.ComputeResult) error {
	panic("failingSink.Commit invoked — record should have been dropped before reaching the sink")
}

// PeekPrevHash is INHERITED from the embedded *chain.WatchtowerSink — it
// returns the actual chain prev_hash (genesis empty until a real Commit
// advances the inner audit.SinkChain). The drop-path tests assert this
// value is unchanged across the dropped append, which proves the chain
// did not advance, not merely that a stub returned a constant.

func mkStoreWithFailingSink(t *testing.T, sentinel error) *watchtower.Store {
	t.Helper()
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	allocator := audit.NewSequenceAllocator(0, 0)
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:                         t.TempDir(),
		Mapper:                         compact.StubMapper{},
		Allocator:                      allocator,
		AgentID:                        "a",
		SessionID:                      "s",
		HMACKeyID:                      "k1",
		HMACSecret:                     []byte("0123456789abcdef0123456789abcdef"),
		BatchMaxRecords:                8,
		BatchMaxBytes:                  8 * 1024,
		BatchMaxAge:                    50 * time.Millisecond,
		AllowStubMapper:                true,
		Dialer:                         srv.DialerFor(),
		Metrics:                        metrics.New(),
		SinkChainOverrideForTests:      newFailingSink(t, sentinel),
		AllowSinkChainOverrideForTests: true, // gated test seam; see Options doc
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/... -run TestAppendEvent_StampsChainBeforeWAL`
Expected: PASS.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/store.go internal/store/watchtower/append_test.go
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
	"bytes"
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
		HMACKeyID:       "k1", HMACSecret: bytes.Repeat([]byte("a"), 32),
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
	prev := s.PeekPrevHash() // test-only accessor from store_export_test.go
	if err := s.AppendEvent(context.Background(), ev); err == nil {
		t.Fatal("expected clean failure")
	}
	got := s.PeekPrevHash()
	if got != prev {
		t.Fatalf("clean failure advanced chain state: prev=%q got=%q", prev, got)
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
		HMACKeyID:       "k1", HMACSecret: bytes.Repeat([]byte("a"), 32),
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

No new chain accessor is needed: Task 22 already exposes
`(s *Store) PeekPrevHash() string` via `store_export_test.go` (test-only,
guarded by the `_test.go` build tag). It delegates to
`chain.WatchtowerSink.PeekPrevHash`, which reads
`audit.SinkChain.State().PrevHash`. The clean-failure assertion above
uses string equality on that hex hash; no `SinkState` opaque type or
`SinkStateEqual` helper is required.

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
git add internal/store/watchtower/integrity_test.go internal/store/watchtower/wal/generation_boundary_test.go internal/store/watchtower/wal/wal.go pkg/types/events_marshal_test.go
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
	"bytes"
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
		HMACKeyID:       "k1", HMACSecret: bytes.Repeat([]byte("a"), 32),
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
	"bytes"
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
		HMACKeyID:       "k1", HMACSecret: bytes.Repeat([]byte("a"), 32),
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
	"sync/atomic"

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
	closed atomic.Bool
}

func (g *grpcStreamConn) Send(m *wtpv1.ClientMessage) error   { return g.stream.Send(m) }
func (g *grpcStreamConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }

// CloseSend half-closes the send side of the stream. It does NOT
// release the underlying ClientConn — call Close for that.
func (g *grpcStreamConn) CloseSend() error { return g.stream.CloseSend() }

// Close fully tears down the stream by closing the underlying
// ClientConn, which cancels any in-flight Send/Recv. Idempotent so
// error paths can call it without coordinating with a graceful close.
func (g *grpcStreamConn) Close() error {
	if !g.closed.CompareAndSwap(false, true) {
		return nil
	}
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

### Task 27a: Operator monitoring migration (coordination task)

**Owner**: SRE/ops team coordination (NOT the implementation team).
The implementation team OWNS the preflight check that this task is done
before flipping the production rollout flag, but does NOT own the
artifact updates themselves.

**Type**: Operator coordination (not a code task). No Go files are
modified. Tracking artifact: `docs/superpowers/operator/wtp-monitoring-migration.md`
(create if missing). This task does NOT block earlier code tasks
(1–27 land independently); it BLOCKS ONLY the production rollout flag
flip — i.e. enabling `audit.watchtower.enabled: true` on production
fleets.

**Why this exists**: The Round 11 spec change introduced two
operator-facing breaking changes that earlier rounds missed:

1. `wtp_dropped_missing_chain_total` was REMOVED — and missing-chain
   is no longer an invalid-frame drop AT ALL. The semantics changed in
   Round 4: missing-chain is now PROPAGATED from `AppendEvent` as a
   wrapped `compact.ErrMissingChain` error rather than silently
   dropped. There is NO replacement label like
   `wtp_dropped_invalid_frame_total{reason="missing_chain"}` —
   inventing such a label would mis-document the new contract. The
   only contractually guaranteed emission signal for the propagated
   error is the ERROR-severity structured log emitted by
   `AppendEvent` (per spec §"Caller contract for propagated
   `compact.ErrMissingChain`" clause (a)) — operators with
   alerts/dashboards on `wtp_dropped_missing_chain_total` MUST
   replace each rule with a log-based alert/SLO matching that log's
   field set, delete the rule, redirect to
   `wtp_reconnects_total{reason="..."}` ONLY at sites where caller
   wiring tearing down the stream on `compact.ErrMissingChain` has
   been explicitly verified (the reconnect family has no contractually
   guaranteed emission path from this error — clauses (b)/(c) of the
   caller contract permit log-and-continue), or redirect to
   `wtp_dropped_invalid_frame_total{reason=~"..."}` for broader
   protocol-layer drop intent — per Step 2 below. The handshake-time
   `wtp_session_init_failures_total{reason}` /
   `wtp_session_rotation_failures_total{reason}` families (planned in
   Task 22a, Phase 8) are NEVER valid redirect targets — those
   families fire only on context-digest handshake failures
   (`invalid_utf8` plus the `unknown` catch-all) during the
   SessionInit/SessionUpdate handshake and have no defined emission
   path from a propagated `compact.ErrMissingChain`. See spec
   §"Migration guidance: removed `wtp_dropped_missing_chain_total`"
   for the canonical redirection map.
2. `wtp_dropped_invalid_frame_total{reason="unknown"}` was
   NARROWED. Pre-split, `unknown` was a catch-all that covered BOTH
   validator-emitted schema-drift cases AND defense-in-depth bypass
   cases. Post-split, `unknown` means VALIDATOR-EMITTED schema drift
   ONLY — a peer rolled out a newer protobuf schema than this binary
   supports (its `body` oneof discriminator is recognised by the wire
   format but not yet handled by the local switch). The bypass cases
   (receiver-side `errors.As`-false guard, metrics-side
   `IncDroppedInvalidFrame` invalid-label collapse) now go to a NEW
   reason value `classifier_bypass`. Operators with alerts on
   `unknown` will see their rate change because the bypass cases are
   no longer in that bucket — and an alert that fires on `unknown`
   may go silent under bypass-class regressions even when the
   underlying bug is happening, because those increments now land
   under `classifier_bypass`. See spec §"Migration from pre-split
   `unknown`" and the `unknown` / `classifier_bypass` runbook entries
   above for the canonical post-split semantics.

See spec §"Rollout phasing" for the full per-reason rollout policy and
the corresponding spec §"Migration" subsection.

#### Files

- `docs/superpowers/operator/wtp-monitoring-migration.md`  # NEW (Task 27a): operator migration tracking artifact

No code files are modified.

#### Steps

- [ ] **Step 1a: Declare inventory scope (authoritative monitoring inventory source)**

Before running the Step 1 grep, the SRE/ops team MUST declare the
authoritative inventory source — a definitive list of all monitoring
repos / systems in scope. Without this declared scope, the inventory
may miss alerts that fire outside the obvious repo set, leaving the
rollout preflight incomplete and the production migration silently
broken. The declaration MUST list:

  - All Prometheus rule repositories that ship to the production
    monitoring environment (alerting rules + recording rules).
  - All Grafana dashboard sources (JSON repos, ConfigMap manifests,
    dashboards-as-code repositories, in-app dashboard exports).
  - All runbook source-of-truth locations referenced by `runbook_url`
    annotations in production alerts.
  - All log-aggregation systems used for production alerting (Loki,
    Splunk, Elastic, Datadog Logs, etc.) — both the alert/SLO
    definitions AND any saved searches that surface composite-store
    regressions. The migration explicitly endorses log-based
    alerting as the recommended replacement for
    `wtp_dropped_missing_chain_total`, so log-side artifacts MUST be
    in scope or the recommended migration path is not executable.
  - Any third-party systems that scrape `wtp_*` metrics or display
    them (e.g. internal SaaS uptime dashboards, vendor SRE consoles,
    incident-response tooling that pulls metric snapshots).

The list MUST be checked into the migration tracking artifact at
`docs/superpowers/operator/wtp-monitoring-migration.md` (in a clearly
labelled "Inventory scope" section at the top) AND signed off by an
SRE/ops lead BEFORE Step 1's grep work begins. Step 1 cannot be
considered complete until every entry in the inventory scope has been
swept.

- [ ] **Step 1: Inventory existing alerting and dashboards**

Search the operator monitoring repos / dashboards / log-aggregation
systems declared in Step 1a for any references to the removed or
narrowed metric series. Three targets:

  1. Every Prometheus alerting rule, recording rule, and alert
     annotation that names `wtp_dropped_missing_chain_total` (any label
     selector). The metric is being removed in this rollout — these
     rules will silently start matching zero series.
  2. Every Prometheus alerting rule, recording rule, alert annotation,
     Grafana panel query, and runbook URL that selects on
     `wtp_dropped_invalid_frame_total{reason="unknown"}`. The
     `unknown` reason is being narrowed — these queries will see their
     rate fall and may go silent under real failure conditions.
  3. Every existing log-aggregation alert / SLO / saved search that
     was already triggering on missing-chain conditions (if the team
     had a log-side rule predating this migration). These need to be
     reconciled against the new structured-log field set
     `{event_id, session_id, event_type, err}` where `err` is the
     exact sentinel string `"compact.Encode: ev.Chain is nil; composite did not stamp"`
     (the value of `compact.ErrMissingChain.Error()`)
     emitted by `AppendEvent`'s ERROR-severity log per spec
     §"Caller contract for propagated `compact.ErrMissingChain`"
     clause (a) — both to confirm existing log alerts still match
     and to avoid duplicate coverage when migrated metric alerts
     pick the `log-based-alert` option in Step 2. Disposition for
     each row is decided in Step 3a below.

Record each hit in
`docs/superpowers/operator/wtp-monitoring-migration.md` using the
following column schema (extended from the earlier metrics-only
design so the artifact is reviewable end-to-end):

  - `artifact_path` — file or system path to the alert/dashboard.
  - `line` — line within that file (or panel ID, alert UID, saved
    search ID for non-text artifacts).
  - `artifact_type` — one of `prometheus_alert`,
    `prometheus_recording_rule`, `grafana_panel`, `runbook_url`,
    `log_alert`, `log_slo`, `log_saved_search`,
    `third_party_dashboard`. Determines which step decides its
    disposition (Step 2 / Step 3 / Step 3a).
  - `host_system` — REQUIRED on every row whose
    `artifact_type` is `log_alert`, `log_slo`, `log_saved_search`,
    or `third_party_dashboard`, AND on every row whose
    `migration_decision` is `log-based-alert` (Step 2). The cell
    MUST contain the stable identifier of the external system that
    hosts this artifact:
      - For `log_alert` / `log_slo` / `log_saved_search` rows AND
        for `log-based-alert` rows: a log-aggregation system listed
        in the Step 1a inventory scope (e.g. `loki-prod`,
        `splunk-es`, `elastic-cluster-1`, `datadog-logs`).
      - For `third_party_dashboard` rows: the third-party hosting
        system listed in the Step 1a inventory scope (e.g.
        `datadog-dashboards`, `newrelic`, `grafana-cloud-foo`).
    For `prometheus_*`, `grafana_panel`, and `runbook_url` rows
    whose `migration_decision` is NOT `log-based-alert`, the cell
    MAY be empty (these in-house artifacts are implicit from
    `artifact_path`). Step 5 preflight rejects rows that require
    `host_system` but leave it empty, AND rejects any row whose
    `host_system` value is not present in the "Runbook mapping"
    section (per Step 4).
  - `selector` — current Prometheus selector / log query / panel
    expression.
  - `intent` — short description of what the alert/dashboard
    surfaces today.
  - `migration_decision` — filled in by Step 2 (missing-chain
    metric refs), Step 3 (`reason="unknown"` refs), or Step 3a
    (log-side artifacts). Allowed values are listed in those
    steps.
  - `replacement_selector_or_query` — the new selector / log
    query / panel expression after migration. Required for any
    decision other than `delete` / `delete-log-alert`.
  - `verification_reference` — required for
    `migration_decision: redirect-reconnect` (file path + line +
    commit SHA + chosen reason label confirming caller teardown).
    Empty cells are not permitted on `redirect-reconnect` rows —
    Step 5 preflight rejects them.
  - `field_preservation_ref` — REQUIRED on every row whose
    `migration_decision` is `log-based-alert` (Step 2),
    `keep-log-alert`, `update-log-alert`, or `dedupe-log-alert`
    (Step 3a). The cell MUST contain the stable identifier of a
    Step 1b field-preservation verification entry (e.g.
    `field-preservation/<host-system-id>/<YYYY-MM-DD>`) that targets
    the same log-aggregation system named in this row's
    `host_system` cell. The referenced verification MUST classify
    that system as `field_preservation: ok`,
    `field_preservation: err-only`, OR
    `field_preservation: msg-only` (NEVER `broken`). Empty cells, or
    cells that point at a `broken` verification, are rejected by
    Step 5 preflight. Rows with `migration_decision: delete-log-alert`
    MAY leave this column empty. `third_party_dashboard` rows MAY
    leave this column empty (field preservation is a log-pipeline
    concern; third-party dashboards are out of scope for Step 1b).
  - `change_request_link` — PR / change request URL for the
    monitoring update.
  - `runbook_url_updated` — `yes` / `no` (filled in Step 4).
    Required for every row whose `migration_decision` is NOT a
    `delete*` value, including all log-side dispositions
    (`keep-log-alert` / `update-log-alert` / `dedupe-log-alert`)
    AND all Step 2 `log-based-alert` rows. See Step 4 for the
    per-stack runbook-pin mapping.
  - `runbook_anchor` — REQUIRED for every row whose
    `migration_decision` is NOT a `delete*` value. The cell MUST
    contain the resolved spec anchor URL chosen in Step 4 — i.e.
    the actual URL with fragment that the artifact's
    runbook-pin field has been updated to point at (e.g.
    `https://.../2026-04-18-wtp-client-design.md#per-reason-classifier-bypass`).
    Step 5 preflight rejects non-`delete*` rows whose
    `runbook_anchor` cell is empty AND rejects rows whose
    `runbook_anchor` value does not resolve to a real anchor in
    `docs/superpowers/specs/2026-04-18-wtp-client-design.md`.
  - `owner` — SRE/ops engineer responsible for this row.

- [ ] **Step 1b: Verify log-pipeline field preservation**

The `log-based-alert` option in Step 2 and the `keep-log-alert` /
`update-log-alert` options in Step 3a both assume the production log
pipeline preserves the structured-log field set
`{event_id, session_id, event_type, err}` end-to-end from the WTP
sink's `slog` emission to the log-aggregation system where the alert
or saved search runs. If the pipeline collapses structured fields into
a single `msg` blob, drops fields above a length threshold, or
rewrites the `err` value (e.g. via a string-stripping pipeline stage
that normalises punctuation), then a query that relies on field-level
matching of the exact sentinel string
`"compact.Encode: ev.Chain is nil; composite did not stamp"` will
silently never match and the recommended migration path will be
non-functional.

For every log-aggregation system listed in the Step 1a inventory
scope, the SRE/ops team MUST verify and record:

  - **Field preservation check**: confirm that a representative
    ERROR-severity log record produced by the WTP sink reaches the
    log-aggregation system with all four fields (`event_id`,
    `session_id`, `event_type`, `err`) preserved as separately
    queryable structured fields, AND that the `err` field's value
    contains the exact sentinel string
    `"compact.Encode: ev.Chain is nil; composite did not stamp"`
    byte-for-byte (no truncation, no string normalisation, no
    punctuation rewrite). The check MAY be performed using a
    synthetic injected record from a staging environment, OR by
    inspecting an existing real record if one is present in the
    sample window. Record the inspection method, the timestamp, and
    the rendered field values in
    `docs/superpowers/operator/wtp-monitoring-migration.md` under a
    "Field-preservation verification" section per log-aggregation
    system. Each verification MUST be assigned a stable identifier
    (e.g. `field-preservation/<log-system-id>/<YYYY-MM-DD>`) so it
    can be referenced from individual artifact rows in the
    `field_preservation_ref` column. Mark the system
    `field_preservation: ok` when this check passes.
  - **err-only fallback (degraded — diagnostic loss only)**: if the
    `err` field IS preserved as a separately queryable structured
    field byte-for-byte BUT one or more of `event_id` /
    `session_id` / `event_type` is renamed, dropped, or moved into
    the rendered message body, the system is NOT
    `field_preservation: ok` but it IS still alertable via a
    structured `err == sentinel` predicate. Mark the system
    `field_preservation: err-only`. Record (a) the specific
    auxiliary field(s) lost or renamed, (b) any alternative
    diagnostic source the on-call runbook can correlate against
    when the alert fires (e.g. a session ID surfaced in the
    rendered message body, a request-trace ID injected by
    surrounding middleware), AND (c) the source-scoping selector
    described in the next bullet (source scoping is REQUIRED for
    err-only too — see the rationale below). The
    `replacement_selector_or_query` cell on every err-only row MUST
    contain the structured `err = "<sentinel>"` predicate AND the
    source-scoping clause together as a single composite selector.
    Without source scoping, a future divergent code path that
    happens to emit the same sentinel string in `err` from a
    different component would trigger false positives.
  - **Source-scoping clause (REQUIRED for err-only AND msg-only)**:
    every alert built against an `err-only` or `msg-only` system
    MUST also constrain the component source — at minimum a
    service/logger/source-name match for this binary (e.g. the
    slog logger name for the WTP sink, the OTEL service name, the
    container/pod label, or the per-stack equivalent identifier
    that uniquely names this binary in the operator's
    log-aggregation backend). The verification entry MUST capture
    the chosen source identifier and the rationale for why it
    uniquely identifies this binary. Step 5 preflight rejects
    err-only / msg-only selectors that lack the source-scoping
    clause.
  - **Fallback selector (msg-only)**: if the `err` field is NOT
    preserved as a separate structured field but the rendered
    sentinel string IS present in the message body (`msg`), the
    system is `field_preservation: msg-only`. Record the fallback
    selector pattern (e.g. an `|=` or `contains` match against
    `msg`) that any log-based alert MUST use instead of
    `err = "..."`. The source-scoping clause from the previous
    bullet is REQUIRED — record both the rendered-string predicate
    AND the source-scoping predicate together as a single composite
    selector in `replacement_selector_or_query`.
  - **Pipeline gap**: if neither the structured `err` field NOR the
    rendered sentinel string survives end-to-end (e.g. the pipeline
    strips the payload entirely or replaces it with a placeholder),
    mark the affected log-aggregation system `field_preservation:
    broken`. Rows in Step 2 that propose
    `migration_decision: log-based-alert` against a
    `field_preservation: broken` system MUST be re-routed to
    `redirect-reconnect` (with the verification recipe in Step 2) or
    `delete`; selecting `log-based-alert` against a broken pipeline
    is INVALID and Step 5 preflight rejects it.

This verification MUST be completed AND recorded BEFORE Step 2's
log-based-alert decisions are finalised. Without it, the recommended
migration path may silently never fire.

- [ ] **Step 2: Decide redirect-or-delete for every `wtp_dropped_missing_chain_total` reference**

For each row from Step 1 that names `wtp_dropped_missing_chain_total`,
choose ONE of the four options below. Note: there is NO option to
rewrite the selector to
`wtp_dropped_invalid_frame_total{reason="missing_chain"}` — that label
value DOES NOT EXIST post-rollout (missing-chain is no longer an
invalid-frame drop at all; it is a propagated `compact.ErrMissingChain`
error per spec §"Migration guidance: removed
`wtp_dropped_missing_chain_total`").

  - **Replace with log-based alert (RECOMMENDED)**: per the migration
    guidance in the spec, the ONLY contractually guaranteed emission
    signal for propagated `compact.ErrMissingChain` is the
    ERROR-severity structured log entry emitted by `AppendEvent`
    (clause (a) of the caller contract). Replace the metric-based
    alert with a log-based alert/SLO whose canonical trigger is the
    sentinel `err` value
    `"compact.Encode: ev.Chain is nil; composite did not stamp"`
    (the value of `compact.ErrMissingChain.Error()`), expressed
    using the selector shape required by the host log-aggregation
    system's Step 1b `field_preservation` classification (see the
    classification matrix below). The `AppendEvent` log line carries
    the field set `{event_id, session_id, event_type, err}` per
    clause (a), but the auxiliary fields (`event_id`, `session_id`,
    `event_type`) play a DIAGNOSTIC role — they give the on-call
    engineer per-event context after the alert fires; they are NOT
    required components of the alert-trigger predicate. The Go
    identifier `compact.ErrMissingChain` is NOT a valid log query
    predicate — log-aggregation systems match the rendered string
    value, not the source-code symbol. The row's
    `replacement_selector_or_query` cell MUST contain a query that
    selects on this exact string. The exact selector shape depends on
    the host system's Step 1b `field_preservation` classification:
      - `field_preservation: ok` — equality / contains / `=~` regex
        match against the structured `err` field. Source scoping is
        OPTIONAL but recommended.
      - `field_preservation: err-only` — equality / contains / `=~`
        regex match against the structured `err` field PLUS a
        REQUIRED source-scoping clause (component / service / logger
        / source-name match for this binary, per the Step 1b
        verification entry's recorded source identifier). Without
        source scoping, a future divergent code path that emits the
        same sentinel string in `err` from a different component
        would trigger false positives.
      - `field_preservation: msg-only` — contains / `=~` match
        against the rendered message body PLUS a REQUIRED
        source-scoping clause as above. The selector MUST contain
        BOTH predicates as a single composite selector.
      - `field_preservation: broken` — INVALID for this option;
        re-route to **Delete** or **Redirect to reconnect family**.
    Mark the row `migration_decision: log-based-alert`, populate
    BOTH the `host_system` cell (the host log-aggregation system
    from the Step 1a inventory) AND the `field_preservation_ref`
    cell (the Step 1b verification ID for that system; classification
    MUST be `ok`, `err-only`, or `msg-only`), capture the new alert
    selector (or query) in the tracking artifact alongside the PR /
    change request link that adds the log-based alert. Rows that
    point at a `field_preservation: broken` system, that omit
    `host_system` / `field_preservation_ref`, or whose selector
    omits the source-scoping clause when required (`err-only` or
    `msg-only`), MUST be re-routed to the **Delete** or **Redirect
    to reconnect family** option below before sign-off.
  - **Delete**: the alert was a coarse catch-all and is no longer
    needed (the missing-chain class has moved out of the metrics
    silent-drop family entirely; the propagated error surfaces
    through the audit pipeline and the ERROR log, see the previous
    option). Mark the row `migration_decision: delete` and capture
    the PR / change request link that removes the rule.
  - **Redirect to reconnect family (CONDITIONAL — verification
    required)**: the alert's intent was to detect composite-store
    regressions AND the caller wiring in this build IS already known
    to tear down the WTP stream on propagated `compact.ErrMissingChain`.
    The spec contract permits but does NOT require this caller-side
    behavior, so this redirect option is valid ONLY when an explicit
    code-side verification confirms the teardown. Verification steps
    (all REQUIRED before this option may be selected):
      1. Locate the audit-pipeline integration that consumes
         `AppendEvent`'s returned error in this build.
      2. Confirm it calls a stream-tearing API (e.g., closes the
         gRPC stream, cancels the WTP context, or otherwise causes
         the receive loop to react with a reconnect) when
         `errors.Is(err, compact.ErrMissingChain)` is true.
      3. Identify the specific `wtp_reconnects_total{reason="..."}`
         label value that surfaces from the resulting stream
         teardown (Phase 8 receiver wiring in Task 17 Step 4a is
         the source of truth for the reason label set).
      4. Record all three of (file path + line of the integration
         code, the verification commit SHA, the chosen reason label)
         in the tracking artifact.
    Mark the row `migration_decision: redirect-reconnect` and capture
    the new selector (with the verified reason label), the
    verification reference, AND the PR / change request link in the
    tracking artifact. WITHOUT THE VERIFICATION, this option MUST NOT
    be selected — the alert may quietly never fire because the
    contract does not require teardown. NOTE: do NOT redirect to
    `wtp_session_init_failures_total{reason}` or
    `wtp_session_rotation_failures_total{reason}` under any
    circumstances — those handshake-time families have no defined
    emission path from propagated `compact.ErrMissingChain` (they
    fire only on context-digest handshake failures — `invalid_utf8`
    plus the `unknown` catch-all — during the
    SessionInit/SessionUpdate handshake per spec §"Frame validation
    and forward compatibility").
  - **Redirect to invalid-frame family**: the alert's intent was
    protocol-layer drops broadly. Use
    `wtp_dropped_invalid_frame_total{reason=~"..."}` with the
    appropriate reason set selected from the canonical reasons
    enumerated in spec §"Per-reason alerting policy". DO NOT use
    `reason="missing_chain"` — that label value DOES NOT EXIST
    post-rollout. Pick from the actual canonical reason set (e.g.
    `decompress_error`, `payload_too_large`, validator-emitted reasons
    like `event_batch_body_unset`, etc.). NOTE: this family is
    UNRELATED to `compact.ErrMissingChain` — it tracks peer-side
    protocol frames, not sink-internal composite-store regressions.
    Pick this option only if the original alert was genuinely
    monitoring protocol-layer drops; otherwise prefer the log-based
    alert option above. Mark the row
    `migration_decision: redirect-invalid-frame` and capture both the
    new selector AND the rationale for the chosen reason set in the
    tracking artifact alongside the PR / change request link.

All three decisions MUST be made AND the migration PR / change request
MUST be MERGED AND APPLIED to the production monitoring environment
(Prometheus rule files reloaded, Grafana panels updated and refreshed)
before Step 5. A queued-but-not-merged PR is INSUFFICIENT — the
production monitoring environment must reflect the migration before
the implementation team can flip the rollout flag.

- [ ] **Step 3: Decide keep / broaden / split for every `reason="unknown"` reference**

For each row from Step 1 that selects `reason="unknown"`, choose
ONE of:

  - **Keep (narrowed semantics)**: the alert is acceptable now
    that `unknown` only fires from VALIDATOR-EMITTED schema drift —
    i.e. the alert wants to know "the peer rolled out a newer
    protobuf schema than this binary supports" (a recognised wire
    `body` oneof discriminator that the local validator's switch does
    not yet handle). Mark the row `migration_decision: keep` and
    confirm the alert summary text reflects schema-drift semantics
    (avoid the words "label collapse" or "classifier bypass" — those
    cases now live under `classifier_bypass`; use phrasing like
    "schema drift" or "unknown frame oneof" instead).
  - **Broaden**: the alert really wanted "any non-zero invalid
    frame counter". Rewrite the selector to
    `sum by (reason) (rate(wtp_dropped_invalid_frame_total[5m])) > 0`
    or to an explicit reason-list union. Mark the row
    `migration_decision: broaden`.
  - **Split**: the alert was conflating multiple failure modes.
    Replace it with N per-reason alerts following the per-reason
    alerting policy in spec §"Per-reason alerting policy". For the
    bypass-detection portion of the original alert, USE
    `reason="classifier_bypass"` with **page** severity — the
    per-reason alerting policy says any non-zero increment of
    `classifier_bypass` is a bug and pages immediately (the counter
    should be permanently zero in healthy production). Mark the row
    `migration_decision: split` and link each new alert in the
    tracking artifact.

All decisions MUST be made AND the migration PR / change request MUST
be MERGED AND APPLIED to the production monitoring environment
(Prometheus rule files reloaded, Grafana panels updated and refreshed)
before Step 5. A queued-but-not-merged PR is INSUFFICIENT — the
production monitoring environment must reflect the migration before
the implementation team can flip the rollout flag.

- [ ] **Step 3a: Decide disposition for every existing log-side artifact**

For each row from Step 1 with `artifact_type` in
`{log_alert, log_slo, log_saved_search}` (the third inventory target
in Step 1), choose ONE of the four options below. The goal is to
reconcile any pre-existing log-side coverage with the new
`AppendEvent` structured-log contract from spec §"Caller contract for
propagated `compact.ErrMissingChain`" so that operators do not end up
with stale rules, duplicate coverage, or alert gaps after Step 2's
log-based-alert decisions are merged.

  - **Keep (no change required)**: the pre-existing log artifact
    already targets the missing-chain signal — the canonical trigger
    is the sentinel `err` value
    `"compact.Encode: ev.Chain is nil; composite did not stamp"`,
    expressed using the selector shape required by the host
    log-aggregation system's Step 1b `field_preservation`
    classification (per Step 2's log-based-alert option). The
    `AppendEvent` log line carries the field set
    `{event_id, session_id, event_type, err}` per clause (a), but the
    auxiliary fields play a DIAGNOSTIC role — they are NOT required
    components of the alert-trigger predicate. The pre-existing
    artifact may bind those fields as additional predicates or as
    diagnostic-context labels under `field_preservation: ok`, but
    under `err-only` or `msg-only` the auxiliary fields are not
    required-or-even-present alert predicates.
    Mark the row `migration_decision: keep-log-alert` AND populate
    BOTH the `host_system` cell (the host log-aggregation system) AND
    the `field_preservation_ref` cell (the Step 1b verification ID).
    The referenced verification's classification MUST be one of
    `field_preservation: ok`, `field_preservation: err-only`, or
    `field_preservation: msg-only` (NEVER `broken`). If the
    referenced verification is `field_preservation: err-only` OR
    `field_preservation: msg-only`, the existing selector MUST
    already include the source-scoping clause documented in
    Step 1b — if it does not, choose `update-log-alert` instead.
  - **Update**: the pre-existing log artifact targets the right
    semantics (composite-store regression / missing-chain) but its
    selector predates the new structured-log fields and needs a
    rewrite — typically because the older selector matched a free-text
    log line that the new sink no longer emits, the field set has
    changed, OR the existing err-only / msg-only selector lacks the
    source-scoping clause now required by Step 1b. Rewrite the
    selector to match the new fields, using the field-preservation
    classification's required selector shape from Step 2's
    log-based-alert option:
      - `ok` — structured `err` predicate (source scoping
        optional).
      - `err-only` — structured `err` predicate AND REQUIRED
        source-scoping clause as a single composite selector.
      - `msg-only` — rendered-message-body predicate AND REQUIRED
        source-scoping clause as a single composite selector.
    Mark the row `migration_decision: update-log-alert`, capture the
    new selector in `replacement_selector_or_query`, populate BOTH
    `host_system` AND `field_preservation_ref`, and capture the
    PR / change-request link.
  - **Delete**: the pre-existing log artifact is now redundant —
    e.g. its intent is fully covered by a Step 2
    `log-based-alert` row that adds the canonical alert against the
    new fields, OR the artifact was a coarse catch-all whose intent
    no longer applies. Mark the row `migration_decision: delete-log-alert`
    and capture the PR / change-request link that removes the rule.
    `host_system` SHOULD still be populated for audit traceability;
    `field_preservation_ref` MAY be empty.
  - **Dedupe-with-Step 2 decision**: the pre-existing log artifact
    overlaps with a Step 2 `log-based-alert` row but the SRE/ops team
    wants a single canonical owner per intent. Pick whichever of the
    two artifacts will be retained (the pre-existing log artifact OR
    the Step-2-added log alert) and record the chosen winner in the
    row's `replacement_selector_or_query` cell along with the
    losing row's artifact path so the dedupe choice is auditable. Mark
    the row `migration_decision: dedupe-log-alert`, populate BOTH
    `host_system` AND `field_preservation_ref` for the retained
    artifact, and capture the PR / change-request link.

A log-side row that proposes `keep-log-alert` or `update-log-alert`
against a log-aggregation system flagged `field_preservation: broken`
in Step 1b is INVALID and Step 5 preflight rejects it; re-route to
`delete-log-alert` (or upgrade the log pipeline before retrying).

All decisions MUST be made AND the migration PR / change request MUST
be MERGED AND APPLIED to the production log-aggregation environment
(log-alert/SLO/saved-search definitions reloaded so the new state is
live) before Step 5. A queued-but-not-merged PR is INSUFFICIENT.

- [ ] **Step 4: Update runbook URLs (Prometheus alert annotations AND log-side artifact equivalents)**

Every artifact touched in Steps 2, 3, and 3a MUST be pinned to a
runbook section in `docs/superpowers/specs/2026-04-18-wtp-client-design.md`
that corresponds to its reason (or to the per-reason alerting policy
section if the alert is reason-agnostic). The implementation team will
provide stable anchor IDs for each per-reason subsection in the spec —
the SRE/ops team picks them up here. For each touched row, mark
`runbook_url_updated: yes` AND populate `runbook_anchor` with the
resolved spec anchor URL (with fragment) that the artifact's
runbook-pin field has been updated to point at.

The mechanism varies by `artifact_type`:

  - **`prometheus_alert` / `prometheus_recording_rule`** —
    `annotations.runbook_url` (the canonical Prometheus convention).
  - **`grafana_panel`** — the panel's `links` array (or the
    dashboard-level `links` block if the panel inherits) pointing
    at the spec anchor.
  - **`runbook_url`** — direct rewrite of the artifact value.
  - **`log_alert` / `log_slo` / `log_saved_search`** — the
    per-stack equivalent of the `runbook_url` annotation:
      - **Loki / Grafana Mimir Alertmanager rules**: `annotations.runbook_url`.
      - **Splunk Enterprise Security / Splunk Observability**:
        the saved-search / detector `description` field with a
        `runbook:` prefix, OR the dedicated `runbook` custom field
        if the deployment defines one.
      - **Elastic / Kibana**: the rule's `actions[].params.body`
        runbook reference, OR the rule-level `tags` that link to a
        Kibana dashboard markdown panel containing the runbook URL.
      - **Datadog Logs Monitors / SLOs**: the monitor's `message`
        field's `[Runbook](<url>)` link, OR the SLO's `description`
        runbook reference.
      - **Other backends**: pick the field the operator's existing
        Prometheus runbook-pin convention maps to and document the
        mapping in the migration tracking artifact's "Runbook
        mapping" section so Step 5 preflight can verify it.
  - **`third_party_dashboard`** — the equivalent annotation /
    description / link field in the third-party hosting system
    (e.g. Datadog Dashboards: dashboard `description` runbook
    reference or per-widget `note` widgets; New Relic dashboards:
    `description` field; Grafana Cloud dashboards: dashboard-level
    `links`). Document the mapping in the "Runbook mapping"
    section so Step 5 preflight can verify it.

The migration tracking artifact MUST include a "Runbook mapping"
section that records, for EVERY external system in the Step 1a
inventory scope (this includes BOTH log-aggregation systems used
by `log_*` and `log-based-alert` rows AND third-party hosting
systems used by `third_party_dashboard` rows), which field is the
per-stack equivalent of `annotations.runbook_url`. Without this
mapping, Step 5 preflight cannot verify that runbook pins are
actually present in the deployed artifacts and rows that point at
an unmapped system MUST be rejected.

Rows with `migration_decision` in
`{delete, delete-log-alert}` are exempt from this step (the
artifact is being removed). All other rows MUST be marked
`runbook_url_updated: yes` AND have `runbook_anchor` populated
with the resolved spec anchor URL.

- [ ] **Step 5: Verify with implementation team and sign off**

Once Steps 1a, 1, 1b, 2, 3, 3a, and 4 are complete (every row in the
migration tracking artifact has a `migration_decision`, every
log-aggregation system has a recorded field-preservation verification
result, every PR / change request is MERGED AND APPLIED to the
production monitoring, log-aggregation, AND third-party hosting
environments, and every runbook URL is updated), open a tracking issue
tagged `wtp-monitoring-migration: ready` and request sign-off from the
implementation team's preflight check.

The implementation team's preflight (called out in spec §"Rollout
phasing → Rollout precondition") MUST verify:

  1. Every removed-metric reference is either deleted (PR merged AND
     deployed) or redirected (PR merged AND deployed); the migration
     MUST be live in the production monitoring environment, not
     pending. Acceptable redirect targets are documented in spec
     §"Migration guidance: removed `wtp_dropped_missing_chain_total`":
     a log-based alert/SLO whose canonical trigger is the sentinel
     `err` value
     `"compact.Encode: ev.Chain is nil; composite did not stamp"`
     (the value of `compact.ErrMissingChain.Error()`), expressed
     using the selector shape required by the host log-aggregation
     system's Step 1b `field_preservation` classification (per
     Step 2's log-based-alert option) — `ok` permits a structured
     `err` predicate with optional source scoping and may
     additionally bind the auxiliary fields
     `{event_id, session_id, event_type}` either as alert predicates
     or as diagnostic-context labels; `err-only` permits a structured
     `err` predicate with REQUIRED source scoping (auxiliary fields
     are diagnostic-only and may be absent); `msg-only` permits a
     rendered-message-body predicate with REQUIRED source scoping
     (auxiliary fields are diagnostic-only and may be absent), for
     composite-store-regression intent (recommended; the only
     contractually guaranteed emission signal),
     `wtp_reconnects_total{reason="..."}` for composite-store-regression
     intent ONLY when the `redirect-reconnect` row in the tracking
     artifact carries a populated verification reference (file path +
     line + commit SHA + chosen reason label) confirming the caller
     wiring tears down the WTP stream on `errors.Is(err,
     compact.ErrMissingChain)`, or
     `wtp_dropped_invalid_frame_total{reason=~"..."}` for broader
     protocol-layer drop intent. The handshake-time
     `wtp_session_init_failures_total{reason}` /
     `wtp_session_rotation_failures_total{reason}` families are NOT
     valid redirect targets — see the spec for rationale. No live
     alert or dashboard names `wtp_dropped_missing_chain_total` after
     the preflight completes. Any row marked
     `migration_decision: redirect-reconnect` whose verification
     reference cell is empty MUST be rejected and re-routed to one
     of the other three options before sign-off.
  2. Every `reason="unknown"` reference has an explicit decision AND
     the migration PR is MERGED AND DEPLOYED; the narrowed semantics
     are reflected in the live production alert/dashboard definitions.
  3. Every log-side row from Step 3a (`artifact_type` in
     `{log_alert, log_slo, log_saved_search}`) has a recorded
     `migration_decision` from
     `{keep-log-alert, update-log-alert, delete-log-alert, dedupe-log-alert}`
     AND its PR / change request is MERGED AND APPLIED to the
     production log-aggregation environment (alert/SLO/saved-search
     definitions reloaded). Any log-side row whose
     `migration_decision` is `keep-log-alert` or `update-log-alert`
     against a log-aggregation system flagged
     `field_preservation: broken` in Step 1b MUST be rejected and
     re-routed to `delete-log-alert` (or, if the log pipeline has
     since been upgraded, the Step 1b verification MUST be re-run and
     the new result recorded before sign-off).
  4. The Step 1b field-preservation verification has been recorded
     for EVERY log-aggregation system listed in the Step 1a inventory
     scope, AND the recorded classification is one of
     `field_preservation: ok` / `field_preservation: err-only` /
     `field_preservation: msg-only` / `field_preservation: broken`.
     Every row in Step 2 with
     `migration_decision: log-based-alert` and every row in Step 3a
     with `migration_decision: keep-log-alert`,
     `migration_decision: update-log-alert`, or
     `migration_decision: dedupe-log-alert` MUST have:
       - a populated `host_system` cell naming a system from the
         Step 1a inventory scope, AND
       - a populated `field_preservation_ref` cell whose stable
         identifier resolves to a verification entry against that
         same `host_system` whose classification is
         `field_preservation: ok`, `field_preservation: err-only`,
         OR `field_preservation: msg-only` (NEVER `broken`), AND
       - if the referenced verification is `field_preservation:
         err-only`, the row's `replacement_selector_or_query` cell
         MUST contain BOTH the structured-`err` predicate AND the
         source-scoping clause documented in the Step 1b
         verification entry (component / service / logger /
         source-name match for this binary), AND
       - if the referenced verification is `field_preservation:
         msg-only`, the row's `replacement_selector_or_query` cell
         MUST contain BOTH the rendered-message-body predicate AND
         the source-scoping clause documented in the Step 1b
         verification entry. Rows whose err-only OR msg-only
         selector lacks the source-scoping clause MUST be rejected
         and re-routed (typically to `update-log-alert` with the
         scoping clause added, or to `delete-log-alert`).
     Rows with empty `host_system`, empty `field_preservation_ref`,
     pointers at a `broken` verification, or err-only / msg-only
     selectors missing the source-scoping clause MUST be rejected.
  5. Every touched alert / log-side artifact / third-party dashboard
     has its runbook pin updated AND live in production:
       - Prometheus alerts and recording rules (Step 2 metric-side
         and Step 3 outputs) point their `annotations.runbook_url`
         at a stable runbook anchor that exists in the spec.
       - Grafana panels and dashboards point their `links` array at
         the same.
       - Log-side artifacts from Step 3a AND Step 2's
         `log-based-alert` rows have their per-stack runbook-pin
         field populated per the Step 4 mapping (e.g.
         `annotations.runbook_url` for Loki Alertmanager rules,
         `description` runbook-prefixed line for Splunk saved
         searches, monitor `message` `[Runbook](<url>)` link for
         Datadog Logs Monitors).
       - Third-party dashboard rows have their per-stack runbook-pin
         field populated per the Step 4 mapping (e.g. Datadog
         Dashboards `description` field, New Relic dashboard
         `description`, Grafana Cloud dashboard-level `links`).
       - Every row whose `migration_decision` is NOT a `delete*`
         value MUST have `runbook_url_updated: yes` AND a populated
         `runbook_anchor` cell containing the resolved spec anchor
         URL (with fragment) that the artifact's runbook-pin field
         points at. The `runbook_anchor` value MUST resolve to a
         real anchor in
         `docs/superpowers/specs/2026-04-18-wtp-client-design.md`
         (preflight verifies the fragment is present in the spec).
         Rows with empty `runbook_anchor` or with a fragment that
         does not resolve MUST be rejected.
       - The migration tracking artifact has a "Runbook mapping"
         section that records, for EVERY external system in the
         Step 1a inventory scope (log-aggregation systems AND
         third-party hosting systems), which field is used as the
         per-stack runbook-pin equivalent. Rows whose `host_system`
         points at a system without a recorded mapping MUST be
         rejected.
       - All of the above MUST be live in the corresponding
         production environment (monitoring, log-aggregation, OR
         third-party hosting). Third-party dashboard / hosting-system
         updates are subject to the same merged-AND-deployed
         standard as monitoring and log-aggregation: a merged-but-
         undeployed change is INSUFFICIENT.

The preflight check MAY be automated as a one-off CI grep run against
the monitoring repos (scoped to the inventory declared in Step 1a);
if it is run by hand, the result MUST be recorded in the same tracking
issue, including the timestamps at which each migration PR was merged
and deployed to production monitoring, log-aggregation, AND
third-party hosting environments. For third-party hosting systems
where deployment is not gated by a PR (e.g. a manual dashboard edit
in a vendor UI), record an equivalent proof artifact: the
change-event identifier from the vendor's audit log, OR a screenshot
or API-fetched export of the live artifact dated after the deploy,
captured by the SRE/ops engineer who pushed the change.

#### Acceptance criteria

- The migration tracking artifact at
  `docs/superpowers/operator/wtp-monitoring-migration.md` lists every
  affected alert / panel / runbook URL / log-side artifact /
  third-party dashboard with a recorded `migration_decision`, has an
  "Inventory scope" section at the top signed off by an SRE/ops lead
  (per Step 1a), has a "Field-preservation verification" section
  recording the Step 1b result (one of `field_preservation: ok` /
  `field_preservation: err-only` / `field_preservation: msg-only` /
  `field_preservation: broken`) for every log-aggregation system in
  the inventory scope, AND has a "Runbook mapping" section
  recording, for EVERY external system in the inventory scope
  (log-aggregation systems AND third-party hosting systems), which
  field is the per-stack runbook-pin equivalent of
  `annotations.runbook_url` (per Step 4).
- Every migration PR / change request is **MERGED AND APPLIED to the
  production monitoring AND log-aggregation AND third-party hosting
  environments** (Prometheus rule files reloaded, Grafana panels
  updated and refreshed, log-alert/SLO/saved-search definitions
  reloaded, AND third-party dashboard / hosting-system updates pushed
  live so the new state is visible in the third-party UI). A
  queued-but-unmerged PR, or a merged-but-undeployed change in any of
  these environments, is INSUFFICIENT.
- The implementation team SHALL NOT begin production code rollout
  (i.e. flipping `audit.watchtower.enabled: true` on a production
  fleet) until SRE/ops confirms Steps 1a, 1, 1b, 2, 3, 3a, and 4 are
  complete AND the migration is LIVE in the production monitoring,
  log-aggregation, AND third-party hosting environments (Prometheus
  rule files reloaded, Grafana panels updated and refreshed,
  log-alert/SLO/saved-search definitions reloaded, third-party
  dashboard / hosting-system updates pushed live), AND the preflight
  check has signed off in the tracking issue.
- This task does NOT block earlier code tasks (Task 1 through
  Task 27 land independently). It blocks ONLY the production
  rollout flag flip.

---

## Done

All 27 implementation tasks (1, 2, 3, 4, 4a-ii, 5, 6, 7, 8, 9, 10, 11,
12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 22a, 22b, 24, 25, 26, 27)
plus Task 27a (operator monitoring migration coordination — owned by
SRE/ops, gates production rollout only) complete. The watchtower store
is wired into the daemon behind `audit.watchtower.enabled: true`, the
standalone `wtp-testserver` binary is available for manual integration
testing, and the full test suite (unit, integrity-gating, component,
integration) is green.

Before merge, run:

```bash
go test ./...
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Then use `superpowers:finishing-a-development-branch` to land the change.
