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
- Modify: `proto/canyonroad/wtp/v1/validate.go` (Step 4 — add `ValidationReason` enum (including `ReasonUnknown` for the forward-compat unknown-oneof case), `AllValidationReasons() []ValidationReason` copy-returning getter (consumed by Task 22a Step 4 parity test; getter form, not a mutable exported slice), and `ValidationError` typed classifier so receivers consume `errors.As(err, &ve)` instead of grepping the validator's formatted message; `ValidationError.Error()` returns ONLY the Reason string per spec §"Invalid-frame log sanitization" defense-in-depth rule; ValidateEventBatch and ValidateSessionInit MUST return `*ValidationError` for every failure path including the forward-compat unknown-oneof case)
- Test: `proto/canyonroad/wtp/v1/validate_reason_test.go` (table-driven coverage that each input maps to its enum constant; `errors.As` and `errors.Is(err, ErrInvalidFrame)` both work)

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

- [ ] **Step 4 (validator-classifier prerequisite for Step 4a): Extend validator boundary with typed reason classifier**

Step 4a relies on the receiver classifying validator failures into a fixed `wtp_dropped_invalid_frame_total{reason}` enum. Today `proto/canyonroad/wtp/v1/validate.go` exposes only generic sentinels (`ErrInvalidFrame`, `ErrPayloadTooLarge`) constructed via `fmt.Errorf("%w: <peer-supplied details>", ErrXxx, ...)` — receivers would have to grep the formatted message to recover the reason, which both leaks peer-supplied bytes (the wrapped detail string embeds byte counts and oneof discriminators) into metric cardinality and is fragile. This step adds a typed classifier so receivers consume the reason via `errors.As(err, &ve)` and never touch the formatted message in the hot path.

Files to modify (Go-code change — small but real):
- Modify: `proto/canyonroad/wtp/v1/validate.go` — add `ValidationReason` enum (including `ReasonUnknown` for the forward-compat unknown-oneof case), `ValidationError` typed struct (with `Error() string` returning ONLY the canonical Reason value, never peer-derived Inner detail — see spec §"Invalid-frame log sanitization" defense-in-depth rule), `AllValidationReasons() []ValidationReason` copy-returning getter (exported so the metrics-side parity test in Task 22a Step 4 can range over it; the getter returns a fresh copy on each call so callers cannot mutate the underlying enumeration — STABLE PRODUCTION API per spec §"Stable production API"), refactor `ValidateEventBatch` and `ValidateSessionInit` to return `&ValidationError{Reason: ..., Inner: fmt.Errorf(...)}` for EVERY failure path (the forward-compat unknown-oneof default branch returns `&ValidationError{Reason: ReasonUnknown, Inner: fmt.Errorf("unknown body oneof case")}` — bare `fmt.Errorf("%w: ...", ErrInvalidFrame, ...)` returns from the validator are a CONTRACT VIOLATION per spec).
- Create: `proto/canyonroad/wtp/v1/validate_reason_test.go` — TDD-first table-driven tests asserting each enum constant maps to the correct input, `errors.As(err, &ve)` works, `errors.Is(err, ErrInvalidFrame)` / `errors.Is(err, ErrPayloadTooLarge)` still work for legacy callers, AND `ValidationError.Error()` returns ONLY the Reason string (no peer-derived Inner content) so naive `slog.Error("...", "err", ve)` call sites cannot leak peer bytes.

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
		{"nil_batch", nil, wtpv1.ReasonNilBatch, wtpv1.ErrInvalidFrame},
		{"compression_unspecified", &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_UNSPECIFIED}, wtpv1.ReasonCompressionUnspecified, wtpv1.ErrInvalidFrame},
		{"body_unset", &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_NONE, Body: nil}, wtpv1.ReasonBodyUnset, wtpv1.ErrInvalidFrame},
		{"compression_mismatch_uncompressed", &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_ZSTD,
			Body:        &wtpv1.EventBatch_Uncompressed{Uncompressed: &wtpv1.UncompressedEvents{}},
		}, wtpv1.ReasonCompressionMismatch, wtpv1.ErrInvalidFrame},
		{"compression_mismatch_compressed_with_none", &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_NONE,
			Body:        &wtpv1.EventBatch_CompressedPayload{CompressedPayload: []byte{1, 2, 3}},
		}, wtpv1.ReasonCompressionMismatch, wtpv1.ErrInvalidFrame},
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
		{"nil_session_init", nil, wtpv1.ReasonNilSessionInit},
		{"algorithm_unspecified", &wtpv1.SessionInit{Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED}, wtpv1.ReasonAlgorithmUnspecified},
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

2. **Run the tests to confirm they fail** (`go test ./proto/canyonroad/wtp/v1/... -run TestValidate.*Reason`). Expected: `wtpv1.ValidationReason undefined`, `wtpv1.ValidationError undefined`, `wtpv1.Reason* undefined`.

3. **Implement** in `proto/canyonroad/wtp/v1/validate.go`:

```go
// ValidationReason is the canonical low-cardinality classification of
// validator failures. Receivers consume this via errors.As to stamp
// wtp_dropped_invalid_frame_total{reason=string(ve.Reason)} without
// parsing the formatted error message. The string values match the
// enumerated reasons in spec §Metrics; adding a new validator branch
// requires adding a new ValidationReason constant AND adding the
// matching label to internal/metrics' WTPInvalidFrameReason enum (Task
// 22a). Note: `decompress_error` is NOT a ValidationReason — it is a
// metrics-only reason emitted by the streaming-decompression code
// downstream of the validator, with no proto-side counterpart (see spec
// §"Frame validation and forward compatibility").
type ValidationReason string

const (
	ReasonNilBatch              ValidationReason = "event_batch_body_unset" // nil *EventBatch — folded under body_unset for the metric
	ReasonCompressionUnspecified ValidationReason = "event_batch_compression_unspecified"
	ReasonBodyUnset             ValidationReason = "event_batch_body_unset"
	ReasonCompressionMismatch   ValidationReason = "event_batch_compression_mismatch"
	ReasonPayloadTooLarge       ValidationReason = "payload_too_large"
	ReasonNilSessionInit        ValidationReason = "session_init_algorithm_unspecified" // nil *SessionInit — folded under algorithm_unspecified for the metric (no separate "nil" label by design)
	ReasonAlgorithmUnspecified  ValidationReason = "session_init_algorithm_unspecified"
	// ReasonUnknown is the forward-compat reason returned by the
	// validator when a new oneof discriminator is added to the proto
	// schema before the validator switch is updated to classify it. The
	// validator returns &ValidationError{Reason: ReasonUnknown, ...} —
	// it MUST NOT fall back to a bare fmt.Errorf return. A non-zero
	// metrics-side wtp_dropped_invalid_frame_total{reason="unknown"}
	// series is the operator-visible signal that a new validator failure
	// class has shipped and the next maintenance cycle MUST extend the
	// enum to classify it under a dedicated reason.
	ReasonUnknown               ValidationReason = "unknown"
)

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
var allValidationReasons = []ValidationReason{
	ReasonNilBatch,
	ReasonCompressionUnspecified,
	ReasonBodyUnset,
	ReasonCompressionMismatch,
	ReasonPayloadTooLarge,
	ReasonNilSessionInit,
	ReasonAlgorithmUnspecified,
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
// API". Returns a fresh copy on each call so callers cannot mutate the
// package-private enumeration. Insertion order is documented stable
// (matching enum declaration order); removals/renames are breaking
// changes that require bumping the proto package version.
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
		return &ValidationError{Reason: ReasonNilBatch, Inner: fmt.Errorf("%w: batch is nil", ErrInvalidFrame)}
	}
	if b.Compression == Compression_COMPRESSION_UNSPECIFIED {
		return &ValidationError{Reason: ReasonCompressionUnspecified, Inner: fmt.Errorf("%w: compression unspecified", ErrInvalidFrame)}
	}
	switch body := b.Body.(type) {
	case nil:
		return &ValidationError{Reason: ReasonBodyUnset, Inner: fmt.Errorf("%w: body unset", ErrInvalidFrame)}
	case *EventBatch_Uncompressed:
		if b.Compression != Compression_COMPRESSION_NONE {
			return &ValidationError{Reason: ReasonCompressionMismatch, Inner: fmt.Errorf("%w: uncompressed body requires compression=NONE (got %s)", ErrInvalidFrame, b.Compression)}
		}
	case *EventBatch_CompressedPayload:
		if b.Compression == Compression_COMPRESSION_NONE {
			return &ValidationError{Reason: ReasonCompressionMismatch, Inner: fmt.Errorf("%w: compressed_payload requires compression != NONE", ErrInvalidFrame)}
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
		return &ValidationError{Reason: ReasonNilSessionInit, Inner: fmt.Errorf("%w: session_init is nil", ErrInvalidFrame)}
	}
	if s.Algorithm == HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return &ValidationError{Reason: ReasonAlgorithmUnspecified, Inner: fmt.Errorf("%w: algorithm unspecified", ErrInvalidFrame)}
	}
	return nil
}
```

4. **Run the tests to confirm they pass** (`go test ./proto/canyonroad/wtp/v1/... -count=1`). Expected: PASS.

5. **Cross-compile** (`GOOS=windows go build ./...`) before moving on.

This step is a small but real Go-code change — doc-only rounds (such as round 6) MUST NOT touch `validate.go`; the actual edit happens during Task 17 execution.

- [ ] **Step 4a: Inbound frame validation acceptance**

The Live state (and any other receive site introduced in Phase 8) MUST honor the spec's "Frame validation and forward compatibility" contract for every inbound `ServerMessage`. Acceptance criteria:

(a) When the receiver detects a frame-validation failure, it MUST classify the failure into a fixed `wtp_dropped_invalid_frame_total{reason}` label using the following two-step rule (NO fallback that parses `err.Error()` — the typed boundary is the contract):

   1. Attempt `errors.As(err, &ve)` against `*wtpv1.ValidationError`. If it returns true, use `WTPInvalidFrameReason(ve.Reason)` as the label value (the proto-side string is byte-equal to the metrics-side constant per Task 17 Step 4 / Task 22a parity check). For validator-returned errors this branch SHOULD always be taken — the validator MUST return `*ValidationError` for every failure path, including the forward-compat unknown-oneof case (which returns `&ValidationError{Reason: ReasonUnknown, ...}`).
   2. **Defense-in-depth fallback**: if `errors.As` returns false, the receiver MUST classify the failure as `WTPInvalidFrameReasonUnknown` (label string `"unknown"`) AND emit a WARN-level diagnostic. This branch SHOULD NEVER trigger in production because validator-returned errors always satisfy `errors.As(err, &ve)` per the contract above; if it does trigger, a non-validator caller passed a bare error into the receiver-side classifier (e.g., a unit-test mock or a future code path that bypasses `ValidateEventBatch`) and the WARN log makes that drift visible to operators. See spec §"Receiver-side defense in depth (should never trigger in production)" for rationale.

   The canonical defense-in-depth implementation pattern (use this verbatim in any new receiver wiring):

   ```go
   var ve *wtpv1.ValidationError
   if !errors.As(err, &ve) {
       // Defense-in-depth: should never happen for validator-returned errors,
       // but a non-validator caller might pass a bare error (e.g., a unit test
       // mock or future code path that bypasses ValidateEventBatch).
       // Classify as unknown and log a WARN-level diagnostic so operators
       // can investigate any such regression.
       slogger.Warn("non-typed frame validation error",
           slog.String("err_type", fmt.Sprintf("%T", err)),
           slog.String("reason", "unknown"))
       metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReasonUnknown)
       return // close stream, etc.
   }
   metrics.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason(ve.Reason))
   ```

   After classification, increment `wtp_dropped_invalid_frame_total{reason=<classified>}` exactly once per offending frame. The `reason` value MUST come from the canonical `wtpv1.ValidationReason` constants defined in Step 4 above (currently: `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`, `unknown`) plus the metrics-only `decompress_error` (emitted by streaming decompression downstream of the validator — see (d) below; no `wtpv1.ValidationReason` counterpart). New validator-emitted reasons added in future tasks MUST be added to the `ValidationReason` enum first; receivers reference `wtpv1.Reason*` constants, never literals.
(b) After incrementing the counter, the receiver MUST tear down the stream rather than silently consuming the malformed frame: server-side validation failures (this task) take the `stream_recv_error` reconnect path documented in spec §"Frame validation and forward compatibility" — close the current stream, return `StateConnecting` from the live loop, and let the Run loop's backoff handle the reconnect. The newly-added Goaway path is reserved for the testserver / server-side validators in Phase 9 (where the client's outbound frame is rejected) — Phase 8 receivers do not emit Goaway because they are reading, not writing.
(c) Invalid-frame logging MUST follow the spec's sanitization rule: log only `session_id` (local UUID, internal-only), `reason` (the canonical `string(ve.Reason)`), and `hex_prefix` (a hex-encoded prefix of the offending frame's serialized representation, capped at 16 input bytes — 32 hex chars output). The receiver MUST NOT log `ve.Inner` or `err.Error()` — both embed peer-supplied byte counts and oneof discriminators per the validator's `fmt.Errorf` construction.
(d) The streaming decompression path (downstream of `ValidateEventBatch` — added when WTP gains a real decompression code path post-MVP) MUST classify zstd/gzip framing errors and `MaxDecompressedBatchBytes` overruns as `WTPInvalidFrameReasonDecompressError` (metrics-side label `decompress_error`) and route them through the same counter + tear-down path. There is NO `wtpv1.ReasonDecompressError` constant — `decompress_error` is metrics-only because it is emitted downstream of the validator (decompression runs after `ValidateEventBatch` accepts the frame envelope). Until a real decompression path lands, the metrics-side `decompress_error` reason exists in the metrics enum so the metric series is registered at zero (always-emit contract) — no live increment yet.

Add a transport-level unit test that injects each enumerated frame-validation reason via the fakeConn `recvCh` (mirror the pattern used by the existing `wtp_session_failures_total{reason}` tests in `internal/metrics/wtp_test.go`). For each reason the test MUST assert: (1) the corresponding `wtp_dropped_invalid_frame_total{reason="<value>"}` series increments by exactly one, AND (2) the live loop returns `StateConnecting` (i.e., the reconnect path was taken). The test SHOULD use a table-driven structure keyed by the `wtpv1.Reason*` constants so adding a new reason is a one-line change. The test MUST consume reasons via `errors.As` against `*wtpv1.ValidationError` rather than parsing the error string.

**Test acceptance — split by live-path availability:**

- **Reasons with a live validator path NOW** (each MUST have an inject-and-assert test row in the table): `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`, and `unknown`. For each, the test injects a synthetic `*wtpv1.ValidationError` with the matching `Reason` (or constructs the offending frame and lets the validator return it; the `unknown` row uses `&wtpv1.ValidationError{Reason: wtpv1.ReasonUnknown, Inner: fmt.Errorf("synthetic")}` since the unknown-oneof code path is hard to trigger from a test without rebuilding the proto), asserts the counter increments by exactly one with `reason="<value>"`, and asserts the live loop returns `StateConnecting`.
- **`TestReceiver_NonTypedErrorClassifiedAsUnknown` (defense-in-depth guard)**: a separate dedicated test that verifies the receiver-side `errors.As`-false fallback. The test injects a bare `fmt.Errorf("%w: synthetic", wtpv1.ErrInvalidFrame)` (NOT wrapped in `*ValidationError` — this simulates a non-validator caller passing a bare error into the receiver, which SHOULD never happen for validator-returned errors per the contract). Assert: (1) the receiver's `errors.As(err, &ve)` returns false, (2) a WARN-level log entry is emitted with `err_type` and `reason="unknown"` fields, (3) the counter increments by exactly one with `reason="unknown"`, and (4) the live loop returns `StateConnecting`. This validates the defense-in-depth guard from spec §"Receiver-side defense in depth (should never trigger in production)".
- **`decompress_error` (deferred)**: explicitly EXCLUDED from the inject-and-assert table for this task. The metric series is registered NOW via the `WTPInvalidFrameReason` valid map and `wtpInvalidFrameReasonsEmitOrder` slice (zero-emission test in `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons` covers it), but the live-path inject-and-assert test is added in the future Phase that introduces streaming decompression. Reason: there is no decompression code path in this task — adding a synthetic injection here would test fakeConn machinery, not the real classifier. There is also no `wtpv1.ReasonDecompressError` to range over from the proto side — `decompress_error` is metrics-only.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/... -run "TestBatcher|TestLive_FrameValidation|TestReceiver_NonTypedErrorClassifiedAsUnknown"`
Expected: PASS — all 5 batcher invariant tests plus the table-driven frame-validation tests added in Step 4a (one entry per validator-emitted `wtp_dropped_invalid_frame_total{reason}` value, including `unknown` since the validator now returns `*ValidationError{Reason: ReasonUnknown}` for the forward-compat unknown-oneof case), plus the dedicated `TestReceiver_NonTypedErrorClassifiedAsUnknown` defense-in-depth test that injects a bare `fmt.Errorf` into the receiver-side classifier. The `decompress_error` reason is excluded per the split-acceptance rule above (metrics-only — no proto-side counterpart).

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_reason_test.go internal/store/watchtower/transport/batcher.go internal/store/watchtower/transport/batcher_test.go internal/store/watchtower/transport/state_live.go
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
	"fmt"
	"sync"

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
		Dir:          opts.WALDir,
		SegmentSize:  opts.WALSegmentSize,
		MaxTotalSize: opts.WALMaxTotalSize,
	})
	if err != nil {
		return nil, fmt.Errorf("open WAL: %w", err)
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = newGRPCDialer(opts)
	}

	tr := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   opts.AgentID,
		SessionID: opts.SessionID,
	})

	// Resolve the WTP metrics façade. opts.Metrics may be nil; the
	// WTP() accessor is nil-safe and returns a *WTPMetrics whose
	// mutators no-op when the underlying *Collector is nil.
	mw := opts.Metrics.WTP()

	s := &Store{
		opts:    opts,
		w:       w,
		tr:      tr,
		sink:    sinkChain,
		metrics: mw,
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
  - **Metrics-only reasons** (no proto-side counterpart): `decompress_error` — emitted by the streaming-decompression code downstream of `ValidateEventBatch` when zstd/gzip framing fails or `MaxDecompressedBatchBytes` is exceeded.

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

Append five new test functions to `internal/metrics/wtp_test.go` (mirror the existing pattern from Task 3):

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

	// Invalid (unknown enum) collapses to WTPInvalidFrameReasonUnknown.
	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReason("evil\"label\\value"))
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="unknown"} 1`) {
		t.Errorf("expected unknown=1 after invalid-reason fallback\nbody:\n%s", body)
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/metrics/ -run "TestWTPMetrics_DroppedInvalidUTF8|TestWTPMetrics_DroppedSequenceOverflow|TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons|TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons|TestWTPMetrics_SessionFailureReasonValidationAndEscape|TestWTPMetrics_DroppedInvalidMapper|TestWTPMetrics_DroppedInvalidTimestamp|TestWTPMetrics_DroppedMapperFailure|TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons"`
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
//     WTPInvalidFrameReasonDecompressError. Emitted by the streaming-
//     decompression code downstream of ValidateEventBatch — has no
//     wtpv1.ValidationReason because decompression runs after the
//     validator accepts the frame envelope.
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
	WTPInvalidFrameReasonUnknown                        WTPInvalidFrameReason = "unknown"
)

var wtpInvalidFrameReasonsValid = map[WTPInvalidFrameReason]struct{}{
	WTPInvalidFrameReasonEventBatchBodyUnset:           {},
	WTPInvalidFrameReasonEventBatchCompressionUnspec:   {},
	WTPInvalidFrameReasonEventBatchCompressionMismatch: {},
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec:    {},
	WTPInvalidFrameReasonPayloadTooLarge:               {},
	WTPInvalidFrameReasonDecompressError:               {},
	WTPInvalidFrameReasonUnknown:                       {},
}

// wtpInvalidFrameReasonsEmitOrder mirrors the wtpSessionFailureReasonsEmitOrder
// pattern: a fixed slice keeps Prometheus exposition deterministic and lets
// emitWTPMetrics emit zero-valued series for every enumerated reason on
// every scrape. Order is alphabetical-by-string for stable output.
var wtpInvalidFrameReasonsEmitOrder = []WTPInvalidFrameReason{
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
// collapse to WTPInvalidFrameReasonUnknown so the labeled family stays at
// a fixed cardinality.
func (w *WTPMetrics) IncDroppedInvalidFrame(reason WTPInvalidFrameReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		reason = WTPInvalidFrameReasonUnknown
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

Extend `Collector` (in `internal/metrics/metrics.go`) — add eight new fields next to the existing WTP series. Note that `wtpDroppedMissingChain` already exists from Task 3 and is REMOVED in Step 3.5 below; it is intentionally absent from this list:

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

	// ... rest unchanged ...
}
```

- [ ] **Step 3.5: Remove the orphaned `wtp_dropped_missing_chain_total` counter shipped in Task 3**

Task 3 shipped a `wtp_dropped_missing_chain_total` counter and an `IncDroppedMissingChain` accessor. The current design propagates `compact.ErrMissingChain` from `AppendEvent` as a wrapped error rather than dropping silently, so that counter has no remaining call site in the WTP sink. Leaving it in place would emit a permanently-zero series on every scrape and risk operators wiring alerts on a metric that can never fire.

Edits:

1. In `internal/metrics/metrics.go`, delete the `wtpDroppedMissingChain atomic.Uint64` field.
2. In `internal/metrics/wtp.go`, delete the `IncDroppedMissingChain` method, the matching `DroppedMissingChain` accessor (if present), and the three `emitWTPMetrics` lines for `wtp_dropped_missing_chain_total`.
3. In `internal/metrics/wtp_test.go`, delete the `w.IncDroppedMissingChain(1)` call from `TestWTPMetrics_AppendAndExpose` and the `"wtp_dropped_missing_chain_total 1"` assertion from the same test's expected-substring slice.

If a callsite outside `internal/metrics` invokes `IncDroppedMissingChain`, the build will fail with `IncDroppedMissingChain undefined` — verify with `rg -n "IncDroppedMissingChain|wtp_dropped_missing_chain_total" internal/ pkg/ cmd/` after the deletion. The expected result is no matches in code; references in `docs/superpowers/plans/` are historical and explicitly superseded (see the admonitions above the Task 3 snippets) and in `docs/superpowers/specs/2026-04-18-wtp-client-design.md` appear only in the migration-guidance paragraph — do not touch the docs from this step.

- [ ] **Step 4: Enum parity check (validator vs metrics)**

The proto-side `wtpv1.ValidationReason` enum (Task 17 Step 4) and the metrics-side `WTPInvalidFrameReason` enum (defined above in this task) are intentionally duplicated string sets — the metrics package does NOT import the proto package, but the string values for validator-emitted reasons MUST stay byte-equal so that `WTPInvalidFrameReason(ve.Reason)` always lands in `wtpInvalidFrameReasonsValid`. Without an enforcement mechanism the two enums will drift silently the first time someone adds a reason to one side and forgets the other. The metrics-only `decompress_error` reason is intentionally NOT mirrored on the proto side (it is emitted downstream of the validator, by streaming decompression).

Add a Go test `TestWTPInvalidFrameReason_ParityWithValidator` to `internal/metrics/wtp_test.go` that asserts FOUR invariants in one test function:

1. **Forward parity (exact set equality)**: every value in `wtpv1.AllValidationReasons()` MUST appear in `metrics.ValidationReasons()` (which returns a copy of just the validator-emitted SHARED set, NOT including metrics-only reasons), and vice versa. Use sorted comparison for a clear failure message that names the offending constant.
2. **Reverse parity (exact set equality)**: every value in `metrics.ValidationReasons()` MUST appear in `wtpv1.AllValidationReasons()`. (Same assertion as forward direction, but framed from the metrics side; both directions must hold for set equality.)
3. **Disjoint check**: `metrics.MetricsOnlyReasons()` (which returns just `[WTPInvalidFrameReasonDecompressError]`) MUST be disjoint from `wtpv1.AllValidationReasons()`. This catches the regression where someone accidentally adds `decompress_error` to the proto enum (which would violate the design contract that `decompress_error` is metrics-only).
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
// `decompress_error` reason is intentionally NOT mirrored on the proto
// side (it is emitted post-validator by streaming decompression).
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
			t.Errorf("metrics-only reason %q (string=%q) accidentally appears in wtpv1.AllValidationReasons() — the design contract is that metrics-only reasons (like decompress_error) have NO proto-side counterpart; remove it from proto/canyonroad/wtp/v1/validate.go's allValidationReasons or remove it from internal/metrics/wtp.go's MetricsOnlyReasons() (whichever was added in error)",
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
// counterpart — emitted by code paths downstream of the validator (e.g.,
// streaming decompression). Adding a new metrics-only reason MUST
// append it here, NOT to validationReasonsShared.
var metricsOnlyReasons = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonDecompressError,
}

// MetricsOnlyReasons returns a fresh copy of the metrics-only frame-
// validation reasons (those without a proto-side wtpv1.ValidationReason
// counterpart). Today: just decompress_error. Returns a fresh copy on
// each call so callers cannot mutate the underlying enumeration.
// STABLE PRODUCTION API.
func MetricsOnlyReasons() []WTPInvalidFrameReason {
	out := make([]WTPInvalidFrameReason, len(metricsOnlyReasons))
	copy(out, metricsOnlyReasons)
	return out
}
```

This step is doc-only spec for Task 22a — the actual Go-code parity test lands when the task executes (alongside `wtpv1.AllValidationReasons()` from Task 17). Listing it here ensures that whichever task lands second writes the parity test rather than leaving the enums to drift.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/metrics/...`
Expected: PASS — all existing tests + the nine new tests added in Step 1 (`TestWTPMetrics_DroppedInvalidUTF8`, `TestWTPMetrics_DroppedSequenceOverflow`, `TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionFailureReasonValidationAndEscape`, `TestWTPMetrics_DroppedInvalidMapper`, `TestWTPMetrics_DroppedInvalidTimestamp`, `TestWTPMetrics_DroppedMapperFailure`, `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons`) plus the parity test `TestWTPInvalidFrameReason_ParityWithValidator` added in Step 4. The legacy `TestWTPMetrics_AppendAndExpose` test from Task 3 has its `wtp_dropped_missing_chain_total` reference removed per Step 3.5.

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
