# Landlock network config wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `landlock.network.allow_connect_tcp` and `landlock.network.allow_bind_tcp` semantically real on the production (wrapper) path. Replace hardcoded `AllowNetwork=true; AllowBind=true` in `api/wrap.go` and `api/core.go` with reads from config. Default connect=true, bind=false. Validate at config load to prevent self-lockout when sandbox network is enabled. Reserve `bind_ports` with a warning; defer enforcement.

**Architecture:** `LandlockNetworkConfig` fields become `*bool` so we can distinguish "unset" from "set to false" (same pattern already used for `Sandbox.UnixSockets.Enabled` and `Sandbox.Seccomp.FileMonitor.Enabled`). `applyDefaultsWithSource` fills nil pointers with the new defaults. `validateConfig` rejects the self-lockout combination with a descriptive error. The server-side wrapper-config construction sites read `*cfg.Landlock.Network.AllowConnectTCP/AllowBindTCP`. The wrapper binary itself (`cmd/agentsh-unixwrap/main.go`) is unchanged — it already consumes the JSON-passed booleans via `builder.SetNetworkAccess`.

**Tech Stack:** Go 1.22+, `gopkg.in/yaml.v3`, `github.com/stretchr/testify`, `log/slog`. Linux-only enforcement; non-Linux stubs unaffected.

**Spec:** `docs/superpowers/specs/2026-04-15-landlock-network-config-design.md`

---

## File Structure

**Modify:**
- `internal/config/config.go` — `LandlockNetworkConfig` fields → `*bool`; defaults in `applyDefaultsWithSource`; validation in `validateConfig`; `bind_ports` warning.
- `internal/landlock/policy.go` — nil-safe dereference of new pointer fields in `BuildFromConfig` (line 290).
- `internal/api/core.go` — replace hardcoded `true` at lines 243-246 with config reads.
- `internal/api/wrap.go` — replace hardcoded `true` at lines 176-178 with config reads.

**Create:**
- `internal/config/landlock_network_test.go` — defaults + validation + warning unit tests.

**Modify (tests):**
- `internal/api/wrap_test.go` — add `TestWrapInit_LandlockNetwork_HonorsConfig` (with Landlock enabled, config controls `allow_network`/`allow_bind` JSON fields).
- `internal/api/core_test.go` (or existing test file for core path) — add equivalent test for the core.go construction path. If no suitable test file exists, create `internal/api/core_landlock_test.go`.

**No changes needed:**
- `cmd/agentsh-unixwrap/main.go` — already consumes `cfg.AllowNetwork` and `cfg.AllowBind` correctly.
- Non-Linux stubs (`ruleset_other.go`, `landlock_hook_other.go`, `landlock_exec_other.go`) — ignore network fields entirely.

---

## Task 1: Change `LandlockNetworkConfig` fields to `*bool` and fix the one in-process consumer

**Files:**
- Modify: `internal/config/config.go:709-713`
- Modify: `internal/landlock/policy.go:290`

- [ ] **Step 1.1: Update the struct definition**

Edit `internal/config/config.go` lines 708-713:

```go
// LandlockNetworkConfig controls Landlock network restrictions (kernel 6.7+).
type LandlockNetworkConfig struct {
	AllowConnectTCP *bool `yaml:"allow_connect_tcp"` // default: true (set by applyDefaults)
	AllowBindTCP    *bool `yaml:"allow_bind_tcp"`    // default: false (set by applyDefaults)
	BindPorts       []int `yaml:"bind_ports"`        // reserved; not yet enforced
}
```

- [ ] **Step 1.2: Update the in-process consumer at `internal/landlock/policy.go:290` to be nil-safe**

Replace the single line:

```go
		b.SetNetworkAccess(cfg.Network.AllowConnectTCP, cfg.Network.AllowBindTCP)
```

with a nil-safe version:

```go
		allowConnect := false
		if cfg.Network.AllowConnectTCP != nil {
			allowConnect = *cfg.Network.AllowConnectTCP
		}
		allowBind := false
		if cfg.Network.AllowBindTCP != nil {
			allowBind = *cfg.Network.AllowBindTCP
		}
		b.SetNetworkAccess(allowConnect, allowBind)
```

Rationale: `BuildFromConfig` may be called with a `LandlockConfig` that wasn't run through `applyDefaults` (the existing tests in `landlock_hook_test.go` do exactly this). Nil means "unspecified" — default to fail-closed (both false). After `applyDefaults` has run, pointers will always be non-nil.

- [ ] **Step 1.3: Verify the build compiles**

Run: `go build ./...`
Expected: exits 0, no compile errors.

- [ ] **Step 1.4: Verify Windows cross-compile still works (project guideline)**

Run: `GOOS=windows go build ./...`
Expected: exits 0.

- [ ] **Step 1.5: Run existing tests to confirm nothing broke**

Run: `go test ./internal/config/... ./internal/landlock/... ./internal/api/...`
Expected: all pass (no test constructed `LandlockNetworkConfig` with field values — verified via grep; zero-value `*bool` is `nil`, which compiles fine).

- [ ] **Step 1.6: Commit**

```bash
git add internal/config/config.go internal/landlock/policy.go
git commit -m "$(cat <<'EOF'
config(landlock): switch AllowConnectTCP/AllowBindTCP to *bool

Prep for honoring landlock.network.* config on the production path.
Pointer types let applyDefaults distinguish "user didn't set" from
"user set false" — same pattern as Sandbox.UnixSockets.Enabled.
The one in-process consumer (landlock/policy.go BuildFromConfig) now
defaults nil to fail-closed (both false).

No behavior change yet: api/wrap.go and api/core.go still hardcode
AllowNetwork=true; AllowBind=true. Fix lands in later commits.

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 2: Add defaults (connect=true, bind=false) in `applyDefaultsWithSource` — TDD

**Files:**
- Create: `internal/config/landlock_network_test.go`
- Modify: `internal/config/config.go` (add block inside `applyDefaultsWithSource`)

- [ ] **Step 2.1: Write the failing tests**

Create `internal/config/landlock_network_test.go`:

```go
package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLandlockNetworkDefaults_FillsConnectTrueBindFalse(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Nil(t, cfg.Landlock.Network.AllowConnectTCP, "omitted field must parse as nil")
	require.Nil(t, cfg.Landlock.Network.AllowBindTCP, "omitted field must parse as nil")

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP, "default must fill AllowConnectTCP")
	require.True(t, *cfg.Landlock.Network.AllowConnectTCP, "default AllowConnectTCP must be true")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP, "default must fill AllowBindTCP")
	require.False(t, *cfg.Landlock.Network.AllowBindTCP, "default AllowBindTCP must be false")
}

func TestLandlockNetworkDefaults_ExplicitValuesPreserved(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: true
  network:
    allow_connect_tcp: false
    allow_bind_tcp: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP)
	require.False(t, *cfg.Landlock.Network.AllowConnectTCP,
		"explicit false for allow_connect_tcp must survive applyDefaults")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP)
	require.True(t, *cfg.Landlock.Network.AllowBindTCP,
		"explicit true for allow_bind_tcp must survive applyDefaults")
}

func TestLandlockNetworkDefaults_LandlockDisabled_StillFilled(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: false
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP,
		"defaults filled unconditionally for diagnostic-dump stability")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP)
}

func TestLandlockBindPortsWarning_EmitsWhenSet(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	yamlData := []byte(`
landlock:
  enabled: true
  network:
    bind_ports: [8080, 9090]
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.Contains(t, buf.String(), "landlock.network.bind_ports",
		"setting bind_ports must emit a warning about non-enforcement")
}

func TestLandlockBindPortsWarning_SilentWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	yamlData := []byte(`
landlock:
  enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.False(t, strings.Contains(buf.String(), "bind_ports"),
		"no warning should fire when bind_ports is empty")
}
```

- [ ] **Step 2.2: Run the failing tests**

Run: `go test ./internal/config/ -run TestLandlockNetwork -v`
Expected: FAIL — defaults aren't implemented, both `AllowConnectTCP` and `AllowBindTCP` stay nil after `applyDefaults`. Warning test also fails (nothing logs).

- [ ] **Step 2.3: Implement defaults and warning in `applyDefaultsWithSource`**

In `internal/config/config.go`, locate `applyDefaultsWithSource` (starts at line 990). Find the end of the Landlock-related defaults section. If none exists, find a natural insertion point near other sandbox defaults (e.g., after the `cfg.Sandbox.Network.*` defaults around line 1080). Add:

```go
	// Landlock network defaults — fail-open for connect (proxy needs it),
	// fail-closed for bind (agents rarely need to listen).
	// Applied unconditionally so diagnostic dumps show explicit values.
	if cfg.Landlock.Network.AllowConnectTCP == nil {
		v := true
		cfg.Landlock.Network.AllowConnectTCP = &v
	}
	if cfg.Landlock.Network.AllowBindTCP == nil {
		v := false
		cfg.Landlock.Network.AllowBindTCP = &v
	}
	if len(cfg.Landlock.Network.BindPorts) > 0 {
		slog.Warn("landlock.network.bind_ports is set but not yet enforced",
			"bind_ports", cfg.Landlock.Network.BindPorts,
			"note", "port-scoped bind rules are a planned follow-up")
	}
```

If `log/slog` isn't already imported in `config.go`, add it to the import block. (Check by running `grep -n '"log/slog"' internal/config/config.go` — if no output, add the import.)

- [ ] **Step 2.4: Run the tests again**

Run: `go test ./internal/config/ -run TestLandlockNetwork -v`
Expected: PASS (all 4 tests). Also `TestLandlockBindPortsWarning_EmitsWhenSet` passes.

- [ ] **Step 2.5: Run all config tests to ensure no regression**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 2.6: Commit**

```bash
git add internal/config/config.go internal/config/landlock_network_test.go
git commit -m "$(cat <<'EOF'
config(landlock): default allow_connect_tcp=true, allow_bind_tcp=false

applyDefaults now fills nil pointer fields on LandlockNetworkConfig so
downstream code can rely on them being non-nil. Emits a one-time warning
if bind_ports is set (field is reserved pending port-scoped rule support).

No production call-site reads the fields yet; wiring lands in the next
commits.

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 3: Add self-lockout validation in `validateConfig` — TDD

**Files:**
- Modify: `internal/config/landlock_network_test.go` (append tests)
- Modify: `internal/config/config.go` (add check in `validateConfig`)

- [ ] **Step 3.1: Append failing validation tests**

Append to `internal/config/landlock_network_test.go`:

```go
func TestLandlockValidation_ConnectFalseWithProxyEnabled_Errors(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = true
	// Fill required defaults to avoid unrelated validation errors.
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.Error(t, err, "must reject connect_tcp=false while proxy enabled")
	require.Contains(t, err.Error(), "landlock.network.allow_connect_tcp")
	require.Contains(t, err.Error(), "sandbox.network.enabled")
}

func TestLandlockValidation_ConnectFalseWithProxyDisabled_OK(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "connect_tcp=false is fine when proxy is off")
}

func TestLandlockValidation_BindFalseAlwaysOK(t *testing.T) {
	tr := true
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &tr
	cfg.Landlock.Network.AllowBindTCP = &f
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "allow_bind_tcp=false with proxy on is the intended secure case")
}

func TestLandlockValidation_LandlockDisabled_NoLockoutCheck(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = false
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "landlock disabled → no lockout check regardless of values")
}
```

- [ ] **Step 3.2: Run the failing tests**

Run: `go test ./internal/config/ -run TestLandlockValidation -v`
Expected: FAIL — `TestLandlockValidation_ConnectFalseWithProxyEnabled_Errors` fails because validateConfig returns nil.

- [ ] **Step 3.3: Add the validation check in `validateConfig`**

In `internal/config/config.go`, locate `validateConfig` at line 1497. Near the end of the function (before the final `return nil`), add:

```go
	// Landlock network self-lockout check: if the user disables outbound TCP
	// under Landlock but the sandbox proxy is enabled, agents can never reach
	// the proxy (which listens on localhost TCP). Fail fast at startup rather
	// than silently breaking every session with ECONNREFUSED.
	if cfg.Landlock.Enabled &&
		cfg.Landlock.Network.AllowConnectTCP != nil &&
		!*cfg.Landlock.Network.AllowConnectTCP &&
		cfg.Sandbox.Network.Enabled {
		return fmt.Errorf(
			"landlock.network.allow_connect_tcp is false but sandbox.network.enabled " +
				"is true: agent processes cannot reach the agentsh proxy without " +
				"outbound TCP. Either set landlock.network.allow_connect_tcp to true, " +
				"or set sandbox.network.enabled to false")
	}
```

- [ ] **Step 3.4: Run the validation tests**

Run: `go test ./internal/config/ -run TestLandlockValidation -v`
Expected: PASS (all 4 tests).

- [ ] **Step 3.5: Run all config tests**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 3.6: Commit**

```bash
git add internal/config/config.go internal/config/landlock_network_test.go
git commit -m "$(cat <<'EOF'
config(landlock): reject allow_connect_tcp=false while sandbox.network is on

validateConfig now returns a descriptive error if the user disables
outbound TCP under Landlock while the agentsh proxy is active — the
combination silently breaks every session (proxy listens on localhost
TCP). Failing fast at startup is strictly better than opaque mid-session
ECONNREFUSED.

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 4: Wire `internal/api/core.go` (`setupSeccompWrapper`) to read config — TDD

**Files:**
- Create: `internal/api/core_landlock_network_test.go`
- Modify: `internal/api/core.go:243-246`

**Context for the executor:** The hardcoded `AllowNetwork=true; AllowBind=true` live inside `setupSeccompWrapper` (`core.go:108`), not in `execInSessionCore`. The existing test `TestSetupSeccompWrapper_Enabled` at `internal/api/seccomp_wrapper_test.go:125` already exercises this function directly — same pattern applies here. Test helper `newTestAppForSeccomp` lives in `seccomp_wrapper_test.go`.

`capabilities.DetectLandlock()` has no mocking seam. On Linux hosts with a modern kernel (6.x+), it returns `Available: true` naturally. On non-Linux or older kernels, skip the test.

- [ ] **Step 4.1: Write the failing test**

Create `internal/api/core_landlock_network_test.go`:

```go
//go:build linux

package api

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/types"
)

// TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig verifies that the
// seccompWrapperConfig JSON produced by setupSeccompWrapper reflects
// landlock.network.allow_connect_tcp / allow_bind_tcp values rather than
// hardcoded true/true.
func TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_false_bind_false", false, false, false, false},
		{"connect_true_bind_true", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind

			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app := newTestAppForSeccomp(t, cfg)
			req := types.ExecRequest{Command: "/bin/echo", Args: []string{"hi"}}

			result := app.setupSeccompWrapper(req, "test-session", nil)
			if result == nil || result.extraCfg == nil {
				t.Fatal("expected non-nil wrapper setup result with extraCfg")
			}
			defer func() {
				if result.extraCfg.notifyParentSock != nil {
					result.extraCfg.notifyParentSock.Close()
				}
				for _, f := range result.extraCfg.extraFiles {
					if f != nil {
						f.Close()
					}
				}
			}()

			seccompJSON, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
			if !ok {
				t.Fatal("AGENTSH_SECCOMP_CONFIG env var not set")
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(seccompJSON), &parsed); err != nil {
				t.Fatalf("unmarshal seccomp config: %v\n%s", err, seccompJSON)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, seccompJSON)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, seccompJSON)
			}
		})
	}
}
```

- [ ] **Step 4.2: Run the failing test**

Run: `go test ./internal/api/ -run TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig -v`
Expected: FAIL — current code hardcodes `AllowNetwork=true; AllowBind=true` regardless of config. The `connect_true_bind_false`, `connect_false_bind_false` subtests fail.

Edge case: if a subtest's `connect=false` combined with `SerializedConfigs` for `allow_network: true` in the default JSON marshal output, note that `allow_network` has `omitempty` — `false` will be absent from the JSON. The test uses `gotNet, _ := parsed["allow_network"].(bool)` which yields the zero value `false` when the key is absent — that matches the expected `wantNet: false` for those cases.

- [ ] **Step 4.3: Fix `internal/api/core.go:243-246`**

Replace lines 243-246:

```go
			// Allow all network by default — agentsh proxy handles network policy.
			// Without this, Landlock ABI v4+ blocks ALL TCP connections.
			seccompCfg.AllowNetwork = true
			seccompCfg.AllowBind = true
```

with:

```go
			// Honor landlock.network.* config. validateConfig already rejects
			// allow_connect_tcp=false while sandbox.network.enabled=true, so reaching
			// this point with AllowConnectTCP=false implies the operator opted out
			// of proxy TCP. Defaults (connect=true, bind=false) come from applyDefaults.
			if a.cfg.Landlock.Network.AllowConnectTCP != nil {
				seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
			}
			if a.cfg.Landlock.Network.AllowBindTCP != nil {
				seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
			}
```

(Nil-checks are defensive: production configs always go through `applyDefaults`, but tests constructing `Config{}` directly without `applyDefaults` might not.)

- [ ] **Step 4.4: Run the test again**

Run: `go test ./internal/api/ -run TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig -v`
Expected: PASS (all subtests).

- [ ] **Step 4.5: Run the full api test suite**

Run: `go test ./internal/api/...`
Expected: PASS.

- [ ] **Step 4.6: Commit**

```bash
git add internal/api/core.go internal/api/core_landlock_network_test.go
git commit -m "$(cat <<'EOF'
api(core): honor landlock.network.* instead of hardcoding AllowBind=true

Replace the two hardcoded assignments in setupSeccompWrapper's
seccompWrapperConfig construction (core.go:243-246) with reads from
the parsed config. agentsh proxy flows still work by default
(AllowConnectTCP defaults to true); allow_bind_tcp now takes effect
(defaults to false).

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 5: Wire `internal/api/wrap.go` to read config — TDD

**Files:**
- Modify: `internal/api/wrap_test.go` (append test)
- Modify: `internal/api/wrap.go:176-178`

**Context for the executor:** `wrapInitCore` is the existing testable entry point, and its seccomp config JSON is returned on `resp.SeccompConfig` (see `TestWrapInit_SeccompConfigContent` at `wrap_test.go:143` for the template).

- [ ] **Step 5.1: Append failing test to `internal/api/wrap_test.go`**

Add to the imports of `wrap_test.go`: `"encoding/json"` and `"github.com/agentsh/agentsh/internal/capabilities"` (only if not already imported — check first with `grep -n "encoding/json\|capabilities" internal/api/wrap_test.go`).

Then append:

```go
func TestWrapInit_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_true_bind_true", true, true, true, true},
		{"connect_false_bind_false", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind
			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
			cfg.Sandbox.Seccomp.Execve.Enabled = true
			cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app, mgr := newTestAppForWrap(t, cfg)
			s, err := mgr.Create(t.TempDir(), "default")
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
				AgentCommand: "/bin/echo",
			})
			if err != nil {
				t.Fatalf("wrapInitCore: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
				t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, resp.SeccompConfig)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, resp.SeccompConfig)
			}
		})
	}
}
```

- [ ] **Step 5.2: Run the failing test**

Run: `go test ./internal/api/ -run TestWrapInit_LandlockNetwork_HonorsConfig -v`
Expected: FAIL — current wrap.go hardcodes both to true.

- [ ] **Step 5.3: Fix `internal/api/wrap.go:176-178`**

Replace lines 176-178:

```go
			// Allow all network by default — agentsh proxy handles network policy.
			seccompCfg.AllowNetwork = true
			seccompCfg.AllowBind = true
```

with:

```go
			// Honor landlock.network.* config. Defaults (connect=true, bind=false)
			// come from applyDefaults; validateConfig already rejects the
			// allow_connect_tcp=false + sandbox.network.enabled=true combination.
			if a.cfg.Landlock.Network.AllowConnectTCP != nil {
				seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
			}
			if a.cfg.Landlock.Network.AllowBindTCP != nil {
				seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
			}
```

- [ ] **Step 5.4: Run the test**

Run: `go test ./internal/api/ -run TestWrapInit_LandlockNetwork_HonorsConfig -v`
Expected: PASS (all subtests).

- [ ] **Step 5.5: Run all api tests**

Run: `go test ./internal/api/...`
Expected: PASS.

- [ ] **Step 5.6: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_test.go
git commit -m "$(cat <<'EOF'
api(wrap): honor landlock.network.* instead of hardcoding AllowBind=true

Second of two construction sites — wrapInitCore now reads
Landlock.Network.AllowConnectTCP/AllowBindTCP from config instead of
hardcoding both to true.

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 6: Back-compat verification test + cross-platform build check

**Files:**
- Modify: `internal/api/wrap_test.go` or `internal/api/core_landlock_test.go` (append one test)

- [ ] **Step 6.1: Append back-compat test**

Add a single end-to-end test that exercises the full pipeline (YAML → `config.Load` → applyDefaults → validateConfig → wrapInitCore JSON) with a minimal "Landlock enabled, nothing else set" config. `config.Load` is the exported public entry point that both parses YAML and runs `applyDefaults` (see `internal/config/config.go:837`), so no test shim is needed.

Append to `internal/api/wrap_test.go`:

```go
func TestWrapInit_LandlockNetwork_BackCompatDefaults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	// Minimal YAML: Landlock enabled, no network block.
	// Exercises the back-compat promise: omitting landlock.network.* must
	// yield allow_network=true (proxy-compatible) and allow_bind=false
	// (new security default, replacing prior accidental permissive behavior).
	yamlData := []byte(`
landlock:
  enabled: true
sandbox:
  unix_sockets:
    enabled: true
    wrapper_bin: /bin/true
  seccomp:
    execve:
      enabled: true
    unix_socket:
      enabled: true
`)
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, yamlData, 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	// Sanity: applyDefaults ran via config.Load.
	if cfg.Landlock.Network.AllowConnectTCP == nil {
		t.Fatal("applyDefaults should have filled AllowConnectTCP")
	}
	if cfg.Landlock.Network.AllowBindTCP == nil {
		t.Fatal("applyDefaults should have filled AllowBindTCP")
	}

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotNet, _ := parsed["allow_network"].(bool)
	gotBind, _ := parsed["allow_bind"].(bool)
	if !gotNet {
		t.Error("back-compat: allow_network should default to true (proxy needs it)")
	}
	if gotBind {
		t.Error("back-compat: allow_bind should default to false (security hardening vs prior accidental permissive)")
	}
}
```

Ensure the following imports are present in `wrap_test.go` (check with `grep -n` first — only add what's missing): `"os"`, `"path/filepath"`, `"github.com/agentsh/agentsh/internal/capabilities"`, `"github.com/agentsh/agentsh/internal/config"`. `encoding/json` was already added in Task 5.

- [ ] **Step 6.2: Run the back-compat test**

Run: `go test ./internal/api/ -run TestWrapInit_LandlockNetwork_BackCompatDefaults -v`
Expected: PASS.

- [ ] **Step 6.3: Run the FULL test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6.4: Windows cross-compile check (project guideline)**

Run: `GOOS=windows go build ./...`
Expected: exits 0.

- [ ] **Step 6.5: Also verify darwin cross-compile**

Run: `GOOS=darwin go build ./...`
Expected: exits 0.

- [ ] **Step 6.6: Commit**

```bash
git add internal/api/wrap_test.go
git commit -m "$(cat <<'EOF'
test(landlock): back-compat check for default network policy

End-to-end test documenting that a minimal Landlock-enabled config with
no network block emits AllowNetwork=true (proxy-compatible) and
AllowBind=false (new security default, replacing prior accidental
permissive behavior).

Spec: docs/superpowers/specs/2026-04-15-landlock-network-config-design.md
EOF
)"
```

---

## Task 7: Final verification + push

- [ ] **Step 7.1: Review the full diff**

Run: `git log --oneline main..HEAD`
Expected: 6 commits, one per task above.

Run: `git diff main..HEAD --stat`
Sanity-check that only the expected files changed.

- [ ] **Step 7.2: Run tests one more time end-to-end**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 7.3: Cross-compile all target platforms**

Run in parallel:
```bash
GOOS=windows go build ./... && GOOS=darwin go build ./... && go build ./...
```
Expected: all exit 0.

- [ ] **Step 7.4: Push to origin**

Run: `git push`
Expected: push succeeds to `main` (or to a feature branch if working on one — follow whatever branch strategy the user confirmed).

---

## Self-Review Checklist

Run through this BEFORE handing off the plan.

**Spec coverage — every spec section maps to at least one task:**

| Spec section                                       | Task(s)          |
|----------------------------------------------------|------------------|
| Config schema change (`*bool`)                     | Task 1           |
| Defaults (connect=true, bind=false)                | Task 2           |
| Validation (lockout check)                         | Task 3           |
| `bind_ports` warning                               | Task 2           |
| Consumer update `api/core.go`                      | Task 4           |
| Consumer update `api/wrap.go`                      | Task 5           |
| Wrapper (`cmd/agentsh-unixwrap`) unchanged         | no task needed   |
| Unit tests (defaults, validation, warning)         | Tasks 2, 3       |
| Integration tests (core, wrap construction sites)  | Tasks 4, 5       |
| Back-compat test                                   | Task 6           |
| Non-Linux stubs unaffected                         | Task 6 (cross-compile) |
| Changelog entry                                    | **Not a code change** — listed in spec's "Rollout" section for PR description; no task needed. |

**Placeholder scan:** No TBDs, no TODO placeholders, no "similar to Task N" references. Each test uses concrete, executable code. Task 4 Step 4.2 has an informational note about `omitempty` JSON behavior — that's explanation, not a placeholder.

**Type consistency:** `AllowConnectTCP` / `AllowBindTCP` (pointer `*bool` in config) vs. `AllowNetwork` / `AllowBind` (plain `bool` on the wrapper JSON struct) — names differ by design. The consumer sites (`core.go`, `wrap.go`) dereference in one step. Consistent across all task snippets.

**Commit messages:** Each references the spec path (`docs/superpowers/specs/2026-04-15-landlock-network-config-design.md`) and names the concrete change. No "misc" commits.
