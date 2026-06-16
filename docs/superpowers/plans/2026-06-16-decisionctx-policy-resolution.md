# Decision-Context Policy Resolution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AgentSH report a `DecisionContext` (hostname, config tags, source-labeled user — OS or Tailscale) to Watchtower on `SessionInit`, so Watchtower can resolve and push the bound policy through the install path that already exists.

**Architecture:** Approach A (agent/process-level). Add a `DecisionContext` message to `wtp-protos` and carry it on `SessionInit`/`SessionUpdate`. On the agent, a new `internal/decisionctx` package resolves the context from pluggable sources; `buildWatchtowerStore` threads it through `watchtower.Options` → `transport.Options` → `sessionInit()`. Policy verification, install (write signed YAML to `policies.dir` + reload/swap), on-disk persistence (= last-known-good), and re-resolution (`PolicyPush`) are all **reused unchanged**.

**Tech Stack:** Go, buf (proto codegen), gRPC bidi stream (WTP), ed25519 policy signing, tailscaled local API over a unix socket.

**Spec:** `docs/superpowers/specs/2026-06-16-identity-context-policy-request-design.md`

---

## File Structure

**`wtp-protos` repo (`/home/eran/work/wtp-protos`):**
- Modify: `proto/canyonroad/wtp/v1/wtp.proto` — add `UserSource` enum, `DecisionContext` message, `SessionInit.decision_context` (field 12), `SessionUpdate.decision_context` (field 5).
- Create: `buf.gen.go-only.yaml` — Go-only codegen template (avoids the Rust toolchain during dev).
- Regenerated: `gen/go/canyonroad/wtp/v1/wtp.pb.go`.

**agentsh repo (`/home/eran/work/agentsh`):**
- Modify: `go.mod` — temporary `replace` → local `wtp-protos/gen/go`.
- Create: `internal/decisionctx/decisionctx.go` — `User`, `DecisionContext`, `Source`, `Resolver`, `Config`, `NewResolver`.
- Create: `internal/decisionctx/sources.go` — hostname / tags / osuser sources.
- Create: `internal/decisionctx/tailscale.go` — tailscale source + `tailscaleStatusFunc` + `parseTailscaleStatus`.
- Create: `internal/decisionctx/tailscale_linux.go` — real local-API socket client (`//go:build linux`).
- Create: `internal/decisionctx/tailscale_other.go` — stub (`//go:build !linux`).
- Create tests: `internal/decisionctx/decisionctx_test.go`, `tailscale_test.go`.
- Modify: `internal/config/config.go` — `WatchtowerDecisionContextConfig` + field on `AuditWatchtowerConfig`.
- Modify: `internal/store/watchtower/transport/transport.go` — `Options.DecisionContext` + set it in `sessionInit()`.
- Modify: `internal/store/watchtower/options.go` — `Options.DecisionContext`.
- Modify: `internal/store/watchtower/store.go` — forward `DecisionContext` into `transport.New`.
- Modify: `internal/server/wtp.go` — build `DecisionContext` from config + resolver, `toWireDecisionContext`, set on `watchtower.Options`, `slog` the result.
- Modify: `internal/store/watchtower/testserver/assertions.go` — `AssertDecisionContext` helper.
- Create: `internal/server/wtp_decisionctx_test.go` — integration test.

---

## Task 0: Proto change + dev `replace`

**Files:**
- Modify: `/home/eran/work/wtp-protos/proto/canyonroad/wtp/v1/wtp.proto`
- Create: `/home/eran/work/wtp-protos/buf.gen.go-only.yaml`
- Modify: `/home/eran/work/agentsh/go.mod`

- [ ] **Step 1: Add the proto messages/fields**

In `/home/eran/work/wtp-protos/proto/canyonroad/wtp/v1/wtp.proto`, add this block immediately after the `HashAlgorithm` enum:

```protobuf
// Decision context reported by the agent so the server can resolve the
// bound policy from identity + environment signals. All fields optional;
// the agent sends what it has. `extra` is an open extension so new
// signals do not require a schema bump.
message DecisionContext {
  string hostname = 1;
  repeated string tags = 2;
  message User {
    string value = 1;
    UserSource source = 2;
  }
  User user = 3;
  map<string, string> extra = 4;
}

enum UserSource {
  USER_SOURCE_UNSPECIFIED = 0;
  USER_SOURCE_OS          = 1;
  USER_SOURCE_TAILSCALE   = 2;
}
```

Add field 12 to `SessionInit` (after `total_chained = 11;`):

```protobuf
  DecisionContext decision_context = 12;  // agent-reported identity/env context
```

Add field 5 to `SessionUpdate` (after `boundary_sequence = 4;`):

```protobuf
  DecisionContext decision_context = 5;   // updated context for mid-session re-resolution
```

- [ ] **Step 2: Add a Go-only codegen template**

Create `/home/eran/work/wtp-protos/buf.gen.go-only.yaml` (avoids needing the Rust/cargo plugins during dev):

```yaml
version: v2
plugins:
  - local: protoc-gen-go
    out: gen/go
    opt: paths=source_relative
  - local: protoc-gen-go-grpc
    out: gen/go
    opt: paths=source_relative
```

- [ ] **Step 3: Lint + regenerate Go bindings**

Run:
```bash
cd /home/eran/work/wtp-protos && buf lint && buf generate --template buf.gen.go-only.yaml
```
Expected: no lint errors; exit 0.

- [ ] **Step 4: Verify the new type exists in generated Go**

Run:
```bash
grep -n "type DecisionContext struct\|UserSource_USER_SOURCE_TAILSCALE\|GetDecisionContext" \
  /home/eran/work/wtp-protos/gen/go/canyonroad/wtp/v1/wtp.pb.go | head
```
Expected: matches for `type DecisionContext struct`, the enum constant, and `func (x *SessionInit) GetDecisionContext()`.

- [ ] **Step 5: Commit in wtp-protos**

```bash
cd /home/eran/work/wtp-protos
git add proto/canyonroad/wtp/v1/wtp.proto buf.gen.go-only.yaml gen/go
git commit -m "feat: add DecisionContext to SessionInit/SessionUpdate"
```

- [ ] **Step 6: Wire the dev `replace` in agentsh and tidy**

Run:
```bash
cd /home/eran/work/agentsh
go mod edit -replace github.com/canyonroad/wtp-protos/gen/go=/home/eran/work/wtp-protos/gen/go
go mod tidy
go build ./... 2>&1 | tail -5
```
Expected: builds cleanly (the new type is now resolvable).

- [ ] **Step 7: Commit the replace**

```bash
cd /home/eran/work/agentsh
git add go.mod go.sum
git commit -m "build: dev replace for local wtp-protos with DecisionContext (drop on v0.2.0 release)"
```

---

## Task 1: `decisionctx` core types + hostname/tags/osuser sources

**Files:**
- Create: `internal/decisionctx/decisionctx.go`
- Create: `internal/decisionctx/sources.go`
- Test: `internal/decisionctx/decisionctx_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/decisionctx/decisionctx_test.go`:

```go
package decisionctx

import (
	"context"
	"testing"
)

func TestResolver_HostnameTagsOSUser(t *testing.T) {
	r := &Resolver{sources: []Source{
		staticHostname("host-1"),
		newTagsSource([]string{"b", "a"}),
		staticOSUser("alice"),
	}}
	dc, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dc.Hostname != "host-1" {
		t.Errorf("hostname = %q, want host-1", dc.Hostname)
	}
	if len(dc.Tags) != 2 || dc.Tags[0] != "a" || dc.Tags[1] != "b" {
		t.Errorf("tags = %v, want sorted [a b]", dc.Tags)
	}
	if dc.User.Value != "alice" || dc.User.Source != SourceOS {
		t.Errorf("user = %+v, want {alice os}", dc.User)
	}
}

// staticHostname/staticOSUser are test-only sources defined here.
type staticHostname string

func (s staticHostname) Name() string { return "hostname" }
func (s staticHostname) Resolve(_ context.Context, into *DecisionContext) error {
	into.Hostname = string(s)
	return nil
}

type staticOSUser string

func (s staticOSUser) Name() string { return "os-user" }
func (s staticOSUser) Resolve(_ context.Context, into *DecisionContext) error {
	into.User = User{Value: string(s), Source: SourceOS}
	return nil
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/decisionctx/ -run TestResolver_HostnameTagsOSUser -v`
Expected: compile failure (`undefined: Resolver`, `Source`, `DecisionContext`, `User`, `SourceOS`, `newTagsSource`).

- [ ] **Step 3: Implement core types + Resolver**

Create `internal/decisionctx/decisionctx.go`:

```go
// Package decisionctx resolves a process-level "decision context"
// (identity + environment signals) that AgentSH reports to Watchtower so
// the server can resolve the bound policy. It has no dependency on the
// WTP proto types; conversion to the wire shape happens in the caller.
package decisionctx

import "context"

// Source labels for User.Source.
const (
	SourceOS        = "os"
	SourceTailscale = "tailscale"
)

// User is the identity slot. Source records which signal produced Value
// so the server can weigh trust (tailscale is stronger than os).
type User struct {
	Value  string
	Source string
}

// DecisionContext is the bundle reported to Watchtower. Fields are
// optional; the agent sends what it has.
type DecisionContext struct {
	Hostname string
	Tags     []string
	User     User
	Extra    map[string]string
}

// Source contributes one or more fields into a DecisionContext. A Source
// that cannot resolve its field returns nil and leaves the field unset —
// resolution must never fail because one signal is unavailable.
type Source interface {
	Name() string
	Resolve(ctx context.Context, into *DecisionContext) error
}

// Resolver runs its sources in order, later sources overriding earlier
// ones (e.g. tailscale overrides os-user in the User slot).
type Resolver struct {
	sources []Source
}

// Resolve runs every source. A source error is swallowed (logged by the
// caller via the returned context being partial); Resolve only returns an
// error for a truly fatal condition, of which there are currently none.
func (r *Resolver) Resolve(ctx context.Context) (DecisionContext, error) {
	dc := DecisionContext{}
	for _, s := range r.sources {
		_ = s.Resolve(ctx, &dc) // partial context on error; never fatal
	}
	return dc, nil
}

// Config drives NewResolver.
type Config struct {
	Tags             []string
	Extra            map[string]string
	TailscaleEnabled bool
	TailscaleSocket  string // "" => platform default
}
```

- [ ] **Step 4: Implement hostname/tags/osuser sources**

Create `internal/decisionctx/sources.go`:

```go
package decisionctx

import (
	"context"
	"os"
	"os/user"
	"sort"
)

// hostnameSource sets Hostname from os.Hostname().
type hostnameSource struct{}

func (hostnameSource) Name() string { return "hostname" }
func (hostnameSource) Resolve(_ context.Context, into *DecisionContext) error {
	h, err := os.Hostname()
	if err != nil {
		return err // swallowed by Resolver; Hostname stays ""
	}
	into.Hostname = h
	return nil
}

// tagsSource sets a sorted copy of the configured tags.
type tagsSource struct{ tags []string }

func newTagsSource(tags []string) tagsSource {
	cp := append([]string(nil), tags...)
	sort.Strings(cp)
	return tagsSource{tags: cp}
}
func (tagsSource) Name() string { return "config-tags" }
func (s tagsSource) Resolve(_ context.Context, into *DecisionContext) error {
	if len(s.tags) > 0 {
		into.Tags = append([]string(nil), s.tags...)
	}
	return nil
}

// osUserSource fills the User slot from os/user.Current().
type osUserSource struct{}

func (osUserSource) Name() string { return "os-user" }
func (osUserSource) Resolve(_ context.Context, into *DecisionContext) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	into.User = User{Value: u.Username, Source: SourceOS}
	return nil
}

// extraSource copies static config extras.
type extraSource struct{ extra map[string]string }

func (extraSource) Name() string { return "extra" }
func (s extraSource) Resolve(_ context.Context, into *DecisionContext) error {
	if len(s.extra) > 0 {
		into.Extra = map[string]string{}
		for k, v := range s.extra {
			into.Extra[k] = v
		}
	}
	return nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/decisionctx/ -run TestResolver_HostnameTagsOSUser -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/decisionctx/decisionctx.go internal/decisionctx/sources.go internal/decisionctx/decisionctx_test.go
git commit -m "feat(decisionctx): core types + hostname/tags/osuser sources"
```

---

## Task 2: Tailscale source (override + platform-guarded local API)

**Files:**
- Create: `internal/decisionctx/tailscale.go`
- Create: `internal/decisionctx/tailscale_linux.go`
- Create: `internal/decisionctx/tailscale_other.go`
- Test: `internal/decisionctx/tailscale_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/decisionctx/tailscale_test.go`:

```go
package decisionctx

import (
	"context"
	"errors"
	"testing"
)

func TestTailscaleSource_OverridesOSUser(t *testing.T) {
	fake := func(_ context.Context, _ string) (string, bool, error) {
		return "eran@example.com", true, nil
	}
	dc := DecisionContext{User: User{Value: "alice", Source: SourceOS}}
	src := newTailscaleSource("", fake)
	if err := src.Resolve(context.Background(), &dc); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dc.User.Value != "eran@example.com" || dc.User.Source != SourceTailscale {
		t.Errorf("user = %+v, want {eran@example.com tailscale}", dc.User)
	}
}

func TestTailscaleSource_AbsentLeavesOSUser(t *testing.T) {
	fake := func(_ context.Context, _ string) (string, bool, error) {
		return "", false, errors.New("dial: no such file")
	}
	dc := DecisionContext{User: User{Value: "alice", Source: SourceOS}}
	src := newTailscaleSource("", fake)
	if err := src.Resolve(context.Background(), &dc); err != nil {
		t.Fatalf("Resolve should swallow unavailability: %v", err)
	}
	if dc.User.Value != "alice" || dc.User.Source != SourceOS {
		t.Errorf("user = %+v, want unchanged {alice os}", dc.User)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	js := []byte(`{"Self":{"UserID":12345},"User":{"12345":{"LoginName":"eran@example.com"}}}`)
	login, ok := parseTailscaleStatus(js)
	if !ok || login != "eran@example.com" {
		t.Fatalf("parseTailscaleStatus = %q,%v want eran@example.com,true", login, ok)
	}
	if _, ok := parseTailscaleStatus([]byte(`{"Self":null}`)); ok {
		t.Errorf("expected ok=false when Self is null")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/decisionctx/ -run 'Tailscale|ParseTailscale' -v`
Expected: compile failure (`undefined: newTailscaleSource`, `parseTailscaleStatus`).

- [ ] **Step 3: Implement the source, the status func type, and the parser**

Create `internal/decisionctx/tailscale.go`:

```go
package decisionctx

import (
	"context"
	"encoding/json"
	"strconv"
)

// tailscaleStatusFunc returns the local node's login name from tailscaled.
// available=false means tailscaled is not running / not reachable; that is
// not an error condition for resolution.
type tailscaleStatusFunc func(ctx context.Context, socket string) (login string, available bool, err error)

// tailscaleSource overrides the User slot with the local Tailscale
// identity when tailscaled is up.
type tailscaleSource struct {
	socket string
	status tailscaleStatusFunc
}

func newTailscaleSource(socket string, status tailscaleStatusFunc) tailscaleSource {
	return tailscaleSource{socket: socket, status: status}
}

func (tailscaleSource) Name() string { return "tailscale" }

func (s tailscaleSource) Resolve(ctx context.Context, into *DecisionContext) error {
	login, ok, _ := s.status(ctx, s.socket) // unavailability is not fatal
	if ok && login != "" {
		into.User = User{Value: login, Source: SourceTailscale}
	}
	return nil
}

// parseTailscaleStatus extracts the local node login from a tailscaled
// /localapi/v0/status JSON body. Platform-neutral so it is testable
// everywhere.
func parseTailscaleStatus(body []byte) (string, bool) {
	var st struct {
		Self *struct {
			UserID int64 `json:"UserID"`
		} `json:"Self"`
		User map[string]struct {
			LoginName string `json:"LoginName"`
		} `json:"User"`
	}
	if err := json.Unmarshal(body, &st); err != nil || st.Self == nil {
		return "", false
	}
	u, ok := st.User[strconv.FormatInt(st.Self.UserID, 10)]
	if !ok || u.LoginName == "" {
		return "", false
	}
	return u.LoginName, true
}
```

- [ ] **Step 4: Implement the platform default status funcs**

Create `internal/decisionctx/tailscale_linux.go`:

```go
//go:build linux

package decisionctx

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

const defaultTailscaleSocket = "/run/tailscale/tailscaled.sock"

// defaultTailscaleStatus queries the tailscaled local API over its unix
// socket. Avoids depending on the heavy tailscale.com module.
func defaultTailscaleStatus(ctx context.Context, socket string) (string, bool, error) {
	if socket == "" {
		socket = defaultTailscaleSocket
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
	// Host is ignored by the unix dialer but required to form a valid URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err // tailscaled not running => unavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", false, err
	}
	login, ok := parseTailscaleStatus(body)
	return login, ok, nil
}
```

Create `internal/decisionctx/tailscale_other.go`:

```go
//go:build !linux

package decisionctx

import "context"

const defaultTailscaleSocket = ""

// defaultTailscaleStatus is a stub on non-Linux platforms: the local-API
// socket transport is Linux-only for v1, so Tailscale identity is reported
// as unavailable and the OS user is used.
func defaultTailscaleStatus(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/decisionctx/ -run 'Tailscale|ParseTailscale' -v`
Expected: PASS (all three).

- [ ] **Step 6: Commit**

```bash
git add internal/decisionctx/tailscale.go internal/decisionctx/tailscale_linux.go internal/decisionctx/tailscale_other.go internal/decisionctx/tailscale_test.go
git commit -m "feat(decisionctx): tailscale source via local-API socket (platform-guarded)"
```

---

## Task 3: `NewResolver` wiring constructor

**Files:**
- Modify: `internal/decisionctx/decisionctx.go`
- Test: `internal/decisionctx/decisionctx_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/decisionctx/decisionctx_test.go`:

```go
func TestNewResolver_IncludesTailscaleWhenEnabled(t *testing.T) {
	r := NewResolver(Config{Tags: []string{"x"}, TailscaleEnabled: true})
	if !hasSource(r, "tailscale") {
		t.Errorf("tailscale source missing when enabled")
	}
	r2 := NewResolver(Config{TailscaleEnabled: false})
	if hasSource(r2, "tailscale") {
		t.Errorf("tailscale source present when disabled")
	}
}

func hasSource(r *Resolver, name string) bool {
	for _, s := range r.sources {
		if s.Name() == name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/decisionctx/ -run TestNewResolver -v`
Expected: FAIL (`undefined: NewResolver`).

- [ ] **Step 3: Implement `NewResolver`**

Append to `internal/decisionctx/decisionctx.go`:

```go
// NewResolver builds the default source chain. Order matters: os-user
// writes the User slot, then tailscale overrides it when enabled+up.
func NewResolver(c Config) *Resolver {
	srcs := []Source{
		hostnameSource{},
		newTagsSource(c.Tags),
		osUserSource{},
		extraSource{extra: c.Extra},
	}
	if c.TailscaleEnabled {
		srcs = append(srcs, newTailscaleSource(c.TailscaleSocket, defaultTailscaleStatus))
	}
	return &Resolver{sources: srcs}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/decisionctx/ -v`
Expected: PASS (all tests in the package).

- [ ] **Step 5: Commit**

```bash
git add internal/decisionctx/decisionctx.go internal/decisionctx/decisionctx_test.go
git commit -m "feat(decisionctx): NewResolver default source chain"
```

---

## Task 4: Config — `decision_context` block

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (add a focused test; file already exists)

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (ensure `os` and `path/filepath` are imported):

```go
func TestAuditWatchtowerConfig_DecisionContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yml := `
audit:
  watchtower:
    enabled: true
    endpoint: "wt:443"
    decision_context:
      tags: ["team-a", "prod"]
      tailscale:
        enabled: true
      extra:
        region: "us-east"
`
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path) // Load takes a file path, not bytes
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dc := cfg.Audit.Watchtower.DecisionContext
	if len(dc.Tags) != 2 || dc.Tags[0] != "team-a" {
		t.Errorf("tags = %v", dc.Tags)
	}
	if dc.Tailscale.Enabled == nil || !*dc.Tailscale.Enabled {
		t.Errorf("tailscale.enabled not parsed")
	}
	if dc.Extra["region"] != "us-east" {
		t.Errorf("extra = %v", dc.Extra)
	}
}
```

> If `Load` rejects this minimal doc on a missing required field, add only the minimal fields it demands; keep the assertions above.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestAuditWatchtowerConfig_DecisionContext -v`
Expected: FAIL (`DecisionContext` field undefined).

- [ ] **Step 3: Add the config structs**

In `internal/config/config.go`, add the field to `AuditWatchtowerConfig` (after the `Filter` field):

```go
	// DecisionContext is reported to Watchtower on SessionInit so the
	// server can resolve the bound policy from identity + environment.
	DecisionContext WatchtowerDecisionContextConfig `yaml:"decision_context"`
```

And add these types near the other `Watchtower*Config` structs:

```go
type WatchtowerDecisionContextConfig struct {
	Tags      []string                  `yaml:"tags"`
	Tailscale WatchtowerTailscaleConfig `yaml:"tailscale"`
	Extra     map[string]string         `yaml:"extra"`
}

type WatchtowerTailscaleConfig struct {
	// Enabled is tri-state: nil => default (resolved at store construction:
	// enabled, but the source self-disables when the socket is absent),
	// false => never query tailscaled, true => always attempt.
	Enabled *bool  `yaml:"enabled"`
	Socket  string `yaml:"socket"` // optional tailscaled socket path override
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestAuditWatchtowerConfig_DecisionContext -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): audit.watchtower.decision_context block"
```

---

## Task 5: Carry `DecisionContext` on the wire (transport + store options)

**Files:**
- Modify: `internal/store/watchtower/transport/transport.go`
- Modify: `internal/store/watchtower/options.go`
- Modify: `internal/store/watchtower/store.go`
- Test: `internal/store/watchtower/transport/decisioncontext_internal_test.go` (new **internal** test file — `package transport` — required to reach the unexported `sessionInit()`)

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/transport/decisioncontext_internal_test.go` as an **internal** test (`package transport`, like the existing `state_live_internal_test.go`) so it can call the unexported `sessionInit()`:

```go
package transport

import (
	"testing"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestSessionInit_CarriesDecisionContext(t *testing.T) {
	dc := &wtpv1.DecisionContext{
		Hostname: "host-1",
		Tags:     []string{"a"},
		User:     &wtpv1.DecisionContext_User{Value: "eran@x", Source: wtpv1.UserSource_USER_SOURCE_TAILSCALE},
	}
	// sessionInit() reads only opts and persistedAck; persistedAck's zero
	// value (seq 0, gen 0) is fine here.
	tr := &Transport{opts: Options{
		AgentID:         "agent-1",
		SessionID:       "sess-1",
		DecisionContext: dc,
	}}
	msg := tr.sessionInit()
	got := msg.GetSessionInit().GetDecisionContext()
	if got.GetHostname() != "host-1" || got.GetUser().GetValue() != "eran@x" {
		t.Fatalf("decision_context not set on SessionInit: %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/ -run TestSessionInit_CarriesDecisionContext -v`
Expected: FAIL (`Options has no field DecisionContext`).

- [ ] **Step 3: Add the transport option + set it in `sessionInit()`**

In `internal/store/watchtower/transport/transport.go`, add to the `Options` struct (right after the `ContextDigest` field, ~line 185):

```go
	// DecisionContext, when non-nil, is reported on SessionInit so the
	// server can resolve the bound policy. Owned by the agent's
	// decisionctx resolver; nil is permitted (field omitted).
	DecisionContext *wtpv1.DecisionContext
```

In `sessionInit()`, add the field to the `&wtpv1.SessionInit{...}` literal (after `TotalChained:`):

```go
				DecisionContext:     t.opts.DecisionContext,
```

- [ ] **Step 4: Add the store option + forward it**

In `internal/store/watchtower/options.go`, add to `Options` (near `AgentID`/`SessionID`):

```go
	// DecisionContext is forwarded to transport.Options.DecisionContext.
	DecisionContext *wtpv1.DecisionContext
```

Ensure the file imports `wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"` (add if missing).

In `internal/store/watchtower/store.go`, in the `transport.New(transport.Options{...})` literal (where `ContextDigest: ctxDigest,` is set, ~line 418), add:

```go
		DecisionContext:         opts.DecisionContext,
```

- [ ] **Step 5: Run the test + package build**

Run: `go test ./internal/store/watchtower/... -run TestSessionInit_CarriesDecisionContext -v && go build ./internal/store/...`
Expected: PASS and clean build.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/transport.go internal/store/watchtower/options.go internal/store/watchtower/store.go internal/store/watchtower/transport/decisioncontext_internal_test.go
git commit -m "feat(watchtower): carry DecisionContext on SessionInit"
```

---

## Task 6: Build + inject the context in `buildWatchtowerStore`

**Files:**
- Modify: `internal/server/wtp.go`
- Test: `internal/server/wtp_decisionctx_test.go` (create)

- [ ] **Step 1: Write the failing test (converter unit)**

Create `internal/server/wtp_decisionctx_test.go`:

```go
package server

import (
	"testing"

	"github.com/agentsh/agentsh/internal/decisionctx"
	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestToWireDecisionContext(t *testing.T) {
	in := decisionctx.DecisionContext{
		Hostname: "h",
		Tags:     []string{"a", "b"},
		User:     decisionctx.User{Value: "eran@x", Source: decisionctx.SourceTailscale},
		Extra:    map[string]string{"region": "us"},
	}
	got := toWireDecisionContext(in)
	if got.GetHostname() != "h" || len(got.GetTags()) != 2 {
		t.Fatalf("hostname/tags wrong: %+v", got)
	}
	if got.GetUser().GetSource() != wtpv1.UserSource_USER_SOURCE_TAILSCALE {
		t.Errorf("source = %v, want TAILSCALE", got.GetUser().GetSource())
	}
	if got.GetExtra()["region"] != "us" {
		t.Errorf("extra not copied")
	}
}
```

> Note: confirm the package name of `internal/server/wtp.go` (it declares `package <name>` at the top — use that, likely `server`). Adjust the test's `package` line to match.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestToWireDecisionContext -v`
Expected: FAIL (`undefined: toWireDecisionContext`).

- [ ] **Step 3: Implement the converter and wire it into `buildWatchtowerStore`**

In `internal/server/wtp.go`, add the converter:

```go
func toWireDecisionContext(dc decisionctx.DecisionContext) *wtpv1.DecisionContext {
	src := wtpv1.UserSource_USER_SOURCE_UNSPECIFIED
	switch dc.User.Source {
	case decisionctx.SourceOS:
		src = wtpv1.UserSource_USER_SOURCE_OS
	case decisionctx.SourceTailscale:
		src = wtpv1.UserSource_USER_SOURCE_TAILSCALE
	}
	out := &wtpv1.DecisionContext{
		Hostname: dc.Hostname,
		Tags:     dc.Tags,
		Extra:    dc.Extra,
	}
	if dc.User.Value != "" || src != wtpv1.UserSource_USER_SOURCE_UNSPECIFIED {
		out.User = &wtpv1.DecisionContext_User{Value: dc.User.Value, Source: src}
	}
	return out
}
```

In `buildWatchtowerStore`, after `agentID := resolveAgentID(cfg)` and before assembling `opts := watchtower.Options{...}`, resolve the context:

```go
	tsEnabled := true
	if cfg.DecisionContext.Tailscale.Enabled != nil {
		tsEnabled = *cfg.DecisionContext.Tailscale.Enabled
	}
	resolver := decisionctx.NewResolver(decisionctx.Config{
		Tags:             cfg.DecisionContext.Tags,
		Extra:            cfg.DecisionContext.Extra,
		TailscaleEnabled: tsEnabled,
		TailscaleSocket:  cfg.DecisionContext.Tailscale.Socket,
	})
	dc, _ := resolver.Resolve(ctx)
	slog.Info("watchtower: resolved decision context",
		"hostname", dc.Hostname,
		"tag_count", len(dc.Tags),
		"user_source", dc.User.Source)
	wireDC := toWireDecisionContext(dc)
```

Add `DecisionContext: wireDC,` to the `watchtower.Options{...}` literal. Ensure imports include `"github.com/agentsh/agentsh/internal/decisionctx"` and the `wtpv1` alias.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/server/ -run TestToWireDecisionContext -v && go build ./internal/server/`
Expected: PASS and clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/server/wtp.go internal/server/wtp_decisionctx_test.go
git commit -m "feat(server): resolve + report DecisionContext on watchtower store build"
```

---

## Task 7: Integration — testserver captures the context; install path unchanged

**Files:**
- Modify: `internal/store/watchtower/testserver/assertions.go`
- Test: `internal/store/watchtower/testserver/assertions_test.go` or a new integration test in the same package

- [ ] **Step 1: Write the failing test**

Add to a test in `internal/store/watchtower/testserver` (e.g. `decisioncontext_test.go`):

```go
package testserver

import (
	"testing"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestAssertDecisionContext(t *testing.T) {
	init := &wtpv1.SessionInit{
		DecisionContext: &wtpv1.DecisionContext{
			Hostname: "h", User: &wtpv1.DecisionContext_User{Value: "eran@x"},
		},
	}
	if err := AssertDecisionContext(init, "h", "eran@x"); err != nil {
		t.Fatalf("AssertDecisionContext: %v", err)
	}
	if AssertDecisionContext(init, "other", "eran@x") == nil {
		t.Errorf("expected mismatch error on hostname")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/testserver/ -run TestAssertDecisionContext -v`
Expected: FAIL (`undefined: AssertDecisionContext`).

- [ ] **Step 3: Implement the assertion helper**

Add to `internal/store/watchtower/testserver/assertions.go`:

```go
// AssertDecisionContext verifies the SessionInit carried the expected
// hostname and user value. Pass "" to skip a field.
func AssertDecisionContext(init *wtpv1.SessionInit, wantHostname, wantUser string) error {
	dc := init.GetDecisionContext()
	if dc == nil {
		return fmt.Errorf("SessionInit.decision_context is nil")
	}
	if wantHostname != "" && dc.GetHostname() != wantHostname {
		return fmt.Errorf("hostname = %q, want %q", dc.GetHostname(), wantHostname)
	}
	if wantUser != "" && dc.GetUser().GetValue() != wantUser {
		return fmt.Errorf("user = %q, want %q", dc.GetUser().GetValue(), wantUser)
	}
	return nil
}
```

Ensure `fmt` and the `wtpv1` alias are imported in `assertions.go`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/store/watchtower/testserver/ -run TestAssertDecisionContext -v`
Expected: PASS.

- [ ] **Step 5: End-to-end check via the existing store→testserver harness**

Add an integration test that builds a `watchtower.Store` with a non-nil `DecisionContext`, points it at the testserver, drives a `SessionInit`, and asserts the server's captured `firstSessionInit` via `AssertDecisionContext`. Reuse the existing store/testserver wiring used by `internal/store/watchtower/*_test.go` (grep for the existing pattern that constructs the testserver + a store and waits for SessionInit). Assert the captured init carries the context.

Run: `go test ./internal/store/watchtower/... -run DecisionContext -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/testserver/
git commit -m "test(watchtower): assert DecisionContext arrives on SessionInit"
```

---

## Task 8: Cross-cutting gates

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `go test ./...`
Expected: PASS (catches the OCSF exhaustiveness test and any package-wide regressions). If a pre-existing flake appears (see project memory), re-run that package once to confirm it is not a regression.

- [ ] **Step 2: Windows cross-compile**

Run: `GOOS=windows go build ./...`
Expected: clean build (the tailscale source compiles via `tailscale_other.go`; the Linux socket client is excluded by build tag).

- [ ] **Step 3: Commit (if any fixups were needed)**

```bash
git add -A
git commit -m "chore: cross-platform + full-suite fixups for decisionctx"
```

---

## Post-implementation (out of band, not blocking this branch)

- In `wtp-protos`: run full `make gen` (Go + Rust), tag `gen/go/v0.2.0`, push.
- In agentsh: `go get github.com/canyonroad/wtp-protos/gen/go@v0.2.0`, then `go mod edit -dropreplace github.com/canyonroad/wtp-protos/gen/go`, `go mod tidy`, re-run `go test ./...`. Commit "build: consume wtp-protos v0.2.0, drop dev replace".
- Watchtower **server** repo: implement DecisionContext → policy resolution (binding by hostname/tags/user). Out of scope for this plan.
- Phase-2 (agentsh): emit `SessionUpdate{decision_context}` on local context change (Tailscale up/down watcher) for mid-session re-resolution.
