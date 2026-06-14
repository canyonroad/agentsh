# Tor Access Control (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deny-by-default `tor:` policy block that blocks (or audits) a sandboxed agent's use of Tor across five vectors — client processes, local SOCKS/control ports, `.onion` DNS, `.onion` HTTP, and Tor relay IPs — emitting a uniform `tor_control` audit event per hit.

**Architecture:** A coordinating `tor.Policy` object (new `internal/tor` package) resolves the `tor:` config once and answers three questions for the existing decision points: `EvalExecve`, `EvalConnect`, `EvalOnionName`. The policy engine consults it (via a `policy.TorChecker` interface, mirroring the existing `ThreatChecker`) at the top of `CheckExecve`, `CheckNetworkCtx`, and `CheckNetworkIP`: a `deny` verdict short-circuits and overrides user `allow` rules; an `audit` verdict attaches metadata and falls through to normal policy (never loosening a user `deny`). Relay-IP membership uses a new reusable `internal/ipset` primitive seeded with the hardcoded Tor directory authorities and optionally refreshed from onionoo. Each enforcement site emits a `tor_control` event when the returned decision carries Tor metadata.

**Tech Stack:** Go; `github.com/gobwas/glob` (already used for matchers); existing `seccomp`/`ptrace`/`netmonitor`/`policy`/`threatfeed` patterns. No new third-party dependencies.

---

## File Structure

**New:**
- `internal/ipset/ipset.go` — IPv4/IPv6 + CIDR membership set (reusable primitive).
- `internal/ipset/ipset_test.go`
- `internal/config/tor.go` — `TorConfig` struct + `ResolveTorConfig` defaults resolution.
- `internal/config/tor_test.go`
- `internal/tor/seed.go` — hardcoded Tor directory-authority / fallback-dir IPs.
- `internal/tor/policy.go` — `Policy`, `Verdict`, `Mode`, the three `Eval*` methods, `IsRelay`.
- `internal/tor/feed.go` — onionoo relay-feed loader + `Syncer` + disk cache.
- `internal/tor/event.go` — `BuildControlEvent` (the `tor_control` event constructor).
- `internal/tor/adapter.go` — `PolicyAdapter` implementing `policy.TorChecker`.
- `internal/tor/policy_test.go`, `internal/tor/seed_test.go`, `internal/tor/feed_test.go`

**Modified:**
- `internal/config/config.go` — add `Tor TorConfig` to the top-level `Config` struct (line 37 area).
- `internal/events/types.go` — add `EventTorControl`, its `EventCategory` entry, and `AllEventTypes` entry.
- `internal/ocsf/registry.go` — add `"tor_control"` to `pendingTypes`.
- `internal/policy/engine.go` — add `TorVerdict`, `TorChecker`, `torChecker` field, `SetTorPolicy`, `Decision.Tor`, and the three pre-checks.
- `internal/netmonitor/dns.go` — emit `tor_control` when `dec.Tor != nil` (vector `onion_dns`).
- `internal/netmonitor/proxy.go` — emit `tor_control` when `dec.Tor != nil` (vector `onion_http`).
- `internal/api/ptrace_handlers.go` — emit `tor_control` in `HandleNetwork` (vectors `socks_port`/`relay_ip`) and `HandleExecve` (vector `process`).
- `internal/server/server.go` — build `tor.Policy` from `cfg.Tor`, call `engine.SetTorPolicy`, start the feed syncer.

---

## Task 1: `internal/ipset` — IP/CIDR membership primitive

**Files:**
- Create: `internal/ipset/ipset.go`
- Test: `internal/ipset/ipset_test.go`

- [ ] **Step 1: Write the failing test**

```go
package ipset

import (
	"net"
	"testing"
)

func TestSet_ContainsIPv4Exact(t *testing.T) {
	s := New()
	if err := s.Add("1.2.3.4"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("expected 1.2.3.4 to be a member")
	}
	if s.Contains(net.ParseIP("1.2.3.5")) {
		t.Fatal("did not expect 1.2.3.5 to be a member")
	}
}

func TestSet_ContainsCIDR(t *testing.T) {
	s := New()
	if err := s.Add("10.0.0.0/8"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("10.255.1.1")) {
		t.Fatal("expected 10.255.1.1 inside 10.0.0.0/8")
	}
	if s.Contains(net.ParseIP("11.0.0.1")) {
		t.Fatal("did not expect 11.0.0.1 inside 10.0.0.0/8")
	}
}

func TestSet_IPv6(t *testing.T) {
	s := New()
	if err := s.Add("2001:db8::/32"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected 2001:db8::1 inside 2001:db8::/32")
	}
}

func TestSet_NilAndEmpty(t *testing.T) {
	s := New()
	if s.Contains(nil) {
		t.Fatal("nil IP must never be a member")
	}
	if s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("empty set must contain nothing")
	}
	if s.Len() != 0 {
		t.Fatalf("Len=%d, want 0", s.Len())
	}
}

func TestSet_AddInvalid(t *testing.T) {
	s := New()
	if err := s.Add("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ipset/`
Expected: FAIL — package/`New` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// Package ipset provides membership testing for sets of individual IP
// addresses and CIDR ranges. A bare IP is stored as a /32 (IPv4) or
// /128 (IPv6) prefix. Safe for concurrent reads after construction;
// callers that mutate after publishing must provide their own locking
// or swap whole sets.
package ipset

import (
	"fmt"
	"net"
)

// Set holds IP/CIDR prefixes for O(n) membership testing. n is the
// number of distinct prefixes added (relay feeds: ~8k); linear scan is
// adequate and avoids a trie dependency. Swap whole sets to update.
type Set struct {
	nets []*net.IPNet
}

// New returns an empty Set.
func New() *Set { return &Set{} }

// Add inserts an IP ("1.2.3.4", "2001:db8::1") or CIDR ("10.0.0.0/8").
func (s *Set) Add(entry string) error {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		s.nets = append(s.nets, ipnet)
		return nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("ipset: invalid entry %q", entry)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	mask := net.CIDRMask(bits, bits)
	s.nets = append(s.nets, &net.IPNet{IP: ip, Mask: mask})
	return nil
}

// Contains reports whether ip falls in any added prefix. nil → false.
func (s *Set) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the number of prefixes in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/ipset/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ipset/
git commit -m "feat(tor): add internal/ipset IP/CIDR membership primitive"
```

---

## Task 2: `internal/config` — `TorConfig` + `ResolveTorConfig`

**Files:**
- Create: `internal/config/tor.go`
- Test: `internal/config/tor_test.go`
- Modify: `internal/config/config.go:37` (add field to `Config`)

- [ ] **Step 1: Write the failing test**

```go
package config

import "testing"

func TestResolveTorConfig_AbsentBlockDeniesByDefault(t *testing.T) {
	// Zero value = block omitted from YAML.
	got := ResolveTorConfig(TorConfig{})
	if !got.Enabled {
		t.Fatal("absent tor block must resolve to enabled (deny-by-default)")
	}
	if got.Mode != "deny" {
		t.Fatalf("Mode=%q, want deny", got.Mode)
	}
	for name, on := range map[string]bool{
		"processes": got.Vectors.Processes, "socks_ports": got.Vectors.SocksPorts,
		"onion_dns": got.Vectors.OnionDNS, "onion_http": got.Vectors.OnionHTTP,
		"relay_ips": got.Vectors.RelayIPs,
	} {
		if !on {
			t.Fatalf("vector %s must default on", name)
		}
	}
	if len(got.ClientBinaries) == 0 || len(got.SocksPorts) == 0 {
		t.Fatal("client_binaries and socks_ports must have defaults")
	}
}

func TestResolveTorConfig_ExplicitDisable(t *testing.T) {
	f := false
	got := ResolveTorConfig(TorConfig{Enabled: &f})
	if got.Enabled {
		t.Fatal("enabled:false must disable Tor controls")
	}
}

func TestResolveTorConfig_ExplicitAllowAndOverrides(t *testing.T) {
	tr := true
	got := ResolveTorConfig(TorConfig{
		Enabled:      &tr,
		Mode:         "allow",
		SocksPorts:   []int{9999},
		ClientBinaries: []string{"only-this"},
	})
	if got.Mode != "allow" {
		t.Fatalf("Mode=%q, want allow", got.Mode)
	}
	if len(got.SocksPorts) != 1 || got.SocksPorts[0] != 9999 {
		t.Fatalf("SocksPorts override not honored: %v", got.SocksPorts)
	}
	if len(got.ClientBinaries) != 1 || got.ClientBinaries[0] != "only-this" {
		t.Fatalf("ClientBinaries override not honored: %v", got.ClientBinaries)
	}
}

func TestResolveTorConfig_InvalidModeFallsBackToDeny(t *testing.T) {
	got := ResolveTorConfig(TorConfig{Mode: "banana"})
	if got.Mode != "deny" {
		t.Fatalf("invalid mode must fall back to deny, got %q", got.Mode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestResolveTorConfig`
Expected: FAIL — `TorConfig`/`ResolveTorConfig` undefined.

- [ ] **Step 3: Write the config struct + resolver**

Create `internal/config/tor.go`:

```go
package config

import "time"

// TorConfig is the raw, as-parsed `tor:` block. A missing block
// deserializes to the zero value; ResolveTorConfig turns that into the
// deny-by-default posture. Enabled is a *bool tri-state (nil → true),
// matching the convention used by SandboxFUSEConfig and WaitKillable.
type TorConfig struct {
	Enabled        *bool          `yaml:"enabled"`
	Mode           string         `yaml:"mode"` // deny | audit | allow
	Vectors        TorVectors     `yaml:"vectors"`
	ClientBinaries []string       `yaml:"client_binaries"`
	SocksPorts     []int          `yaml:"socks_ports"`
	ControlPorts   []int          `yaml:"control_ports"`
	SocksLoopbackOnly *bool       `yaml:"socks_loopback_only"`
	RelayFeed      TorRelayFeed   `yaml:"relay_feed"`
}

// TorVectors toggles each enforcement door. Pointers so an operator can
// relax one door (set false) without the zero value disabling all.
type TorVectors struct {
	Processes  *bool `yaml:"processes"`
	SocksPorts *bool `yaml:"socks_ports"`
	OnionDNS   *bool `yaml:"onion_dns"`
	OnionHTTP  *bool `yaml:"onion_http"`
	RelayIPs   *bool `yaml:"relay_ips"`
}

// TorRelayFeed configures the optional onionoo relay-IP feed.
type TorRelayFeed struct {
	Enabled      bool          `yaml:"enabled"`
	Sources      []string      `yaml:"sources"`
	LocalLists   []string      `yaml:"local_lists"`
	SyncInterval time.Duration `yaml:"sync_interval"`
	CacheDir     string        `yaml:"cache_dir"`
}

// ResolvedTorConfig is the fully-defaulted, value-typed form consumed by
// internal/tor. All bools are concrete; all lists are non-empty unless
// the feature is disabled.
type ResolvedTorConfig struct {
	Enabled        bool
	Mode           string
	Vectors        ResolvedTorVectors
	ClientBinaries []string
	SocksPorts     []int
	ControlPorts   []int
	SocksLoopbackOnly bool
	RelayFeed      TorRelayFeed
}

type ResolvedTorVectors struct {
	Processes, SocksPorts, OnionDNS, OnionHTTP, RelayIPs bool
}

// DefaultTorClientBinaries is the recommended client-binary deny list.
var DefaultTorClientBinaries = []string{
	"tor", "obfs4proxy", "snowflake-client", "lyrebird", "meek-client", "torsocks",
}

// ResolveTorConfig applies deny-by-default semantics. Absent block (zero
// value) → enabled, mode=deny, all vectors on, default binaries/ports.
func ResolveTorConfig(in TorConfig) ResolvedTorConfig {
	boolOr := func(p *bool, def bool) bool {
		if p == nil {
			return def
		}
		return *p
	}
	mode := in.Mode
	switch mode {
	case "deny", "audit", "allow":
	default:
		mode = "deny"
	}
	out := ResolvedTorConfig{
		Enabled: boolOr(in.Enabled, true),
		Mode:    mode,
		Vectors: ResolvedTorVectors{
			Processes:  boolOr(in.Vectors.Processes, true),
			SocksPorts: boolOr(in.Vectors.SocksPorts, true),
			OnionDNS:   boolOr(in.Vectors.OnionDNS, true),
			OnionHTTP:  boolOr(in.Vectors.OnionHTTP, true),
			RelayIPs:   boolOr(in.Vectors.RelayIPs, true),
		},
		ClientBinaries:    in.ClientBinaries,
		SocksPorts:        in.SocksPorts,
		ControlPorts:      in.ControlPorts,
		SocksLoopbackOnly: boolOr(in.SocksLoopbackOnly, true),
		RelayFeed:         in.RelayFeed,
	}
	if len(out.ClientBinaries) == 0 {
		out.ClientBinaries = append([]string(nil), DefaultTorClientBinaries...)
	}
	if len(out.SocksPorts) == 0 {
		out.SocksPorts = []int{9050, 9150}
	}
	if len(out.ControlPorts) == 0 {
		out.ControlPorts = []int{9051}
	}
	return out
}
```

- [ ] **Step 4: Add the field to the top-level `Config` struct**

In `internal/config/config.go`, add the `Tor` field after line 37 (`ThreatFeeds`):

```go
	ThreatFeeds       ThreatFeedsConfig       `yaml:"threat_feeds"`
	Tor               TorConfig               `yaml:"tor"`
	PackageChecks     PackageChecksConfig     `yaml:"package_checks"`
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/config/ -run TestResolveTorConfig`
Expected: PASS.
Run: `go build ./...`
Expected: clean (new field parses).

- [ ] **Step 6: Commit**

```bash
git add internal/config/tor.go internal/config/tor_test.go internal/config/config.go
git commit -m "feat(tor): add tor config block with deny-by-default resolution"
```

---

## Task 3: `internal/tor` — directory-authority seed

**Files:**
- Create: `internal/tor/seed.go`
- Test: `internal/tor/seed_test.go`

> The Tor directory authorities are a small, near-static set published in
> the Tor source (`src/app/config/auth_dirs.inc`). A Tor client must reach
> one (or a fallback dir) to bootstrap, so blocking them breaks Tor without
> any feed. Use the well-known authority IPv4 addresses below.

- [ ] **Step 1: Write the failing test**

```go
package tor

import (
	"net"
	"testing"
)

func TestDirectoryAuthoritySeed_NonEmptyAndValid(t *testing.T) {
	seed := DirectoryAuthoritySeed()
	if len(seed) < 5 {
		t.Fatalf("expected several authority IPs, got %d", len(seed))
	}
	for _, s := range seed {
		if net.ParseIP(s) == nil {
			t.Fatalf("seed entry %q is not a valid IP", s)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tor/ -run TestDirectoryAuthoritySeed`
Expected: FAIL — package/`DirectoryAuthoritySeed` undefined.

- [ ] **Step 3: Write the seed**

```go
package tor

// DirectoryAuthoritySeed returns the well-known Tor directory-authority
// IPv4 addresses. These are near-static (changes require a Tor release)
// and a client must contact one — or a fallback dir — to bootstrap, so
// this list breaks Tor without any external feed. Source: Tor's
// src/app/config/auth_dirs.inc. Operators extend coverage via the
// onionoo relay feed (Task 5) or relay_feed.local_lists.
func DirectoryAuthoritySeed() []string {
	return []string{
		"128.31.0.39",    // moria1
		"86.59.21.38",    // tor26
		"199.58.81.140",  // dizum
		"192.36.123.159", // bastet
		"66.111.2.131",   // Faravahar
		"131.188.40.189", // gabelmoo
		"193.23.244.244", // dannenberg
		"171.25.193.9",   // maatuska
		"154.35.175.225", // longclaw
		"204.13.164.118", // serge
	}
}
```

> Note for implementer: if any authority IP has changed since this plan
> was written, cross-check the current `auth_dirs.inc`. Staleness only
> weakens the seed; the feed and other vectors remain authoritative.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tor/ -run TestDirectoryAuthoritySeed`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tor/seed.go internal/tor/seed_test.go
git commit -m "feat(tor): add directory-authority seed IPs"
```

---

## Task 4: `internal/tor` — `Policy` core (the three Eval methods)

**Files:**
- Create: `internal/tor/policy.go`
- Test: `internal/tor/policy_test.go`

- [ ] **Step 1: Write the failing test**

```go
package tor

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func newDenyPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(config.ResolveTorConfig(config.TorConfig{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestPolicy_EvalExecve_DenyTorBinary(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"})
	if !ok || v.Vector != "process" || v.Decision != "deny" {
		t.Fatalf("got ok=%v verdict=%+v, want deny/process", ok, v)
	}
	v, ok = p.EvalExecve("/usr/bin/torsocks", []string{"torsocks", "curl"})
	if !ok || v.Decision != "deny" {
		t.Fatalf("torsocks should be denied: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalExecve("/usr/bin/curl", []string{"curl"}); ok {
		t.Fatal("curl must not be a Tor match")
	}
}

func TestPolicy_EvalConnect_SocksPortLoopback(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9050)
	if !ok || v.Vector != "socks_port" || v.Decision != "deny" {
		t.Fatalf("loopback :9050 should deny: ok=%v v=%+v", ok, v)
	}
	// Default socks_loopback_only=true: non-loopback :9050 is not Tor.
	if _, ok := p.EvalConnect(net.ParseIP("203.0.113.7"), 9050); ok {
		t.Fatal("non-loopback :9050 must not match when loopback_only")
	}
}

func TestPolicy_EvalConnect_RelaySeedIP(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalConnect(net.ParseIP("128.31.0.39"), 443) // moria1 authority
	if !ok || v.Vector != "relay_ip" || v.Decision != "deny" {
		t.Fatalf("authority IP should deny: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalConnect(net.ParseIP("1.1.1.1"), 443); ok {
		t.Fatal("non-relay IP must not match")
	}
}

func TestPolicy_EvalOnionName(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalOnionName("abcdefghij234567.onion")
	if !ok || v.Vector != "onion_dns" || v.Decision != "deny" {
		t.Fatalf(".onion should deny: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalOnionName("example.com"); ok {
		t.Fatal("clearnet host must not match")
	}
}

func TestPolicy_AuditMode(t *testing.T) {
	tr := true
	p, _ := New(config.ResolveTorConfig(config.TorConfig{Enabled: &tr, Mode: "audit"}))
	v, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"})
	if !ok || v.Decision != "audit" {
		t.Fatalf("audit mode must report audit: ok=%v v=%+v", ok, v)
	}
}

func TestPolicy_AllowMode_NoMatches(t *testing.T) {
	tr := true
	p, _ := New(config.ResolveTorConfig(config.TorConfig{Enabled: &tr, Mode: "allow"}))
	if _, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"}); ok {
		t.Fatal("allow mode: Tor vectors must be no-ops")
	}
	if _, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9050); ok {
		t.Fatal("allow mode: connect must be a no-op")
	}
}

func TestPolicy_DisabledVector(t *testing.T) {
	tr, f := true, false
	p, _ := New(config.ResolveTorConfig(config.TorConfig{
		Enabled: &tr,
		Vectors: config.TorVectors{Processes: &f},
	}))
	if _, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"}); ok {
		t.Fatal("processes vector disabled: must not match")
	}
	// other vectors still active
	if _, ok := p.EvalOnionName("x.onion"); !ok {
		t.Fatal("onion_dns still enabled: should match")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tor/ -run TestPolicy`
Expected: FAIL — `New`/`Policy`/`Verdict` undefined.

- [ ] **Step 3: Write the policy**

```go
package tor

import (
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/ipset"
)

// Mode constants.
const (
	ModeDeny  = "deny"
	ModeAudit = "audit"
	ModeAllow = "allow"
)

// Vector constants (also used as the tor_control event's vector field).
const (
	VectorProcess   = "process"
	VectorSocksPort = "socks_port"
	VectorOnionDNS  = "onion_dns"
	VectorOnionHTTP = "onion_http"
	VectorRelayIP   = "relay_ip"
)

// Verdict is the result of a positive Tor match.
type Verdict struct {
	Vector   string // one of the Vector* constants
	Mode     string // resolved policy mode
	Decision string // "deny" or "audit" (allow mode never yields a verdict)
	Target   string // binary path, ip:port, or onion host
}

// Policy answers Tor questions for the enforcement points. Construct once
// via New; the relay set may be swapped concurrently via SetRelays.
type Policy struct {
	cfg          config.ResolvedTorConfig
	binBasenames map[string]struct{}
	socksPorts   map[int]struct{}
	controlPorts map[int]struct{}
	seed         *ipset.Set    // directory-authority seed (immutable)
	relays       atomic.Pointer[ipset.Set] // feed-populated, hot-swappable
}

// New builds a Policy from resolved config. Returns a Policy even when
// disabled (its Eval* methods are then no-ops).
func New(cfg config.ResolvedTorConfig) (*Policy, error) {
	p := &Policy{
		cfg:          cfg,
		binBasenames: map[string]struct{}{},
		socksPorts:   map[int]struct{}{},
		controlPorts: map[int]struct{}{},
		seed:         ipset.New(),
	}
	for _, b := range cfg.ClientBinaries {
		p.binBasenames[strings.ToLower(b)] = struct{}{}
	}
	for _, port := range cfg.SocksPorts {
		p.socksPorts[port] = struct{}{}
	}
	for _, port := range cfg.ControlPorts {
		p.controlPorts[port] = struct{}{}
	}
	for _, ip := range DirectoryAuthoritySeed() {
		_ = p.seed.Add(ip) // seed entries are known-valid
	}
	p.relays.Store(ipset.New())
	return p, nil
}

// Mode returns the resolved mode.
func (p *Policy) Mode() string { return p.cfg.Mode }

// active reports whether a verdict should be produced at all.
func (p *Policy) active() bool {
	return p != nil && p.cfg.Enabled && (p.cfg.Mode == ModeDeny || p.cfg.Mode == ModeAudit)
}

// decisionForMode maps the policy mode to a verdict decision.
func (p *Policy) decisionForMode() string {
	if p.cfg.Mode == ModeAudit {
		return ModeAudit
	}
	return ModeDeny
}

func (p *Policy) verdict(vector, target string) (Verdict, bool) {
	return Verdict{
		Vector:   vector,
		Mode:     p.cfg.Mode,
		Decision: p.decisionForMode(),
		Target:   target,
	}, true
}

// EvalExecve reports whether filename is a Tor client binary.
func (p *Policy) EvalExecve(filename string, argv []string) (Verdict, bool) {
	if !p.active() || !p.cfg.Vectors.Processes {
		return Verdict{}, false
	}
	base := strings.ToLower(filepath.Base(filename))
	if _, ok := p.binBasenames[base]; ok {
		return p.verdict(VectorProcess, filename)
	}
	return Verdict{}, false
}

// EvalConnect reports whether a connect to ip:port targets Tor (a local
// SOCKS/control port, or a known relay IP).
func (p *Policy) EvalConnect(ip net.IP, port int) (Verdict, bool) {
	if !p.active() {
		return Verdict{}, false
	}
	if p.cfg.Vectors.SocksPorts {
		_, isSocks := p.socksPorts[port]
		_, isCtrl := p.controlPorts[port]
		if isSocks || isCtrl {
			if !p.cfg.SocksLoopbackOnly || (ip != nil && ip.IsLoopback()) {
				return p.verdict(VectorSocksPort, net.JoinHostPort(ipString(ip), itoa(port)))
			}
		}
	}
	if p.cfg.Vectors.RelayIPs && ip != nil {
		if p.seed.Contains(ip) || p.relays.Load().Contains(ip) {
			return p.verdict(VectorRelayIP, net.JoinHostPort(ipString(ip), itoa(port)))
		}
	}
	return Verdict{}, false
}

// EvalOnionName reports whether host is a .onion address. vector is
// onion_dns; callers in the HTTP path relabel to onion_http.
func (p *Policy) EvalOnionName(host string) (Verdict, bool) {
	if !p.active() || !p.cfg.Vectors.OnionDNS {
		return Verdict{}, false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "onion" || strings.HasSuffix(h, ".onion") {
		return p.verdict(VectorOnionDNS, host)
	}
	return Verdict{}, false
}

// SetRelays swaps the feed-populated relay set (called by the Syncer).
func (p *Policy) SetRelays(s *ipset.Set) {
	if p == nil || s == nil {
		return
	}
	p.relays.Store(s)
}

// RelayFeedEnabled reports whether the onionoo feed should run.
func (p *Policy) RelayFeedEnabled() bool {
	return p != nil && p.cfg.Enabled && p.cfg.Vectors.RelayIPs && p.cfg.RelayFeed.Enabled
}

// RelayFeedConfig exposes the feed config for the Syncer.
func (p *Policy) RelayFeedConfig() config.TorRelayFeed { return p.cfg.RelayFeed }

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func itoa(i int) string {
	// strconv.Itoa without the import churn in callers that already use it.
	return strconvItoa(i)
}
```

Add a tiny helper file or inline `strconv`. Simplest: replace `itoa`/`ipString` usage with `strconv` directly. To avoid the indirection above, use this `policy.go` import block and drop the `itoa`/`strconvItoa` shim — change `itoa(port)` to `strconv.Itoa(port)` and import `"strconv"`. (Do this now: import `strconv`, delete the `itoa` and `strconvItoa` references, call `strconv.Itoa(port)`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tor/ -run TestPolicy`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tor/policy.go internal/tor/policy_test.go
git commit -m "feat(tor): add Policy with EvalExecve/EvalConnect/EvalOnionName"
```

---

## Task 5: `internal/tor` — onionoo relay feed loader + syncer

**Files:**
- Create: `internal/tor/feed.go`
- Test: `internal/tor/feed_test.go`

> onionoo `details` returns `{"relays":[{"or_addresses":["1.2.3.4:9001","[2001:db8::1]:443"]},...]}`.
> We extract the host of each `or_addresses` entry into an `ipset.Set`.
> Modeled on `internal/threatfeed/syncer.go`: periodic fetch, last-good
> reuse on failure, disk cache, plus a fold-in of `local_lists` and the
> always-present directory-authority seed (held separately in Policy).

- [ ] **Step 1: Write the failing test**

```go
package tor

import (
	"net"
	"strings"
	"testing"
)

func TestParseOnionoo(t *testing.T) {
	body := `{"relays":[
		{"or_addresses":["128.66.0.1:9001","[2001:db8::2]:443"]},
		{"or_addresses":["128.66.0.2:443"]},
		{"or_addresses":["garbage"]}
	]}`
	ips, err := parseOnionoo(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseOnionoo: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("want 3 parseable IPs, got %d (%v)", len(ips), ips)
	}
	set := buildSet(ips)
	if !set.Contains(net.ParseIP("128.66.0.1")) {
		t.Fatal("expected 128.66.0.1 in set")
	}
	if !set.Contains(net.ParseIP("2001:db8::2")) {
		t.Fatal("expected IPv6 relay in set")
	}
}

func TestParseOnionoo_Malformed(t *testing.T) {
	if _, err := parseOnionoo(strings.NewReader("{not json")); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tor/ -run TestParseOnionoo`
Expected: FAIL — `parseOnionoo`/`buildSet` undefined.

- [ ] **Step 3: Write the feed**

```go
package tor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/ipset"
)

const maxOnionooSize = 200 * 1024 * 1024 // 200 MB; onionoo details is large

// parseOnionoo extracts relay host IPs from an onionoo `details` document.
// Unparseable or_addresses entries are skipped (best-effort).
func parseOnionoo(r io.Reader) ([]string, error) {
	var doc struct {
		Relays []struct {
			OrAddresses []string `json:"or_addresses"`
		} `json:"relays"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	var ips []string
	for _, relay := range doc.Relays {
		for _, addr := range relay.OrAddresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			if net.ParseIP(host) == nil {
				continue
			}
			ips = append(ips, host)
		}
	}
	return ips, nil
}

// buildSet constructs an ipset.Set from a list of IP/CIDR strings,
// skipping invalid entries.
func buildSet(entries []string) *ipset.Set {
	s := ipset.New()
	for _, e := range entries {
		_ = s.Add(e)
	}
	return s
}

// Syncer periodically refreshes a Policy's relay set from onionoo
// sources + local lists. Modeled on internal/threatfeed.Syncer.
type Syncer struct {
	pol      *Policy
	sources  []string
	locals   []string
	interval time.Duration
	cacheDir string
	client   *http.Client
	logger   *slog.Logger
	lastGood []string
}

// NewSyncer builds a relay-feed syncer for the given Policy.
func NewSyncer(pol *Policy, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg := pol.RelayFeedConfig()
	interval := cfg.SyncInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Syncer{
		pol:      pol,
		sources:  cfg.Sources,
		locals:   cfg.LocalLists,
		interval: interval,
		cacheDir: cfg.CacheDir,
		client:   &http.Client{Timeout: 60 * time.Second},
		logger:   logger,
	}
}

// Run loads the disk cache, performs an initial sync, then refreshes on
// the configured interval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	if cached := s.loadCache(); len(cached) > 0 {
		s.pol.SetRelays(buildSet(cached))
		s.lastGood = cached
		s.logger.Info("tor relay cache loaded", "ips", len(cached))
	}
	s.sync(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sync(ctx)
		}
	}
}

func (s *Syncer) sync(ctx context.Context) {
	var all []string
	anySucceeded := false
	for _, src := range s.sources {
		ips, err := s.fetch(ctx, src)
		if err != nil {
			s.logger.Warn("tor relay feed fetch failed", "source", src, "error", err)
			continue
		}
		anySucceeded = true
		all = append(all, ips...)
	}
	for _, path := range s.locals {
		ips, err := s.parseLocal(path)
		if err != nil {
			s.logger.Warn("tor relay local list failed", "path", path, "error", err)
			continue
		}
		anySucceeded = true
		all = append(all, ips...)
	}
	if !anySucceeded {
		// Keep last-good (already applied); seed in Policy still enforces.
		s.logger.Warn("tor relay feed: all sources failed, retaining cache+seed",
			"cached_ips", len(s.lastGood))
		return
	}
	s.pol.SetRelays(buildSet(all))
	s.lastGood = all
	if err := s.saveCache(all); err != nil {
		s.logger.Warn("tor relay cache save failed", "error", err)
	}
	s.logger.Info("tor relay feed synced", "ips", len(all))
}

func (s *Syncer) fetch(ctx context.Context, src string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseOnionoo(&io.LimitedReader{R: resp.Body, N: maxOnionooSize})
}

func (s *Syncer) parseLocal(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ips []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line) // IP or CIDR; ipset.Add validates
	}
	return ips, sc.Err()
}

func (s *Syncer) cachePath() string {
	dir := s.cacheDir
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "tor-relays.txt")
}

func (s *Syncer) loadCache() []string {
	p := s.cachePath()
	if p == "" {
		return nil
	}
	ips, err := s.parseLocal(p)
	if err != nil {
		return nil
	}
	return ips
}

func (s *Syncer) saveCache(ips []string) error {
	p := s.cachePath()
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(strings.Join(ips, "\n")), 0o644)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tor/ -run TestParseOnionoo`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tor/feed.go internal/tor/feed_test.go
git commit -m "feat(tor): add onionoo relay-feed loader and syncer"
```

---

## Task 6: `tor_control` event type + OCSF registration + event constructor

**Files:**
- Modify: `internal/events/types.go` (3 spots)
- Modify: `internal/ocsf/registry.go:26` (pendingTypes)
- Create: `internal/tor/event.go`
- Test: rely on existing `internal/ocsf` exhaustiveness test + a new constructor test.

- [ ] **Step 1: Add the event type to `internal/events/types.go`**

Add to the Network block (after line 29):

```go
	EventConnectRedirectFallback EventType = "connect_redirect_fallback"
	EventTorControl              EventType = "tor_control"
)
```

Add to `EventCategory` (in the Network section, after line 199):

```go
	EventConnectRedirectFallback: "network",
	EventTorControl:              "network",
```

Add to `AllEventTypes` (in the Network line, line 291-292):

```go
	EventDNSRedirect, EventConnectRedirect, EventConnectRedirectFallback,
	EventTorControl,
```

- [ ] **Step 2: Register in OCSF pendingTypes**

In `internal/ocsf/registry.go`, add to the Network Activity group in `pendingTypes` (after line 66, `"transparent_net_setup": {},`):

```go
	"transparent_net_setup":  {},
	"tor_control":            {},
```

- [ ] **Step 3: Run the exhaustiveness test to confirm it passes**

Run: `go test ./internal/ocsf/`
Expected: PASS (the new type is now in `pendingTypes`, so `TestExhaustiveness_AllEventTypesRegistered` is satisfied).

> If you skip Step 2, this test FAILS with the new `tor_control` type
> listed as unregistered. That is the gotcha this step prevents.

- [ ] **Step 4: Write the event constructor test**

Create `internal/tor/event_test.go`:

```go
package tor

import "testing"

func TestBuildControlEvent(t *testing.T) {
	ev := BuildControlEvent("sess-1", "cmd-1", 4242, Verdict{
		Vector: VectorProcess, Mode: ModeDeny, Decision: ModeDeny, Target: "/usr/bin/tor",
	})
	if ev.Type != "tor_control" {
		t.Fatalf("Type=%q, want tor_control", ev.Type)
	}
	if ev.SessionID != "sess-1" || ev.CommandID != "cmd-1" {
		t.Fatal("session/command not propagated")
	}
	if ev.Fields["vector"] != "process" || ev.Fields["decision"] != "deny" {
		t.Fatalf("fields wrong: %+v", ev.Fields)
	}
	if ev.PID != 4242 {
		t.Fatalf("PID=%d, want 4242", ev.PID)
	}
}
```

- [ ] **Step 5: Write the constructor**

Create `internal/tor/event.go`:

```go
package tor

import (
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// BuildControlEvent constructs a tor_control audit event from a Verdict.
// Callers append+publish it via their session emitter.
func BuildControlEvent(sessionID, commandID string, pid int, v Verdict) types.Event {
	return types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "tor_control",
		SessionID: sessionID,
		CommandID: commandID,
		PID:       pid,
		Fields: map[string]any{
			"vector":   v.Vector,
			"mode":     v.Mode,
			"decision": v.Decision,
			"target":   v.Target,
			"rule":     "tor",
		},
	}
}
```

> Verify `types.Event` has a `PID int` field; the existing seccomp events
> set PID (see `internal/events/types.go` seccomp doc comment). If the
> field name differs, adjust the assignment and the test.

- [ ] **Step 6: Run tests**

Run: `go test ./internal/tor/ ./internal/ocsf/ ./internal/events/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/events/types.go internal/ocsf/registry.go internal/tor/event.go internal/tor/event_test.go
git commit -m "feat(tor): add tor_control event type, OCSF registration, constructor"
```

---

## Task 7: Policy engine — `TorChecker` interface, `Decision.Tor`, setter, adapter

**Files:**
- Modify: `internal/policy/engine.go` (Decision struct ~133, Engine struct ~38, add interface + setter near `SetThreatStore` ~398)
- Create: `internal/tor/adapter.go`
- Test: `internal/policy/engine_tor_test.go` (setter wiring) + adapter compile check

- [ ] **Step 1: Add the interface, result type, field, and setter to `engine.go`**

After the `ThreatChecker` interface (line 36), add:

```go
// TorVerdict mirrors tor.Verdict at the policy layer (avoids a policy→tor
// import). tor.PolicyAdapter translates between the two.
type TorVerdict struct {
	Vector   string
	Mode     string
	Decision string // "deny" or "audit"
	Target   string
}

// TorChecker is the optional Tor coordinator. internal/tor.PolicyAdapter
// satisfies it. All methods return (verdict, true) only on a Tor match
// the caller should act on (deny short-circuits; audit attaches+continues).
type TorChecker interface {
	EvalExecve(filename string, argv []string) (TorVerdict, bool)
	EvalConnect(ip net.IP, port int) (TorVerdict, bool)
	EvalOnionName(host string) (TorVerdict, bool)
}
```

Add the field to the `Engine` struct (after line 73, `threatAction string`):

```go
	threatStore  ThreatChecker
	threatAction string

	// Optional Tor coordinator (deny-by-default Tor controls).
	torChecker TorChecker
```

Add the `Tor` field to the `Decision` struct (after line 144, `ThreatAction string`):

```go
	ThreatAction string // "deny" or "audit" — set when a threat feed matched
	Tor          *TorVerdict // non-nil when a Tor vector matched (deny or audit)
```

Add the setter near `SetThreatStore` (after line 404):

```go
// SetTorPolicy installs the optional Tor coordinator. Pass nil to disable.
func (e *Engine) SetTorPolicy(tc TorChecker) {
	e.torChecker = tc
}
```

Confirm `net` is already imported in `engine.go` (it is — `CheckNetworkIP` uses `net.IP`).

- [ ] **Step 2: Write the adapter test (compile + translate)**

Create `internal/tor/adapter_test.go`:

```go
package tor

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestPolicyAdapter_ImplementsTorChecker(t *testing.T) {
	p, _ := New(config.ResolveTorConfig(config.TorConfig{}))
	var tc policy.TorChecker = &PolicyAdapter{Policy: p} // compile-time check
	v, ok := tc.EvalConnect(net.ParseIP("127.0.0.1"), 9050)
	if !ok || v.Vector != "socks_port" || v.Decision != "deny" {
		t.Fatalf("adapter EvalConnect wrong: ok=%v v=%+v", ok, v)
	}
}
```

- [ ] **Step 3: Write the adapter**

Create `internal/tor/adapter.go`:

```go
package tor

import (
	"net"

	"github.com/agentsh/agentsh/internal/policy"
)

// PolicyAdapter adapts *Policy to policy.TorChecker (policy→tor would be
// an import cycle, so the bridge lives here, like threatfeed.PolicyAdapter).
type PolicyAdapter struct {
	Policy *Policy
}

func conv(v Verdict, ok bool) (policy.TorVerdict, bool) {
	if !ok {
		return policy.TorVerdict{}, false
	}
	return policy.TorVerdict{Vector: v.Vector, Mode: v.Mode, Decision: v.Decision, Target: v.Target}, true
}

func (a *PolicyAdapter) EvalExecve(filename string, argv []string) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalExecve(filename, argv))
}

func (a *PolicyAdapter) EvalConnect(ip net.IP, port int) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalConnect(ip, port))
}

func (a *PolicyAdapter) EvalOnionName(host string) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalOnionName(host))
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/tor/ ./internal/policy/`
Expected: PASS (and no import cycle).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/engine.go internal/tor/adapter.go internal/tor/adapter_test.go
git commit -m "feat(tor): add TorChecker interface, Decision.Tor, adapter"
```

---

## Task 8: Engine integration — Tor pre-checks in the three Check methods

**Files:**
- Modify: `internal/policy/engine.go` — `CheckExecve` (~1357), `CheckNetworkCtx` (~1056), `CheckNetworkIP` (~498)
- Test: `internal/policy/engine_tor_test.go`

> Pattern per method: a `deny` verdict short-circuits and overrides user
> rules; an `audit` verdict attaches `dec.Tor` via a named-return + defer
> so it never loosens normal evaluation. We use a small fake TorChecker in
> tests.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/engine_tor_test.go`:

```go
package policy

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

type fakeTor struct {
	execve, connect, onion *TorVerdict
}

func (f *fakeTor) EvalExecve(string, []string) (TorVerdict, bool) {
	if f.execve == nil {
		return TorVerdict{}, false
	}
	return *f.execve, true
}
func (f *fakeTor) EvalConnect(net.IP, int) (TorVerdict, bool) {
	if f.connect == nil {
		return TorVerdict{}, false
	}
	return *f.connect, true
}
func (f *fakeTor) EvalOnionName(string) (TorVerdict, bool) {
	if f.onion == nil {
		return TorVerdict{}, false
	}
	return *f.onion, true
}

func newAllowAllEngine(t *testing.T) *Engine {
	t.Helper()
	// A policy that would ALLOW everything, so we can prove Tor overrides it.
	p := &Policy{
		NetworkRules: []NetworkRule{{Name: "allow-all", Ports: []int{9050}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-all"}},
	}
	e, err := NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestCheckExecve_TorDenyOverridesAllow(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{execve: &TorVerdict{Vector: "process", Mode: "deny", Decision: "deny", Target: "/usr/bin/tor"}})
	dec := e.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision=%v, want deny", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Vector != "process" {
		t.Fatalf("dec.Tor missing/wrong: %+v", dec.Tor)
	}
}

func TestCheckNetworkIP_TorDenySocksPort(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "socks_port", Mode: "deny", Decision: "deny", Target: "127.0.0.1:9050"}})
	dec := e.CheckNetworkIP("", net.ParseIP("127.0.0.1"), 9050)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("want tor deny, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkIP_TorAuditDoesNotLoosenUserDeny(t *testing.T) {
	// Policy denies by default (no matching rule for this IP/port).
	p := &Policy{NetworkRules: []NetworkRule{{Name: "deny-all", Decision: "deny"}}}
	e, _ := NewEngine(p, false, false)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "relay_ip", Mode: "audit", Decision: "audit", Target: "1.2.3.4:443"}})
	dec := e.CheckNetworkIP("", net.ParseIP("1.2.3.4"), 443)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("audit must not loosen a deny; got %v", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Decision != "audit" {
		t.Fatalf("audit verdict must attach; got %+v", dec.Tor)
	}
}

func TestCheckNetworkCtx_TorOnionDeny(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{onion: &TorVerdict{Vector: "onion_dns", Mode: "deny", Decision: "deny", Target: "x.onion"}})
	dec := e.CheckNetworkCtx(nil, "x.onion", 53)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("want onion deny, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}
```

> Adjust the literal `Policy`/`NetworkRule`/`CommandRule` field names in
> `newAllowAllEngine` to match the actual structs in `internal/policy`
> (read `model.go`/`engine.go`). The behavioral asserts are the contract.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestCheck.*Tor`
Expected: FAIL — pre-checks not implemented (decisions come back `allow`/no `Tor`).

- [ ] **Step 3: Add the pre-check to `CheckExecve`**

Convert the signature to a named return and insert the Tor pre-check at the very top. Change line 1357 from:

```go
func (e *Engine) CheckExecve(filename string, argv []string, depth int) Decision {
	cmdLower := strings.ToLower(filename)
```

to:

```go
func (e *Engine) CheckExecve(filename string, argv []string, depth int) (dec Decision) {
	if e.torChecker != nil {
		if v, ok := e.torChecker.EvalExecve(filename, argv); ok {
			tv := TorVerdict(v)
			if v.Decision == "deny" {
				d := e.wrapDecision(string(types.DecisionDeny), "tor:"+v.Vector, "blocked by Tor policy", nil)
				d.Tor = &tv
				d.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, CommandRule{})
				return d
			}
			defer func() { dec.Tor = &tv }() // audit: attach, don't loosen
		}
	}
	cmdLower := strings.ToLower(filename)
```

Then change the two existing `return dec` statements in the function body (the matched-rule return at ~1428 and the default-deny return at ~1434) from `return dec` to keep working with the named return — they already assign `dec := e.wrapDecision(...)`. Rename those local `dec :=` to `dec =` so they target the named return:
- Line ~1426: `dec := e.wrapDecision(...)` → `dec = e.wrapDecision(...)`
- Line ~1432: `dec := e.wrapDecision(...)` → `dec = e.wrapDecision(...)`

(Both already `return dec` immediately after, which now returns the named value so the deferred audit-attach runs.)

- [ ] **Step 4: Add the pre-check to `CheckNetworkIP`**

Change line 498 from:

```go
func (e *Engine) CheckNetworkIP(domain string, ip net.IP, port int) Decision {
	if e.policy == nil {
```

to:

```go
func (e *Engine) CheckNetworkIP(domain string, ip net.IP, port int) (dec Decision) {
	if e.torChecker != nil {
		if v, ok := e.torChecker.EvalConnect(ip, port); ok {
			tv := TorVerdict(v)
			if v.Decision == "deny" {
				d := e.wrapDecision(string(types.DecisionDeny), "tor:"+v.Vector, "blocked by Tor policy", nil)
				d.Tor = &tv
				return d
			}
			defer func() { dec.Tor = &tv }()
		}
	}
	if e.policy == nil {
```

Then change every local `dec := e.wrapDecision(...)` inside `CheckNetworkIP` (lines ~566 and ~575) to `dec = e.wrapDecision(...)`, and the early `return Decision{...}` at line ~500 stays as-is (no Tor match path returns before the defer is registered only when ok; when policy==nil and no tor match, returning a literal is fine).

> Note: the `if e.policy == nil { return Decision{...} }` early return at
> line ~500 returns a literal, not the named `dec`. That is correct: if a
> Tor `deny` matched we already returned above; if a Tor `audit` matched,
> `e.policy == nil` is not a realistic path in production (engine always
> has a policy), and returning allow-without-Tor-attach there is
> acceptable. Leave it.

- [ ] **Step 5: Add the pre-check to `CheckNetworkCtx`**

Change line 1056 from:

```go
func (e *Engine) CheckNetworkCtx(ctx context.Context, domain string, port int) Decision {
	domain = strings.ToLower(strings.TrimSpace(domain))
```

to:

```go
func (e *Engine) CheckNetworkCtx(ctx context.Context, domain string, port int) (dec Decision) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if e.torChecker != nil {
		if v, ok := e.torChecker.EvalOnionName(domain); ok {
			tv := TorVerdict(v)
			if v.Decision == "deny" {
				d := e.wrapDecision(string(types.DecisionDeny), "tor:"+v.Vector, "blocked by Tor policy", nil)
				d.Tor = &tv
				return d
			}
			defer func() { dec.Tor = &tv }()
		}
	}
```

Then change every local `dec := e.wrapDecision(...)` inside `CheckNetworkCtx` (lines ~1064, ~1144, ~1153) to `dec = e.wrapDecision(...)`. The threat-feed `return dec` at ~1069 already returns; convert its `dec :=` to `dec =` as well so the named return is used consistently.

> `TorVerdict(v)` is a direct conversion because the field sets are
> identical; `tv` is addressable so `&tv` is safe to store.

- [ ] **Step 6: Run tests**

Run: `go test ./internal/policy/`
Expected: PASS (new Tor tests + existing engine tests unaffected — verify no regressions).

- [ ] **Step 7: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_tor_test.go
git commit -m "feat(tor): consult Tor coordinator in CheckExecve/CheckNetworkCtx/CheckNetworkIP"
```

---

## Task 9: Emit `tor_control` at the enforcement points

**Files:**
- Modify: `internal/netmonitor/dns.go` (in `handle`, after `dec` computed ~line 120)
- Modify: `internal/netmonitor/proxy.go` (in `handleHTTP`, after `dec` computed ~line 390)
- Modify: `internal/api/ptrace_handlers.go` (`HandleNetwork` and `HandleExecve`, after the decision)

> Each site already has an emitter and a `policy.Decision`. When
> `dec.Tor != nil`, build and emit a `tor_control` event via
> `tor.BuildControlEvent`. The HTTP site relabels the vector to
> `onion_http` (the engine's `EvalOnionName` reports `onion_dns`). Import
> `github.com/agentsh/agentsh/internal/tor` in each file.

- [ ] **Step 1: DNS site — `internal/netmonitor/dns.go`**

After line 120 (`dec = d.maybeApprove(ctx, commandID, dec, "dns", domain)`), add:

```go
	if dec.Tor != nil && d.emit != nil {
		tev := tor.BuildControlEvent(d.sessionID, commandID, 0, tor.Verdict{
			Vector: dec.Tor.Vector, Mode: dec.Tor.Mode, Decision: dec.Tor.Decision, Target: dec.Tor.Target,
		})
		_ = d.emit.AppendEvent(context.Background(), tev)
		d.emit.Publish(tev)
	}
```

Add `"github.com/agentsh/agentsh/internal/tor"` to the imports.

- [ ] **Step 2: HTTP site — `internal/netmonitor/proxy.go`**

After line 390 (`dec = p.maybeApprove(ctx, commandID, dec, "network", host)`), add (relabel vector to `onion_http`):

```go
	if dec.Tor != nil && p.emit != nil {
		vector := dec.Tor.Vector
		if vector == tor.VectorOnionDNS {
			vector = tor.VectorOnionHTTP
		}
		tev := tor.BuildControlEvent(p.sessionID, commandID, 0, tor.Verdict{
			Vector: vector, Mode: dec.Tor.Mode, Decision: dec.Tor.Decision, Target: dec.Tor.Target,
		})
		_ = p.emit.AppendEvent(context.Background(), tev)
		p.emit.Publish(tev)
	}
```

Add `"github.com/agentsh/agentsh/internal/tor"` to the imports.

- [ ] **Step 3: ptrace network site — `internal/api/ptrace_handlers.go` `HandleNetwork`**

After the `decision := pe.CheckNetwork(checkAddr, checkPort)` line, add (use the session's emitter — read how `HandleNetwork` already emits its `ptrace_network` event and reuse that emitter and PID):

```go
	if decision.Tor != nil {
		tev := tor.BuildControlEvent(nc.SessionID, s.CurrentCommandID(), nc.PID, tor.Verdict{
			Vector: decision.Tor.Vector, Mode: decision.Tor.Mode, Decision: decision.Tor.Decision, Target: decision.Tor.Target,
		})
		s.EmitEvent(ctx, tev) // use whatever emit helper this handler already uses
	}
```

> Implementer: match the actual emit mechanism in `ptrace_handlers.go`
> (e.g. `r.emit`, `s.Emit`, or an events sink). Read the surrounding
> `HandleNetwork` body — it already emits a network event; emit the
> `tor_control` event the same way. `tor.BuildControlEvent` is the only
> new call. Add the `internal/tor` import.

- [ ] **Step 4: ptrace execve site — `internal/api/ptrace_handlers.go` `HandleExecve`**

After the execve decision is computed (the `CheckExecve` result, ~line 135), add:

```go
	if decision.Tor != nil {
		tev := tor.BuildControlEvent(sessionID, s.CurrentCommandID(), pid, tor.Verdict{
			Vector: decision.Tor.Vector, Mode: decision.Tor.Mode, Decision: decision.Tor.Decision, Target: decision.Tor.Target,
		})
		s.EmitEvent(ctx, tev) // same emit mechanism as the surrounding handler
	}
```

> Use the same emit mechanism and the `pid`/`sessionID` variables already
> present in `HandleExecve`.

- [ ] **Step 5: Build and run package tests**

Run: `go build ./... && go test ./internal/netmonitor/ ./internal/api/`
Expected: clean build; tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/dns.go internal/netmonitor/proxy.go internal/api/ptrace_handlers.go
git commit -m "feat(tor): emit tor_control events at DNS/HTTP/connect/execve sites"
```

---

## Task 10: Server wiring

**Files:**
- Modify: `internal/server/server.go` (after the threat-feed block, ~line 198)

- [ ] **Step 1: Build the Tor policy and wire it in**

After the threat-feed wiring block (line 198) and before `limits := engine.Limits()` (line 200), add:

```go
	torCfg := config.ResolveTorConfig(cfg.Tor)
	var torSyncer *tor.Syncer
	if torCfg.Enabled {
		torPol, err := tor.New(torCfg)
		if err != nil {
			return nil, fmt.Errorf("tor policy: %w", err)
		}
		engine.SetTorPolicy(&tor.PolicyAdapter{Policy: torPol})
		slog.Info("tor access control enabled", "mode", torCfg.Mode)
		if torPol.RelayFeedEnabled() {
			if torCfg.RelayFeed.CacheDir == "" {
				// default cache dir alongside threat-feeds
				torCfg.RelayFeed.CacheDir = filepath.Join(config.GetDataDir(), "tor-relays")
				torPol, _ = tor.New(torCfg) // rebuild with cache dir set
				engine.SetTorPolicy(&tor.PolicyAdapter{Policy: torPol})
			}
			torSyncer = tor.NewSyncer(torPol, slog.Default())
		}
	}
```

> Simplify the cache-dir handling if `ResolveTorConfig` is extended to
> default `RelayFeed.CacheDir`. The double-`New` above is a pragmatic
> way to inject the default without changing the resolver; if you prefer,
> add the default to `ResolveTorConfig` instead and delete the rebuild.

- [ ] **Step 2: Start the syncer in the server's run/start path**

Find where `threatSyncer.Run(ctx)` / `.Start()` is launched (search `threatSyncer` in `server.go`) and start the Tor syncer the same way, guarded by nil:

```go
	if torSyncer != nil {
		go torSyncer.Run(ctx)
	}
```

> Place this beside the existing `threatSyncer` goroutine launch so it
> shares the same lifecycle context. If `threatSyncer` is started via a
> struct field on the server, store `torSyncer` analogously (add a
> `torSyncer *tor.Syncer` field next to `threatSyncer` at line 78).

Add imports to `server.go`: `"github.com/agentsh/agentsh/internal/tor"` (and confirm `fmt`, `path/filepath`, `log/slog`, `config` already imported — they are).

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(tor): wire Tor policy and relay-feed syncer into server startup"
```

---

## Task 11: End-to-end integration tests + gates

**Files:**
- Create: `internal/tor/integration_test.go` (engine-level end-to-end through the real `tor.Policy`)

- [ ] **Step 1: Write an engine-level end-to-end test using the real Policy + adapter**

Create `internal/tor/integration_test.go`:

```go
package tor_test

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/tor"
	"github.com/agentsh/agentsh/pkg/types"
)

func denyEngine(t *testing.T) *policy.Engine {
	t.Helper()
	// Minimal allow-all policy so any deny we see comes from Tor.
	p := &policy.Policy{
		CommandRules: []policy.CommandRule{{Name: "allow-all", Decision: "allow"}},
		NetworkRules: []policy.NetworkRule{{Name: "allow-all", Decision: "allow"}},
	}
	e, err := policy.NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tp, _ := tor.New(config.ResolveTorConfig(config.TorConfig{}))
	e.SetTorPolicy(&tor.PolicyAdapter{Policy: tp})
	return e
}

func TestE2E_TorBlocksAllVectors(t *testing.T) {
	e := denyEngine(t)

	if d := e.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("process vector: %+v", d)
	}
	if d := e.CheckNetworkIP("", net.ParseIP("127.0.0.1"), 9050); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("socks_port vector: %+v", d)
	}
	if d := e.CheckNetworkIP("", net.ParseIP("128.31.0.39"), 443); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("relay_ip vector: %+v", d)
	}
	if d := e.CheckNetworkCtx(nil, "abc.onion", 53); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("onion_dns vector: %+v", d)
	}
}
```

> Adjust `policy.Policy`/`CommandRule`/`NetworkRule` literals to the real
> struct field names (read `internal/policy/model.go`). The four asserts
> are the contract: deny-by-default blocks every vector through the real
> coordinator.

- [ ] **Step 2: Run the new test**

Run: `go test ./internal/tor/`
Expected: PASS.

- [ ] **Step 3: Full test suite (catches the OCSF exhaustiveness cross-package test)**

Run: `go test ./...`
Expected: PASS. If `internal/ocsf` fails on `tor_control`, re-check Task 6 Step 2.

- [ ] **Step 4: Cross-compile gate (per CLAUDE.md / AGENTS.md)**

Run: `GOOS=windows go build ./...`
Expected: clean (the `tor` config parses and builds on Windows; enforcement is Linux-runtime).

- [ ] **Step 5: roborev gate (per standing rule)**

Run roborev on the branch; fix every finding above `low` before proceeding.

- [ ] **Step 6: Commit**

```bash
git add internal/tor/integration_test.go
git commit -m "test(tor): end-to-end deny-by-default coverage across all vectors"
```

---

## Self-Review

**Spec coverage:**
- Top-level `tor:` block, deny-by-default, tri-state Enabled → Task 2. ✓
- Five vectors (process/socks_port/onion_dns/onion_http/relay_ip) → Tasks 4 (Eval), 8 (engine), 9 (emit). ✓
- Coordinator (approach A: dedicated checks + shared Policy, deny overrides allow, audit never loosens) → Tasks 4, 7, 8. ✓
- Built-in directory-authority seed (feed-independent) → Task 3, used in Task 4. ✓
- Net-new `ipset` primitive → Task 1. ✓
- Opt-in onionoo relay feed (all relays; disk cache; fail-closed to seed) → Task 5, wired in Task 10. ✓
- One `tor_control` event + OCSF registration gotcha → Task 6. ✓
- Honest subsystem scope: enforcement rides existing decision points (DNS/HTTP/ptrace-connect/execve); a door whose subsystem is off is a no-op → reflected by integrating at those exact sites (Task 9) and documented in the spec. ✓
- Gates: full `go test ./...`, `GOOS=windows go build`, roborev → Task 11. ✓
- Phase 2 (SOCKS gateway) intentionally absent. ✓

**Placeholder scan:** No "TBD"/"implement later". The few implementer notes (emit mechanism in `ptrace_handlers.go`, exact `policy.Policy` literal field names) point at concrete code to read and adapt, with the behavioral contract pinned by tests — not deferred work.

**Type consistency:** `Verdict`/`TorVerdict` field sets are identical (Vector/Mode/Decision/Target) so the `TorVerdict(v)` conversion in Task 8 and the `conv()` translation in Task 7 hold. Vector constants (`process`,`socks_port`,`onion_dns`,`onion_http`,`relay_ip`) are defined once in Task 4 and reused in Tasks 6/9. `EvalExecve/EvalConnect/EvalOnionName` signatures match across `tor.Policy` (Task 4), `policy.TorChecker` (Task 7), and the adapter (Task 7).

**Known adaptation points (read-before-write, not placeholders):**
1. `internal/policy` struct literal field names in tests (`Policy`, `CommandRule`, `NetworkRule`) — read `model.go`.
2. The exact emit mechanism + PID/session variables in `ptrace_handlers.go` `HandleNetwork`/`HandleExecve` — mirror the handler's existing event emission.
3. `types.Event.PID` field name — confirm in `pkg/types`.
