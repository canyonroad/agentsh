# Tor Access Control — Phase 2 (Onion Gateway) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `tor.mode: allow` and an `onion_rules:` list is present, turn agentsh into a SOCKS5-aware **managed Tor egress** that permits or denies individual `.onion`/clearnet targets per rule, forwarding allowed streams to the real Tor SOCKS daemon and resetting denied ones — with a `tor_control{vector: onion}` audit event per decision.

**Architecture:** A new per-session SOCKS5 front-end (`internal/netmonitor/socks.go`) terminates the app's SOCKS5 handshake, reads the CONNECT target, asks the existing global `tor.Policy` whether that target is allowed (new `EvalSocksTarget` against compiled `onion_rules`), and either proxies the stream to the real Tor daemon (acting as a SOCKS5 client) or replies "connection not allowed by ruleset" and closes. The front-end reuses the `tor.Policy` config source of truth, the `tor_control` event schema (new `vector: onion`), and the per-session emitter/sessionID already threaded through `TransparentTCP`. The transparent-TCP interceptor routes connections whose original destination is a configured Tor SOCKS port into this front-end instead of plain byte-splicing.

**Tech Stack:** Go 1.x, `internal/tor` (policy), `internal/netmonitor` (front-end + interception), `internal/config` (parsing), `internal/policy` (engine seam), `internal/session` (per-session gateway address), `github.com/google/uuid`, stdlib `net`.

## Global Constraints

- **Phase 2 is allow-mode-only.** The front-end is inert unless `tor.enabled: true` AND `tor.mode: allow` AND `len(onion_rules) > 0`. In `deny`/`audit` mode the Phase 1 controls are unchanged and the gateway never starts.
- **Fail-closed.** A SOCKS target that matches no `onion_rules` entry is **denied** (reset). Malformed SOCKS, an unreachable upstream, or any I/O error closes the client connection — never falls open to a direct connection.
- **Deny-by-default unaffected.** Adding an empty/absent `onion_rules` to an `allow`-mode config keeps today's behavior (Tor permitted, unfiltered). Phase 1 deny-by-default semantics (`ResolveTorConfig`) must not change.
- **Cross-compile clean.** `GOOS=windows go build ./...` must pass. Config parsing and the SOCKS protocol/front-end code are platform-neutral (no build tags); only the transparent-TCP routing hook (`transparent_tcp.go`, already `//go:build linux`) is Linux-gated.
- **OCSF.** `tor_control` is already registered in `internal/ocsf/registry.go`; `vector: onion` is a new *field value*, not a new `events.EventType`, so no registry change is required. A full `go test ./...` still runs (per Phase 1 spec) to confirm.
- **Honest scope.** Per-onion filtering only applies to Tor SOCKS connections that actually reach agentsh's transparent-TCP interceptor. In sandbox modes where the app reaches a loopback Tor daemon that is not within agentsh's interception, allow-mode degrades to Phase-1 allow (unfiltered) — documented in Task 8, not papered over.
- **Naming/precedence:** `onion_rules` are evaluated in listed order, first match wins (mirrors `connect_redirects` and `network_rules`). Glob matching uses `filepath.Match` semantics, consistent with `EvalExecve`.
- Verify cross-compile, run `go test ./...`, and run roborev between tasks; fix everything above low before proceeding (per `CLAUDE.md` / `AGENTS.md` and the Phase 1 spec gates).

---

## File Structure

- **`internal/config/tor.go`** (modify) — add `TorOnionRule`, `TorConfig.OnionRules`, `ResolvedTorConfig.OnionRules`; thread through `ResolveTorConfig` with decision validation.
- **`internal/tor/gateway.go`** (create) — compiled onion-rule matchers, `GatewayActive()`, `EvalSocksTarget()`, `UpstreamSocksAddr()`. Keeps `policy.go` focused on Phase 1.
- **`internal/tor/policy.go`** (modify) — add `VectorOnion` constant; build the compiled onion rules in `New`; allow `Verdict.Decision == "allow"`.
- **`internal/tor/adapter.go`** (modify) — extend `PolicyAdapter` with the two new seam methods (only if the engine needs them; see Task 6 — the front-end uses `*tor.Policy` directly, the engine seam is for the SOCKS-port routing predicate).
- **`internal/netmonitor/socks.go`** (create) — SOCKS5 wire parse/encode helpers + `handleTorSocks` orchestration + `TorGatewayPolicy` interface.
- **`internal/netmonitor/transparent_tcp.go`** (modify) — route original-destination = Tor SOCKS port into `handleTorSocks`; add `SetTorGateway`.
- **`internal/session/manager.go`** (modify) — per-session gateway address accessors (used for events/diagnostics; the front-end logic itself lives in netmonitor).
- **`internal/api/app.go`** (modify) — construct the front-end policy view + upstream addr and hand them to `TransparentTCP` when the gateway is active.
- **`internal/server/server.go`** (modify) — expose the constructed `*tor.Policy` so `App` can reach it (today only the `PolicyAdapter` is wired into the engine).
- **`docs/superpowers/specs/2026-06-14-tor-access-control-design.md`** (modify) — flip the Phase 2 section from "sketch" to "implemented"; document the honest-scope limitation.

---

## Task 1: Config — `onion_rules` parsing & resolution

**Files:**
- Modify: `internal/config/tor.go`
- Test: `internal/config/tor_test.go` (create if absent; otherwise append)

**Interfaces:**
- Produces:
  - `type TorOnionRule struct { Onion string; Decision string }`
  - `TorConfig.OnionRules []TorOnionRule` (yaml `onion_rules`)
  - `ResolvedTorConfig.OnionRules []TorOnionRule`
  - `ResolveTorConfig` copies/validates onion rules: `Decision` defaults to `"deny"` unless it is exactly `"allow"`.

- [ ] **Step 1: Write the failing test**

Append to `internal/config/tor_test.go`:

```go
func TestResolveTorConfig_OnionRules(t *testing.T) {
	in := TorConfig{
		Mode: "allow",
		OnionRules: []TorOnionRule{
			{Onion: "abc.onion", Decision: "allow"},
			{Onion: "*", Decision: "deny"},
			{Onion: "weird.onion", Decision: "bogus"}, // invalid → deny
		},
	}
	out := ResolveTorConfig(in)
	if len(out.OnionRules) != 3 {
		t.Fatalf("want 3 onion rules, got %d", len(out.OnionRules))
	}
	if out.OnionRules[0].Decision != "allow" {
		t.Errorf("rule0 decision = %q, want allow", out.OnionRules[0].Decision)
	}
	if out.OnionRules[1].Decision != "deny" {
		t.Errorf("rule1 decision = %q, want deny", out.OnionRules[1].Decision)
	}
	if out.OnionRules[2].Decision != "deny" {
		t.Errorf("rule2 (invalid) decision = %q, want deny", out.OnionRules[2].Decision)
	}
}

func TestResolveTorConfig_OnionRulesAbsent(t *testing.T) {
	out := ResolveTorConfig(TorConfig{Mode: "allow"})
	if len(out.OnionRules) != 0 {
		t.Fatalf("absent onion_rules should resolve empty, got %d", len(out.OnionRules))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestResolveTorConfig_OnionRules -v`
Expected: FAIL — `TorOnionRule` undefined / `OnionRules` not a field.

- [ ] **Step 3: Write minimal implementation**

In `internal/config/tor.go`, add the rule type after `TorRelayFeed`:

```go
// TorOnionRule is one Phase 2 gateway rule: match a SOCKS CONNECT target
// host (a .onion address or a clearnet host, with filepath.Match globbing)
// and allow or deny it. Evaluated in listed order, first match wins.
type TorOnionRule struct {
	Onion    string `yaml:"onion"`
	Decision string `yaml:"decision"` // allow | deny
}
```

Add the field to `TorConfig` (after `RelayFeed`):

```go
	OnionRules        []TorOnionRule `yaml:"onion_rules"`
```

Add the field to `ResolvedTorConfig` (after `RelayFeed`):

```go
	OnionRules        []TorOnionRule
```

In `ResolveTorConfig`, before `return out`, add:

```go
	for _, r := range in.OnionRules {
		decision := "deny"
		if r.Decision == "allow" {
			decision = "allow"
		}
		out.OnionRules = append(out.OnionRules, TorOnionRule{Onion: r.Onion, Decision: decision})
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestResolveTorConfig_OnionRules -v`
Expected: PASS (both new tests).

- [ ] **Step 5: Commit**

```bash
git add internal/config/tor.go internal/config/tor_test.go
git commit -m "feat(tor): parse onion_rules config for Phase 2 gateway"
```

---

## Task 2: `tor.Policy` — onion-rule matching & gateway activation

**Files:**
- Create: `internal/tor/gateway.go`
- Modify: `internal/tor/policy.go`
- Test: `internal/tor/gateway_test.go`

**Interfaces:**
- Consumes: `config.ResolvedTorConfig.OnionRules`, `config.ResolvedTorConfig.SocksPorts`, the existing `Verdict` struct and `New` constructor.
- Produces (on `*Policy`):
  - `const VectorOnion = "onion"` (in `policy.go`, with the other `Vector*` consts)
  - `func (p *Policy) GatewayActive() bool`
  - `func (p *Policy) EvalSocksTarget(host string, port int) (Verdict, bool)` — `ok=true` whenever `GatewayActive()`; `Decision` is `"allow"` or `"deny"`; default (no rule matches) is `"deny"`.
  - `func (p *Policy) UpstreamSocksAddr() string` — `"127.0.0.1:<first socks port>"`, or `""` if none.
  - field `onionRules []onionRule` populated in `New`.

- [ ] **Step 1: Write the failing test**

Create `internal/tor/gateway_test.go`:

```go
package tor

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func gwPolicy(t *testing.T, rules []config.TorOnionRule) *Policy {
	t.Helper()
	p, err := New(config.ResolvedTorConfig{
		Enabled:    true,
		Mode:       ModeAllow,
		SocksPorts: []int{9050, 9150},
		Vectors:    config.ResolvedTorVectors{Processes: true, SocksPorts: true, Onion: true, RelayIPs: true},
		OnionRules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGatewayActive(t *testing.T) {
	if gwPolicy(t, nil).GatewayActive() {
		t.Error("no onion_rules → gateway inactive")
	}
	if !gwPolicy(t, []config.TorOnionRule{{Onion: "*", Decision: "deny"}}).GatewayActive() {
		t.Error("allow mode + onion_rules → gateway active")
	}
	// deny mode is never a gateway, even with rules.
	p, _ := New(config.ResolvedTorConfig{Enabled: true, Mode: ModeDeny, SocksPorts: []int{9050},
		OnionRules: []config.TorOnionRule{{Onion: "*", Decision: "deny"}}})
	if p.GatewayActive() {
		t.Error("deny mode must not activate gateway")
	}
}

func TestEvalSocksTarget(t *testing.T) {
	p := gwPolicy(t, []config.TorOnionRule{
		{Onion: "good.onion", Decision: "allow"},
		{Onion: "*.evil.onion", Decision: "deny"},
		{Onion: "*", Decision: "deny"},
	})
	cases := []struct {
		host    string
		wantDec string
	}{
		{"good.onion", "allow"},
		{"GOOD.onion", "allow"},  // case-insensitive
		{"x.evil.onion", "deny"}, // glob
		{"random.onion", "deny"}, // catch-all
		{"example.com", "deny"},  // clearnet via Tor, catch-all denies
	}
	for _, c := range cases {
		v, ok := p.EvalSocksTarget(c.host, 443)
		if !ok {
			t.Fatalf("%s: expected ok (gateway active)", c.host)
		}
		if v.Decision != c.wantDec {
			t.Errorf("%s: decision = %q, want %q", c.host, v.Decision, c.wantDec)
		}
		if v.Vector != VectorOnion {
			t.Errorf("%s: vector = %q, want onion", c.host, v.Vector)
		}
	}
}

func TestEvalSocksTarget_NoMatchFailsClosed(t *testing.T) {
	p := gwPolicy(t, []config.TorOnionRule{{Onion: "only.onion", Decision: "allow"}})
	v, ok := p.EvalSocksTarget("other.onion", 443)
	if !ok || v.Decision != "deny" {
		t.Fatalf("unmatched target must fail closed: ok=%v dec=%q", ok, v.Decision)
	}
}

func TestUpstreamSocksAddr(t *testing.T) {
	if got := gwPolicy(t, nil).UpstreamSocksAddr(); got != "127.0.0.1:9050" {
		t.Errorf("UpstreamSocksAddr = %q, want 127.0.0.1:9050", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tor/ -run 'TestGateway|TestEvalSocks|TestUpstream' -v`
Expected: FAIL — `GatewayActive`, `EvalSocksTarget`, `VectorOnion`, `UpstreamSocksAddr` undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/tor/policy.go`, add the constant to the `Vector*` block:

```go
	VectorOnion     = "onion" // Phase 2 SOCKS gateway
```

Add a field to the `Policy` struct (after `relays`):

```go
	onionRules []onionRule // Phase 2 gateway rules, compiled in order
```

In `New`, after the relay-seed loop and before `p.relays.Store(...)`, add:

```go
	for _, r := range cfg.OnionRules {
		p.onionRules = append(p.onionRules, onionRule{
			pattern:  strings.ToLower(strings.TrimSpace(r.Onion)),
			decision: r.Decision,
		})
	}
```

Create `internal/tor/gateway.go`:

```go
package tor

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// onionRule is a compiled Phase 2 gateway rule.
type onionRule struct {
	pattern  string // lowercased onion/host glob (filepath.Match)
	decision string // "allow" | "deny"
}

// GatewayActive reports whether the Phase 2 SOCKS onion gateway should run:
// enabled, mode=allow, and at least one onion rule configured.
func (p *Policy) GatewayActive() bool {
	return p != nil && p.cfg.Enabled && p.cfg.Mode == ModeAllow && len(p.onionRules) > 0
}

// EvalSocksTarget evaluates a SOCKS CONNECT target host:port against the
// onion rules. When the gateway is active it always returns ok=true with a
// concrete allow/deny decision; an unmatched target fails closed (deny).
func (p *Policy) EvalSocksTarget(host string, port int) (Verdict, bool) {
	if !p.GatewayActive() {
		return Verdict{}, false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	target := net.JoinHostPort(host, strconv.Itoa(port))
	for _, r := range p.onionRules {
		if r.pattern == h {
			return p.onionVerdict(r.decision, target), true
		}
		if m, err := filepath.Match(r.pattern, h); err == nil && m {
			return p.onionVerdict(r.decision, target), true
		}
	}
	return p.onionVerdict("deny", target), true // fail closed
}

func (p *Policy) onionVerdict(decision, target string) Verdict {
	return Verdict{
		Vector:   VectorOnion,
		Mode:     p.cfg.Mode,
		Decision: decision,
		Target:   target,
	}
}

// UpstreamSocksAddr returns the loopback address of the real Tor SOCKS
// daemon (the gateway forwards allowed streams here). Empty if unset.
func (p *Policy) UpstreamSocksAddr() string {
	if p == nil || len(p.cfg.SocksPorts) == 0 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(p.cfg.SocksPorts[0]))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tor/ -run 'TestGateway|TestEvalSocks|TestUpstream' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tor/gateway.go internal/tor/policy.go internal/tor/gateway_test.go
git commit -m "feat(tor): onion-rule matching + gateway activation (EvalSocksTarget)"
```

---

## Task 3: SOCKS5 wire parse/encode helpers

**Files:**
- Create: `internal/netmonitor/socks.go`
- Test: `internal/netmonitor/socks_test.go`

**Interfaces:**
- Produces (package `netmonitor`, unexported, pure I/O over `io.Reader`/`io.Writer`):
  - `func readSocksGreeting(r io.Reader) error` — reads `VER NMETHODS METHODS`, errors unless `VER==5`.
  - `func writeSocksMethod(w io.Writer, method byte) error` — writes `05 <method>`.
  - `type socksReq struct { atyp byte; addr []byte; host string; port int }`
  - `func readSocksConnect(r io.Reader) (socksReq, error)` — reads `VER CMD RSV ATYP ADDR PORT`, errors unless `VER==5 && CMD==1`.
  - `func encodeConnectReq(req socksReq) []byte` — re-encodes the request to send upstream.
  - `func writeSocksReply(w io.Writer, rep byte) error` — writes `05 REP 00 01 00000000 0000` (IPv4 null bind addr).
  - SOCKS reply constants: `socksRepSuccess = 0x00`, `socksRepNotAllowed = 0x02`, `socksRepGeneralFailure = 0x01`.

- [ ] **Step 1: Write the failing test**

Create `internal/netmonitor/socks_test.go`:

```go
package netmonitor

import (
	"bytes"
	"testing"
)

func TestReadSocksConnect_Domain(t *testing.T) {
	// VER CMD RSV ATYP LEN "ab.onion" PORT(443)
	host := "ab.onion"
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	buf = append(buf, []byte(host)...)
	buf = append(buf, 0x01, 0xBB) // 443
	req, err := readSocksConnect(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "ab.onion" || req.port != 443 || req.atyp != 0x03 {
		t.Fatalf("got host=%q port=%d atyp=%d", req.host, req.port, req.atyp)
	}
}

func TestReadSocksConnect_IPv4(t *testing.T) {
	buf := []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x00, 0x50} // 10.0.0.7:80
	req, err := readSocksConnect(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "10.0.0.7" || req.port != 80 {
		t.Fatalf("got host=%q port=%d", req.host, req.port)
	}
}

func TestReadSocksConnect_RejectsNonConnect(t *testing.T) {
	buf := []byte{0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0, 80} // CMD=2 (bind)
	if _, err := readSocksConnect(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected error for non-CONNECT command")
	}
}

func TestEncodeConnectReq_RoundTrips(t *testing.T) {
	host := "x.onion"
	in := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	in = append(in, []byte(host)...)
	in = append(in, 0x01, 0xBB)
	req, err := readSocksConnect(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeConnectReq(req); !bytes.Equal(got, in) {
		t.Fatalf("re-encode mismatch:\n got %v\nwant %v", got, in)
	}
}

func TestGreetingAndReply(t *testing.T) {
	greet := []byte{0x05, 0x01, 0x00} // 1 method: no-auth
	if err := readSocksGreeting(bytes.NewReader(greet)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeSocksReply(&out, socksRepNotAllowed); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, socksRepNotAllowed, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("reply = %v, want %v", out.Bytes(), want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/ -run 'TestReadSocks|TestEncodeConnect|TestGreeting' -v`
Expected: FAIL — undefined `readSocksConnect` etc.

- [ ] **Step 3: Write minimal implementation**

Create `internal/netmonitor/socks.go`:

```go
package netmonitor

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5 reply codes (RFC 1928).
const (
	socksVer               = 0x05
	socksCmdConnect        = 0x01
	socksRepSuccess        = 0x00
	socksRepGeneralFailure = 0x01
	socksRepNotAllowed     = 0x02 // connection not allowed by ruleset

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// readSocksGreeting consumes the client's method-selection greeting:
// VER NMETHODS METHODS...
func readSocksGreeting(r io.Reader) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	if head[0] != socksVer {
		return fmt.Errorf("socks: bad version 0x%02x", head[0])
	}
	n := int(head[1])
	if n > 0 {
		if _, err := io.ReadFull(r, make([]byte, n)); err != nil {
			return err
		}
	}
	return nil
}

// writeSocksMethod replies to the greeting with the selected method.
func writeSocksMethod(w io.Writer, method byte) error {
	_, err := w.Write([]byte{socksVer, method})
	return err
}

type socksReq struct {
	atyp byte
	addr []byte // raw address bytes (domain text, or 4/16-byte IP)
	host string
	port int
}

// readSocksConnect reads a CONNECT request: VER CMD RSV ATYP ADDR PORT.
func readSocksConnect(r io.Reader) (socksReq, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return socksReq{}, err
	}
	if head[0] != socksVer {
		return socksReq{}, fmt.Errorf("socks: bad version 0x%02x", head[0])
	}
	if head[1] != socksCmdConnect {
		return socksReq{}, fmt.Errorf("socks: unsupported command 0x%02x", head[1])
	}
	var req socksReq
	req.atyp = head[3]
	switch req.atyp {
	case atypIPv4:
		req.addr = make([]byte, 4)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypIPv6:
		req.addr = make([]byte, 16)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return socksReq{}, err
		}
		req.addr = make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = string(req.addr)
	default:
		return socksReq{}, fmt.Errorf("socks: bad atyp 0x%02x", req.atyp)
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(r, portB); err != nil {
		return socksReq{}, err
	}
	req.port = int(binary.BigEndian.Uint16(portB))
	return req, nil
}

// encodeConnectReq re-serializes a CONNECT request for the upstream Tor SOCKS.
func encodeConnectReq(req socksReq) []byte {
	out := []byte{socksVer, socksCmdConnect, 0x00, req.atyp}
	if req.atyp == atypDomain {
		out = append(out, byte(len(req.addr)))
	}
	out = append(out, req.addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(req.port))
	return append(out, p[:]...)
}

// writeSocksReply writes a reply with a null IPv4 bind address.
func writeSocksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socksVer, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/ -run 'TestReadSocks|TestEncodeConnect|TestGreeting' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/socks_test.go
git commit -m "feat(tor): SOCKS5 greeting/CONNECT parse + reply encode helpers"
```

---

## Task 4: Tor onion gateway handler (`handleTorSocks`)

**Files:**
- Modify: `internal/netmonitor/socks.go`
- Test: `internal/netmonitor/socks_handler_test.go`

**Interfaces:**
- Consumes: `socksReq`, `readSocksGreeting`, `writeSocksMethod`, `readSocksConnect`, `encodeConnectReq`, `writeSocksReply`, the `Emitter` interface (`internal/netmonitor/proxy.go:25`), `tor.Verdict` + `tor.BuildControlEvent` + `tor.VectorOnion`.
- Produces:
  - `type TorGatewayPolicy interface { GatewayActive() bool; EvalSocksTarget(host string, port int) (tor.Verdict, bool) }` (satisfied by `*tor.Policy`).
  - `func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string) error` — terminates the client SOCKS5 handshake, evaluates the target, forwards allowed streams to `upstreamAddr` (as a SOCKS5 client) or replies `socksRepNotAllowed`; emits one `tor_control{vector: onion}` event per decision.

- [ ] **Step 1: Write the failing test**

Create `internal/netmonitor/socks_handler_test.go`:

```go
package netmonitor

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/tor"
	"github.com/agentsh/agentsh/pkg/types"
)

// fakeGatewayPolicy allows exactly one host.
type fakeGatewayPolicy struct{ allow string }

func (f fakeGatewayPolicy) GatewayActive() bool { return true }
func (f fakeGatewayPolicy) EvalSocksTarget(host string, port int) (tor.Verdict, bool) {
	dec := "deny"
	if host == f.allow {
		dec = "allow"
	}
	return tor.Verdict{Vector: tor.VectorOnion, Mode: "allow", Decision: dec, Target: host}, true
}

// captureEmitter records published events.
type captureEmitter struct {
	mu  sync.Mutex
	evs []types.Event
}

func (c *captureEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	c.mu.Lock()
	c.evs = append(c.evs, ev)
	c.mu.Unlock()
	return nil
}
func (c *captureEmitter) Publish(_ types.Event) {}
func (c *captureEmitter) events() []types.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]types.Event(nil), c.evs...)
}

// fakeTorUpstream is a minimal SOCKS5 server that always succeeds and echoes.
func fakeTorUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = readSocksGreeting(c)
				_ = writeSocksMethod(c, 0x00)
				if _, err := readSocksConnect(c); err != nil {
					return
				}
				_ = writeSocksReply(c, socksRepSuccess)
				_, _ = io.Copy(c, c) // echo
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// drive runs a SOCKS5 client handshake for host:port over conn and returns the reply code.
func driveClient(t *testing.T, conn net.Conn, host string, port int) byte {
	t.Helper()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // greeting
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(encodeConnectReq(socksReq{atyp: atypDomain, addr: []byte(host), host: host, port: port}))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func TestHandleTorSocks_Allowed(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()

	client, server := net.Pipe()
	emit := &captureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()

	rep := driveClient(t, client, "ok.onion", 443)
	if rep != socksRepSuccess {
		t.Fatalf("allowed target got reply 0x%02x, want success", rep)
	}
	// data path echoes through real upstream
	_, _ = client.Write([]byte("ping"))
	got := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
	client.Close()

	assertOneOnionEvent(t, emit, "allow")
}

func TestHandleTorSocks_Denied(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()

	client, server := net.Pipe()
	emit := &captureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()

	rep := driveClient(t, client, "blocked.onion", 443)
	if rep != socksRepNotAllowed {
		t.Fatalf("denied target got reply 0x%02x, want not-allowed", rep)
	}
	client.Close()
	assertOneOnionEvent(t, emit, "deny")
}

func assertOneOnionEvent(t *testing.T, emit *captureEmitter, wantDecision string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range emit.events() {
			if ev.Type == "tor_control" && ev.Fields["vector"] == tor.VectorOnion {
				if ev.Fields["decision"] != wantDecision {
					t.Fatalf("event decision = %v, want %v", ev.Fields["decision"], wantDecision)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no tor_control{vector:onion,decision:%s} event seen", wantDecision)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestHandleTorSocks -v`
Expected: FAIL — `TorGatewayPolicy` / `handleTorSocks` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/netmonitor/socks.go`:

```go
import (
	"context"

	"github.com/agentsh/agentsh/internal/tor"
)
// (merge these into the existing import block; net/encoding-binary/io/fmt already present)

// TorGatewayPolicy is the subset of *tor.Policy the SOCKS front-end needs.
type TorGatewayPolicy interface {
	GatewayActive() bool
	EvalSocksTarget(host string, port int) (tor.Verdict, bool)
}

// handleTorSocks terminates a client SOCKS5 CONNECT, evaluates the target
// against the onion gateway policy, and either proxies the stream to the
// real Tor SOCKS daemon at upstreamAddr or replies "not allowed by ruleset".
// Fail-closed on any error. Emits one tor_control{vector:onion} event.
func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string) error {
	defer conn.Close()

	if err := readSocksGreeting(conn); err != nil {
		return err
	}
	if err := writeSocksMethod(conn, 0x00); err != nil { // no-auth
		return err
	}
	req, err := readSocksConnect(conn)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}

	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, v)
	}
	if !ok || v.Decision != "allow" {
		_ = writeSocksReply(conn, socksRepNotAllowed)
		return nil
	}

	up, err := net.DialTimeout("tcp", upstreamAddr, 20*time.Second)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	defer up.Close()

	// Act as a SOCKS5 client to the real Tor daemon for the same target.
	if _, err := up.Write([]byte{socksVer, 0x01, 0x00}); err != nil { // greeting: 1 method, no-auth
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := io.ReadFull(up, make([]byte, 2)); err != nil { // method selection
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := up.Write(encodeConnectReq(req)); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	upReply, err := readSocksReply(up)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	// Relay the upstream's reply verbatim to the client.
	if _, err := conn.Write(upReply); err != nil {
		return err
	}

	splice(conn, up)
	return nil
}

// readSocksReply reads a full SOCKS5 reply (VER REP RSV ATYP ADDR PORT).
func readSocksReply(r io.Reader) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		head = append(head, lb[0])
		addrLen = int(lb[0])
	default:
		return nil, fmt.Errorf("socks: bad reply atyp 0x%02x", head[3])
	}
	rest := make([]byte, addrLen+2) // addr + port
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

func splice(a, b net.Conn) {
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(a, b); errCh <- e }()
	go func() { _, e := io.Copy(b, a); errCh <- e }()
	<-errCh
}

func emitOnionEvent(emit Emitter, sessionID, commandID string, v tor.Verdict) {
	if emit == nil {
		return
	}
	ev := tor.BuildControlEvent(sessionID, commandID, 0, v)
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}
```

Note: `time` is already imported by other netmonitor files but not yet by `socks.go` — add `"time"` to the import block. Confirm the final import set is `context`, `encoding/binary`, `fmt`, `io`, `net`, `time`, and `github.com/agentsh/agentsh/internal/tor`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestHandleTorSocks -v`
Expected: PASS (both allowed and denied).

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go
git commit -m "feat(tor): SOCKS5 onion gateway handler (forward allowed, reset denied)"
```

---

## Task 5: Route Tor SOCKS-port connections into the gateway (transparent_tcp)

**Files:**
- Modify: `internal/netmonitor/transparent_tcp.go`
- Test: `internal/netmonitor/transparent_tcp_gateway_test.go`

**Interfaces:**
- Consumes: `TorGatewayPolicy`, `handleTorSocks`, the existing `TransparentTCP` struct + `handle` method.
- Produces:
  - `type torGatewayConfig struct { pol TorGatewayPolicy; upstream string; socksPorts map[int]struct{} }`
  - `func (t *TransparentTCP) SetTorGateway(pol TorGatewayPolicy, upstream string, socksPorts []int)` — stores an `atomic.Pointer[torGatewayConfig]`; nil/empty input clears it.
  - `func (t *TransparentTCP) torGatewayFor(port int) (*torGatewayConfig, bool)` — returns the config when active and `port` is a configured Tor SOCKS port.
  - In `handle`: after `originalDst` yields `dstPort`, if `torGatewayFor(dstPort)` matches, call `handleTorSocks(conn, cfg.upstream, cfg.pol, t.emit, t.sessionID, commandID)` and return (skip the normal splice path).

- [ ] **Step 1: Write the failing test**

Create `internal/netmonitor/transparent_tcp_gateway_test.go`:

```go
//go:build linux

package netmonitor

import "testing"

func TestSetTorGateway_PortPredicate(t *testing.T) {
	tcp := &TransparentTCP{}
	tcp.SetTorGateway(fakeGatewayPolicy{allow: "ok.onion"}, "127.0.0.1:9050", []int{9050, 9150})

	if _, ok := tcp.torGatewayFor(9050); !ok {
		t.Error("9050 should route to gateway")
	}
	if _, ok := tcp.torGatewayFor(9150); !ok {
		t.Error("9150 should route to gateway")
	}
	if _, ok := tcp.torGatewayFor(443); ok {
		t.Error("443 must NOT route to gateway")
	}

	// Clearing disables routing.
	tcp.SetTorGateway(nil, "", nil)
	if _, ok := tcp.torGatewayFor(9050); ok {
		t.Error("cleared gateway must not route")
	}
}
```

(`fakeGatewayPolicy` is defined in `socks_handler_test.go`, same package.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestSetTorGateway -v`
Expected: FAIL — `SetTorGateway` / `torGatewayFor` undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/netmonitor/transparent_tcp.go`, add a field to the `TransparentTCP` struct (after `dbBypass`):

```go
	torGW atomic.Pointer[torGatewayConfig]
```

Add the type and methods (near the bottom of the file, before `originalDst`):

```go
type torGatewayConfig struct {
	pol        TorGatewayPolicy
	upstream   string
	socksPorts map[int]struct{}
}

// SetTorGateway enables (or, with nil/empty args, disables) Phase 2 onion
// gateway routing for connections whose original destination is a Tor SOCKS
// port. Safe to call concurrently.
func (t *TransparentTCP) SetTorGateway(pol TorGatewayPolicy, upstream string, socksPorts []int) {
	if t == nil {
		return
	}
	if pol == nil || upstream == "" || len(socksPorts) == 0 {
		t.torGW.Store(nil)
		return
	}
	ports := make(map[int]struct{}, len(socksPorts))
	for _, p := range socksPorts {
		ports[p] = struct{}{}
	}
	t.torGW.Store(&torGatewayConfig{pol: pol, upstream: upstream, socksPorts: ports})
}

// torGatewayFor returns the gateway config when it is active and port is a
// configured Tor SOCKS port.
func (t *TransparentTCP) torGatewayFor(port int) (*torGatewayConfig, bool) {
	cfg := t.torGW.Load()
	if cfg == nil || !cfg.pol.GatewayActive() {
		return nil, false
	}
	if _, ok := cfg.socksPorts[port]; !ok {
		return nil, false
	}
	return cfg, true
}
```

In `handle`, insert the routing check immediately after the `redirectHostPort := ...` / `commandID` are known — specifically right after the `engine := t.policyEngine()` line and before the connect-redirect evaluation:

```go
	if cfg, ok := t.torGatewayFor(dstPort); ok {
		return handleTorSocks(conn, cfg.upstream, cfg.pol, t.emit, t.sessionID, commandID)
	}
```

(Place it after `commandID` is assigned at `transparent_tcp.go` ~line 114 so the event carries the command id. `handleTorSocks` calls `conn.Close()` itself; returning here skips the normal `defer conn.Close()` double-close because `defer` on an already-closed conn is a no-op.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestSetTorGateway -v`
Expected: PASS.

- [ ] **Step 5: Run the full netmonitor package to catch regressions**

Run: `go test ./internal/netmonitor/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/transparent_tcp.go internal/netmonitor/transparent_tcp_gateway_test.go
git commit -m "feat(tor): route Tor SOCKS-port connections into the onion gateway"
```

---

## Task 6: Expose `*tor.Policy` from the server to the App

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/api/app.go`
- Test: `internal/server/server_test.go` (append) — or a focused App accessor test if server tests are heavy.

**Interfaces:**
- Consumes: the `torPol` already built in `server.go:210`.
- Produces:
  - `Server` retains `torPol *tor.Policy` (new field) set during construction.
  - `App` gains a `torPolicy *tor.Policy` field, populated wherever `App` is constructed from server state (follow the existing `a.policy`, `a.approvals`, `a.dbBypass` wiring).
  - `func (a *App) torGateway() (pol *tor.Policy, upstream string, socksPorts []int, ok bool)` — returns `ok=true` only when `a.torPolicy != nil && a.torPolicy.GatewayActive()`.

- [ ] **Step 1: Write the failing test**

Append to the appropriate App test file (`internal/api/app_test.go`); if none exists, create it:

```go
func TestApp_torGateway(t *testing.T) {
	pol, err := tor.New(config.ResolvedTorConfig{
		Enabled: true, Mode: tor.ModeAllow, SocksPorts: []int{9050},
		OnionRules: []config.TorOnionRule{{Onion: "*", Decision: "deny"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &App{torPolicy: pol}
	p, upstream, ports, ok := a.torGateway()
	if !ok || p == nil || upstream != "127.0.0.1:9050" || len(ports) != 1 {
		t.Fatalf("torGateway() = %v %q %v %v", p, upstream, ports, ok)
	}

	// Inactive when no policy.
	if _, _, _, ok := (&App{}).torGateway(); ok {
		t.Error("nil torPolicy must be inactive")
	}
}
```

Add imports `"github.com/agentsh/agentsh/internal/config"` and `"github.com/agentsh/agentsh/internal/tor"` to the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestApp_torGateway -v`
Expected: FAIL — `App` has no `torPolicy` field / no `torGateway` method.

- [ ] **Step 3: Write minimal implementation**

In `internal/server/server.go`, add a `torPol *tor.Policy` field to the `Server` struct (near `torSyncer`). In the constructor block at lines 203–219, capture the policy outside the `if`:

```go
	torCfg := config.ResolveTorConfig(cfg.Tor)
	var torSyncer *tor.Syncer
	var torPol *tor.Policy
	if torCfg.Enabled {
		if torCfg.RelayFeed.Enabled && torCfg.RelayFeed.CacheDir == "" {
			torCfg.RelayFeed.CacheDir = filepath.Join(config.GetDataDir(), "tor-relays")
		}
		p, err := tor.New(torCfg)
		if err != nil {
			return nil, fmt.Errorf("tor policy: %w", err)
		}
		torPol = p
		engine.SetTorPolicy(&tor.PolicyAdapter{Policy: torPol})
		slog.Info("tor access control enabled", "mode", torCfg.Mode)
		if torPol.RelayFeedEnabled() {
			torSyncer = tor.NewSyncer(torPol, slog.Default())
		}
	}
```

Assign `torPol:` into the `Server{...}` literal (near `torSyncer:` at ~line 782) and thread it into the `App` wherever `App` is built (search for where `a.policy`/the `App` struct literal is constructed from `Server`; add `torPolicy: s.torPol`).

In `internal/api/app.go`, add the field to the `App` struct:

```go
	torPolicy *tor.Policy
```

Add the accessor (anywhere in `app.go`):

```go
// torGateway reports the Phase 2 onion-gateway wiring when active.
func (a *App) torGateway() (pol *tor.Policy, upstream string, socksPorts []int, ok bool) {
	if a == nil || a.torPolicy == nil || !a.torPolicy.GatewayActive() {
		return nil, "", nil, false
	}
	return a.torPolicy, a.torPolicy.UpstreamSocksAddr(), a.torPolicy.ConfiguredSocksPorts(), true
}
```

This needs `*tor.Policy` to expose its configured SOCKS ports. Add to `internal/tor/gateway.go`:

```go
// ConfiguredSocksPorts returns the SOCKS ports treated as Tor (for routing).
func (p *Policy) ConfiguredSocksPorts() []int {
	if p == nil {
		return nil
	}
	return append([]int(nil), p.cfg.SocksPorts...)
}
```

Add the `tor` import to `internal/api/app.go` if not already present.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestApp_torGateway -v`
Expected: PASS.

- [ ] **Step 5: Build the whole tree**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/server/server.go internal/api/app.go internal/tor/gateway.go internal/api/app_test.go
git commit -m "feat(tor): expose tor.Policy to App for gateway wiring"
```

---

## Task 7: Start the gateway per session (lifecycle wiring)

**Files:**
- Modify: `internal/api/app.go` (`tryStartTransparentNetwork`)
- Modify: `internal/session/manager.go` (gateway-address accessors, for diagnostics)
- Test: `internal/session/manager_test.go` (append)

**Interfaces:**
- Consumes: `App.torGateway()`, `TransparentTCP.SetTorGateway`.
- Produces:
  - `func (s *Session) SetTorGatewayAddr(addr string)` / `func (s *Session) TorGatewayAddr() string` (mutex-guarded, mirroring existing `Session` accessors).
  - In `tryStartTransparentNetwork`, after `StartTransparentTCP` succeeds: if `a.torGateway()` is active, call `tcp.SetTorGateway(pol, upstream, socksPorts)` and `s.SetTorGatewayAddr(upstream)`.

- [ ] **Step 1: Write the failing test (session accessor)**

Append to `internal/session/manager_test.go`:

```go
func TestSession_TorGatewayAddr(t *testing.T) {
	s := &Session{}
	if s.TorGatewayAddr() != "" {
		t.Error("default gateway addr should be empty")
	}
	s.SetTorGatewayAddr("127.0.0.1:9050")
	if s.TorGatewayAddr() != "127.0.0.1:9050" {
		t.Errorf("got %q", s.TorGatewayAddr())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/session/ -run TestSession_TorGatewayAddr -v`
Expected: FAIL — accessors undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/session/manager.go`, add a field to `Session` (look at the existing mutex-guarded fields; reuse the session's existing `sync.Mutex`/`sync.RWMutex`):

```go
	torGatewayAddr string
```

Add accessors (place near `CurrentCommandID`):

```go
// SetTorGatewayAddr records the per-session Tor onion-gateway upstream addr.
func (s *Session) SetTorGatewayAddr(addr string) {
	s.mu.Lock()
	s.torGatewayAddr = addr
	s.mu.Unlock()
}

// TorGatewayAddr returns the recorded gateway upstream addr (empty if none).
func (s *Session) TorGatewayAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.torGatewayAddr
}
```

(Confirm the lock field name by reading the `Session` struct at `internal/session/manager.go:29`; use whatever mutex the sibling accessors use. If `CurrentCommandID` uses `s.mu`, match it.)

In `internal/api/app.go`, in `tryStartTransparentNetwork`, right after the `tcp, tcpPort, err := netmonitor.StartTransparentTCP(...)` success check, add:

```go
	if pol, upstream, socksPorts, ok := a.torGateway(); ok {
		tcp.SetTorGateway(pol, upstream, socksPorts)
		s.SetTorGatewayAddr(upstream)
		slog.Info("tor onion gateway active for session", "session", s.ID, "upstream", upstream)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/session/ -run TestSession_TorGatewayAddr -v`
Expected: PASS.

- [ ] **Step 5: Build + vet the touched packages**

Run: `go build ./... && go vet ./internal/api/ ./internal/session/ ./internal/netmonitor/`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/api/app.go internal/session/manager.go internal/session/manager_test.go
git commit -m "feat(tor): start onion gateway per session in transparent network setup"
```

---

## Task 8: Docs, spec status, and full gates

**Files:**
- Modify: `docs/superpowers/specs/2026-06-14-tor-access-control-design.md`
- Modify: any sample config / README that documents the `tor:` block (search first).

**Interfaces:**
- Consumes: nothing (documentation + verification only).

- [ ] **Step 1: Update the design spec Phase 2 section**

In `docs/superpowers/specs/2026-06-14-tor-access-control-design.md`:

- Change the header `**Status:**` line to: `**Status:** Approved — Phase 1 + Phase 2 implemented`.
- Change the `## Phase 2 (sketch — documented, not built)` heading to `## Phase 2 (onion gateway — implemented)`.
- Append this honest-scope paragraph at the end of the Phase 2 section:

```markdown
**Honest scope (Phase 2).** Per-`.onion` filtering applies to Tor SOCKS
connections that reach agentsh's transparent-TCP interceptor (original
destination = a configured `socks_ports` entry). A `.onion`/clearnet target
matching no `onion_rules` entry is denied (fail-closed); allowed targets are
forwarded to the real Tor SOCKS daemon at `127.0.0.1:<socks_ports[0]>`. In
sandbox modes where the app reaches a loopback Tor daemon that is *not* within
agentsh's interception, allow-mode degrades to Phase-1 allow (Tor permitted,
unfiltered) — the operator must route the Tor SOCKS port through agentsh's
transparent interception for the gateway to take effect. The gateway emits one
`tor_control{vector: onion, decision: allow|deny}` event per CONNECT; like the
other connection-layer vectors it reports `pid: 0` and is correlated by session
and target.
```

- [ ] **Step 2: Update sample config (if present)**

Run: `grep -rln "onion_rules\|tor:" --include=*.yaml --include=*.yml --include=*.md . | grep -v docs/superpowers/plans`
For any sample config that shows the `tor:` block, add a commented allow-mode example:

```yaml
# Phase 2 onion gateway: permit specific onions, deny the rest.
# tor:
#   mode: allow
#   onion_rules:
#     - onion: "abcdefghij234567.onion"
#       decision: allow
#     - onion: "*"
#       decision: deny
```

- [ ] **Step 3: Cross-compile gate**

Run: `GOOS=windows go build ./...`
Expected: clean (config + SOCKS code is platform-neutral; the routing hook is already `//go:build linux`).

- [ ] **Step 4: Full test gate**

Run: `go test ./...`
Expected: PASS, including `TestExhaustiveness_AllEventTypesRegistered` in `internal/ocsf` (no new `EventType`, so it stays green).

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-06-14-tor-access-control-design.md
git commit -m "docs(tor): mark Phase 2 onion gateway implemented; document honest scope"
```

- [ ] **Step 6: roborev**

Run roborev on the branch; fix everything above low before declaring done (per Phase 1 spec gates and `feedback_roborev_between_tasks`).

---

## Self-Review

**1. Spec coverage** (against the Phase 2 sketch, design spec lines 356–384):
- "Redirect the app→`127.0.0.1:9050` connection … into agentsh's own SOCKS5 front-end" → Task 5 (transparent-TCP routing) + Task 7 (per-session start). The redirect uses SO_ORIGINAL_DST already read by `transparent_tcp.handle`; honest-scope limit documented (Task 8).
- "New `internal/netmonitor/socks.go` parses the SOCKS5 greeting + CONNECT request and extracts the target host" → Tasks 3 + 4.
- "Match the target against `onion_rules` … through `tor.Policy`" → Tasks 1 + 2 (`EvalSocksTarget`).
- "Allowed streams forwarded to the real Tor SOCKS daemon; denied streams are reset. Stateful, fail-closed." → Task 4 (`handleTorSocks`: forward vs `socksRepNotAllowed`; fail-closed on no-match and on errors).
- "Reuses connect-redirect, `tor.Policy`, and the `tor_control` event schema (new `vector: onion`)" → `VectorOnion` (Task 2), `tor.BuildControlEvent` reuse (Task 4), `tor.Policy` config source of truth.
- Config example (`onion_rules`, `*: deny`) → Task 1 parsing + Task 8 sample.

**2. Placeholder scan:** No "TBD"/"implement later". Every code step shows full code; the one judgment call (which `Session` mutex to reuse) is flagged with the exact file:line to read first, not left vague.

**3. Type consistency:**
- `EvalSocksTarget(host string, port int) (tor.Verdict, bool)` — identical signature in the `TorGatewayPolicy` interface (Task 4), the `fakeGatewayPolicy` test double (Task 4), and `*tor.Policy` (Task 2). ✓
- `Verdict.Decision` values: Phase 1 uses `"deny"`/`"audit"`; Task 2 adds `"allow"` for the gateway only. `BuildControlEvent` copies the field verbatim — no enum gate to update. ✓
- `SetTorGateway(pol TorGatewayPolicy, upstream string, socksPorts []int)` — same in Task 5 (definition) and Task 7 (call). ✓
- `ConfiguredSocksPorts()` defined in Task 6, consumed by `torGateway()` in the same task. ✓
- `VectorOnion = "onion"` defined once (Task 2), referenced in tests + handler. ✓

**Open verification for the implementer (do before Task 5/7):**
- Confirm `transparent_tcp.handle` reaches Tor-SOCKS connections in your target sandbox mode. If loopback Tor is not within transparent interception, add the documented iptables `REDIRECT` of `socks_ports` → the gateway (out of scope for this plan's code; noted in Task 8 honest-scope).
- Confirm the `Session` lock field name at `internal/session/manager.go:29` before writing Task 7's accessors.
