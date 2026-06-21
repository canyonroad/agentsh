# Tor Access Control — Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Phase-2 allow-mode onion-gateway fail-open gap: guarantee the app's Tor SOCKS connection reaches the gateway (force-redirect), deny Tor for the session when the gateway can't be wired (fail-closed), and fix the pre-existing gap where per-session policy engines drop the Tor coordinator.

**Architecture:** One per-session predicate at startup picks a branch. Force-redirect adds a netns loopback-DNAT for `socks_ports` so loopback Tor reaches the existing transparent-TCP interceptor. Fail-closed attaches a deny-mode Tor policy clone to the session's engine. A foundational task first wires the shared Tor coordinator onto every per-session engine, since the fail-closed seam and Phase-1 enforcement both depend on it.

**Tech Stack:** Go, Linux network namespaces + iptables (`internal/netmonitor/netns_linux.go`), the policy engine + Tor coordinator (`internal/policy`, `internal/tor`), session/app wiring (`internal/api`).

## Global Constraints

- **No new data path; no new `events.EventType`.** Reuse the `tor_control` event (`Type: "tor_control"`, free-form `Fields map[string]any`); add observability via a new `vector` value and `Fields` keys only. (OCSF registry exhaustiveness is keyed on `EventType` — reusing `tor_control` leaves it untouched.)
- **No new config knobs.** Behavior derives from existing `tor.mode` / `onion_rules` / `socks_ports`.
- **Never mutate the shared `tor.Policy` or the global `*policy.Engine` for one session.** `SetTorPolicy` writes `e.torChecker` without a lock; only ever call it on a freshly-constructed per-session engine, guarded by `eng != a.Policy()`.
- **Force-redirect is all-or-nothing.** If any force-redirect step fails to install, the session must NOT proceed with interceptor-up-but-unfiltered-Tor; `SetupNetNS` already `rollbackAll()`s on any rule failure and returns an error, which routes the session to the fail-closed branch.
- **Rule ordering invariant:** the loopback-DNAT rules for `socks_ports` MUST be emitted before the `127.0.0.0/8 -j RETURN` rule, or the RETURN short-circuits them.
- **Cross-compile:** `internal/netmonitor/netns_linux.go` is linux-only with a `netns_other.go` stub; any `SetupNetNS` signature change updates BOTH. `GOOS=windows go build ./...` must stay clean.
- **Staging discipline:** stage only changed files by explicit path; never `git add -A`/`git add .` (the repo carries untracked `.claude/worktrees/*`, `*.key.json`, `.agentsh/`, `.superpowers/sdd/*`).
- **Branch:** `feat-tor-phase3-gateway-failopen` (already created; design committed at `d797cf26`).

## File Structure

- `internal/api/session_policy.go` — add `attachSessionTor` (Task 0) + `attachDenyTor` (Task 3); both decorate a session engine with a Tor coordinator.
- `internal/api/core.go` — call `attachSessionTor` before each `s.SetPolicyEngine` (Task 0); call `applyTorFailClosed` after the transparent-network block (Task 3).
- `internal/tor/policy.go` — add `VectorGateway` const (Task 1).
- `internal/tor/gateway.go` — add `DenyModeClone` (Task 1).
- `internal/tor/event.go` — add `BuildGatewayEvent` (Task 1).
- `internal/netmonitor/netns_linux.go` — add `natOutputRules` pure helper + `torRedirectPorts` param to `SetupNetNS` + `route_localnet` (Task 2).
- `internal/netmonitor/netns_other.go` — update the `SetupNetNS` stub signature (Task 2).
- `internal/api/app.go` — pass `socksPorts` into `SetupNetNS`; emit the force-redirect event (Task 2/3); `gatewayBranchFor` predicate (Task 3); static startup advisory (Task 5).
- `internal/server/server.go` — static startup advisory log (Task 5).
- `docs/superpowers/specs/2026-06-14-tor-access-control-design.md` — append Phase 3 status (Task 5).

---

### Task 0: Attach the shared Tor coordinator to per-session engines

Fixes the pre-existing gap: a session that compiles its own engine from a named policy file gets `torChecker == nil`, so ptrace `CheckExecve`/`CheckNetwork` skip Tor entirely. The fail-closed seam (Task 3) builds on this.

**Files:**
- Modify: `internal/api/session_policy.go` (add helper)
- Modify: `internal/api/core.go:568`, `:758`, `:1500` (call sites — verify exact lines before editing)
- Test: `internal/api/session_policy_tor_test.go` (create)

**Interfaces:**
- Consumes: `App.torPolicy *tor.Policy` (app.go:130); `App.Policy() *policy.Engine`; `policy.Engine.SetTorPolicy(tc policy.TorChecker)`; `tor.PolicyAdapter{Policy: *tor.Policy}` (satisfies `policy.TorChecker`).
- Produces: `func (a *App) attachSessionTor(eng *policy.Engine)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/api/session_policy_tor_test.go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/tor"
)

func newDenyTorPolicy(t *testing.T) *tor.Policy {
	t.Helper()
	p, err := tor.New(config.ResolveTorConfig(config.TorConfig{Mode: "deny"}))
	if err != nil {
		t.Fatalf("tor.New: %v", err)
	}
	return p
}

// A per-session engine (distinct from the global one) must enforce Tor after
// attachSessionTor — without it, CheckExecve("tor") would be allowed.
func TestAttachSessionTor_PerSessionEngineEnforcesTor(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{torPolicy: newDenyTorPolicy(t), policy: global}

	sessionEng, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	a.attachSessionTor(sessionEng)

	dec := sessionEng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Action != "deny" {
		t.Fatalf("per-session engine should deny the tor binary, got action=%q", dec.Action)
	}
}

// The global engine must NOT be re-decorated (guard prevents racing shared state).
func TestAttachSessionTor_SkipsGlobalEngine(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{torPolicy: newDenyTorPolicy(t), policy: global}
	a.attachSessionTor(global) // same pointer as a.Policy()
	// Global had no tor checker; attaching to it is skipped, so tor stays absent.
	dec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Action == "deny" {
		t.Fatal("global engine must not be decorated by attachSessionTor")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestAttachSessionTor -v`
Expected: FAIL — `a.attachSessionTor` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/session_policy.go` (add `"github.com/agentsh/agentsh/internal/tor"` to imports):

```go
// attachSessionTor installs the shared Tor coordinator on a per-session engine.
// The process-global engine already carries it (set once at server start in
// server.go); sessions that compiled their own engine from a named policy file
// would otherwise have torChecker == nil, silently skipping the ptrace
// connect/execve Tor vectors. Guarded so the shared global engine is never
// re-written (SetTorPolicy is unsynchronized).
func (a *App) attachSessionTor(eng *policy.Engine) {
	if a == nil || a.torPolicy == nil || eng == nil {
		return
	}
	if eng == a.Policy() {
		return
	}
	eng.SetTorPolicy(&tor.PolicyAdapter{Policy: a.torPolicy})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestAttachSessionTor -v`
Expected: PASS (both).

- [ ] **Step 5: Wire the three call sites**

In `internal/api/core.go`, immediately before each `s.SetPolicyEngine(engine)` (lines ~568, ~758, ~1500 — confirm by reading), insert:

```go
	a.attachSessionTor(engine)
	s.SetPolicyEngine(engine)
```

(At line ~1500 the variable is also `engine`; verify the local name at each site and match it.)

- [ ] **Step 6: Build + full api package test + commit**

Run: `go build ./... && go test ./internal/api/ -run 'TestAttachSessionTor|TestSession' -v`
Expected: PASS.

```bash
git add internal/api/session_policy.go internal/api/session_policy_tor_test.go internal/api/core.go
git commit -m "fix(tor): attach Tor coordinator to per-session policy engines"
```

---

### Task 1: tor-package primitives (VectorGateway, DenyModeClone, BuildGatewayEvent)

**Files:**
- Modify: `internal/tor/policy.go` (add `VectorGateway` const)
- Modify: `internal/tor/gateway.go` (add `DenyModeClone`)
- Modify: `internal/tor/event.go` (add `BuildGatewayEvent`)
- Test: `internal/tor/gateway_test.go` (add cases), `internal/tor/event_test.go` (add cases) — create if absent.

**Interfaces:**
- Consumes: `tor.New(cfg config.ResolvedTorConfig) (*Policy, error)`; `Policy.cfg config.ResolvedTorConfig` (unexported, same package); `ModeDeny` const; `types.Event`.
- Produces: `const VectorGateway = "gateway"`; `func (p *Policy) DenyModeClone() (*Policy, error)`; `func BuildGatewayEvent(sessionID, decision, reason string, enforced bool) types.Event`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/tor/gateway_test.go (add)
func TestDenyModeClone_ForcesDenyWithoutMutatingOriginal(t *testing.T) {
	allow, err := New(config.ResolveTorConfig(config.TorConfig{
		Mode:       "allow",
		OnionRules: []config.TorOnionRule{{Onion: "*", Decision: "deny"}},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	deny, err := allow.DenyModeClone()
	if err != nil {
		t.Fatalf("DenyModeClone: %v", err)
	}
	if deny.Mode() != ModeDeny {
		t.Fatalf("clone mode = %q, want deny", deny.Mode())
	}
	if allow.Mode() != ModeAllow {
		t.Fatalf("original mutated: mode = %q, want allow", allow.Mode())
	}
	// Deny-mode clone enforces the Phase-1 execve vector; allow-mode never does.
	if _, ok := deny.EvalExecve("/usr/bin/tor", nil); !ok {
		t.Fatal("deny clone should match the tor binary via EvalExecve")
	}
	if _, ok := allow.EvalExecve("/usr/bin/tor", nil); ok {
		t.Fatal("allow-mode original should not produce an execve verdict")
	}
}
```

```go
// internal/tor/event_test.go (add)
func TestBuildGatewayEvent_Fields(t *testing.T) {
	ev := BuildGatewayEvent("session-1", "deny", "proxy_env_fallback", false)
	if ev.Type != "tor_control" {
		t.Fatalf("type = %q, want tor_control", ev.Type)
	}
	if ev.Fields["vector"] != VectorGateway {
		t.Fatalf("vector = %v, want %q", ev.Fields["vector"], VectorGateway)
	}
	if ev.Fields["decision"] != "deny" || ev.Fields["reason"] != "proxy_env_fallback" {
		t.Fatalf("unexpected fields: %v", ev.Fields)
	}
	if ev.Fields["enforced"] != false {
		t.Fatalf("enforced = %v, want false", ev.Fields["enforced"])
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tor/ -run 'TestDenyModeClone|TestBuildGatewayEvent' -v`
Expected: FAIL — undefined `DenyModeClone`, `BuildGatewayEvent`, `VectorGateway`.

- [ ] **Step 3: Implement**

In `internal/tor/policy.go`, add to the Vector constants block:

```go
	VectorGateway   = "gateway" // Phase 3 session-level onion-gateway wiring outcome
```

In `internal/tor/gateway.go`, add:

```go
// DenyModeClone returns a sibling Policy built from the same resolved config
// but with Mode forced to deny. Used for fail-closed sessions where the onion
// gateway cannot be wired: the session enforces Phase-1 Tor deny instead of
// silently allowing unfiltered Tor. The receiver is not modified.
func (p *Policy) DenyModeClone() (*Policy, error) {
	if p == nil {
		return nil, nil
	}
	cfg := p.cfg // value copy; New only reads the (shared) slices
	cfg.Mode = ModeDeny
	return New(cfg)
}
```

In `internal/tor/event.go`, add (imports `time`, `uuid`, `types` are already present):

```go
// BuildGatewayEvent constructs a session-level tor_control event describing the
// Phase 3 onion-gateway wiring outcome. decision is "allow" (force-redirect
// armed) or "deny" (fail-closed). reason names the cause. enforced is false
// only when a fail-closed deny cannot actually be enforced (no live syscall
// enforcement subsystem for the session).
func BuildGatewayEvent(sessionID, decision, reason string, enforced bool) types.Event {
	return types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "tor_control",
		SessionID: sessionID,
		Fields: map[string]any{
			"vector":   VectorGateway,
			"decision": decision,
			"reason":   reason,
			"enforced": enforced,
			"rule":     "tor",
		},
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tor/ -run 'TestDenyModeClone|TestBuildGatewayEvent' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tor/policy.go internal/tor/gateway.go internal/tor/event.go internal/tor/gateway_test.go internal/tor/event_test.go
git commit -m "feat(tor): VectorGateway, DenyModeClone, BuildGatewayEvent (Phase 3 primitives)"
```

---

### Task 2: netns force-redirect (loopback-DNAT for socks_ports)

**Files:**
- Modify: `internal/netmonitor/netns_linux.go` (add `natOutputRules` + `torRedirectPorts` param + `route_localnet`)
- Modify: `internal/netmonitor/netns_other.go` (stub signature)
- Modify: `internal/api/app.go:715` (pass `socksPorts` into `SetupNetNS`)
- Test: `internal/netmonitor/netns_rules_test.go` (create — pure, no root)

**Interfaces:**
- Consumes: existing `SetupNetNS(ctx, nsName, subnetCIDR, hostIf, nsIf, hostIPCIDR, nsIPCIDR string, proxyTCPPort, dnsUDPPort int) (*NetNS, error)`; `a.torGateway()` → `(pol, upstream, socksPorts, ok)`.
- Produces: `SetupNetNS(..., dnsUDPPort int, torRedirectPorts []int) (*NetNS, error)` (new final param); `func natOutputRules(hostIP, hostTCP, hostDNS string, torRedirectPorts []int) [][]string`.

- [ ] **Step 1: Write the failing test (pure rule generation)**

```go
// internal/netmonitor/netns_rules_test.go
//go:build linux

package netmonitor

import "testing"

func TestNatOutputRules_LoopbackDNATBeforeLoopbackReturn(t *testing.T) {
	rules := natOutputRules("10.0.0.1", "10.0.0.1:5000", "10.0.0.1:5300", []int{9050, 9150})

	idxReturn := -1
	idx9050, idx9150 := -1, -1
	for i, r := range rules {
		joined := ""
		for _, a := range r {
			joined += a + " "
		}
		switch {
		case contains(r, "127.0.0.0/8") && contains(r, "RETURN"):
			idxReturn = i
		case contains(r, "127.0.0.1") && contains(r, "9050"):
			idx9050 = i
		case contains(r, "127.0.0.1") && contains(r, "9150"):
			idx9150 = i
		}
		_ = joined
	}
	if idx9050 < 0 || idx9150 < 0 || idxReturn < 0 {
		t.Fatalf("missing rules: dnat9050=%d dnat9150=%d return=%d", idx9050, idx9150, idxReturn)
	}
	if idx9050 >= idxReturn || idx9150 >= idxReturn {
		t.Fatalf("loopback DNAT must precede 127.0.0.0/8 RETURN: dnat9050=%d dnat9150=%d return=%d", idx9050, idx9150, idxReturn)
	}
}

func TestNatOutputRules_NoTorPorts_NoLoopbackDNAT(t *testing.T) {
	rules := natOutputRules("10.0.0.1", "10.0.0.1:5000", "10.0.0.1:5300", nil)
	for _, r := range rules {
		if contains(r, "127.0.0.1") && contains(r, "DNAT") {
			t.Fatal("no Tor ports → no loopback DNAT rule expected")
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/netmonitor/ -run TestNatOutputRules -v`
Expected: FAIL — `natOutputRules` undefined.

- [ ] **Step 3: Implement `natOutputRules` + rewire `SetupNetNS`**

In `internal/netmonitor/netns_linux.go` add `"strconv"` to imports, and add:

```go
// natOutputRules returns the ordered nat OUTPUT rule bodies (args after
// "OUTPUT") for the session netns. Tor SOCKS ports get a loopback DNAT inserted
// BEFORE the 127.0.0.0/8 RETURN so the app's connect(127.0.0.1:<port>) is
// steered across the veth to the host interceptor; all other loopback traffic
// is still exempted. Ordering is a correctness invariant (see Phase 3 design).
func natOutputRules(hostIP, hostTCP, hostDNS string, torRedirectPorts []int) [][]string {
	rules := [][]string{
		{"-d", hostIP, "-j", "RETURN"},
	}
	for _, p := range torRedirectPorts {
		rules = append(rules, []string{
			"-d", "127.0.0.1", "-p", "tcp", "--dport", strconv.Itoa(p),
			"-j", "DNAT", "--to-destination", hostTCP,
		})
	}
	rules = append(rules,
		[]string{"-d", "127.0.0.0/8", "-j", "RETURN"},
		[]string{"-p", "tcp", "-j", "DNAT", "--to-destination", hostTCP},
		[]string{"-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", hostDNS},
	)
	return rules
}
```

Change the `SetupNetNS` signature to add the final param:

```go
func SetupNetNS(ctx context.Context, nsName string, subnetCIDR string, hostIf string, nsIf string, hostIPCIDR string, nsIPCIDR string, proxyTCPPort int, dnsUDPPort int, torRedirectPorts []int) (*NetNS, error) {
```

Replace the inline OUTPUT-rule block (currently lines ~121–144, from `hostTCP := ...` through the udp DNAT) with:

```go
	// Netns DNAT outbound to host-side interceptors.
	hostTCP := fmt.Sprintf("%s:%d", hostIP, proxyTCPPort)
	hostDNS := fmt.Sprintf("%s:%d", hostIP, dnsUDPPort)
	if len(torRedirectPorts) > 0 {
		// Permit routing of loopback-destined packets so the Tor SOCKS DNAT can
		// forward them across the veth to the host interceptor.
		if err := run(ctx, "ip", "netns", "exec", nsName, "sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"); err != nil {
			rollbackAll()
			cleanupNS()
			return nil, err
		}
	}
	for _, body := range natOutputRules(hostIP, hostTCP, hostDNS, torRedirectPorts) {
		args := append([]string{"ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT"}, body...)
		if err := run(ctx, args[0], args[1:]...); err != nil {
			rollbackAll()
			cleanupNS()
			return nil, err
		}
	}
```

- [ ] **Step 4: Update the non-linux stub**

In `internal/netmonitor/netns_other.go`, match the new signature:

```go
func SetupNetNS(ctx context.Context, nsName string, subnetCIDR string, hostIf string, nsIf string, hostIPCIDR string, nsIPCIDR string, proxyTCPPort int, dnsUDPPort int, torRedirectPorts []int) (*NetNS, error) {
```

(Keep its existing body, e.g. `return nil, errNetNSUnsupported` — read the file and preserve whatever it returns.)

- [ ] **Step 5: Pass the ports from app.go**

In `internal/api/app.go` `tryStartTransparentNetwork`, capture the gateway ports and pass them. Replace the gateway block + `SetupNetNS` call:

```go
	var torRedirectPorts []int
	if pol, upstream, socksPorts, ok := a.torGateway(); ok {
		tcp.SetTorGateway(pol, upstream, socksPorts)
		torRedirectPorts = socksPorts
		slog.Info("tor onion gateway active for session", "session", s.ID, "upstream", upstream)
	}
	// ... StartDNS unchanged ...
	ns, err := netmonitor.SetupNetNS(ctx, nsName, subnetCIDR, hostIf, nsIf, hostIPCIDR, nsIPCIDR, tcpPort, dnsPort, torRedirectPorts)
```

- [ ] **Step 6: Run tests + both builds**

Run: `go test ./internal/netmonitor/ -run TestNatOutputRules -v && go build ./... && GOOS=windows go build ./...`
Expected: PASS; both builds clean.

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/netns_linux.go internal/netmonitor/netns_other.go internal/netmonitor/netns_rules_test.go internal/api/app.go
git commit -m "feat(tor): netns loopback-DNAT force-redirect of Tor SOCKS ports"
```

---

### Task 3: Branch predicate + fail-closed deny + gateway events

**Files:**
- Modify: `internal/api/app.go` (add `gatewayBranchFor`; emit force-redirect event in `tryStartTransparentNetwork`)
- Modify: `internal/api/session_policy.go` (add `attachDenyTor`)
- Modify: `internal/api/core.go` (call `applyTorFailClosed` after the transparent-network block ~813)
- Test: `internal/api/tor_failclosed_test.go` (create)

**Interfaces:**
- Consumes: `App.torPolicy`; `Policy.GatewayActive()`; `Policy.DenyModeClone()`; `tor.BuildGatewayEvent`; `clonePolicy`; `policy.NewEngineWithVariables`; `App.execveEnforcementActive()`; `s.PolicyEngine()` / `s.SetPolicyEngine()`.
- Produces: `func gatewayBranchFor(gatewayActive, interceptorUp bool) gatewayBranch`; `func (a *App) attachDenyTor(s *session.Session, deny *tor.Policy) bool`; `func (a *App) applyTorFailClosed(ctx context.Context, s *session.Session, interceptorUp bool)`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/api/tor_failclosed_test.go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/tor"
)

func TestGatewayBranchFor(t *testing.T) {
	cases := []struct {
		active, up bool
		want       gatewayBranch
	}{
		{false, false, gatewayNone},
		{false, true, gatewayNone},
		{true, true, gatewayForceRedirect},
		{true, false, gatewayFailClosed},
	}
	for _, c := range cases {
		if got := gatewayBranchFor(c.active, c.up); got != c.want {
			t.Fatalf("gatewayBranchFor(%v,%v)=%v want %v", c.active, c.up, got, c.want)
		}
	}
}

// Default-engine session: attachDenyTor must give it a NEW per-session engine
// that denies Tor, without mutating the shared global engine.
func TestAttachDenyTor_DefaultEngine_ClonesAndDenies(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global: %v", err)
	}
	a := &App{policy: global, cfg: &config.Config{}}
	deny, _ := tor.New(config.ResolveTorConfig(config.TorConfig{Mode: "deny"}))

	s := &session.Session{} // PolicyEngine() == nil → policyEngineFor returns global
	ok := a.attachDenyTor(s, deny)
	if !ok {
		t.Fatal("attachDenyTor should succeed")
	}
	if s.PolicyEngine() == nil || s.PolicyEngine() == global {
		t.Fatal("session must get its own cloned engine, not the global one")
	}
	if dec := s.PolicyEngine().CheckExecve("/usr/bin/tor", []string{"tor"}, 0); dec.Action != "deny" {
		t.Fatalf("session engine should deny tor, got %q", dec.Action)
	}
	if dec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); dec.Action == "deny" {
		t.Fatal("global engine must remain undecorated")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/api/ -run 'TestGatewayBranchFor|TestAttachDenyTor' -v`
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Implement the predicate (app.go)**

```go
type gatewayBranch int

const (
	gatewayNone gatewayBranch = iota
	gatewayForceRedirect
	gatewayFailClosed
)

// gatewayBranchFor selects the Phase 3 branch from the per-session predicate.
func gatewayBranchFor(gatewayActive, interceptorUp bool) gatewayBranch {
	switch {
	case !gatewayActive:
		return gatewayNone
	case interceptorUp:
		return gatewayForceRedirect
	default:
		return gatewayFailClosed
	}
}
```

- [ ] **Step 4: Implement `attachDenyTor` (session_policy.go)**

```go
// attachDenyTor makes a session enforce Tor deny (fail-closed). If the session
// already has its OWN engine, the deny coordinator is installed on it directly.
// Otherwise the session is using the shared global engine; we clone that
// engine's policy, attach deny-Tor to the clone, and install it per session —
// never mutating shared state. Returns true if a deny coordinator was installed.
func (a *App) attachDenyTor(s *session.Session, deny *tor.Policy) bool {
	if a == nil || s == nil || deny == nil {
		return false
	}
	adapter := &tor.PolicyAdapter{Policy: deny}
	if eng := s.PolicyEngine(); eng != nil && eng != a.Policy() {
		eng.SetTorPolicy(adapter)
		return true
	}
	base := a.Policy().Policy()
	clone := clonePolicy(base)
	enforceApprovals := a.cfg.Approvals.Enabled && a.cfg.Approvals.Mode != ""
	eng, err := policy.NewEngineWithVariables(clone, enforceApprovals, true, nil)
	if err != nil || eng == nil {
		return false
	}
	eng.SetTorPolicy(adapter)
	s.SetPolicyEngine(eng)
	return true
}
```

- [ ] **Step 5: Implement `applyTorFailClosed` (session_policy.go) + emit force-redirect event (app.go)**

In `internal/api/session_policy.go`:

```go
// applyTorFailClosed denies Tor for a session when the onion gateway is active
// in policy but could not be wired (proxy-env fallback or transparent disabled).
// No-op when the gateway is inactive or the interceptor came up (force-redirect
// handled it). Emits one session-level gateway event recording the outcome.
func (a *App) applyTorFailClosed(ctx context.Context, s *session.Session, interceptorUp bool) {
	if a.torPolicy == nil || !a.torPolicy.GatewayActive() {
		return
	}
	if gatewayBranchFor(true, interceptorUp) != gatewayFailClosed {
		return
	}
	deny, err := a.torPolicy.DenyModeClone()
	attached := false
	if err == nil {
		attached = a.attachDenyTor(s, deny)
	}
	enforced := attached && a.execveEnforcementActive()
	reason := "proxy_env_fallback"
	if !a.cfg.Sandbox.Network.Transparent.Enabled {
		reason = "transparent_disabled"
	}
	ev := tor.BuildGatewayEvent(s.ID, "deny", reason, enforced)
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
}
```

In `internal/api/app.go` `tryStartTransparentNetwork`, after `SetupNetNS` succeeds and when `len(torRedirectPorts) > 0`, emit the armed event (place just before the function's `return nil`):

```go
	if len(torRedirectPorts) > 0 {
		gw := tor.BuildGatewayEvent(s.ID, "allow", "force_redirect_installed", true)
		_ = a.store.AppendEvent(ctx, gw)
		a.broker.Publish(gw)
	}
```

(Add `"github.com/agentsh/agentsh/internal/tor"` to app.go imports if not already present.)

- [ ] **Step 6: Call `applyTorFailClosed` from core.go**

In `internal/api/core.go`, replace the transparent-network block (~811–end of that `if`) so the interceptor outcome is captured and fail-closed runs in every path:

```go
	interceptorUp := false
	if a.cfg.Sandbox.Network.Transparent.Enabled {
		if err := a.tryStartTransparentNetwork(ctx, s); err != nil {
			fail := types.Event{ /* existing transparent_net_failed event, unchanged */ }
			_ = a.store.AppendEvent(ctx, fail)
			a.broker.Publish(fail)
		} else {
			interceptorUp = true
		}
	}
	a.applyTorFailClosed(ctx, s, interceptorUp)
```

(Preserve the existing `transparent_net_failed` event body exactly; only add the `interceptorUp` tracking and the `applyTorFailClosed` call.)

- [ ] **Step 7: Run tests + build**

Run: `go test ./internal/api/ -run 'TestGatewayBranchFor|TestAttachDenyTor|TestAttachSessionTor' -v && go build ./... && GOOS=windows go build ./...`
Expected: PASS; builds clean.

- [ ] **Step 8: Commit**

```bash
git add internal/api/app.go internal/api/session_policy.go internal/api/core.go internal/api/tor_failclosed_test.go
git commit -m "feat(tor): Phase 3 branch predicate + fail-closed deny + gateway events"
```

---

### Task 4: Gated netns integration test (loopback Tor → gateway filters)

Proves force-redirect end-to-end: loopback traffic to a Tor SOCKS port is actually filtered by `onion_rules`. Needs root + Linux + iptables; gated like the repo's other netns integration tests.

**Files:**
- Test: `internal/api/tor_gateway_integration_linux_test.go` (create)

**Interfaces:**
- Consumes: the same gating helper the existing netns/transparent integration tests use (find it: `grep -rn "skip" internal/api/*linux_test.go | grep -i 'root\|netns'`). Reuse that skip guard verbatim.

- [ ] **Step 1: Write the integration test**

Model it on the nearest existing transparent-network integration test (locate with `grep -rln "SetupNetNS\|StartTransparentTCP" internal/api/*_test.go`). The test must:
1. Skip unless running as root on Linux with iptables available (reuse the existing guard).
2. Start a fake Tor SOCKS5 server bound to `127.0.0.1:9050` that completes the SOCKS handshake and echoes (reuse the fake-upstream pattern from `internal/netmonitor/socks_handler_test.go`).
3. Build an `App` with `tor.mode: allow` and `onion_rules: [{onion: "allowed.onion", decision: allow}, {onion: "*", decision: deny}]`, transparent network enabled.
4. Create a session, then from inside the netns (`ip netns exec <ns> ...` or a dialer bound into the ns) issue two SOCKS CONNECTs to `127.0.0.1:9050` — one to `allowed.onion:80`, one to `blocked.onion:80`.
5. Assert the allowed target gets a success SOCKS reply and the blocked target gets `socksRepNotAllowed` (0x02) — proving the loopback connection reached `handleTorSocks` via the force-redirect.

- [ ] **Step 2: Run (on a root Linux host)**

Run: `sudo -E go test ./internal/api/ -run TestTorGatewayForceRedirect_Integration -v`
Expected: PASS where privileged; SKIP otherwise. Also confirm it SKIPs cleanly as non-root: `go test ./internal/api/ -run TestTorGatewayForceRedirect_Integration -v`.

- [ ] **Step 3: Commit**

```bash
git add internal/api/tor_gateway_integration_linux_test.go
git commit -m "test(tor): gated netns integration — loopback Tor reaches the gateway"
```

---

### Task 5: Static startup advisory + spec status + final gates

**Files:**
- Modify: `internal/server/server.go` (advisory log near the tor-enable block ~206–218)
- Modify: `docs/superpowers/specs/2026-06-14-tor-access-control-design.md` (append Phase 3 status)
- Test: none new (advisory is a log line; covered by build).

- [ ] **Step 1: Add the startup advisory**

In `internal/server/server.go`, inside the `if torCfg.Enabled` block after the policy is built, add:

```go
		if torCfg.Mode == "allow" && len(torCfg.OnionRules) > 0 && !cfg.Sandbox.Network.Transparent.Enabled {
			slog.Warn("tor onion gateway configured (mode=allow + onion_rules) but transparent network is disabled; every session will fail-closed (Tor denied). Enable sandbox.network.transparent to use the gateway.")
		}
```

- [ ] **Step 2: Update the design spec status**

In `docs/superpowers/specs/2026-06-14-tor-access-control-design.md`, under the Phase 2 "Honest scope (Phase 2)" paragraph, append a short note:

```markdown
**Phase 3 (fail-open gap closed — implemented).** The silent degrade described
above is closed: in netns transparent mode a loopback-DNAT force-redirect steers
the app's Tor SOCKS connection into the gateway automatically; in any mode where
the gateway cannot be wired the session fails closed (Tor denied, `tor_control`
`vector: gateway` audit event). See
`docs/superpowers/specs/2026-06-20-tor-access-control-phase3-design.md`.
```

- [ ] **Step 3: Full gates**

Run:
```
go build ./...
GOOS=windows go build ./...
gofmt -l internal/api internal/tor internal/netmonitor internal/server
go test ./internal/tor/ ./internal/netmonitor/ ./internal/api/ ./internal/server/
go test ./...
```
Expected: builds clean; `gofmt -l` empty; touched packages green; full suite green except known pre-existing local-env flakes (the `internal/fsmonitor` FUSE flake and the documented `-race` DB-proxy/transport-loss flakes are not regressions).

- [ ] **Step 4: Commit**

```bash
git add internal/server/server.go docs/superpowers/specs/2026-06-14-tor-access-control-design.md
git commit -m "feat(tor): startup advisory for ungatewayable allow-mode + Phase 3 spec status"
```

---

## Self-Review

**Spec coverage:** Force-redirect (Branch 1) → Task 2 + Task 3 event. Fail-closed (Branch 2) → Task 3 (`applyTorFailClosed`/`attachDenyTor`), posture = deny + audit. Per-session-engine Tor attachment (the discovered gap, folded in by user decision) → Task 0. No-new-knobs → honored (only derived behavior). Events (`vector: gateway`, `reason`, `enforced`) → Task 1 + Task 3. Rule ordering / fully-installed-or-deny → Task 2 (ordering test + `SetupNetNS` rollback routing to fail-closed). Honest-scope floor (`enforced: false`) → Task 3 (`enforced := attached && execveEnforcementActive()`). Static advisory → Task 5. Testing matrix → Tasks 0–4. Cross-compile → Task 2/5.

**Type consistency:** `SetupNetNS` final param `torRedirectPorts []int` is used identically in netns_linux.go, netns_other.go, and the app.go call. `attachSessionTor`/`attachDenyTor`/`applyTorFailClosed`/`gatewayBranchFor`/`natOutputRules`/`DenyModeClone`/`BuildGatewayEvent` signatures match between their definition task and consumer task. `gatewayBranch` constants (`gatewayNone`/`gatewayForceRedirect`/`gatewayFailClosed`) defined in Task 3 Step 3, consumed in Step 4–5 and the test.

**Placeholder scan:** the integration test (Task 4) intentionally describes structure rather than full code because it must mirror an existing in-repo gating helper and fake-upstream pattern the implementer will locate; every other code step contains complete, compilable code.
