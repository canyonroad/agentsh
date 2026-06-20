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
