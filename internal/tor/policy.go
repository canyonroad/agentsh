package tor

import (
	"net"
	"path/filepath"
	"strconv"
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
	VectorOnion     = "onion" // Phase 2 SOCKS gateway
)

// Verdict is the result of a positive Tor match.
type Verdict struct {
	Vector   string // one of the Vector* constants
	Mode     string // resolved policy mode
	Decision string // "deny" or "audit"; also "allow" for the Phase 2 onion gateway
	Target   string // binary path, ip:port, or onion host
}

// Policy answers Tor questions for the enforcement points. Construct once
// via New; the relay set may be swapped concurrently via SetRelays.
type Policy struct {
	cfg          config.ResolvedTorConfig
	binBasenames map[string]struct{}
	binPatterns  []string // lowercased raw client_binary entries, for glob matching
	socksPorts   map[int]struct{}
	controlPorts map[int]struct{}
	seed         *ipset.Set                // directory-authority seed (immutable)
	relays       atomic.Pointer[ipset.Set] // feed-populated, hot-swappable
	onionRules   []onionRule               // Phase 2 gateway rules, compiled in order
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
		lb := strings.ToLower(b)
		p.binBasenames[lb] = struct{}{}
		p.binPatterns = append(p.binPatterns, lb)
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
	for _, r := range cfg.OnionRules {
		p.onionRules = append(p.onionRules, onionRule{
			pattern:  strings.ToLower(strings.TrimSpace(r.Onion)),
			decision: r.Decision,
		})
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

// EvalExecve reports whether filename is a Tor client binary. Configured
// entries match by exact basename (O(1) map) or as a path/basename glob
// (filepath.Match against the full lowercased path and the basename).
func (p *Policy) EvalExecve(filename string, argv []string) (Verdict, bool) {
	if !p.active() || !p.cfg.Vectors.Processes {
		return Verdict{}, false
	}
	base := strings.ToLower(filepath.Base(filename))
	if _, ok := p.binBasenames[base]; ok {
		return p.verdict(VectorProcess, filename)
	}
	lf := strings.ToLower(filename)
	for _, pat := range p.binPatterns {
		if m, err := filepath.Match(pat, base); err == nil && m {
			return p.verdict(VectorProcess, filename)
		}
		if m, err := filepath.Match(pat, lf); err == nil && m {
			return p.verdict(VectorProcess, filename)
		}
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
				return p.verdict(VectorSocksPort, net.JoinHostPort(ipString(ip), strconv.Itoa(port)))
			}
		}
	}
	if p.cfg.Vectors.RelayIPs && ip != nil {
		if p.seed.Contains(ip) || p.relays.Load().Contains(ip) {
			return p.verdict(VectorRelayIP, net.JoinHostPort(ipString(ip), strconv.Itoa(port)))
		}
	}
	return Verdict{}, false
}

// EvalOnionName reports whether host is a .onion address. The single
// vectors.onion toggle governs both the DNS and HTTP enforcement points
// (both flow through this method); events still tag the firing layer —
// the DNS path uses onion_dns and the HTTP proxy relabels to onion_http.
func (p *Policy) EvalOnionName(host string) (Verdict, bool) {
	if !p.active() || !p.cfg.Vectors.Onion {
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
