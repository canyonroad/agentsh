package config

import "time"

// TorConfig is the raw, as-parsed `tor:` block. A missing block
// deserializes to the zero value; ResolveTorConfig turns that into the
// deny-by-default posture. Enabled is a *bool tri-state (nil → true),
// matching the convention used by SandboxFUSEConfig and WaitKillable.
type TorConfig struct {
	Enabled           *bool          `yaml:"enabled"`
	Mode              string         `yaml:"mode"` // deny | audit | allow
	Vectors           TorVectors     `yaml:"vectors"`
	ClientBinaries    []string       `yaml:"client_binaries"`
	SocksPorts        []int          `yaml:"socks_ports"`
	ControlPorts      []int          `yaml:"control_ports"`
	SocksLoopbackOnly *bool          `yaml:"socks_loopback_only"`
	RelayFeed         TorRelayFeed   `yaml:"relay_feed"`
	OnionRules        []TorOnionRule `yaml:"onion_rules"`
}

// TorVectors toggles each enforcement door. Pointers so an operator can
// relax one door (set false) without the zero value disabling all.
type TorVectors struct {
	Processes  *bool `yaml:"processes"`
	SocksPorts *bool `yaml:"socks_ports"`
	Onion      *bool `yaml:"onion"`
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

// TorOnionRule is one Phase 2 gateway rule: match a SOCKS CONNECT target
// host (a .onion address or a clearnet host, with filepath.Match globbing)
// and allow or deny it. Evaluated in listed order, first match wins.
type TorOnionRule struct {
	Onion    string `yaml:"onion"`
	Decision string `yaml:"decision"` // allow | deny
}

// ResolvedTorConfig is the fully-defaulted, value-typed form consumed by
// internal/tor. All bools are concrete; all lists are non-empty unless
// the feature is disabled.
type ResolvedTorConfig struct {
	Enabled           bool
	Mode              string
	Vectors           ResolvedTorVectors
	ClientBinaries    []string
	SocksPorts        []int
	ControlPorts      []int
	SocksLoopbackOnly bool
	RelayFeed         TorRelayFeed
	OnionRules        []TorOnionRule
}

type ResolvedTorVectors struct {
	Processes, SocksPorts, Onion, RelayIPs bool
}

// DefaultTorClientBinaries is the recommended client-binary deny list.
var DefaultTorClientBinaries = []string{
	"tor", "obfs4proxy", "snowflake-client", "lyrebird", "meek-client", "torsocks",
}

// DefaultOnionooSource is the canonical relay-feed source used when the
// feed is enabled but no sources/local lists are configured.
const DefaultOnionooSource = "https://onionoo.torproject.org/details"

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
			Onion:      boolOr(in.Vectors.Onion, true),
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
	if out.RelayFeed.Enabled && len(out.RelayFeed.Sources) == 0 && len(out.RelayFeed.LocalLists) == 0 {
		out.RelayFeed.Sources = []string{DefaultOnionooSource}
	}
	for _, r := range in.OnionRules {
		decision := "deny"
		if r.Decision == "allow" {
			decision = "allow"
		}
		out.OnionRules = append(out.OnionRules, TorOnionRule{Onion: r.Onion, Decision: decision})
	}
	return out
}
